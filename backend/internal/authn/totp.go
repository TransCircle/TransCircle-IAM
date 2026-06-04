package authn

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp/totp"

	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/keys"
	"github.com/transcircle/iam/internal/store"
)

// TOTPService manages time-based one-time-password factors.
type TOTPService struct {
	ks     *keys.KeyStore
	issuer string
}

// NewTOTPService builds the service. issuer appears in the authenticator app.
func NewTOTPService(ks *keys.KeyStore, issuer string) *TOTPService {
	return &TOTPService{ks: ks, issuer: issuer}
}

func totpAAD(userID uuid.UUID) string { return "totp:" + userID.String() }

// BeginEnroll generates an unconfirmed TOTP secret and returns the otpauth URL
// (for the QR code). Overwrites any pending unconfirmed secret.
func (s *TOTPService) BeginEnroll(ctx context.Context, db store.DBTX, userID uuid.UUID, account string) (otpauthURL string, err error) {
	secret := crypto.NewTOTPSecretBase32(20)
	enc, nonce, ver, err := s.ks.EncryptSecret([]byte(secret), totpAAD(userID))
	if err != nil {
		return "", err
	}
	_, err = db.Exec(ctx,
		`INSERT INTO totp_secrets (user_id, secret_encrypted, secret_nonce, dek_version, confirmed_at)
		 VALUES ($1,$2,$3,$4,NULL)
		 ON CONFLICT (user_id) DO UPDATE
		   SET secret_encrypted=EXCLUDED.secret_encrypted, secret_nonce=EXCLUDED.secret_nonce,
		       dek_version=EXCLUDED.dek_version, confirmed_at=NULL`,
		userID, enc, nonce, ver)
	if err != nil {
		return "", err
	}
	return s.otpauthURL(account, secret), nil
}

// ConfirmEnroll validates the first code and marks the factor confirmed.
func (s *TOTPService) ConfirmEnroll(ctx context.Context, db store.DBTX, userID uuid.UUID, code string) error {
	secret, err := s.loadSecret(ctx, db, userID)
	if err != nil {
		return err
	}
	if !totp.Validate(code, secret) {
		return errors.New("authn: TOTP 验证码错误")
	}
	_, err = db.Exec(ctx, `UPDATE totp_secrets SET confirmed_at=now() WHERE user_id=$1`, userID)
	return err
}

// Verify validates a login TOTP code against the confirmed secret.
func (s *TOTPService) Verify(ctx context.Context, st *store.Store, userID uuid.UUID, code string) (bool, error) {
	secret, err := s.loadConfirmedSecret(ctx, st, userID)
	if err != nil {
		return false, err
	}
	return totp.Validate(code, secret), nil
}

// HasConfirmed reports whether the user has a confirmed TOTP factor.
func (s *TOTPService) HasConfirmed(ctx context.Context, db store.DBTX, userID uuid.UUID) (bool, error) {
	var n int
	err := db.QueryRow(ctx,
		`SELECT count(*) FROM totp_secrets WHERE user_id=$1 AND confirmed_at IS NOT NULL`, userID).Scan(&n)
	return n > 0, err
}

// Remove deletes the user's TOTP factor.
func (s *TOTPService) Remove(ctx context.Context, db store.DBTX, userID uuid.UUID) error {
	_, err := db.Exec(ctx, `DELETE FROM totp_secrets WHERE user_id=$1`, userID)
	return err
}

func (s *TOTPService) loadSecret(ctx context.Context, db store.DBTX, userID uuid.UUID) (string, error) {
	var enc, nonce []byte
	var ver int
	err := db.QueryRow(ctx,
		`SELECT secret_encrypted, secret_nonce, dek_version FROM totp_secrets WHERE user_id=$1`, userID).
		Scan(&enc, &nonce, &ver)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errors.New("authn: 未开始 TOTP 绑定")
	}
	if err != nil {
		return "", err
	}
	pt, err := s.ks.DecryptSecret(enc, nonce, ver, totpAAD(userID))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func (s *TOTPService) loadConfirmedSecret(ctx context.Context, st *store.Store, userID uuid.UUID) (string, error) {
	var enc, nonce []byte
	var ver int
	err := st.Pool.QueryRow(ctx,
		`SELECT secret_encrypted, secret_nonce, dek_version FROM totp_secrets WHERE user_id=$1 AND confirmed_at IS NOT NULL`, userID).
		Scan(&enc, &nonce, &ver)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", errors.New("authn: 无已确认的 TOTP")
	}
	if err != nil {
		return "", err
	}
	pt, err := s.ks.DecryptSecret(enc, nonce, ver, totpAAD(userID))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func (s *TOTPService) otpauthURL(account, secret string) string {
	label := url.PathEscape(s.issuer + ":" + account)
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", s.issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return fmt.Sprintf("otpauth://totp/%s?%s", label, v.Encode())
}

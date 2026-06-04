package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/store"
)

// WebAuthnService wraps go-webauthn. The relying-party config is loaded from the
// DB per request so admin edits take effect without redeploy (must-fix #13: edits
// are validated before save in the settings handler).
type WebAuthnService struct {
	st     *store.Store
	rdb    redis.UniversalClient
	issuer string
}

// NewWebAuthnService builds the service.
func NewWebAuthnService(st *store.Store, issuer string) *WebAuthnService {
	return &WebAuthnService{st: st, rdb: st.Redis, issuer: issuer}
}

// waUser adapts our user + credentials to the webauthn.User interface.
type waUser struct {
	id      []byte
	name    string
	display string
	creds   []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return u.id }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.display }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (s *WebAuthnService) instance(ctx context.Context) (*webauthn.WebAuthn, error) {
	var (
		rpID, rpName, uv string
		origins          []string
	)
	err := s.st.Pool.QueryRow(ctx,
		`SELECT rp_id, rp_display_name, origins, user_verification FROM webauthn_rp_config WHERE id=1`).
		Scan(&rpID, &rpName, &origins, &uv)
	if errors.Is(err, pgx.ErrNoRows) {
		// Fall back to issuer-derived defaults.
		u, _ := url.Parse(s.issuer)
		rpID = u.Hostname()
		rpName = "TransCircle IAM"
		origins = []string{s.issuer}
		uv = "required"
	} else if err != nil {
		return nil, err
	}
	return webauthn.New(&webauthn.Config{
		RPID:          rpID,
		RPDisplayName: rpName,
		RPOrigins:     origins,
	})
}

func (s *WebAuthnService) loadUser(ctx context.Context, u UserInfo) (*waUser, error) {
	rows, err := s.st.Pool.Query(ctx,
		`SELECT credential_id, public_key, attestation_type, aaguid, sign_count, transports, backup_eligible, backup_state
		   FROM webauthn_credentials WHERE user_id=$1`, u.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	wu := &waUser{id: u.ID[:], name: u.Username, display: u.DisplayName}
	for rows.Next() {
		var (
			credID, pub, aaguid []byte
			attType             string
			signCount           int64
			transports          []string
			be, bs              bool
		)
		if err := rows.Scan(&credID, &pub, &attType, &aaguid, &signCount, &transports, &be, &bs); err != nil {
			return nil, err
		}
		tr := make([]protocol.AuthenticatorTransport, len(transports))
		for i, t := range transports {
			tr[i] = protocol.AuthenticatorTransport(t)
		}
		wu.creds = append(wu.creds, webauthn.Credential{
			ID:              credID,
			PublicKey:       pub,
			AttestationType: attType,
			Transport:       tr,
			Flags:           webauthn.CredentialFlags{BackupEligible: be, BackupState: bs},
			Authenticator:   webauthn.Authenticator{AAGUID: aaguid, SignCount: uint32(signCount)},
		})
	}
	return wu, rows.Err()
}

// UserInfo is the minimal user identity needed for WebAuthn ceremonies.
type UserInfo struct {
	ID          uuid.UUID
	Username    string
	DisplayName string
}

const waSessionTTL = 2 * time.Minute

func regKey(ticket string) string   { return "auth:webauthn:reg:" + ticket }
func loginKey(ticket string) string { return "auth:webauthn:login:" + ticket }

// BeginRegistration starts a passkey registration ceremony.
func (s *WebAuthnService) BeginRegistration(ctx context.Context, u UserInfo) (options *protocol.CredentialCreation, ticket string, err error) {
	w, err := s.instance(ctx)
	if err != nil {
		return nil, "", err
	}
	wu, err := s.loadUser(ctx, u)
	if err != nil {
		return nil, "", err
	}
	opts, session, err := w.BeginRegistration(wu)
	if err != nil {
		return nil, "", err
	}
	ticket, err = s.storeSession(ctx, regKey, session)
	if err != nil {
		return nil, "", err
	}
	return opts, ticket, nil
}

// FinishRegistration verifies the attestation and persists the new credential.
func (s *WebAuthnService) FinishRegistration(ctx context.Context, db store.DBTX, u UserInfo, ticket, name string, r *http.Request) error {
	w, err := s.instance(ctx)
	if err != nil {
		return err
	}
	session, err := s.takeSession(ctx, regKey, ticket)
	if err != nil {
		return err
	}
	wu, err := s.loadUser(ctx, u)
	if err != nil {
		return err
	}
	cred, err := w.FinishRegistration(wu, *session, r)
	if err != nil {
		return fmt.Errorf("authn: 注册验证失败: %w", err)
	}
	transports := make([]string, len(cred.Transport))
	for i, t := range cred.Transport {
		transports[i] = string(t)
	}
	if name == "" {
		name = "通行密钥"
	}
	_, err = db.Exec(ctx,
		`INSERT INTO webauthn_credentials
		   (id, user_id, credential_id, public_key, attestation_type, aaguid, sign_count, transports, backup_eligible, backup_state, name)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		crypto.NewUUIDv7(), u.ID, cred.ID, cred.PublicKey, cred.AttestationType, cred.Authenticator.AAGUID,
		int64(cred.Authenticator.SignCount), transports, cred.Flags.BackupEligible, cred.Flags.BackupState, name)
	return err
}

// BeginLogin starts a passkey assertion ceremony.
func (s *WebAuthnService) BeginLogin(ctx context.Context, u UserInfo) (options *protocol.CredentialAssertion, ticket string, err error) {
	w, err := s.instance(ctx)
	if err != nil {
		return nil, "", err
	}
	wu, err := s.loadUser(ctx, u)
	if err != nil {
		return nil, "", err
	}
	if len(wu.creds) == 0 {
		return nil, "", errors.New("authn: 该用户未绑定通行密钥")
	}
	opts, session, err := w.BeginLogin(wu)
	if err != nil {
		return nil, "", err
	}
	ticket, err = s.storeSession(ctx, loginKey, session)
	if err != nil {
		return nil, "", err
	}
	return opts, ticket, nil
}

// FinishLogin verifies the assertion and updates the credential sign counter.
func (s *WebAuthnService) FinishLogin(ctx context.Context, u UserInfo, ticket string, r *http.Request) error {
	w, err := s.instance(ctx)
	if err != nil {
		return err
	}
	session, err := s.takeSession(ctx, loginKey, ticket)
	if err != nil {
		return err
	}
	wu, err := s.loadUser(ctx, u)
	if err != nil {
		return err
	}
	cred, err := w.FinishLogin(wu, *session, r)
	if err != nil {
		return fmt.Errorf("authn: 通行密钥验证失败: %w", err)
	}
	_, _ = s.st.Pool.Exec(ctx,
		`UPDATE webauthn_credentials SET sign_count=$2, last_used_at=now() WHERE credential_id=$1`,
		cred.ID, int64(cred.Authenticator.SignCount))
	return nil
}

// HasCredential reports whether the user has at least one passkey.
func (s *WebAuthnService) HasCredential(ctx context.Context, db store.DBTX, userID uuid.UUID) (bool, error) {
	var n int
	err := db.QueryRow(ctx, `SELECT count(*) FROM webauthn_credentials WHERE user_id=$1`, userID).Scan(&n)
	return n > 0, err
}

// Credential is a user-facing passkey summary.
type Credential struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// ListCredentials returns a user's passkeys.
func (s *WebAuthnService) ListCredentials(ctx context.Context, userID uuid.UUID) ([]Credential, error) {
	rows, err := s.st.Pool.Query(ctx,
		`SELECT id, name, created_at, last_used_at FROM webauthn_credentials WHERE user_id=$1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.ID, &c.Name, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteCredential removes one passkey belonging to the user.
func (s *WebAuthnService) DeleteCredential(ctx context.Context, db store.DBTX, userID, credID uuid.UUID) error {
	_, err := db.Exec(ctx, `DELETE FROM webauthn_credentials WHERE id=$1 AND user_id=$2`, credID, userID)
	return err
}

func (s *WebAuthnService) storeSession(ctx context.Context, keyFn func(string) string, session *webauthn.SessionData) (string, error) {
	ticket := crypto.RandomToken(18)
	raw, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	if err := s.rdb.Set(ctx, keyFn(ticket), raw, waSessionTTL).Err(); err != nil {
		return "", err
	}
	return ticket, nil
}

func (s *WebAuthnService) takeSession(ctx context.Context, keyFn func(string) string, ticket string) (*webauthn.SessionData, error) {
	raw, err := s.rdb.GetDel(ctx, keyFn(ticket)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, errors.New("authn: 会话已过期，请重试")
	}
	if err != nil {
		return nil, err
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(raw, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

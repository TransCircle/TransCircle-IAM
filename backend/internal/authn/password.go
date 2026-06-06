// Package authn implements credential verification and multi-factor enrollment:
// passwords (argon2id), WebAuthn/passkeys, TOTP, and one-time recovery codes.
package authn

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/store"
)

// ErrPasswordPolicy is returned when a new password violates policy.
var ErrPasswordPolicy = errors.New("authn: password policy violation")

// ErrNoCredential means the user has no password set.
var ErrNoCredential = errors.New("authn: no credential")

// PasswordService verifies and updates passwords with history + policy.
type PasswordService struct {
	hasher    *crypto.Hasher
	minLen    int
	historyN  int
	dummyHash string
}

// NewPasswordService builds the service. A dummy hash is precomputed so failed
// logins for unknown users still spend hashing time (anti-enumeration).
func NewPasswordService(h *crypto.Hasher, minLen, historyN int) *PasswordService {
	if minLen < 8 {
		minLen = 8
	}
	dummy, _ := h.Hash(context.Background(), crypto.RandomToken(16))
	return &PasswordService{hasher: h, minLen: minLen, historyN: historyN, dummyHash: dummy}
}

// BurnTime runs a verify against a dummy hash to equalize login timing.
func (s *PasswordService) BurnTime(ctx context.Context, plaintext string) {
	if s.dummyHash != "" {
		_, _ = s.hasher.Verify(ctx, plaintext, s.dummyHash)
	}
}

// SetInitial creates the credential row for a brand-new user (change required).
func (s *PasswordService) SetInitial(ctx context.Context, db store.DBTX, userID uuid.UUID, plaintext string) error {
	hash, err := s.hasher.Hash(ctx, plaintext)
	if err != nil {
		return err
	}
	_, err = db.Exec(ctx,
		`INSERT INTO user_credentials (user_id, password_hash, password_change_required)
		 VALUES ($1,$2,true)
		 ON CONFLICT (user_id) DO UPDATE SET password_hash=EXCLUDED.password_hash, password_change_required=true`,
		userID, hash)
	return err
}

// SetByAdmin sets a user's password out-of-band (admin reset). It replaces the
// credential and synchronizes the force-password-change gate on both tables.
func (s *PasswordService) SetByAdmin(ctx context.Context, db store.DBTX, userID uuid.UUID, plaintext string, forceChange bool) error {
	hash, err := s.hasher.Hash(ctx, plaintext)
	if err != nil {
		return err
	}
	if _, err := db.Exec(ctx,
		`INSERT INTO user_credentials (user_id, password_hash, password_change_required, previous_hashes)
		 VALUES ($1, $2, $3, '{}')
		 ON CONFLICT (user_id) DO UPDATE
		   SET password_hash=EXCLUDED.password_hash,
		       password_change_required=EXCLUDED.password_change_required,
		       previous_hashes='{}', password_updated_at=now()`,
		userID, hash, forceChange); err != nil {
		return err
	}
	_, err = db.Exec(ctx, `UPDATE users SET force_password_change=$2 WHERE id=$1`, userID, forceChange)
	return err
}

// Verify checks a login password. Returns ErrNoCredential / crypto.ErrMismatch.
// On a parameter upgrade it transparently re-hashes in the background tx-free.
func (s *PasswordService) Verify(ctx context.Context, st *store.Store, userID uuid.UUID, plaintext string) error {
	var hash string
	err := st.Pool.QueryRow(ctx, `SELECT password_hash FROM user_credentials WHERE user_id=$1`, userID).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoCredential
	}
	if err != nil {
		return err
	}
	needsRehash, err := s.hasher.Verify(ctx, plaintext, hash)
	if err != nil {
		return err
	}
	if needsRehash {
		if nh, herr := s.hasher.Hash(ctx, plaintext); herr == nil {
			_, _ = st.Pool.Exec(ctx, `UPDATE user_credentials SET password_hash=$2 WHERE user_id=$1`, userID, nh)
		}
	}
	return nil
}

// Change validates and updates a password, enforcing length + reuse history, and
// clears the force-change gate (on both tables) within the caller's tx.
func (s *PasswordService) Change(ctx context.Context, db store.DBTX, userID uuid.UUID, plaintext string) error {
	if len([]rune(plaintext)) < s.minLen {
		return fmt.Errorf("%w: 密码至少需要 %d 个字符", ErrPasswordPolicy, s.minLen)
	}
	var current string
	var prev []string
	err := db.QueryRow(ctx,
		`SELECT password_hash, previous_hashes FROM user_credentials WHERE user_id=$1`, userID).Scan(&current, &prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	// Reuse check against current + history.
	for _, h := range append([]string{current}, prev...) {
		if h == "" {
			continue
		}
		if _, verr := s.hasher.Verify(ctx, plaintext, h); verr == nil {
			return fmt.Errorf("%w: 不能重复使用最近用过的密码", ErrPasswordPolicy)
		}
	}
	newHash, err := s.hasher.Hash(ctx, plaintext)
	if err != nil {
		return err
	}
	history := append([]string{current}, prev...)
	history = trimHistory(history, s.historyN)

	_, err = db.Exec(ctx,
		`UPDATE user_credentials
		    SET password_hash=$2, previous_hashes=$3, password_change_required=false, password_updated_at=now()
		  WHERE user_id=$1`, userID, newHash, history)
	if err != nil {
		return err
	}
	_, err = db.Exec(ctx, `UPDATE users SET force_password_change=false WHERE id=$1`, userID)
	return err
}

func trimHistory(h []string, n int) []string {
	out := make([]string, 0, n)
	for _, x := range h {
		if x == "" {
			continue
		}
		out = append(out, x)
		if len(out) >= n {
			break
		}
	}
	return out
}

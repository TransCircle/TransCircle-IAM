package authn

import (
	"context"

	"github.com/google/uuid"

	"github.com/transcircle/iam/internal/store"
)

// MFAStatus summarizes a user's bound factors (for /me and onboarding gates).
type MFAStatus struct {
	Passkeys      int  `json:"passkeys"`
	TOTP          bool `json:"totp"`
	RecoveryCodes int  `json:"recovery_codes"`
}

// HasAny reports whether at least one usable MFA factor is bound.
func (st MFAStatus) HasAny() bool { return st.Passkeys > 0 || st.TOTP }

// MFA aggregates factor queries.
type MFA struct{}

// Status returns a user's MFA factor summary.
func (MFA) Status(ctx context.Context, db store.DBTX, userID uuid.UUID) (MFAStatus, error) {
	var s MFAStatus
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM webauthn_credentials WHERE user_id=$1`, userID).Scan(&s.Passkeys); err != nil {
		return s, err
	}
	var totpN int
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM totp_secrets WHERE user_id=$1 AND confirmed_at IS NOT NULL`, userID).Scan(&totpN); err != nil {
		return s, err
	}
	s.TOTP = totpN > 0
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM recovery_codes WHERE user_id=$1 AND used_at IS NULL`, userID).Scan(&s.RecoveryCodes); err != nil {
		return s, err
	}
	return s, nil
}

package keys

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/config"
	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/store"
)

// EnsureDEK returns the active DEK, generating and persisting one if absent.
// Idempotent: safe to call from a re-runnable bootstrap.
func EnsureDEK(ctx context.Context, tx store.DBTX, cfg *config.Config) (dek []byte, version int, err error) {
	kek, kekID, err := loadKEK(cfg)
	if err != nil {
		return nil, 0, err
	}

	var (
		ciphertext []byte
		wrapped    bool
		nonce      []byte
	)
	row := tx.QueryRow(ctx,
		`SELECT version, dek_ciphertext, kek_wrapped, kek_nonce FROM crypto_keys WHERE status='active'`)
	scanErr := row.Scan(&version, &ciphertext, &wrapped, &nonce)
	switch {
	case scanErr == nil:
		if wrapped {
			if kek == nil {
				return nil, 0, fmt.Errorf("keys: active DEK is KEK-wrapped but no KEK configured")
			}
			dek, err = crypto.Open(kek, ciphertext, nonce, "dek-wrap")
			if err != nil {
				return nil, 0, fmt.Errorf("keys: unwrap DEK: %w", err)
			}
		} else {
			dek = ciphertext
		}
		return dek, version, nil
	case errors.Is(scanErr, pgx.ErrNoRows):
		// generate below
	default:
		return nil, 0, scanErr
	}

	dek, err = crypto.NewKey(32)
	if err != nil {
		return nil, 0, err
	}
	version = 1
	var storedCipher, storedNonce []byte
	var kekKid *string
	if cfg.KEKEnabled {
		storedCipher, storedNonce, err = crypto.Seal(kek, dek, "dek-wrap")
		if err != nil {
			return nil, 0, err
		}
		wrapped = true
		k := kekID
		kekKid = &k
	} else {
		storedCipher = dek
		wrapped = false
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO crypto_keys (id, version, purpose, dek_ciphertext, kek_wrapped, kek_nonce, kek_kid, status)
		 VALUES ($1, $2, 'dek', $3, $4, $5, $6, 'active')`,
		crypto.NewUUIDv7(), version, storedCipher, wrapped, storedNonce, kekKid)
	if err != nil {
		return nil, 0, fmt.Errorf("keys: insert DEK: %w", err)
	}
	return dek, version, nil
}

// EnsureSigningKey generates an active RS256 signing key if none exists.
func EnsureSigningKey(ctx context.Context, tx store.DBTX, dek []byte, dekVersion int) error {
	var count int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM signing_keys WHERE status='active'`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	return insertSigningKey(ctx, tx, dek, dekVersion, "active")
}

func insertSigningKey(ctx context.Context, tx store.DBTX, dek []byte, dekVersion int, status string) error {
	priv, err := crypto.GenerateSigningKey()
	if err != nil {
		return err
	}
	kid, err := crypto.KID(&priv.PublicKey)
	if err != nil {
		return err
	}
	pubJWK, err := crypto.PublicJWK(kid, &priv.PublicKey)
	if err != nil {
		return err
	}
	der, err := crypto.MarshalPrivateKey(priv)
	if err != nil {
		return err
	}
	enc, nonce, err := crypto.Seal(dek, der, "signing:"+kid)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO signing_keys (id, kid, algorithm, public_jwk, private_key_enc, private_key_nonce, dek_version, status, activated_at)
		 VALUES ($1,$2,'RS256',$3,$4,$5,$6,$7, CASE WHEN $7='active' THEN now() ELSE NULL END)`,
		crypto.NewUUIDv7(), kid, pubJWK, enc, nonce, dekVersion, status)
	if err != nil {
		return fmt.Errorf("keys: insert signing key: %w", err)
	}
	return nil
}

// RotateSigningKeyTx performs the rotation inside a caller-supplied transaction
// and returns the new active key's kid, so callers can write an audit record in
// the SAME transaction (audit fail-closed with rotation). Demotes the current
// active key to 'previous' and creates a new active key; previous keys remain in
// JWKS until retired (must-fix #7).
func RotateSigningKeyTx(ctx context.Context, tx pgx.Tx, cfg *config.Config) (newKID string, err error) {
	dek, dekVer, derr := EnsureDEK(ctx, tx, cfg)
	if derr != nil {
		return "", derr
	}
	// Retire keys older than 'previous'; demote current active -> previous.
	if _, derr = tx.Exec(ctx,
		`UPDATE signing_keys SET status='retired', retired_at=now() WHERE status='previous'`); derr != nil {
		return "", derr
	}
	if _, derr = tx.Exec(ctx,
		`UPDATE signing_keys SET status='previous' WHERE status='active'`); derr != nil {
		return "", derr
	}
	if derr = insertSigningKey(ctx, tx, dek, dekVer, "active"); derr != nil {
		return "", derr
	}
	if derr = tx.QueryRow(ctx, `SELECT kid FROM signing_keys WHERE status='active'`).Scan(&newKID); derr != nil {
		return "", derr
	}
	return newKID, nil
}

// RotateSigningKey runs RotateSigningKeyTx in its own transaction (used by callers
// that do not need to bundle other work atomically).
func RotateSigningKey(ctx context.Context, st *store.Store, cfg *config.Config) (newKID string, err error) {
	err = st.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		kid, e := RotateSigningKeyTx(ctx, tx, cfg)
		newKID = kid
		return e
	})
	if err != nil {
		return "", err
	}
	return newKID, nil
}

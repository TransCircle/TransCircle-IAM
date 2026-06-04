package keys

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/store"
)

// namedSecret is the encrypted-at-rest envelope stored in system_settings.
type namedSecret struct {
	Enc   string `json:"enc"`
	Nonce string `json:"nonce"`
	Ver   int    `json:"ver"`
}

// EnsureNamedSecret generates and persists a random 32-byte secret under the
// given settings key if absent (e.g. the OAuth HMAC global secret). Idempotent.
func EnsureNamedSecret(ctx context.Context, tx store.DBTX, dek []byte, dekVer int, name string) error {
	var existing string
	err := tx.QueryRow(ctx, `SELECT value::text FROM system_settings WHERE key=$1`, name).Scan(&existing)
	if err == nil {
		return nil // already present
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	secret, err := crypto.NewKey(32)
	if err != nil {
		return err
	}
	enc, nonce, sealErr := crypto.Seal(dek, secret, "named:"+name)
	if sealErr != nil {
		return sealErr
	}
	payload, _ := json.Marshal(namedSecret{
		Enc:   base64.StdEncoding.EncodeToString(enc),
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		Ver:   dekVer,
	})
	_, err = tx.Exec(ctx,
		`INSERT INTO system_settings (key, value) VALUES ($1, $2::jsonb) ON CONFLICT (key) DO NOTHING`,
		name, string(payload))
	return err
}

// LoadNamedSecret decrypts a named secret previously stored by EnsureNamedSecret.
func (ks *KeyStore) LoadNamedSecret(ctx context.Context, st *store.Store, name string) ([]byte, error) {
	var raw string
	err := st.Pool.QueryRow(ctx, `SELECT value::text FROM system_settings WHERE key=$1`, name).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("keys: named secret %q not found; run `iam bootstrap`", name)
	}
	if err != nil {
		return nil, err
	}
	var ns namedSecret
	if err := json.Unmarshal([]byte(raw), &ns); err != nil {
		return nil, err
	}
	enc, err := base64.StdEncoding.DecodeString(ns.Enc)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.StdEncoding.DecodeString(ns.Nonce)
	if err != nil {
		return nil, err
	}
	return ks.DecryptSecret(enc, nonce, ns.Ver, "named:"+name)
}

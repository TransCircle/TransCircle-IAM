// Package keys is the runtime key store: it loads the data-encryption key (DEK)
// and OIDC signing keys from the database at startup (decrypting with an optional
// KEK), keeps them in memory, and exposes envelope encrypt/decrypt plus the
// signing-key provider consumed by the OAuth/OIDC layer.
package keys

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/transcircle/iam/internal/config"
	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/store"
)

// SigningKey is an in-memory OIDC signing key (private material + public JWK).
type SigningKey struct {
	KID       string
	Algorithm string
	Private   *rsa.PrivateKey
	PublicJWK json.RawMessage
	Status    string // active | previous
}

// KeyStore holds decrypted keys in memory. It is safe for concurrent use.
type KeyStore struct {
	mu sync.RWMutex

	deks          map[int][]byte // version -> raw 32-byte DEK
	activeDEKVer  int
	signingByKID  map[string]*SigningKey
	activeSigning *SigningKey
	jwks          []json.RawMessage // active + previous public JWKs
}

// Load reads all DEKs and active/previous signing keys from the database.
func Load(ctx context.Context, st *store.Store, cfg *config.Config) (*KeyStore, error) {
	ks := &KeyStore{
		deks:         map[int][]byte{},
		signingByKID: map[string]*SigningKey{},
	}

	kek, kekID, err := loadKEK(cfg)
	if err != nil {
		return nil, err
	}

	if err := ks.loadDEKs(ctx, st, kek, kekID); err != nil {
		return nil, err
	}
	if ks.activeDEKVer == 0 {
		return nil, fmt.Errorf("keys: no active DEK found; run `iam bootstrap`")
	}
	if err := ks.loadSigningKeys(ctx, st); err != nil {
		return nil, err
	}
	if ks.activeSigning == nil {
		return nil, fmt.Errorf("keys: no active signing key found; run `iam bootstrap`")
	}
	return ks, nil
}

func (ks *KeyStore) loadDEKs(ctx context.Context, st *store.Store, kek []byte, kekID string) error {
	rows, err := st.Pool.Query(ctx,
		`SELECT version, dek_ciphertext, kek_wrapped, kek_nonce, kek_kid, status FROM crypto_keys`)
	if err != nil {
		return fmt.Errorf("keys: query DEKs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			version    int
			ciphertext []byte
			wrapped    bool
			nonce      []byte
			kid        *string
			status     string
		)
		if err := rows.Scan(&version, &ciphertext, &wrapped, &nonce, &kid, &status); err != nil {
			return err
		}
		var dek []byte
		if wrapped {
			if kek == nil {
				return fmt.Errorf("keys: DEK v%d is KEK-wrapped but no KEK configured", version)
			}
			if kid != nil && *kid != "" && *kid != kekID {
				return fmt.Errorf("keys: configured KEK id %q does not match DEK v%d (%q)", kekID, version, *kid)
			}
			dek, err = crypto.Open(kek, ciphertext, nonce, "dek-wrap")
			if err != nil {
				return fmt.Errorf("keys: unwrap DEK v%d: %w", version, err)
			}
		} else {
			dek = ciphertext
		}
		if len(dek) != 32 {
			return fmt.Errorf("keys: DEK v%d wrong size %d", version, len(dek))
		}
		ks.deks[version] = dek
		if status == "active" {
			ks.activeDEKVer = version
		}
	}
	return rows.Err()
}

func (ks *KeyStore) loadSigningKeys(ctx context.Context, st *store.Store) error {
	rows, err := st.Pool.Query(ctx,
		`SELECT kid, algorithm, public_jwk, private_key_enc, private_key_nonce, dek_version, status
		   FROM signing_keys WHERE status IN ('active','previous')`)
	if err != nil {
		return fmt.Errorf("keys: query signing keys: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			kid, alg, status string
			pubJWK           []byte
			privEnc, nonce   []byte
			dekVer           int
		)
		if err := rows.Scan(&kid, &alg, &pubJWK, &privEnc, &nonce, &dekVer, &status); err != nil {
			return err
		}
		dek, ok := ks.deks[dekVer]
		if !ok {
			return fmt.Errorf("keys: signing key %s references missing DEK v%d", kid, dekVer)
		}
		der, err := crypto.Open(dek, privEnc, nonce, "signing:"+kid)
		if err != nil {
			return fmt.Errorf("keys: decrypt signing key %s: %w", kid, err)
		}
		priv, err := crypto.UnmarshalPrivateKey(der)
		if err != nil {
			return fmt.Errorf("keys: parse signing key %s: %w", kid, err)
		}
		sk := &SigningKey{KID: kid, Algorithm: alg, Private: priv, PublicJWK: pubJWK, Status: status}
		ks.signingByKID[kid] = sk
		ks.jwks = append(ks.jwks, json.RawMessage(pubJWK))
		if status == "active" {
			ks.activeSigning = sk
		}
	}
	return rows.Err()
}

// EncryptSecret encrypts plaintext under the active DEK. aad provides domain
// separation. Returns the ciphertext, nonce, and DEK version used.
func (ks *KeyStore) EncryptSecret(plaintext []byte, aad string) (ciphertext, nonce []byte, version int, err error) {
	ks.mu.RLock()
	dek := ks.deks[ks.activeDEKVer]
	version = ks.activeDEKVer
	ks.mu.RUnlock()
	ciphertext, nonce, err = crypto.Seal(dek, plaintext, aad)
	return ciphertext, nonce, version, err
}

// DecryptSecret decrypts a secret encrypted with the given DEK version.
func (ks *KeyStore) DecryptSecret(ciphertext, nonce []byte, version int, aad string) ([]byte, error) {
	ks.mu.RLock()
	dek, ok := ks.deks[version]
	ks.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("keys: unknown DEK version %d", version)
	}
	return crypto.Open(dek, ciphertext, nonce, aad)
}

// ActiveSigningKey returns the current signing key for issuing tokens.
func (ks *KeyStore) ActiveSigningKey() *SigningKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.activeSigning
}

// SigningKeyByKID returns a signing key by id (for verification during rotation).
func (ks *KeyStore) SigningKeyByKID(kid string) (*SigningKey, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	sk, ok := ks.signingByKID[kid]
	return sk, ok
}

// JWKS returns the public JWK set document (active + previous keys).
func (ks *KeyStore) JWKS() map[string]any {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	keys := make([]json.RawMessage, len(ks.jwks))
	copy(keys, ks.jwks)
	return map[string]any{"keys": keys}
}

// StartAutoReload periodically reloads keys from the database so a signing-key
// rotation performed on one replica propagates to all others within `interval`.
// The goroutine stops when ctx is cancelled.
func (ks *KeyStore) StartAutoReload(ctx context.Context, st *store.Store, cfg *config.Config, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = ks.Reload(ctx, st, cfg)
			}
		}
	}()
}

// Reload refreshes keys from the database (after a rotation).
func (ks *KeyStore) Reload(ctx context.Context, st *store.Store, cfg *config.Config) error {
	fresh, err := Load(ctx, st, cfg)
	if err != nil {
		return err
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.deks = fresh.deks
	ks.activeDEKVer = fresh.activeDEKVer
	ks.signingByKID = fresh.signingByKID
	ks.activeSigning = fresh.activeSigning
	ks.jwks = fresh.jwks
	return nil
}

func loadKEK(cfg *config.Config) (kek []byte, kekID string, err error) {
	if !cfg.KEKEnabled {
		return nil, "", nil
	}
	raw := strings.TrimSpace(cfg.KEK)
	if raw == "" && cfg.KEKFile != "" {
		b, rerr := os.ReadFile(cfg.KEKFile)
		if rerr != nil {
			return nil, "", fmt.Errorf("keys: read KEK file: %w", rerr)
		}
		raw = strings.TrimSpace(string(b))
	}
	if raw == "" {
		return nil, "", fmt.Errorf("keys: KEK enabled but no key provided")
	}
	kek, err = base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, "", fmt.Errorf("keys: decode KEK: %w", err)
	}
	if len(kek) != 32 {
		return nil, "", fmt.Errorf("keys: KEK must be 32 bytes (got %d)", len(kek))
	}
	return kek, crypto.KEKID(kek), nil
}

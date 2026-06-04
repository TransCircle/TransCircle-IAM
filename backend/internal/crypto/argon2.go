// Package crypto provides password/secret hashing (argon2id), envelope
// encryption of secrets at rest (AES-256-GCM under a DB-stored DEK), and OIDC
// signing-key material. All secret verification across the system goes through
// the single Hasher here so parameters stay consistent and upgradable.
package crypto

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrMismatch is returned by Verify when the secret does not match.
var ErrMismatch = errors.New("crypto: hash mismatch")

// Hasher computes and verifies argon2id PHC strings. A bounded semaphore caps
// concurrent hashes to prevent a login flood from exhausting memory (must-fix #11).
type Hasher struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLen     uint32
	keyLen      uint32
	sem         chan struct{}
}

// NewHasher builds a Hasher. maxConcurrent must be >= 1.
func NewHasher(memoryKiB, iterations uint32, parallelism uint8, maxConcurrent int) *Hasher {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	return &Hasher{
		memory:      memoryKiB,
		iterations:  iterations,
		parallelism: parallelism,
		saltLen:     16,
		keyLen:      32,
		sem:         make(chan struct{}, maxConcurrent),
	}
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.sem }

// Hash returns a PHC-encoded argon2id hash of secret.
func (h *Hasher) Hash(ctx context.Context, secret string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()

	salt := make([]byte, h.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}
	key := argon2.IDKey([]byte(secret), salt, h.iterations, h.memory, h.parallelism, h.keyLen)
	return encodePHC(h.memory, h.iterations, h.parallelism, salt, key), nil
}

// Verify checks secret against a PHC hash in constant time. needsRehash is true
// when the stored parameters differ from the current configured ones.
func (h *Hasher) Verify(ctx context.Context, secret, phc string) (needsRehash bool, err error) {
	mem, iters, par, salt, want, err := decodePHC(phc)
	if err != nil {
		return false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, err
	}
	defer h.release()

	got := argon2.IDKey([]byte(secret), salt, iters, mem, par, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, ErrMismatch
	}
	needsRehash = mem != h.memory || iters != h.iterations || par != h.parallelism
	return needsRehash, nil
}

func encodePHC(mem, iters uint32, par uint8, salt, key []byte) string {
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, mem, iters, par, b64.EncodeToString(salt), b64.EncodeToString(key))
}

func decodePHC(phc string) (mem, iters uint32, par uint8, salt, key []byte, err error) {
	parts := strings.Split(phc, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, key]
	if len(parts) != 6 || parts[1] != "argon2id" {
		err = errors.New("crypto: invalid PHC string")
		return
	}
	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return
	}
	if version != argon2.Version {
		err = fmt.Errorf("crypto: unsupported argon2 version %d", version)
		return
	}
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iters, &par); err != nil {
		return
	}
	b64 := base64.RawStdEncoding
	if salt, err = b64.DecodeString(parts[4]); err != nil {
		return
	}
	if key, err = b64.DecodeString(parts[5]); err != nil {
		return
	}
	return
}

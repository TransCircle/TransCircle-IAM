package crypto

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// NewUUIDv7 returns a time-ordered UUIDv7 for use as a primary key.
func NewUUIDv7() uuid.UUID {
	// uuid.NewV7 only errors if the system RNG fails, which is fatal anyway.
	id, err := uuid.NewV7()
	if err != nil {
		panic(fmt.Sprintf("crypto: uuidv7: %v", err))
	}
	return id
}

// RandomToken returns a URL-safe random string carrying nBytes of entropy.
func RandomToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto: rand: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// RecoveryCode returns a human-friendly one-time recovery code (e.g. a7f2-9k3m-xq8t).
func RecoveryCode() string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789" // no ambiguous chars
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto: rand: %v", err))
	}
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(alphabet[int(c)%len(alphabet)])
	}
	return sb.String()
}

// NewTOTPSecretBase32 returns a base32 (no padding) secret suitable for TOTP.
func NewTOTPSecretBase32(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto: rand: %v", err))
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

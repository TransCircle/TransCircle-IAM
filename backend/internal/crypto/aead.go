package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Seal encrypts plaintext with AES-256-GCM under key (32 bytes). aad provides
// domain separation (e.g. "totp:<userid>") binding the ciphertext to its record.
// Returns the ciphertext and the random nonce separately.
func Seal(key, plaintext []byte, aad string) (ciphertext, nonce []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("read nonce: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, []byte(aad))
	return ciphertext, nonce, nil
}

// Open decrypts ciphertext produced by Seal.
func Open(key, ciphertext, nonce []byte, aad string) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("crypto: bad nonce size")
	}
	pt, err := gcm.Open(nil, nonce, ciphertext, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("crypto: open: %w", err)
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// NewKey returns n random bytes (e.g. a 32-byte DEK).
func NewKey(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// KEKID returns a short stable identifier for a KEK so a boot-time key mismatch
// can be detected without revealing the key.
func KEKID(kek []byte) string {
	sum := sha256.Sum256(kek)
	return hex.EncodeToString(sum[:4])
}

package crypto

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"crypto/rand"

	jose "github.com/go-jose/go-jose/v4"
)

// GenerateSigningKey creates a fresh 2048-bit RSA key for OIDC signing.
func GenerateSigningKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// MarshalPrivateKey encodes a private key as PKCS#8 DER (to be encrypted at rest).
func MarshalPrivateKey(key *rsa.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(key)
}

// UnmarshalPrivateKey decodes a PKCS#8 DER RSA private key.
func UnmarshalPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("crypto: not an RSA private key")
	}
	return rk, nil
}

// KID derives a stable key id from the public key DER.
func KID(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])[:16], nil
}

// PublicJWK returns the RFC7517 JSON Web Key for a public signing key.
func PublicJWK(kid string, pub *rsa.PublicKey) (json.RawMessage, error) {
	jwk := jose.JSONWebKey{
		Key:       pub,
		KeyID:     kid,
		Algorithm: "RS256",
		Use:       "sig",
	}
	b, err := jwk.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

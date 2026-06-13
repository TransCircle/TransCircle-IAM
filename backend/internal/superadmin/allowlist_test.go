package superadmin

import (
	"testing"

	"github.com/google/uuid"
)

var (
	testDEK   = []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	testUser  = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	otherUser = uuid.MustParse("22222222-2222-2222-2222-222222222222")
)

func TestSignVerifyRoundTrip(t *testing.T) {
	sig := sign(testDEK, 1, testUser)
	if !verify(testDEK, 1, testUser, sig) {
		t.Fatal("a freshly-signed grant failed to verify")
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	sig := sign(testDEK, 1, testUser)

	if verify(testDEK, 1, otherUser, sig) {
		t.Error("signature verified for a different user id")
	}
	if verify(testDEK, 2, testUser, sig) {
		t.Error("signature verified under a different DEK version")
	}
	if verify([]byte("ffffffffffffffffffffffffffffffff"), 1, testUser, sig) {
		t.Error("signature verified under a different DEK (forged without the key)")
	}

	bad := append([]byte(nil), sig...)
	bad[0] ^= 0xff
	if verify(testDEK, 1, testUser, bad) {
		t.Error("a tampered signature verified")
	}
}

func TestVerifyGrantBindsActiveVersion(t *testing.T) {
	g := Grant{UserID: testUser, DEKVersion: 1, Sig: sign(testDEK, 1, testUser)}
	if !VerifyGrant(testDEK, 1, g) {
		t.Fatal("valid grant rejected at the active version")
	}
	// A row whose recorded version differs from the active DEK version cannot be
	// verified with the current key and must be treated as invalid.
	if VerifyGrant(testDEK, 2, g) {
		t.Error("grant verified although the active DEK version moved on")
	}
}

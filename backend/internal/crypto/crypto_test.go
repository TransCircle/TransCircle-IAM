package crypto

import (
	"context"
	"testing"
)

func TestArgon2RoundTrip(t *testing.T) {
	h := NewHasher(16384, 1, 1, 4)
	ctx := context.Background()
	phc, err := h.Hash(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := h.Verify(ctx, "correct horse battery staple", phc); err != nil {
		t.Fatalf("verify should succeed: %v", err)
	}
	if _, err := h.Verify(ctx, "wrong password", phc); err == nil {
		t.Fatal("verify should fail for wrong password")
	}
}

func TestArgon2NeedsRehash(t *testing.T) {
	weak := NewHasher(8192, 1, 1, 2)
	strong := NewHasher(16384, 2, 1, 2)
	ctx := context.Background()
	phc, _ := weak.Hash(ctx, "pw")
	needsRehash, err := strong.Verify(ctx, "pw", phc)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !needsRehash {
		t.Fatal("expected needsRehash=true for outdated params")
	}
}

func TestAEADRoundTrip(t *testing.T) {
	key, _ := NewKey(32)
	ct, nonce, err := Seal(key, []byte("super secret"), "totp:user-1")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	pt, err := Open(key, ct, nonce, "totp:user-1")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(pt) != "super secret" {
		t.Fatalf("got %q", pt)
	}
	// Wrong AAD must fail (domain separation).
	if _, err := Open(key, ct, nonce, "totp:user-2"); err == nil {
		t.Fatal("open with wrong AAD should fail")
	}
}

func TestSigningKeyRoundTrip(t *testing.T) {
	priv, err := GenerateSigningKey()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	der, err := MarshalPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := UnmarshalPrivateKey(der)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.N.Cmp(priv.N) != 0 {
		t.Fatal("round-trip mismatch")
	}
	kid, err := KID(&priv.PublicKey)
	if err != nil || len(kid) != 16 {
		t.Fatalf("kid: %v len=%d", err, len(kid))
	}
	if _, err := PublicJWK(kid, &priv.PublicKey); err != nil {
		t.Fatalf("jwk: %v", err)
	}
}

func TestUUIDv7Ordering(t *testing.T) {
	a := NewUUIDv7()
	b := NewUUIDv7()
	if a == b {
		t.Fatal("uuids should differ")
	}
}

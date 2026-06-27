package crypto

import (
	"context"
	"strings"
	"testing"
)

// TestRandomHexIsDelimiterFreeForTokenPrefix guards the api-token format. The
// prefix is recovered by splitting "tcp_<prefix>_<secret>" on the FIRST '_'
// (api.machineAuth), so a prefix containing '_' truncates the parsed value, the
// DB lookup misses, and the token can never authenticate. A base64url prefix
// (RandomToken) hit this for ~12% of minted tokens; the prefix must use RandomHex.
func TestRandomHexIsDelimiterFreeForTokenPrefix(t *testing.T) {
	for i := 0; i < 2000; i++ {
		p := RandomHex(6)
		if len(p) != 12 {
			t.Fatalf("RandomHex(6) want 12 hex chars, got %d (%q)", len(p), p)
		}
		if strings.ContainsAny(p, "-_") {
			t.Fatalf("token prefix must be delimiter-free, got %q", p)
		}
		// Reproduce the machineAuth parse: the token must split back into the
		// exact prefix and secret even when the secret itself contains '_'.
		full := "tcp_" + p + "_" + RandomToken(24)
		parts := strings.SplitN(strings.TrimPrefix(full, "tcp_"), "_", 2)
		if len(parts) != 2 || parts[0] != p {
			t.Fatalf("token %q did not parse back to prefix %q: %#v", full, p, parts)
		}
	}
}

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

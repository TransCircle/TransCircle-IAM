package oauth

import "testing"

func TestPermHashStableAndOrderIndependent(t *testing.T) {
	a := permHash([]string{"doc.read", "doc.write"})
	b := permHash([]string{"doc.write", "doc.read"})
	if a != b {
		t.Fatalf("hash should be order-independent: %s vs %s", a, b)
	}
	c := permHash([]string{"doc.read"})
	if a == c {
		t.Fatal("different permission sets should hash differently")
	}
	if permHash(nil) != "0" {
		t.Fatal("empty set should hash to 0")
	}
}

func TestSplitScopes(t *testing.T) {
	got := splitScopes("openid profile  tc.permissions")
	if len(got) != 3 || got[2] != "tc.permissions" {
		t.Fatalf("unexpected: %#v", got)
	}
}

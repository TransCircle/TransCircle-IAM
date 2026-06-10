package avatars

import "testing"

func TestUserURL(t *testing.T) {
	cases := []struct {
		issuer, userID, want string
	}{
		{"https://iam.example.com", "abc", "https://iam.example.com/api/v1/avatars/u/abc"},
		// trailing slash on the issuer must not double up.
		{"https://iam.example.com/", "abc", "https://iam.example.com/api/v1/avatars/u/abc"},
	}
	for _, c := range cases {
		if got := UserURL(c.issuer, c.userID); got != c.want {
			t.Errorf("UserURL(%q,%q) = %q, want %q", c.issuer, c.userID, got, c.want)
		}
	}
}

func TestFileFromPublicURL(t *testing.T) {
	valid := "/api/v1/avatars/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b.png"
	if got := fileFromPublicURL(valid); got != "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b.png" {
		t.Errorf("valid url => %q", got)
	}
	for _, bad := range []string{
		"",                                  // no avatar set
		"https://evil.example.com/x.png",    // foreign
		"/api/v1/avatars/../../etc/passwd",  // traversal
		"/api/v1/avatars/u/abc",             // the per-user URL, not a file
		"/api/v1/avatars/not-a-uuid.png",    // bad name
	} {
		if got := fileFromPublicURL(bad); got != "" {
			t.Errorf("fileFromPublicURL(%q) = %q, want empty", bad, got)
		}
	}
}

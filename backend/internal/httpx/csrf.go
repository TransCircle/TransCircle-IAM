package httpx

import (
	"crypto/subtle"
	"net/http"

	"github.com/transcircle/iam/internal/crypto"
)

const csrfHeader = "X-CSRF-Token"

// CSRF enforces double-submit-cookie protection on unsafe, cookie-authenticated
// requests. A readable token cookie is issued; unsafe methods must echo it in the
// X-CSRF-Token header. exempt covers token/introspect/revoke (not cookie-authed).
func CSRF(cookies Cookies, cookieBase string, exempt func(*http.Request) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := cookies.Get(r, cookieBase)
			if token == "" {
				token = crypto.RandomToken(24)
				cookies.SetReadable(w, cookieBase, token, 0)
			}
			if !isSafeMethod(r.Method) && (exempt == nil || !exempt(r)) {
				sent := r.Header.Get(csrfHeader)
				if sent == "" || subtle.ConstantTimeCompare([]byte(sent), []byte(token)) != 1 {
					Error(w, r, ErrForbidden.WithDetail("CSRF 校验失败"))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isSafeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

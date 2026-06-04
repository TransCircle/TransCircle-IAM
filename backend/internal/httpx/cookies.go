package httpx

import (
	"net/http"
	"strings"
)

// Cookies builds Set-Cookie values honoring the deployment's security posture.
// When not Secure (local http dev), the __Host- prefix is stripped so cookies
// still set; in prod (Secure) the prefix is kept for its hardening guarantees.
type Cookies struct {
	Secure   bool
	SameSite http.SameSite
	Domain   string
}

// Name resolves the effective cookie name for the current security posture.
func (c Cookies) Name(base string) string {
	if !c.Secure {
		return strings.TrimPrefix(base, "__Host-")
	}
	return base
}

// Set writes a cookie. maxAgeSeconds <= 0 means a session cookie.
func (c Cookies) Set(w http.ResponseWriter, base, value string, maxAgeSeconds int) {
	ck := &http.Cookie{
		Name:     c.Name(base),
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: c.SameSite,
	}
	if maxAgeSeconds > 0 {
		ck.MaxAge = maxAgeSeconds
	}
	// __Host- cookies must not set Domain; only set Domain for non-host cookies.
	if c.Domain != "" && !strings.HasPrefix(base, "__Host-") {
		ck.Domain = c.Domain
	}
	http.SetCookie(w, ck)
}

// SetReadable sets a cookie readable by JS (used for the CSRF token mirror).
func (c Cookies) SetReadable(w http.ResponseWriter, base, value string, maxAgeSeconds int) {
	ck := &http.Cookie{
		Name:     c.Name(base),
		Value:    value,
		Path:     "/",
		HttpOnly: false,
		Secure:   c.Secure,
		SameSite: c.SameSite,
	}
	if maxAgeSeconds > 0 {
		ck.MaxAge = maxAgeSeconds
	}
	http.SetCookie(w, ck)
}

// Clear expires a cookie.
func (c Cookies) Clear(w http.ResponseWriter, base string) {
	http.SetCookie(w, &http.Cookie{
		Name:     c.Name(base),
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Secure,
		SameSite: c.SameSite,
		MaxAge:   -1,
	})
}

// Get reads a cookie value by its base name.
func (c Cookies) Get(r *http.Request, base string) string {
	if ck, err := r.Cookie(c.Name(base)); err == nil {
		return ck.Value
	}
	return ""
}

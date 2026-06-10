package httpx

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/logging"
)

type ctxKey int

const (
	ctxRequestID ctxKey = iota
	ctxClientIP
	ctxUserAgent
)

// RequestID assigns a request id, exposes it, and attaches a scoped logger.
func RequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Request-Id")
			if id == "" {
				id = crypto.RandomToken(12)
			}
			w.Header().Set("X-Request-Id", id)
			ctx := context.WithValue(r.Context(), ctxRequestID, id)
			ctx = context.WithValue(ctx, ctxUserAgent, r.UserAgent())
			l := logging.From(ctx).With("request_id", id, "method", r.Method, "path", r.URL.Path)
			ctx = logging.WithContext(ctx, l)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Recoverer converts panics into a logged 500 without leaking a stack trace.
func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logging.From(r.Context()).Error("panic recovered", "panic", rec)
				Error(w, r, ErrInternal)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// RealIP derives the client IP, trusting X-Forwarded-For only when the immediate
// peer is within a configured trusted-proxy CIDR.
func RealIP(trusted []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := peerAddr(r.RemoteAddr)
			if ip.IsValid() && peerTrusted(ip, trusted) {
				if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
					first := strings.TrimSpace(strings.Split(xff, ",")[0])
					if parsed, err := netip.ParseAddr(first); err == nil {
						ip = parsed
					}
				}
			}
			ctx := context.WithValue(r.Context(), ctxClientIP, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func peerAddr(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, _ := netip.ParseAddr(host)
	return addr
}

func peerTrusted(ip netip.Addr, trusted []netip.Prefix) bool {
	return slices.ContainsFunc(trusted, func(p netip.Prefix) bool { return p.Contains(ip) })
}

// SecurityHeaders sets conservative security headers. TLS is terminated at the
// upstream reverse proxy (your nginx).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		// Defense-in-depth CSP for an IAM console: no inline/remote scripts (the
		// Vite bundle is same-origin hashed assets), blob:/data: only for avatar
		// previews, and no framing. The CSRF cookie is JS-readable by design, so a
		// strict script-src is the key guard against token theft via XSS. (In the
		// nginx-fronted deployment, also set this on the SPA document responses.)
		h.Set("Content-Security-Policy",
			"default-src 'self'; base-uri 'self'; object-src 'none'; "+
				"frame-ancestors 'none'; form-action 'self'; "+
				"img-src 'self' data: blob:; font-src 'self'; "+
				"style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// CORS allows the configured SPA origins with credentials.
func CORS(origins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(origins))
	for _, o := range origins {
		allowed[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && allowed[origin] {
				h := w.Header()
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Access-Control-Allow-Credentials", "true")
				h.Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, X-Request-Id")
				h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				h.Set("Vary", "Origin")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ClientIP returns the derived client IP string for the request.
func ClientIP(ctx context.Context) string {
	if ip, ok := ctx.Value(ctxClientIP).(netip.Addr); ok && ip.IsValid() {
		return ip.String()
	}
	return ""
}

// ReqID returns the request id.
func ReqID(ctx context.Context) string {
	if id, ok := ctx.Value(ctxRequestID).(string); ok {
		return id
	}
	return ""
}

// UserAgent returns the request User-Agent header.
func UserAgent(ctx context.Context) string {
	if ua, ok := ctx.Value(ctxUserAgent).(string); ok {
		return ua
	}
	return ""
}

// Package server wires the chi router, middleware stack, and all subsystem
// routes into a single http.Handler.
package server

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/transcircle/iam/internal/config"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/logging"
	"github.com/transcircle/iam/internal/store"
)

// Version is overridden at build time via -ldflags.
var Version = "dev"

// Deps are the runtime dependencies shared by all handlers.
type Deps struct {
	Cfg   *config.Config
	Store *store.Store
	Log   *slog.Logger
	// Subsystem route mounters are registered by the application wiring in
	// cmd/iam; keeping them as a slice avoids import cycles between server and
	// the feature packages.
	Mounters []RouteMounter
	// GlobalMiddleware runs after the base stack and before any route (e.g.
	// session resolution and CSRF).
	GlobalMiddleware []func(http.Handler) http.Handler
}

// RouteMounter lets a subsystem attach its routes to a router.
type RouteMounter interface {
	Mount(r chi.Router)
}

// Server holds the composed HTTP handler.
type Server struct {
	deps   Deps
	router chi.Router
}

// New builds the server and mounts all routes.
func New(deps Deps) *Server {
	r := chi.NewRouter()

	// Base middleware applied to every request.
	r.Use(injectLogger(deps.Log))
	r.Use(httpx.RequestID())
	r.Use(httpx.Recoverer)
	r.Use(httpx.RealIP(deps.Cfg.TrustedProxies))
	r.Use(httpx.SecurityHeaders)
	r.Use(httpx.CORS(deps.Cfg.CORSOrigins))

	for _, mw := range deps.GlobalMiddleware {
		r.Use(mw)
	}

	s := &Server{deps: deps, router: r}

	// Operational endpoints (no auth, no deps in healthz).
	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)
	r.Get("/version", s.handleVersion)

	for _, m := range deps.Mounters {
		m.Mount(r)
	}

	// Serve the embedded SPA for everything not matched above.
	r.NotFound(spaHandler())
	return s
}

// Handler returns the composed HTTP handler.
func (s *Server) Handler() http.Handler { return s.router }

func injectLogger(l *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := logging.WithContext(r.Context(), l)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

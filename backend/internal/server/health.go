package server

import (
	"net/http"
	"sync/atomic"

	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/logging"
)

// draining is flipped during graceful shutdown so /readyz starts failing and
// the load balancer stops routing new traffic.
var draining atomic.Bool

// SetDraining marks the server as draining (used during graceful shutdown).
func SetDraining() { draining.Store(true) }

// handleHealthz is a liveness probe that never touches dependencies.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz is a readiness probe: it checks Postgres + Redis and drain state.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if draining.Load() {
		httpx.JSON(w, r, http.StatusServiceUnavailable, map[string]string{"status": "draining"})
		return
	}
	if err := s.deps.Store.Ping(r.Context()); err != nil {
		// Log the detail server-side; the dependency error text embeds the DB
		// DSN (host/user/db) and must not be returned to an unauthenticated caller.
		logging.From(r.Context()).Error("readiness check failed", "error", err)
		httpx.JSON(w, r, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
		return
	}
	httpx.JSON(w, r, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, r, http.StatusOK, map[string]string{
		"version": Version,
		"env":     s.deps.Cfg.Env,
	})
}

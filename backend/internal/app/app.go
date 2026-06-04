// Package app is the composition root: it loads config, opens connections, wires
// every subsystem together, and implements each CLI subcommand.
package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/transcircle/iam/internal/config"
	"github.com/transcircle/iam/internal/db"
	"github.com/transcircle/iam/internal/logging"
	"github.com/transcircle/iam/internal/server"
	"github.com/transcircle/iam/internal/store"
)

// runtime bundles the shared dependencies built once at startup.
type runtime struct {
	cfg *config.Config
	st  *store.Store
}

func setup(ctx context.Context) (*runtime, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	st, err := store.Open(ctx, cfg.DatabaseURL, cfg.RedisURL)
	if err != nil {
		return nil, err
	}
	return &runtime{cfg: cfg, st: st}, nil
}

// MigrateOnly applies migrations and exits.
func MigrateOnly(ctx context.Context) error {
	rt, err := setup(ctx)
	if err != nil {
		return err
	}
	defer rt.st.Close()
	n, err := db.Migrate(ctx, rt.st.Pool)
	if err != nil {
		return err
	}
	fmt.Printf("migrations applied: %d\n", n)
	return nil
}

// Healthcheck probes local readiness for container HEALTHCHECK directives.
func Healthcheck(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	url := "http://127.0.0.1" + cfg.HTTPListen + "/readyz"
	if cfg.HTTPListen[0] == ':' {
		url = "http://127.0.0.1" + cfg.HTTPListen + "/readyz"
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("readyz returned %d", resp.StatusCode)
	}
	return nil
}

// Serve runs the HTTP server until the context is cancelled.
func Serve(ctx context.Context) error {
	rt, err := setup(ctx)
	if err != nil {
		return err
	}
	defer rt.st.Close()

	log := logging.New(rt.cfg.Env)

	// Single-container self-initialization: migrate + provision keys/first-admin
	// (idempotent, advisory-locked so --scale replicas don't race).
	out, err := ensureInitialized(ctx, rt)
	if err != nil {
		return fmt.Errorf("initialize: %w", err)
	}
	if out != nil {
		out.GeneratedAt = time.Now()
		if werr := writeBootstrapOutput(rt.cfg.BootstrapOutFile, out); werr != nil {
			log.Warn("could not persist first-admin credentials", "error", werr)
		}
	}

	deps, err := buildDeps(ctx, rt, log)
	if err != nil {
		return err
	}

	srv := server.New(deps)

	httpSrv := &http.Server{
		Addr:              rt.cfg.HTTPListen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	metricsSrv := &http.Server{
		Addr:              rt.cfg.MetricsListen,
		Handler:           metricsMux(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		log.Info("http listening", "addr", rt.cfg.HTTPListen)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http server: %w", err)
		}
	}()
	go func() {
		log.Info("metrics listening", "addr", rt.cfg.MetricsListen)
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("metrics server: %w", err)
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		return err
	}

	// Graceful shutdown: stop accepting, drain readiness, then close.
	server.SetDraining()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = metricsSrv.Shutdown(shutdownCtx)
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	log.Info("shutdown complete")
	return nil
}

func metricsMux() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	return mux
}

// Package store owns the database and Redis connection lifecycle plus the
// transaction (unit-of-work) helper that guarantees atomicity across the system.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// DBTX is the subset of pgx used by repositories. Both *pgxpool.Pool and pgx.Tx
// satisfy it, so the same query code runs inside or outside a transaction.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

var _ DBTX = (*pgxpool.Pool)(nil)
var _ DBTX = (pgx.Tx)(nil)

// Store bundles the Postgres pool and Redis client.
type Store struct {
	Pool  *pgxpool.Pool
	Redis redis.UniversalClient
}

// Open establishes both connections and verifies them.
func Open(ctx context.Context, databaseURL, redisURL string) (*Store, error) {
	pcfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	pcfg.MaxConns = 16
	pcfg.MaxConnLifetime = time.Hour
	pcfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	ropt, err := redis.ParseURL(redisURL)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	rdb := redis.NewClient(ropt)
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		pool.Close()
		_ = rdb.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return &Store{Pool: pool, Redis: rdb}, nil
}

// Close releases both connections.
func (s *Store) Close() {
	if s.Pool != nil {
		s.Pool.Close()
	}
	if s.Redis != nil {
		_ = s.Redis.Close()
	}
}

// Ping checks liveness of both backends (used by /readyz).
func (s *Store) Ping(ctx context.Context) error {
	if err := s.Pool.Ping(ctx); err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	if err := s.Redis.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	return nil
}

// postCommitHook runs after a successful commit (best-effort side effects such
// as cache invalidation). Hooks never affect the committed result.
type txContext struct {
	hooks []func(context.Context)
}

type txCtxKey struct{}

// WithTx runs fn inside a transaction. If fn returns an error or panics the
// transaction is rolled back; otherwise it commits and runs post-commit hooks.
// This is the single atomicity primitive for the whole system.
func (s *Store) WithTx(ctx context.Context, fn func(ctx context.Context, tx pgx.Tx) error) error {
	return s.withTxOpts(ctx, pgx.TxOptions{}, fn)
}

// WithSerializableTx runs fn at SERIALIZABLE isolation with bounded retries on
// serialization failures (40001). Use only for invariant-critical writes.
func (s *Store) WithSerializableTx(ctx context.Context, fn func(ctx context.Context, tx pgx.Tx) error) error {
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		err := s.withTxOpts(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable}, fn)
		if err == nil {
			return nil
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "40001" {
			lastErr = err
			time.Sleep(time.Duration(attempt+1) * 5 * time.Millisecond)
			continue
		}
		return err
	}
	return fmt.Errorf("serializable tx exhausted retries: %w", lastErr)
}

func (s *Store) withTxOpts(ctx context.Context, opts pgx.TxOptions, fn func(ctx context.Context, tx pgx.Tx) error) (err error) {
	tx, err := s.Pool.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	tctx := &txContext{}
	innerCtx := context.WithValue(ctx, txCtxKey{}, tctx)

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(context.Background())
			panic(p) // re-panic after rollback; top-level Recoverer handles it
		}
	}()

	if err = fn(innerCtx, tx); err != nil {
		_ = tx.Rollback(context.Background())
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	// Post-commit hooks: best-effort, isolated from the committed result.
	for _, h := range tctx.hooks {
		runHookSafe(ctx, h)
	}
	return nil
}

// AfterCommit registers a side effect to run after the current transaction
// commits. If called outside a transaction the hook runs immediately.
func AfterCommit(ctx context.Context, hook func(context.Context)) {
	if tctx, ok := ctx.Value(txCtxKey{}).(*txContext); ok {
		tctx.hooks = append(tctx.hooks, hook)
		return
	}
	runHookSafe(ctx, hook)
}

func runHookSafe(ctx context.Context, h func(context.Context)) {
	defer func() { _ = recover() }() // a panicking hook must never corrupt state
	h(ctx)
}

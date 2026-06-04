// Package db embeds the SQL migrations and applies them under a Postgres
// advisory lock so exactly one applier runs across replicas / the one-shot
// migrate service. Migrations are immutable, forward-only, numbered .up.sql
// files; each is applied in its own transaction and recorded in
// schema_migrations (the authoritative DDL version per the plan).
package db

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.up.sql
var migrationsFS embed.FS

// advisoryLockKey is a fixed application-defined key for pg_advisory_lock.
const advisoryLockKey int64 = 6_421_775_004_991_001

type migration struct {
	version int64
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations dir: %w", err)
	}
	var out []migration
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		verStr, _, ok := strings.Cut(name, "_")
		if !ok {
			return nil, fmt.Errorf("malformed migration filename %q", name)
		}
		ver, err := strconv.ParseInt(verStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("migration %q: bad version: %w", name, err)
		}
		content, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", name, err)
		}
		out = append(out, migration{version: ver, name: name, sql: string(content)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// Migrate applies all pending migrations. It is safe to call concurrently from
// multiple processes; the advisory lock serializes them and applied versions
// are skipped.
func Migrate(ctx context.Context, pool *pgxpool.Pool) (applied int, err error) {
	migs, err := loadMigrations()
	if err != nil {
		return 0, err
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("acquire conn: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", advisoryLockKey); err != nil {
		return 0, fmt.Errorf("acquire advisory lock: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", advisoryLockKey)
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    bigint PRIMARY KEY,
			name       text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return 0, fmt.Errorf("ensure schema_migrations: %w", err)
	}

	appliedSet := map[int64]bool{}
	rows, err := conn.Query(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return 0, fmt.Errorf("read applied versions: %w", err)
	}
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return 0, err
		}
		appliedSet[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, m := range migs {
		if appliedSet[m.version] {
			continue
		}
		if err := applyOne(ctx, conn.Conn(), m); err != nil {
			return applied, fmt.Errorf("apply migration %s: %w", m.name, err)
		}
		applied++
	}
	return applied, nil
}

func applyOne(ctx context.Context, conn *pgx.Conn, m migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	if _, err := tx.Exec(ctx, m.sql); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		"INSERT INTO schema_migrations (version, name) VALUES ($1, $2)", m.version, m.name); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

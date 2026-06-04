//go:build integration

// Package itest holds end-to-end integration tests that need a live Postgres +
// Redis. They are excluded from the default build and run only with
// `go test -tags=integration ./...` when IAM_TEST_DATABASE_URL / IAM_TEST_REDIS_URL
// are set (e.g. against the docker-compose postgres/redis).
package itest

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/authz"
	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/db"
	"github.com/transcircle/iam/internal/rbac"
	"github.com/transcircle/iam/internal/store"
)

func openStore(t *testing.T) *store.Store {
	dsn := os.Getenv("IAM_TEST_DATABASE_URL")
	redisURL := os.Getenv("IAM_TEST_REDIS_URL")
	if dsn == "" || redisURL == "" {
		t.Skip("IAM_TEST_DATABASE_URL / IAM_TEST_REDIS_URL not set")
	}
	st, err := store.Open(context.Background(), dsn, redisURL)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return st
}

func TestMigrateAndEffectivePermissions(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	defer st.Close()

	if _, err := db.Migrate(ctx, st.Pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// The seeded catalog must satisfy the Go-declared permission constants.
	if err := authz.New(st).VerifyCatalog(ctx); err != nil {
		t.Fatalf("catalog verification: %v", err)
	}

	repo := rbac.Repo{}
	user := &rbac.User{
		ID: crypto.NewUUIDv7(), Username: "itest-" + crypto.RandomToken(4),
		Status: "active", IsActive: true,
	}
	err := st.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := repo.CreateUser(ctx, tx, user); err != nil {
			return err
		}
		// Grant super_admin (all system permissions) via direct role.
		if err := repo.AddUserRole(ctx, tx, user.ID, rbac.SuperAdminRole, user.ID); err != nil {
			return err
		}
		return repo.BumpPermVersion(ctx, tx, user.ID)
	})
	if err != nil {
		t.Fatalf("setup user: %v", err)
	}

	perms, err := repo.EffectivePermissions(ctx, st.Pool, user.ID, &rbac.SystemAppID)
	if err != nil {
		t.Fatalf("effective perms: %v", err)
	}
	found := false
	for _, p := range perms {
		if p.PermKey == authz.PermUsersRead {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected super_admin to include %s, got %d perms", authz.PermUsersRead, len(perms))
	}

	// Cleanup.
	_, _ = st.Pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, user.ID)
}

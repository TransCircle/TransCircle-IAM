//go:build integration

package itest

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/config"
	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/db"
	"github.com/transcircle/iam/internal/keys"
	"github.com/transcircle/iam/internal/rbac"
	"github.com/transcircle/iam/internal/superadmin"
)

// TestSuperAdminReconcile is the end-to-end guarantee: on boot, the live
// super_admin grants are force-aligned to the signed allowlist. It seeds four
// kinds of state — a config root, a directly DB-injected super_admin, a
// group-conferred super_admin, a validly-signed allowlist row, and a forged
// (bad-signature) row — then runs Reconcile and asserts only the root and the
// validly-signed user keep super_admin.
func TestSuperAdminReconcile(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	defer st.Close()
	if _, err := db.Migrate(ctx, st.Pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	repo := rbac.Repo{}
	cfg := &config.Config{} // KEK off: DEK stored bare, which is fine for the test

	sfx := crypto.RandomToken(4)
	root := &rbac.User{ID: crypto.NewUUIDv7(), Username: "itest-root-" + sfx, Status: "active", IsActive: true}
	intruder := &rbac.User{ID: crypto.NewUUIDv7(), Username: "itest-intruder-" + sfx, Status: "active", IsActive: true}
	legit := &rbac.User{ID: crypto.NewUUIDv7(), Username: "itest-legit-" + sfx, Status: "active", IsActive: true}
	forged := &rbac.User{ID: crypto.NewUUIDv7(), Username: "itest-forged-" + sfx, Status: "active", IsActive: true}
	gmember := &rbac.User{ID: crypto.NewUUIDv7(), Username: "itest-gm-" + sfx, Status: "active", IsActive: true}
	// deleted is validly signed but soft-deleted: it must NOT be re-granted.
	deleted := &rbac.User{ID: crypto.NewUUIDv7(), Username: "itest-deleted-" + sfx, Status: "active", IsActive: true}
	groupID := crypto.NewUUIDv7()
	allUsers := []*rbac.User{root, intruder, legit, forged, gmember, deleted}

	defer func() {
		for _, u := range allUsers {
			_, _ = st.Pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID)
		}
		_, _ = st.Pool.Exec(ctx, `DELETE FROM groups WHERE id=$1`, groupID)
	}()

	// Seed all four tamper/grant scenarios in one tx.
	err := st.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		dek, dekVer, err := keys.EnsureDEK(ctx, tx, cfg)
		if err != nil {
			return err
		}
		for _, u := range allUsers {
			if err := repo.CreateUser(ctx, tx, u); err != nil {
				return err
			}
		}
		// (a) Direct DB tamper: super_admin injected straight into user_roles.
		if err := repo.AddUserRole(ctx, tx, intruder.ID, rbac.SuperAdminRole, intruder.ID); err != nil {
			return err
		}
		// (b) Group-conferred super_admin tamper.
		if err := repo.CreateGroup(ctx, tx, &rbac.Group{ID: groupID, Key: "itest-grp-" + sfx, DisplayName: "g"}); err != nil {
			return err
		}
		if err := repo.AddGroupRole(ctx, tx, groupID, rbac.SuperAdminRole); err != nil {
			return err
		}
		if err := repo.AddGroupMember(ctx, tx, groupID, gmember.ID); err != nil {
			return err
		}
		// (c) A valid, signed allowlist row.
		if err := superadmin.UpsertGrant(ctx, tx, dek, dekVer, legit.ID, legit.Username, "test"); err != nil {
			return err
		}
		// (d) A forged allowlist row, hand-inserted with a bogus signature.
		if _, err = tx.Exec(ctx,
			`INSERT INTO super_admin_grants (user_id, username, dek_version, sig, note) VALUES ($1,$2,$3,$4,'')`,
			forged.ID, forged.Username, dekVer, []byte("not-a-valid-signature")); err != nil {
			return err
		}
		// (e) A validly-signed row whose user is then soft-deleted: must not regain.
		if err := superadmin.UpsertGrant(ctx, tx, dek, dekVer, deleted.ID, deleted.Username, "test"); err != nil {
			return err
		}
		return repo.SoftDeleteUser(ctx, tx, deleted.ID)
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Run reconcile in its own tx, like a real boot.
	var res superadmin.ReconcileResult
	err = st.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		dek, dekVer, err := keys.EnsureDEK(ctx, tx, cfg)
		if err != nil {
			return err
		}
		res, err = superadmin.Reconcile(ctx, tx, dek, dekVer, root.Username)
		return err
	})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	hasSuper := func(id uuid.UUID) bool {
		var n int
		if err := st.Pool.QueryRow(ctx,
			`SELECT count(*) FROM user_roles WHERE user_id=$1 AND role_id=$2`, id, rbac.SuperAdminRole).Scan(&n); err != nil {
			t.Fatalf("query user_roles: %v", err)
		}
		return n > 0
	}

	if !hasSuper(root.ID) {
		t.Error("root must hold super_admin after reconcile")
	}
	if !hasSuper(legit.ID) {
		t.Error("validly-allowlisted user must hold super_admin")
	}
	if hasSuper(intruder.ID) {
		t.Error("directly DB-injected super_admin must be stripped")
	}
	if hasSuper(forged.ID) {
		t.Error("forged allowlist row must NOT confer super_admin")
	}
	if hasSuper(deleted.ID) {
		t.Error("soft-deleted allowlisted user must NOT be re-granted super_admin")
	}

	var groupLinks int
	if err := st.Pool.QueryRow(ctx,
		`SELECT count(*) FROM group_roles WHERE role_id=$1`, rbac.SuperAdminRole).Scan(&groupLinks); err != nil {
		t.Fatalf("query group_roles: %v", err)
	}
	if groupLinks != 0 {
		t.Errorf("super_admin must never be group-conferred; found %d group link(s)", groupLinks)
	}

	foundIgnored := false
	for _, n := range res.IgnoredRows {
		if n == forged.Username {
			foundIgnored = true
		}
	}
	if !foundIgnored {
		t.Errorf("forged row %q should be reported in IgnoredRows, got %v", forged.Username, res.IgnoredRows)
	}
}

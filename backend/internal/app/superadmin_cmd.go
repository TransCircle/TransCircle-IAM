package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/keys"
	"github.com/transcircle/iam/internal/rbac"
	"github.com/transcircle/iam/internal/superadmin"
)

// lockSuperAdmin serializes a CLI allowlist mutation against a concurrent boot
// reconcile on another replica by taking the same advisory lock the bootstrap
// path holds (bootstrapLockKey, defined in bootstrap.go). Without it, an add could
// be granted then immediately stripped by a racing reconcile (or vice versa) until
// the next restart.
func lockSuperAdmin(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, bootstrapLockKey)
	return err
}

// SuperAdmin manages the super-admin allowlist — the only sanctioned way to add
// or remove a super admin. The live super_admin grants in user_roles are
// force-aligned to this list on every boot (superadmin.Reconcile), so this
// command, run from the server shell, is the sole durable channel: the web/API
// can never grant super_admin (enforced since the bootstrap-only change), and a
// direct DB edit is wiped on the next restart.
//
//	iam super-admin add <username> [note]   add (or re-affirm) a super admin
//	iam super-admin remove <username>        remove a super admin (not the root)
//	iam super-admin list                     list the allowlist
func SuperAdmin(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: iam super-admin <add|remove|list> [args]")
	}
	switch args[0] {
	case "add":
		if len(args) < 2 {
			return fmt.Errorf("usage: iam super-admin add <username> [note]")
		}
		note := ""
		if len(args) >= 3 {
			note = args[2]
		}
		return superAdminAdd(ctx, args[1], note)
	case "remove", "rm":
		if len(args) < 2 {
			return fmt.Errorf("usage: iam super-admin remove <username>")
		}
		return superAdminRemove(ctx, args[1])
	case "list", "ls":
		return superAdminList(ctx)
	default:
		return fmt.Errorf("unknown super-admin command %q", args[0])
	}
}

// superAdminAdd writes a signed allowlist row and grants the role immediately, so
// the change takes effect without waiting for the next boot's reconcile.
func superAdminAdd(ctx context.Context, username, note string) error {
	rt, err := setup(ctx)
	if err != nil {
		return err
	}
	defer rt.st.Close()
	repo := rbac.Repo{}

	return rt.st.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := lockSuperAdmin(ctx, tx); err != nil {
			return err
		}
		dek, dekVer, err := keys.EnsureDEK(ctx, tx, rt.cfg)
		if err != nil {
			return err
		}
		u, err := repo.GetUserByUsername(ctx, tx, username)
		if err != nil {
			return err
		}
		if err := superadmin.UpsertGrant(ctx, tx, dek, dekVer, u.ID, u.Username, note); err != nil {
			return err
		}
		if err := repo.EnsureRoleHasAllSystemPerms(ctx, tx, rbac.SuperAdminRole); err != nil {
			return err
		}
		if err := repo.AddUserRole(ctx, tx, u.ID, rbac.SuperAdminRole, uuid.Nil); err != nil {
			return err
		}
		if err := repo.BumpEpoch(ctx, tx); err != nil {
			return err
		}
		fmt.Printf("super-admin: 已将 %s 加入超级管理员名单并立即生效。\n", u.Username)
		return nil
	})
}

// superAdminRemove removes a user from the allowlist and revokes the live role.
// The configured bootstrap admin is the un-removable root.
func superAdminRemove(ctx context.Context, username string) error {
	rt, err := setup(ctx)
	if err != nil {
		return err
	}
	defer rt.st.Close()
	repo := rbac.Repo{}

	return rt.st.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := lockSuperAdmin(ctx, tx); err != nil {
			return err
		}
		u, err := repo.GetUserByUsername(ctx, tx, username)
		if err != nil {
			return err
		}
		// The configured bootstrap admin is the un-removable root. Compare by
		// user_id, NOT the CLI string: usernames are citext (case-insensitive), so a
		// string compare would let `remove Admin` slip past a root named `admin`.
		root, rerr := repo.GetUserByUsername(ctx, tx, rt.cfg.BootstrapAdminUsername)
		switch {
		case rerr == nil && root.ID == u.ID:
			return fmt.Errorf("super-admin: 系统初始超级管理员 %q 不可删除", u.Username)
		case rerr != nil && !errors.Is(rerr, rbac.ErrNotFound):
			return rerr
		}
		removed, err := superadmin.DeleteGrant(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		if err := repo.RemoveUserRole(ctx, tx, u.ID, rbac.SuperAdminRole); err != nil {
			return err
		}
		if err := repo.BumpEpoch(ctx, tx); err != nil {
			return err
		}
		if removed {
			fmt.Printf("super-admin: 已将 %s 移出名单并撤销其 super_admin 角色。\n", u.Username)
		} else {
			fmt.Printf("super-admin: %s 本不在名单中；已确保其未持有 super_admin 角色。\n", u.Username)
		}
		return nil
	})
}

// superAdminList prints the un-removable root plus every allowlist row, flagging
// any row whose signature does not verify (those are ignored + stripped on boot).
func superAdminList(ctx context.Context) error {
	rt, err := setup(ctx)
	if err != nil {
		return err
	}
	defer rt.st.Close()

	return rt.st.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		dek, dekVer, err := keys.EnsureDEK(ctx, tx, rt.cfg)
		if err != nil {
			return err
		}
		grants, err := superadmin.ListGrants(ctx, tx)
		if err != nil {
			return err
		}

		fmt.Printf("初始超级管理员（不可删除）: %s\n", rt.cfg.BootstrapAdminUsername)
		if len(grants) == 0 {
			fmt.Println("名单（CLI 添加）: 空")
			return nil
		}
		fmt.Println("名单（CLI 添加）:")
		for _, g := range grants {
			status := "签名有效"
			if !superadmin.VerifyGrant(dek, dekVer, g) {
				status = "签名无效(启动将被忽略并剥离)"
			}
			tag := ""
			if g.Username == rt.cfg.BootstrapAdminUsername {
				tag = " [初始]"
			}
			line := fmt.Sprintf("  - %s%s  添加于 %s  %s", g.Username, tag, g.AddedAt.Format("2006-01-02 15:04:05"), status)
			if g.Note != "" {
				line += "  备注: " + g.Note
			}
			fmt.Println(line)
		}
		return nil
	})
}

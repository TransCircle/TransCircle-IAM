package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/authn"
	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/db"
	"github.com/transcircle/iam/internal/keys"
	"github.com/transcircle/iam/internal/rbac"
)

// bootstrapOutput is written (0600) so the operator can retrieve the first-admin
// credentials and recovery codes once.
type bootstrapOutput struct {
	Username      string    `json:"username"`
	TempPassword  string    `json:"temp_password"`
	RecoveryCodes []string  `json:"recovery_codes"`
	GeneratedAt   time.Time `json:"generated_at"`
	Note          string    `json:"note"`
}

// bootstrapLockKey serializes initialization across replicas (distinct from the
// migration advisory-lock key).
const bootstrapLockKey int64 = 6_421_775_004_991_002

// ensureInitialized applies migrations and idempotently provisions keys, the
// WebAuthn RP config, and the first admin under an advisory lock so multiple
// replicas starting at once cannot race. Returns the first-admin output the
// first time it is created, or nil if the system was already initialized.
func ensureInitialized(ctx context.Context, rt *runtime) (*bootstrapOutput, error) {
	if _, err := db.Migrate(ctx, rt.st.Pool); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}

	conn, err := rt.st.Pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire conn: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", bootstrapLockKey); err != nil {
		return nil, fmt.Errorf("acquire bootstrap lock: %w", err)
	}
	defer func() { _, _ = conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", bootstrapLockKey) }()

	hasher := crypto.NewHasher(rt.cfg.Argon2Memory, rt.cfg.Argon2Iterations, rt.cfg.Argon2Parallelism, rt.cfg.Argon2MaxConcurrent)
	passwords := authn.NewPasswordService(hasher, 12, 5)
	recovery := authn.NewRecoveryService(hasher)
	repo := rbac.Repo{}

	var out *bootstrapOutput
	err = rt.st.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		dek, dekVer, err := keys.EnsureDEK(ctx, tx, rt.cfg)
		if err != nil {
			return err
		}
		if err := keys.EnsureSigningKey(ctx, tx, dek, dekVer); err != nil {
			return err
		}
		if err := keys.EnsureNamedSecret(ctx, tx, dek, dekVer, "oauth.hmac_secret"); err != nil {
			return err
		}
		if err := ensureWebAuthnRP(ctx, tx, rt.cfg.Issuer); err != nil {
			return err
		}

		// Self-heal the built-in roles every boot: re-grant all system permissions
		// to super_admin and admin (repairs an accidental permission wipe).
		if err := repo.EnsureRoleHasAllSystemPerms(ctx, tx, rbac.SuperAdminRole); err != nil {
			return err
		}
		if err := repo.EnsureRoleHasAllSystemPerms(ctx, tx, rbac.AdminRole); err != nil {
			return err
		}

		n, err := repo.CountUsers(ctx, tx)
		if err != nil {
			return err
		}
		if n > 0 {
			// System already has users: unconditionally re-grant the super_admin
			// AND admin direct roles to the bootstrap admin on every boot, so an
			// accidental role removal or permission wipe always self-heals on a
			// restart. (To permanently stop this, DELETE the bootstrap admin
			// account — a disabled-but-present account still gets re-granted.)
			if err := ensureBootstrapAdminRoles(ctx, tx, repo, rt.cfg.BootstrapAdminUsername); err != nil {
				return err
			}
			return nil
		}

		admin := &rbac.User{
			ID:                  crypto.NewUUIDv7(),
			Username:            rt.cfg.BootstrapAdminUsername,
			Email:               rt.cfg.BootstrapAdminEmail,
			DisplayName:         "系统管理员",
			Status:              "active",
			IsActive:            true,
			ForcePasswordChange: true,
			MustEnrollMFA:       true,
		}
		if err := repo.CreateUser(ctx, tx, admin); err != nil {
			return err
		}
		tempPassword := crypto.RandomToken(12)
		if err := passwords.SetInitial(ctx, tx, admin.ID, tempPassword); err != nil {
			return err
		}
		if err := repo.AddUserRole(ctx, tx, admin.ID, rbac.SuperAdminRole, admin.ID); err != nil {
			return err
		}
		if err := repo.AddUserRole(ctx, tx, admin.ID, rbac.AdminRole, admin.ID); err != nil {
			return err
		}
		codes, err := recovery.Generate(ctx, tx, admin.ID, 10)
		if err != nil {
			return err
		}
		out = &bootstrapOutput{
			Username:      admin.Username,
			TempPassword:  tempPassword,
			RecoveryCodes: codes,
			Note:          "首次登录将强制修改密码并绑定 Passkey/TOTP。请妥善保存恢复码后删除本文件。",
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Bootstrap initializes the system and exits (CLI subcommand).
func Bootstrap(ctx context.Context) error {
	rt, err := setup(ctx)
	if err != nil {
		return err
	}
	defer rt.st.Close()

	out, err := ensureInitialized(ctx, rt)
	if err != nil {
		return err
	}
	if out == nil {
		fmt.Println("bootstrap: 系统已初始化，跳过首管理员创建。")
		return nil
	}
	out.GeneratedAt = time.Now()
	return writeBootstrapOutput(rt.cfg.BootstrapOutFile, out)
}

// ensureBootstrapAdminRoles re-grants the super_admin AND admin direct roles to
// the configured bootstrap admin on every boot (idempotent), so an accidental
// role removal or permission wipe always self-heals on restart. If the bootstrap
// admin account has been deleted, there is nothing to recover to.
func ensureBootstrapAdminRoles(ctx context.Context, tx pgx.Tx, repo rbac.Repo, adminUsername string) error {
	admin, err := repo.GetUserByUsername(ctx, tx, adminUsername)
	if errors.Is(err, rbac.ErrNotFound) {
		return nil // no bootstrap admin to recover to
	}
	if err != nil {
		return err
	}
	for _, role := range []uuid.UUID{rbac.SuperAdminRole, rbac.AdminRole} {
		if err := repo.AddUserRole(ctx, tx, admin.ID, role, admin.ID); err != nil {
			return err
		}
	}
	if err := repo.BumpPermVersion(ctx, tx, admin.ID); err != nil {
		return err
	}
	fmt.Printf("bootstrap: 已确保 %s 持有 super_admin 与 admin 直接角色。\n", admin.Username)
	return nil
}

func ensureWebAuthnRP(ctx context.Context, tx pgx.Tx, issuer string) error {
	u, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("parse issuer: %w", err)
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO webauthn_rp_config (id, rp_id, rp_display_name, origins, attestation, user_verification)
		 VALUES (1, $1, $2, $3, 'none', 'required')
		 ON CONFLICT (id) DO NOTHING`,
		u.Hostname(), "TransCircle IAM", []string{issuer})
	return err
}

func writeBootstrapOutput(path string, out *bootstrapOutput) error {
	data, _ := json.MarshalIndent(out, "", "  ")
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
			if err := os.WriteFile(path, data, 0o600); err == nil {
				fmt.Printf("bootstrap: 首管理员凭据已写入 %s (0600)。\n", path)
				fmt.Printf("           用户名: %s  临时密码: %s\n", out.Username, out.TempPassword)
				return nil
			}
		}
	}
	// Fallback: print to stdout.
	fmt.Println("bootstrap: 无法写入凭据文件，输出到标准输出：")
	fmt.Println(string(data))
	return nil
}

// Admin runs offline break-glass operations.
//
//	iam admin reset-mfa <username>   clear all MFA factors and force re-enrollment
func Admin(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: iam admin <reset-mfa> [args]")
	}
	switch args[0] {
	case "reset-mfa":
		if len(args) < 2 {
			return fmt.Errorf("usage: iam admin reset-mfa <username>")
		}
		return adminResetMFA(ctx, args[1])
	case "grant-super-admin":
		if len(args) < 2 {
			return fmt.Errorf("usage: iam admin grant-super-admin <username>")
		}
		return adminGrantSuperAdmin(ctx, args[1])
	case "reset-password":
		if len(args) < 2 {
			return fmt.Errorf("usage: iam admin reset-password <username> [new-password]")
		}
		explicit := ""
		if len(args) >= 3 {
			explicit = args[2]
		}
		return adminResetPassword(ctx, args[1], explicit)
	default:
		return fmt.Errorf("unknown admin command %q", args[0])
	}
}

// adminResetPassword is the break-glass password reset. With no password given it
// generates a temporary one and forces a change at next login; with an explicit
// password it sets it directly. Existing MFA factors are left intact.
func adminResetPassword(ctx context.Context, username, explicit string) error {
	rt, err := setup(ctx)
	if err != nil {
		return err
	}
	defer rt.st.Close()
	repo := rbac.Repo{}
	hasher := crypto.NewHasher(rt.cfg.Argon2Memory, rt.cfg.Argon2Iterations, rt.cfg.Argon2Parallelism, rt.cfg.Argon2MaxConcurrent)

	password := explicit
	force := false
	if password == "" {
		password = crypto.RandomToken(9)
		force = true
	}
	hash, err := hasher.Hash(ctx, password)
	if err != nil {
		return err
	}

	return rt.st.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		u, err := repo.GetUserByUsername(ctx, tx, username)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO user_credentials (user_id, password_hash, password_change_required, previous_hashes)
			 VALUES ($1, $2, $3, '{}')
			 ON CONFLICT (user_id) DO UPDATE
			   SET password_hash=EXCLUDED.password_hash,
			       password_change_required=EXCLUDED.password_change_required,
			       previous_hashes='{}', password_updated_at=now()`,
			u.ID, hash, force); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET force_password_change=$2 WHERE id=$1`, u.ID, force); err != nil {
			return err
		}
		if force {
			fmt.Printf("admin: 已为 %s 设置临时密码: %s （下次登录须改密）。\n", username, password)
		} else {
			fmt.Printf("admin: 已为 %s 设置新密码。\n", username)
		}
		return nil
	})
}

// adminGrantSuperAdmin re-grants the super_admin role to a user and re-syncs the
// role's permissions — the break-glass recovery for a self-inflicted lockout.
func adminGrantSuperAdmin(ctx context.Context, username string) error {
	rt, err := setup(ctx)
	if err != nil {
		return err
	}
	defer rt.st.Close()
	repo := rbac.Repo{}

	return rt.st.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		u, err := repo.GetUserByUsername(ctx, tx, username)
		if err != nil {
			return err
		}
		if err := repo.EnsureRoleHasAllSystemPerms(ctx, tx, rbac.SuperAdminRole); err != nil {
			return err
		}
		if err := repo.AddUserRole(ctx, tx, u.ID, rbac.SuperAdminRole, u.ID); err != nil {
			return err
		}
		if err := repo.BumpPermVersion(ctx, tx, u.ID); err != nil {
			return err
		}
		fmt.Printf("admin: 已将 super_admin 授予用户 %s 并重置该角色权限。\n", username)
		return nil
	})
}

func adminResetMFA(ctx context.Context, username string) error {
	rt, err := setup(ctx)
	if err != nil {
		return err
	}
	defer rt.st.Close()
	repo := rbac.Repo{}

	return rt.st.WithTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		u, err := repo.GetUserByUsername(ctx, tx, username)
		if err != nil {
			return err
		}
		for _, q := range []string{
			`DELETE FROM webauthn_credentials WHERE user_id=$1`,
			`DELETE FROM totp_secrets WHERE user_id=$1`,
			`DELETE FROM recovery_codes WHERE user_id=$1`,
		} {
			if _, err := tx.Exec(ctx, q, u.ID); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE users SET must_enroll_mfa=true WHERE id=$1`, u.ID); err != nil {
			return err
		}
		fmt.Printf("admin: 已重置用户 %s 的全部 MFA 因子，下次登录需重新绑定。\n", username)
		return nil
	})
}

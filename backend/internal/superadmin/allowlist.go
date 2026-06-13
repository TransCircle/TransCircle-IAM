// Package superadmin owns the authoritative super-admin allowlist and the
// boot-time reconciliation that makes the built-in super_admin role
// tamper-resistant.
//
// "Who is a super admin" is NOT the live user_roles grant — that table is just a
// cache of the policy. The policy is this allowlist: a signed table whose rows
// are produced only by the `iam super-admin` CLI. On every boot Reconcile
// force-aligns user_roles to exactly {config bootstrap admin} ∪ {verified rows},
// so a direct DB edit of user_roles (or a group hung off super_admin) is wiped
// on restart and a hand-inserted allowlist row without a valid signature is
// ignored.
package superadmin

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/transcircle/iam/internal/rbac"
	"github.com/transcircle/iam/internal/store"
)

// macDomain domain-separates the allowlist signing sub-key from any other use of
// the DEK, so the DEK is never used directly as an HMAC key here.
const macDomain = "tc:superadmin-allowlist:v1"

// sign computes the per-row tag binding a user id to the DEK version that signed
// it. Including the version means a future DEK rotation predictably invalidates
// old rows (they would need re-signing) instead of silently verifying.
func sign(dek []byte, dekVersion int, userID uuid.UUID) []byte {
	subkey := hmacSum(dek, []byte(macDomain))
	msg := fmt.Sprintf("v1|%d|%s", dekVersion, userID.String())
	return hmacSum(subkey, []byte(msg))
}

// verify reports whether sig is the valid tag for (dekVersion, userID) under dek,
// in constant time.
func verify(dek []byte, dekVersion int, userID uuid.UUID, sig []byte) bool {
	return hmac.Equal(sign(dek, dekVersion, userID), sig)
}

func hmacSum(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// Grant is one allowlist row.
type Grant struct {
	UserID     uuid.UUID
	Username   string
	DEKVersion int
	Sig        []byte
	Note       string
	AddedAt    time.Time
}

// VerifyGrant reports whether g's signature is valid under the active DEK. A row
// signed with a different DEK version (e.g. after a future rotation) cannot be
// verified with the current key and is treated as invalid.
func VerifyGrant(dek []byte, dekVersion int, g Grant) bool {
	return dekVersion == g.DEKVersion && verify(dek, g.DEKVersion, g.UserID, g.Sig)
}

// ListGrants returns every allowlist row, oldest first.
func ListGrants(ctx context.Context, db store.DBTX) ([]Grant, error) {
	rows, err := db.Query(ctx,
		`SELECT user_id, username, dek_version, sig, note, added_at
		   FROM super_admin_grants ORDER BY added_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Grant{}
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.UserID, &g.Username, &g.DEKVersion, &g.Sig, &g.Note, &g.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// UpsertGrant inserts or re-affirms a signed allowlist row for userID.
func UpsertGrant(ctx context.Context, db store.DBTX, dek []byte, dekVersion int, userID uuid.UUID, username, note string) error {
	sig := sign(dek, dekVersion, userID)
	_, err := db.Exec(ctx,
		`INSERT INTO super_admin_grants (user_id, username, dek_version, sig, note)
		 VALUES ($1,$2,$3,$4,$5)
		 ON CONFLICT (user_id) DO UPDATE
		   SET username=EXCLUDED.username, dek_version=EXCLUDED.dek_version,
		       sig=EXCLUDED.sig, note=EXCLUDED.note`,
		userID, username, dekVersion, sig, note)
	return err
}

// DeleteGrant removes userID from the allowlist; the bool reports whether a row
// was actually present.
func DeleteGrant(ctx context.Context, db store.DBTX, userID uuid.UUID) (bool, error) {
	tag, err := db.Exec(ctx, `DELETE FROM super_admin_grants WHERE user_id=$1`, userID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ReconcileResult summarizes what the boot-time alignment changed.
type ReconcileResult struct {
	Authorized    int      // size of the authoritative super-admin set
	Granted       int      // users that gained the direct super_admin role
	Revoked       int      // direct super_admin grants stripped (not on the list)
	GroupsCleared int      // group→super_admin links removed
	IgnoredRows   []string // usernames of allowlist rows whose signature failed
}

// Changed reports whether the reconcile mutated any grant.
func (r ReconcileResult) Changed() bool {
	return r.Granted > 0 || r.Revoked > 0 || r.GroupsCleared > 0
}

// Reconcile force-aligns the live super_admin grants to the authoritative set =
// {root user, resolved by username} ∪ {signed rows that verify}. It must run
// inside the advisory-locked bootstrap transaction. super_admin is never
// conferred through a group, so every group→super_admin link is dropped.
//
// A deleted root account is not recreated here (matches the existing bootstrap
// self-heal semantics); recover it with `iam super-admin add`.
func Reconcile(ctx context.Context, tx store.DBTX, dek []byte, dekVersion int, rootUsername string) (ReconcileResult, error) {
	var res ReconcileResult
	repo := rbac.Repo{}

	// 1. Build the authoritative user-id set: the config root plus every row
	//    whose signature verifies. Rows that fail verification are recorded and
	//    skipped — they will be reconciled away in step 4.
	authorized := map[uuid.UUID]struct{}{}
	if root, err := repo.GetUserByUsername(ctx, tx, rootUsername); err == nil {
		authorized[root.ID] = struct{}{}
	} else if !errors.Is(err, rbac.ErrNotFound) {
		return res, err
	}

	// Read allowlist rows joined to their user's liveness. A row is authorized only
	// if its signature verifies AND the user is not soft-deleted — otherwise a
	// deleted-but-allowlisted account would be re-granted super_admin on every boot
	// (SoftDeleteUser does not cascade-remove the grant row; the FK only fires on a
	// hard delete). Fully drain + close before any write on this tx.
	type grantRow struct {
		userID   uuid.UUID
		username string
		dekVer   int
		sig      []byte
		live     bool
	}
	gr, err := tx.Query(ctx,
		`SELECT g.user_id, g.username, g.dek_version, g.sig, (u.deleted_at IS NULL)
		   FROM super_admin_grants g JOIN users u ON u.id = g.user_id`)
	if err != nil {
		return res, err
	}
	var grantRows []grantRow
	for gr.Next() {
		var g grantRow
		if scanErr := gr.Scan(&g.userID, &g.username, &g.dekVer, &g.sig, &g.live); scanErr != nil {
			gr.Close()
			return res, scanErr
		}
		grantRows = append(grantRows, g)
	}
	gr.Close()
	if err := gr.Err(); err != nil {
		return res, err
	}
	for _, g := range grantRows {
		if !VerifyGrant(dek, dekVersion, Grant{UserID: g.userID, DEKVersion: g.dekVer, Sig: g.sig}) {
			res.IgnoredRows = append(res.IgnoredRows, g.username)
			continue
		}
		if !g.live {
			continue // soft-deleted user: do not re-grant; an operator can prune the row
		}
		authorized[g.userID] = struct{}{}
	}
	res.Authorized = len(authorized)

	// 2. super_admin is never group-conferred: drop every group→super_admin link.
	tag, err := tx.Exec(ctx, `DELETE FROM group_roles WHERE role_id=$1`, rbac.SuperAdminRole)
	if err != nil {
		return res, err
	}
	res.GroupsCleared = int(tag.RowsAffected())

	// 3. Read the current DIRECT holders. Fully drain + close before any write,
	//    so the next Exec on this tx is not blocked by an open portal.
	holderRows, err := tx.Query(ctx, `SELECT user_id FROM user_roles WHERE role_id=$1`, rbac.SuperAdminRole)
	if err != nil {
		return res, err
	}
	var holderIDs []uuid.UUID
	for holderRows.Next() {
		var id uuid.UUID
		if scanErr := holderRows.Scan(&id); scanErr != nil {
			holderRows.Close()
			return res, scanErr
		}
		holderIDs = append(holderIDs, id)
	}
	holderRows.Close()
	if err := holderRows.Err(); err != nil {
		return res, err
	}
	holders := make(map[uuid.UUID]struct{}, len(holderIDs))
	for _, id := range holderIDs {
		holders[id] = struct{}{}
	}

	// 4. Revoke the direct role from anyone not authorized.
	for _, id := range holderIDs {
		if _, ok := authorized[id]; !ok {
			if err := repo.RemoveUserRole(ctx, tx, id, rbac.SuperAdminRole); err != nil {
				return res, err
			}
			res.Revoked++
		}
	}
	// 5. Grant the direct role to authorized users who lack it. granted_by is left
	//    NULL (uuid.Nil) to denote a system/bootstrap action.
	for id := range authorized {
		if _, ok := holders[id]; !ok {
			if err := repo.AddUserRole(ctx, tx, id, rbac.SuperAdminRole, uuid.Nil); err != nil {
				return res, err
			}
			res.Granted++
		}
	}

	// 6. Any change invalidates cached effective permissions globally.
	if res.Changed() {
		if err := repo.BumpEpoch(ctx, tx); err != nil {
			return res, err
		}
	}
	return res, nil
}

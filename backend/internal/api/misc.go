package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/audit"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/keys"
)

// ----- Admin sessions -----

func (h *Handlers) listUserSessions(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	// A plain admin must not inspect another admin/super-admin's sessions.
	if err := h.assertCanManageUser(ctx, actorID(r), id); err != nil {
		return err
	}
	list, err := h.Sessions.ListForUser(r.Context(), id)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"sessions": list})
	return nil
}

func (h *Handlers) revokeSession(w http.ResponseWriter, r *http.Request) error {
	sid, err := pathUUID(r, "sid")
	if err != nil {
		return err
	}
	ctx := r.Context()
	// Resolve the session owner and enforce the manage-user relationship so a
	// plain admin cannot revoke another admin/super-admin's session.
	var owner uuid.UUID
	err = h.Store.Pool.QueryRow(ctx, `SELECT user_id FROM sessions WHERE id=$1`, sid).Scan(&owner)
	if errors.Is(err, pgx.ErrNoRows) {
		httpx.NoContent(w) // nothing to revoke (idempotent)
		return nil
	}
	if err != nil {
		return err
	}
	if err := h.assertCanManageUser(ctx, actorID(r), owner); err != nil {
		return err
	}
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Sessions.Revoke(ctx, tx, sid); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.session.revoke", TargetType: "session", TargetID: sid.String()})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) revokeAllUserSessions(w http.ResponseWriter, r *http.Request) error {
	id, err := pathUUID(r, "id")
	if err != nil {
		return err
	}
	ctx := r.Context()
	if err := h.assertCanManageUser(ctx, actorID(r), id); err != nil {
		return err
	}
	err = h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if err := h.Sessions.RevokeAllForUser(ctx, tx, id, nil); err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.session.revoke_all", TargetType: "user", TargetID: id.String()})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

// ----- Audit -----

func (h *Handlers) listAudit(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	f := audit.Filter{
		Action: q.Get("action"),
		Actor:  q.Get("actor"),
		Result: q.Get("result"),
		Limit:  queryInt(r, "limit", 50),
		Offset: queryInt(r, "offset", 0),
	}
	if s := q.Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			f.Since = &t
		}
	}
	if s := q.Get("until"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			f.Until = &t
		}
	}
	entries, err := h.Audit.List(r.Context(), f)
	if err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"entries": entries})
	return nil
}

// ----- Settings: WebAuthn RP + policy -----

type webauthnRP struct {
	RPID             string   `json:"rp_id"`
	RPDisplayName    string   `json:"rp_display_name"`
	Origins          []string `json:"origins"`
	Attestation      string   `json:"attestation"`
	UserVerification string   `json:"user_verification"`
}

func (h *Handlers) getWebAuthnRP(w http.ResponseWriter, r *http.Request) error {
	var rp webauthnRP
	err := h.Store.Pool.QueryRow(r.Context(),
		`SELECT rp_id, rp_display_name, origins, attestation, user_verification FROM webauthn_rp_config WHERE id=1`).
		Scan(&rp.RPID, &rp.RPDisplayName, &rp.Origins, &rp.Attestation, &rp.UserVerification)
	if err != nil {
		return httpx.ErrNotFound.WithDetail("WebAuthn 配置缺失")
	}
	httpx.JSON(w, r, http.StatusOK, rp)
	return nil
}

func (h *Handlers) updateWebAuthnRP(w http.ResponseWriter, r *http.Request) error {
	var rp webauthnRP
	if err := httpx.DecodeJSON(r, &rp); err != nil {
		return err
	}
	// Validate (must-fix #13): rp_id and origins must be well-formed https.
	if rp.RPID == "" || len(rp.Origins) == 0 {
		return httpx.ErrBadRequest.WithDetail("rp_id 与 origins 必填")
	}
	for _, o := range rp.Origins {
		if len(o) < 8 || (o[:7] != "http://" && o[:8] != "https://") {
			return httpx.ErrBadRequest.WithDetail("origin 必须是合法 URL: " + o)
		}
	}
	if rp.Attestation == "" {
		rp.Attestation = "none"
	}
	if rp.UserVerification == "" {
		rp.UserVerification = "required"
	}
	ctx := r.Context()
	err := h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE webauthn_rp_config SET rp_id=$1, rp_display_name=$2, origins=$3, attestation=$4, user_verification=$5 WHERE id=1`,
			rp.RPID, rp.RPDisplayName, rp.Origins, rp.Attestation, rp.UserVerification)
		if err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.settings.webauthn_update", TargetType: "settings", TargetID: "webauthn"})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

func (h *Handlers) getPolicy(w http.ResponseWriter, r *http.Request) error {
	var raw string
	err := h.Store.Pool.QueryRow(r.Context(), `SELECT value::text FROM system_settings WHERE key='security.policy'`).Scan(&raw)
	if err != nil {
		raw = "{}"
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write([]byte(raw))
	return nil
}

func (h *Handlers) updatePolicy(w http.ResponseWriter, r *http.Request) error {
	var policy map[string]any
	if err := httpx.DecodeJSON(r, &policy); err != nil {
		return err
	}
	ctx := r.Context()
	// The email-change lock is a super-admin-only policy: a plain admin holding
	// iam.settings.write must not flip it in either direction (omitting the key
	// counts as turning it off, so that is gated too). Non-boolean values are
	// rejected outright — the SQL reader compares value->>'...' = 'true', so a
	// string "true" would otherwise enable the lock while dodging this gate.
	var next bool
	if v, ok := policy["disable_self_email_change"]; ok {
		b, isBool := v.(bool)
		if !isBool {
			return httpx.ErrBadRequest.WithDetail("disable_self_email_change 必须是布尔值")
		}
		next = b
	}
	actor := actorID(r)
	err := h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		// The gate must compare against COMMITTED state inside the writing tx:
		// without the exclusive lock, a plain admin's stale full-object upsert
		// racing a super-admin's flip would silently erase the fresh value.
		if err := h.Repo.LockPolicyExclusive(ctx, tx); err != nil {
			return err
		}
		cur, err := h.Repo.EmailChangeRestricted(ctx, tx)
		if err != nil {
			return err
		}
		if next != cur {
			super, err := h.isSuperAdmin(ctx, actor)
			if err != nil {
				return err
			}
			if !super {
				return httpx.ErrForbidden.WithDetail("仅超级管理员可更改邮箱锁定策略")
			}
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO system_settings (key, value) VALUES ('security.policy', $1::jsonb)
			 ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`, mustJSON(policy))
		if err != nil {
			return err
		}
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.settings.policy_update", TargetType: "settings", TargetID: "policy"})
	})
	if err != nil {
		return err
	}
	httpx.NoContent(w)
	return nil
}

// ----- Security: keys -----

func (h *Handlers) listKeys(w http.ResponseWriter, r *http.Request) error {
	rows, err := h.Store.Pool.Query(r.Context(),
		`SELECT kid, algorithm, status, created_at, activated_at FROM signing_keys ORDER BY created_at DESC`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type keyInfo struct {
		KID         string     `json:"kid"`
		Algorithm   string     `json:"algorithm"`
		Status      string     `json:"status"`
		CreatedAt   time.Time  `json:"created_at"`
		ActivatedAt *time.Time `json:"activated_at"`
	}
	out := []keyInfo{}
	for rows.Next() {
		var k keyInfo
		if err := rows.Scan(&k.KID, &k.Algorithm, &k.Status, &k.CreatedAt, &k.ActivatedAt); err != nil {
			return err
		}
		out = append(out, k)
	}
	var dekVersion int
	_ = h.Store.Pool.QueryRow(r.Context(), `SELECT version FROM crypto_keys WHERE status='active'`).Scan(&dekVersion)
	httpx.JSON(w, r, http.StatusOK, map[string]any{"signing_keys": out, "active_dek_version": dekVersion})
	return nil
}

func (h *Handlers) rotateSigningKey(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	var newKID string
	// Rotation and its audit record commit atomically (fail-closed): if the audit
	// write fails the rotation rolls back.
	err := h.tx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		kid, e := keys.RotateSigningKeyTx(ctx, tx, h.Cfg)
		if e != nil {
			return e
		}
		newKID = kid
		return h.Audit.Write(ctx, tx, audit.Event{Action: "iam.security.rotate_key", TargetType: "signing_key", TargetID: kid})
	})
	if err != nil {
		return err
	}
	// Reload published keys only after the rotation has committed.
	if err := h.Keys.Reload(ctx, h.Store, h.Cfg); err != nil {
		return err
	}
	httpx.JSON(w, r, http.StatusOK, map[string]string{"new_kid": newKID})
	return nil
}

// ----- Dashboard -----

func (h *Handlers) dashboardStats(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	stats := map[string]int{}
	for key, q := range map[string]string{
		"users":        `SELECT count(*) FROM users WHERE deleted_at IS NULL`,
		"applications": `SELECT count(*) FROM applications WHERE deleted_at IS NULL`,
		"clients":      `SELECT count(*) FROM oauth_clients`,
		"groups":       `SELECT count(*) FROM groups`,
		"sessions":     `SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > now()`,
	} {
		var n int
		_ = h.Store.Pool.QueryRow(ctx, q).Scan(&n)
		stats[key] = n
	}
	httpx.JSON(w, r, http.StatusOK, map[string]any{"stats": stats})
	return nil
}

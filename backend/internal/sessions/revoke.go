package sessions

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/transcircle/iam/internal/store"
)

// Revoke force-logs-out a single session and tombstones it in Redis so every
// replica drops it immediately.
func (m *Manager) Revoke(ctx context.Context, db store.DBTX, id uuid.UUID) error {
	var expiresAt time.Time
	err := db.QueryRow(ctx,
		`UPDATE sessions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL RETURNING expires_at`, id).
		Scan(&expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // already revoked or missing: idempotent
	}
	if err != nil {
		return err // a real DB error must not be reported as a successful revoke
	}
	// Tombstone only after the surrounding transaction commits, so a rolled-back
	// revoke (e.g. a failed audit write in the same tx) never force-logs-out a
	// still-valid session. All callers run inside Store.WithTx.
	store.AfterCommit(ctx, func(ctx context.Context) { m.tombstone(ctx, id, expiresAt) })
	return nil
}

// RevokeAllForUser revokes every active session for a user, optionally keeping
// one (the caller's current session).
func (m *Manager) RevokeAllForUser(ctx context.Context, db store.DBTX, userID uuid.UUID, except *uuid.UUID) error {
	rows, err := db.Query(ctx,
		`UPDATE sessions SET revoked_at=now()
		   WHERE user_id=$1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR id <> $2)
		 RETURNING id, expires_at`, userID, except)
	if err != nil {
		return err
	}
	defer rows.Close()
	type tomb struct {
		id  uuid.UUID
		exp time.Time
	}
	var tombs []tomb
	for rows.Next() {
		var t tomb
		if err := rows.Scan(&t.id, &t.exp); err != nil {
			return err
		}
		tombs = append(tombs, t)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	store.AfterCommit(ctx, func(ctx context.Context) {
		for _, t := range tombs {
			m.tombstone(ctx, t.id, t.exp)
		}
	})
	return nil
}

func (m *Manager) tombstone(ctx context.Context, id uuid.UUID, expiresAt time.Time) {
	ttl := time.Until(expiresAt)
	if ttl < time.Minute {
		ttl = time.Minute
	}
	pipe := m.st.Redis.Pipeline()
	pipe.Del(ctx, mirrorKey(id))
	pipe.Set(ctx, tombstoneKey(id), "1", ttl)
	_, _ = pipe.Exec(ctx)
}

// ListForUser returns a user's active sessions (newest first).
func (m *Manager) ListForUser(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	rows, err := m.st.Pool.Query(ctx,
		`SELECT id, user_id, created_at, last_seen_at, expires_at, idle_expires_at, revoked_at,
		        host(ip), user_agent, amr, aal, mfa_satisfied, mfa_satisfied_at, impersonator_user_id
		   FROM sessions WHERE user_id=$1 AND revoked_at IS NULL AND expires_at > now()
		 ORDER BY last_seen_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var s Session
		var ip *string
		if err := rows.Scan(&s.ID, &s.UserID, &s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt, &s.IdleExpiresAt,
			&s.RevokedAt, &ip, &s.UserAgent, &s.AMR, &s.AAL, &s.MFASatisfied, &s.MFAAt, &s.ImpersonatorID); err != nil {
			return nil, err
		}
		if ip != nil {
			s.IP = *ip
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

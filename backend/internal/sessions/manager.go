// Package sessions manages login sessions. Postgres is the authoritative device
// list; Redis provides a fast-path mirror and a revocation tombstone so remote
// force-logout propagates instantly across stateless replicas.
package sessions

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/transcircle/iam/internal/store"
)

// ErrInvalid means the session is missing, revoked, or expired.
var ErrInvalid = errors.New("sessions: invalid session")

// Session is a login session / device record.
type Session struct {
	ID             uuid.UUID  `json:"id"`
	UserID         uuid.UUID  `json:"user_id"`
	CreatedAt      time.Time  `json:"created_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	ExpiresAt      time.Time  `json:"expires_at"`
	IdleExpiresAt  time.Time  `json:"idle_expires_at"`
	RevokedAt      *time.Time `json:"revoked_at"`
	IP             string     `json:"ip"`
	UserAgent      string     `json:"user_agent"`
	AMR            []string   `json:"amr"`
	AAL            int        `json:"aal"`
	MFASatisfied   bool       `json:"mfa_satisfied"`
	MFAAt          *time.Time `json:"mfa_satisfied_at"`
	ImpersonatorID *uuid.UUID `json:"impersonator_user_id"`
}

// Manager owns session lifecycle.
type Manager struct {
	st          *store.Store
	idleTTL     time.Duration
	absoluteTTL time.Duration
	// mirrorTTL caps how long the Redis fast-path mirror is trusted. It is short
	// so that a failed revocation tombstone self-heals (Resolve then falls back to
	// the authoritative Postgres row). Session idle/absolute expiry is enforced by
	// timestamps inside the mirror, not by this TTL.
	mirrorTTL time.Duration
}

// NewManager builds a session manager.
func NewManager(st *store.Store, idleTTL, absoluteTTL time.Duration) *Manager {
	mirrorTTL := 5 * time.Minute
	if idleTTL < mirrorTTL {
		mirrorTTL = idleTTL
	}
	return &Manager{st: st, idleTTL: idleTTL, absoluteTTL: absoluteTTL, mirrorTTL: mirrorTTL}
}

// CreateParams describes a new session.
type CreateParams struct {
	UserID       uuid.UUID
	IP           string
	UserAgent    string
	AMR          []string
	AAL          int
	MFASatisfied bool
	// StepUp marks the session's MFA as "fresh" for step-up — true only for a
	// strong factor (TOTP/passkey), false for recovery-code or password-only
	// logins, so recovery codes never satisfy step-up.
	StepUp         bool
	ImpersonatorID *uuid.UUID
}

// Create inserts a session and writes its Redis mirror. Runs inside the caller's tx.
func (m *Manager) Create(ctx context.Context, db store.DBTX, p CreateParams) (*Session, error) {
	now := time.Now()
	s := &Session{
		ID:             uuid.New(), // random v4: this id is the bearer cookie value
		UserID:         p.UserID,
		CreatedAt:      now,
		LastSeenAt:     now,
		ExpiresAt:      now.Add(m.absoluteTTL),
		IdleExpiresAt:  now.Add(m.idleTTL),
		IP:             p.IP,
		UserAgent:      p.UserAgent,
		AMR:            orEmpty(p.AMR),
		AAL:            p.AAL,
		MFASatisfied:   p.MFASatisfied,
		ImpersonatorID: p.ImpersonatorID,
	}
	// mfa_satisfied_at drives the step-up freshness window; only set it for a
	// strong factor, never for recovery-code logins.
	if p.StepUp {
		s.MFAAt = &now
	}
	var ipArg any
	if p.IP != "" {
		ipArg = p.IP
	}
	_, err := db.Exec(ctx,
		`INSERT INTO sessions (id, user_id, expires_at, idle_expires_at, ip, user_agent, amr, aal, mfa_satisfied, mfa_satisfied_at, impersonator_user_id)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		s.ID, s.UserID, s.ExpiresAt, s.IdleExpiresAt, ipArg, s.UserAgent, s.AMR, s.AAL, s.MFASatisfied, s.MFAAt, s.ImpersonatorID)
	if err != nil {
		return nil, err
	}
	// Mirror is written after commit so a rolled-back session never appears.
	store.AfterCommit(ctx, func(ctx context.Context) { m.writeMirror(ctx, s) })
	return s, nil
}

// orEmpty coalesces a nil slice to an empty one so the NOT NULL amr text[]
// column (explicitly listed in the INSERT, so DEFAULT '{}' is bypassed) never
// receives a SQL NULL regardless of what a caller passes.
func orEmpty(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func mirrorKey(id uuid.UUID) string    { return "session:" + id.String() }
func tombstoneKey(id uuid.UUID) string { return "revoked:session:" + id.String() }

func (m *Manager) writeMirror(ctx context.Context, s *Session) {
	raw, err := json.Marshal(s)
	if err != nil {
		return
	}
	_ = m.st.Redis.Set(ctx, mirrorKey(s.ID), raw, m.mirrorTTL).Err()
}

// Resolve loads and validates a session by id (the cookie value).
func (m *Manager) Resolve(ctx context.Context, id uuid.UUID) (*Session, error) {
	if exists, _ := m.st.Redis.Exists(ctx, tombstoneKey(id)).Result(); exists == 1 {
		return nil, ErrInvalid
	}
	// Fast path: Redis mirror.
	if raw, err := m.st.Redis.Get(ctx, mirrorKey(id)).Bytes(); err == nil {
		var s Session
		if json.Unmarshal(raw, &s) == nil && m.valid(&s) {
			m.touch(ctx, &s)
			return &s, nil
		}
	} else if !errors.Is(err, redis.Nil) {
		// fall through to DB
	}
	// Authoritative path: Postgres.
	s, err := m.load(ctx, id)
	if err != nil {
		return nil, err
	}
	if !m.valid(s) {
		return nil, ErrInvalid
	}
	m.writeMirror(ctx, s)
	m.touch(ctx, s)
	return s, nil
}

func (m *Manager) valid(s *Session) bool {
	now := time.Now()
	return s.RevokedAt == nil && now.Before(s.ExpiresAt) && now.Before(s.IdleExpiresAt)
}

func (m *Manager) load(ctx context.Context, id uuid.UUID) (*Session, error) {
	var s Session
	var ip *string
	err := m.st.Pool.QueryRow(ctx,
		`SELECT id, user_id, created_at, last_seen_at, expires_at, idle_expires_at, revoked_at,
		        host(ip), user_agent, amr, aal, mfa_satisfied, mfa_satisfied_at, impersonator_user_id
		   FROM sessions WHERE id=$1`, id).
		Scan(&s.ID, &s.UserID, &s.CreatedAt, &s.LastSeenAt, &s.ExpiresAt, &s.IdleExpiresAt, &s.RevokedAt,
			&ip, &s.UserAgent, &s.AMR, &s.AAL, &s.MFASatisfied, &s.MFAAt, &s.ImpersonatorID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInvalid
	}
	if err != nil {
		return nil, err
	}
	if ip != nil {
		s.IP = *ip
	}
	return &s, nil
}

// touch slides the idle deadline (throttled to once a minute) and refreshes the
// Redis mirror TTL.
func (m *Manager) touch(ctx context.Context, s *Session) {
	now := time.Now()
	if now.Sub(s.LastSeenAt) < time.Minute {
		return
	}
	newIdle := now.Add(m.idleTTL)
	if newIdle.After(s.ExpiresAt) {
		newIdle = s.ExpiresAt
	}
	s.LastSeenAt = now
	s.IdleExpiresAt = newIdle
	_, _ = m.st.Pool.Exec(ctx,
		`UPDATE sessions SET last_seen_at=$2, idle_expires_at=$3 WHERE id=$1 AND revoked_at IS NULL`,
		s.ID, now, newIdle)
	m.writeMirror(ctx, s)
}

// MarkMFASatisfied records a fresh MFA on the session (for step-up). It only
// updates a still-valid session and fails closed otherwise.
func (m *Manager) MarkMFASatisfied(ctx context.Context, db store.DBTX, id uuid.UUID, amr string, aal int) error {
	now := time.Now()
	ct, err := db.Exec(ctx,
		`UPDATE sessions SET mfa_satisfied=true, mfa_satisfied_at=$2, aal=$3,
		        amr = (SELECT array(SELECT DISTINCT unnest(amr || $4::text[])))
		   WHERE id=$1 AND revoked_at IS NULL AND expires_at > now() AND idle_expires_at > now()`,
		id, now, aal, []string{amr})
	if err != nil {
		return err
	}
	if ct.RowsAffected() != 1 {
		return ErrInvalid
	}
	store.AfterCommit(ctx, func(ctx context.Context) { _ = m.st.Redis.Del(ctx, mirrorKey(id)).Err() })
	return nil
}

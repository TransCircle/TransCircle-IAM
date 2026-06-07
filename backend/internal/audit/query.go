package audit

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Entry is a returned audit record.
type Entry struct {
	ID           uuid.UUID       `json:"id"`
	OccurredAt   time.Time       `json:"occurred_at"`
	ActorUserID  *uuid.UUID      `json:"actor_user_id"`
	ActorLabel   string          `json:"actor_label"`
	Impersonator *uuid.UUID      `json:"impersonator_user_id"`
	Action       string          `json:"action"`
	TargetType   string          `json:"target_type"`
	TargetID     string          `json:"target_id"`
	TargetLabel  string          `json:"target_label"`
	Result       string          `json:"result"`
	IP           string          `json:"ip"`
	UserAgent    string          `json:"user_agent"`
	RequestID    string          `json:"request_id"`
	Metadata     json.RawMessage `json:"metadata"`
}

// Filter narrows an audit query.
type Filter struct {
	Action string
	Actor  string // username substring or actor label
	Result string
	Since  *time.Time
	Until  *time.Time
	Limit  int
	Offset int
}

// List returns audit entries matching the filter, newest first.
func (wr *Writer) List(ctx context.Context, f Filter) ([]Entry, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	// Resolve a human-readable target label at query time: prefer the label stored
	// on the event, otherwise look the object up by its target_id so the UI never
	// has to show a bare internal id. The filtered page is materialized first (CTE)
	// so the joins only run over the returned rows.
	const q = `
WITH a AS (
  SELECT id, occurred_at, actor_user_id, actor_label, impersonator_user_id, action,
         target_type, target_id, target_label, result, ip, user_agent, request_id, metadata
  FROM audit_log
  WHERE ($1='' OR action ILIKE '%'||$1||'%')
    AND ($2='' OR actor_label ILIKE '%'||$2||'%')
    AND ($3='' OR result = $3)
    AND ($4::timestamptz IS NULL OR occurred_at >= $4)
    AND ($5::timestamptz IS NULL OR occurred_at <= $5)
  ORDER BY occurred_at DESC
  LIMIT $6 OFFSET $7
)
SELECT a.id, a.occurred_at, a.actor_user_id, a.actor_label, a.impersonator_user_id, a.action,
       a.target_type, a.target_id,
       COALESCE(NULLIF(a.target_label, ''), u.username, oc.client_name, app.display_name,
                g.display_name, ro.display_name, pm.display_name, '') AS target_label,
       a.result, host(a.ip), a.user_agent, a.request_id, a.metadata
FROM a
LEFT JOIN users u          ON a.target_type = 'user'        AND a.target_id = u.id::text
LEFT JOIN oauth_clients oc ON a.target_type = 'client'      AND a.target_id = oc.client_id
LEFT JOIN applications app ON a.target_type = 'application' AND a.target_id = app.id::text
LEFT JOIN groups g         ON a.target_type = 'group'       AND a.target_id = g.id::text
LEFT JOIN roles ro         ON a.target_type = 'role'        AND a.target_id = ro.id::text
LEFT JOIN permissions pm   ON a.target_type = 'permission'  AND a.target_id = pm.id::text
ORDER BY a.occurred_at DESC`
	rows, err := wr.st.Pool.Query(ctx, q, f.Action, f.Actor, f.Result, f.Since, f.Until, f.Limit, f.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		var e Entry
		var ip *string
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.ActorUserID, &e.ActorLabel, &e.Impersonator,
			&e.Action, &e.TargetType, &e.TargetID, &e.TargetLabel, &e.Result, &ip,
			&e.UserAgent, &e.RequestID, &e.Metadata); err != nil {
			return nil, err
		}
		if ip != nil {
			e.IP = *ip
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

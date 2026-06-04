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
	const q = `
SELECT id, occurred_at, actor_user_id, actor_label, impersonator_user_id, action,
       target_type, target_id, target_label, result, host(ip), user_agent, request_id, metadata
FROM audit_log
WHERE ($1='' OR action ILIKE '%'||$1||'%')
  AND ($2='' OR actor_label ILIKE '%'||$2||'%')
  AND ($3='' OR result = $3)
  AND ($4::timestamptz IS NULL OR occurred_at >= $4)
  AND ($5::timestamptz IS NULL OR occurred_at <= $5)
ORDER BY occurred_at DESC
LIMIT $6 OFFSET $7`
	rows, err := wr.st.Pool.Query(ctx, q, f.Action, f.Actor, f.Result, f.Since, f.Until, f.Limit, f.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
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

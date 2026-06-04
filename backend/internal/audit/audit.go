// Package audit records security-relevant actions to the append-only audit_log.
// Mutating actions write in the SAME transaction as the change (fail-closed);
// non-mutation events (login failures, denials) write via their own short
// transaction so they are never silently dropped (must-fix #14).
package audit

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/transcircle/iam/internal/authctx"
	"github.com/transcircle/iam/internal/httpx"
	"github.com/transcircle/iam/internal/logging"
	"github.com/transcircle/iam/internal/store"
)

// Result values.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
	ResultDenied  = "denied"
)

// Event is a single audit record. Actor/IP/UA/request-id are filled from context.
type Event struct {
	Action      string
	Result      string
	TargetType  string
	TargetID    string
	TargetLabel string
	Metadata    map[string]any
	// ActorOverride is used when there is no principal in context yet (e.g. a
	// failed login names the attempted username here).
	ActorLabel string
}

// Writer persists audit events.
type Writer struct {
	st *store.Store
}

// NewWriter builds an audit writer.
func NewWriter(st *store.Store) *Writer { return &Writer{st: st} }

// sensitiveKeys are stripped from metadata before persistence.
var sensitiveKeys = map[string]bool{
	"password": true, "secret": true, "token": true, "code": true,
	"private_key": true, "client_secret": true, "totp": true, "recovery_code": true,
}

func redact(m map[string]any) []byte {
	if m == nil {
		return []byte("{}")
	}
	clean := make(map[string]any, len(m))
	for k, v := range m {
		if sensitiveKeys[k] {
			clean[k] = "[redacted]"
			continue
		}
		clean[k] = v
	}
	b, err := json.Marshal(clean)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// Write records ev inside the provided transaction. Use this for mutating
// actions so the audit row commits atomically with the change.
func (wr *Writer) Write(ctx context.Context, db store.DBTX, ev Event) error {
	var actorID any
	var actorLabel string
	var imp any
	if p, ok := authctx.From(ctx); ok {
		if p.UserID != uuid.Nil {
			actorID = p.UserID
		}
		actorLabel = p.Username
		if p.IsMachine {
			actorLabel = "machine:" + p.TokenName
		}
		if p.ImpersonatorID != uuid.Nil {
			imp = p.ImpersonatorID
		}
	}
	if ev.ActorLabel != "" {
		actorLabel = ev.ActorLabel
	}
	result := ev.Result
	if result == "" {
		result = ResultSuccess
	}
	var ipArg any
	if ip := httpx.ClientIP(ctx); ip != "" {
		ipArg = ip
	}

	_, err := db.Exec(ctx,
		`INSERT INTO audit_log
		   (id, actor_user_id, actor_label, impersonator_user_id, action, target_type, target_id, target_label, result, ip, user_agent, request_id, metadata)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		uuid.New(), actorID, actorLabel, imp, ev.Action, ev.TargetType, ev.TargetID, ev.TargetLabel,
		result, ipArg, httpx.UserAgent(ctx), httpx.ReqID(ctx), redact(ev.Metadata))
	return err
}

// Log records a non-mutation event in its own short transaction. Failures are
// logged but never block the request (at-least-once best effort).
func (wr *Writer) Log(ctx context.Context, ev Event) {
	if err := wr.Write(ctx, wr.st.Pool, ev); err != nil {
		logging.From(ctx).Error("audit write failed", "action", ev.Action, "error", err)
	}
}

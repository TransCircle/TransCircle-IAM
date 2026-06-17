// Package mfaverify implements the standalone two-factor verification flow that
// applications can outsource to the IAM. An application (authenticated by an API
// token carrying the iam.mfa.verify scope) creates a verification request and
// receives a hosted URL; it redirects the end user there to complete TOTP or a
// passkey assertion against their IAM account; the application then reads the
// authoritative result back from the IAM with its API token.
//
// State is ephemeral and lives in Redis under a short TTL -- the same pattern as
// OAuth consent tickets and login tickets. There is no durable table.
package mfaverify

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrNotFound is returned when a verification id is unknown or has expired.
var ErrNotFound = errors.New("mfaverify: not found")

const (
	StatusPending  = "pending"
	StatusVerified = "verified"
)

func key(id string) string { return "mfaverify:" + id }

// Record is the full server-side state of one verification request.
type Record struct {
	ID string `json:"id"`
	// RequestedBy is the API token name that created the request (for audit/UX).
	RequestedBy string `json:"requested_by"`
	// CreatedByTokenID binds the record to the API token that created it; only
	// that token may read the result back (prevents cross-token result reads).
	CreatedByTokenID string `json:"created_by_token_id"`
	// RequireUserID, when set, pins the verification to a specific IAM user: the
	// browser session completing it must belong to this user or it is rejected.
	RequireUserID string `json:"require_user_id"`
	// RequireUserLabel is the human label the app supplied (username it asked for).
	RequireUserLabel string `json:"require_user_label"`
	// RedirectURI, when set, is where the browser is sent back after success.
	RedirectURI string `json:"redirect_uri"`
	// AllowedFactors limits which factors may satisfy the request (subset of
	// {"totp","passkey"}); empty means any factor the user has.
	AllowedFactors []string `json:"allowed_factors"`

	Status     string     `json:"status"`
	UserID     string     `json:"user_id"`  // who completed it
	Username   string     `json:"username"` // who completed it
	Factor     string     `json:"factor"`   // factor used: otp | webauthn
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	VerifiedAt *time.Time `json:"verified_at"`
}

// Create persists a new pending record with the given TTL.
func Create(ctx context.Context, rdb redis.UniversalClient, rec Record, ttl time.Duration) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return rdb.Set(ctx, key(rec.ID), raw, ttl).Err()
}

// Get loads a record, returning ErrNotFound once it has expired or never existed.
func Get(ctx context.Context, rdb redis.UniversalClient, id string) (*Record, error) {
	raw, err := rdb.Get(ctx, key(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var rec Record
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// Completion outcomes returned by Complete.
const (
	CompleteOK      = "ok"      // pending -> verified, this caller won
	CompleteAlready = "already" // someone already completed it (single-use)
	CompleteExpired = "expired" // the record expired or never existed
)

// completeScript atomically transitions a record from pending to the supplied
// verified value EXACTLY ONCE, preserving the record's remaining TTL. The GET
// guard means an expired key is never recreated (no resurrection), and the
// "verified" substring check means an already-completed record is never
// overwritten — so the authoritative result (user/factor/time) is immutable.
var completeScript = redis.NewScript(`
local cur = redis.call('GET', KEYS[1])
if not cur then return 'expired' end
if string.find(cur, '"status":"verified"', 1, true) then return 'already' end
redis.call('SET', KEYS[1], ARGV[1], 'KEEPTTL')
return 'ok'
`)

// Complete writes the mutated (verified) record back atomically and single-use.
// rec must already carry Status=verified and the completing user/factor. Returns
// CompleteOK, CompleteAlready, or CompleteExpired.
func Complete(ctx context.Context, rdb redis.UniversalClient, rec *Record) (string, error) {
	raw, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	res, err := completeScript.Run(ctx, rdb, []string{key(rec.ID)}, raw).Result()
	if err != nil {
		return "", err
	}
	s, _ := res.(string)
	return s, nil
}

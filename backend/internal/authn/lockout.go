package authn

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// Lockout implements sliding-window brute-force protection keyed per-user and
// per-IP in Redis (shared across replicas). It fails closed on Redis outage for
// auth paths.
type Lockout struct {
	rdb       redis.UniversalClient
	threshold int
	window    time.Duration
	duration  time.Duration
}

// NewLockout builds the lockout limiter.
func NewLockout(rdb redis.UniversalClient, threshold int, window, duration time.Duration) *Lockout {
	return &Lockout{rdb: rdb, threshold: threshold, window: window, duration: duration}
}

func failKey(subject string) string   { return "lockout:fail:" + subject }
func lockedKey(subject string) string { return "lockout:locked:" + subject }

// Locked reports whether the subject (user id or ip) is currently locked.
func (l *Lockout) Locked(ctx context.Context, subjects ...string) (bool, error) {
	for _, s := range subjects {
		n, err := l.rdb.Exists(ctx, lockedKey(s)).Result()
		if err != nil {
			return true, err // fail closed
		}
		if n == 1 {
			return true, nil
		}
	}
	return false, nil
}

// RecordFailure increments failure counters and locks the subject if over threshold.
func (l *Lockout) RecordFailure(ctx context.Context, subjects ...string) {
	for _, s := range subjects {
		key := failKey(s)
		pipe := l.rdb.Pipeline()
		incr := pipe.Incr(ctx, key)
		pipe.Expire(ctx, key, l.window)
		if _, err := pipe.Exec(ctx); err != nil {
			continue
		}
		if incr.Val() >= int64(l.threshold) {
			_ = l.rdb.Set(ctx, lockedKey(s), "1", l.duration).Err()
			_ = l.rdb.Del(ctx, key).Err()
		}
	}
}

// Reset clears failure counters after a successful login.
func (l *Lockout) Reset(ctx context.Context, subjects ...string) {
	for _, s := range subjects {
		_ = l.rdb.Del(ctx, failKey(s)).Err()
	}
}

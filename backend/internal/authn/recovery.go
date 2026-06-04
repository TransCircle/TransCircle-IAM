package authn

import (
	"context"

	"github.com/google/uuid"

	"github.com/transcircle/iam/internal/crypto"
	"github.com/transcircle/iam/internal/store"
)

// RecoveryService manages one-time recovery codes (hashed, single-use).
type RecoveryService struct {
	hasher *crypto.Hasher
}

// NewRecoveryService builds the service.
func NewRecoveryService(h *crypto.Hasher) *RecoveryService {
	return &RecoveryService{hasher: h}
}

// Generate creates a fresh batch of plaintext codes, invalidating any old batch,
// and returns the plaintext codes once (the caller shows them to the user).
func (s *RecoveryService) Generate(ctx context.Context, db store.DBTX, userID uuid.UUID, n int) ([]string, error) {
	if n <= 0 {
		n = 10
	}
	if _, err := db.Exec(ctx, `DELETE FROM recovery_codes WHERE user_id=$1`, userID); err != nil {
		return nil, err
	}
	batch := uuid.New()
	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		code := crypto.RecoveryCode()
		hash, err := s.hasher.Hash(ctx, code)
		if err != nil {
			return nil, err
		}
		if _, err := db.Exec(ctx,
			`INSERT INTO recovery_codes (id, user_id, code_hash, batch_id) VALUES ($1,$2,$3,$4)`,
			crypto.NewUUIDv7(), userID, hash, batch); err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}
	return codes, nil
}

// Consume atomically marks a matching unused code as used. Returns true on success.
func (s *RecoveryService) Consume(ctx context.Context, st *store.Store, userID uuid.UUID, code string) (bool, error) {
	rows, err := st.Pool.Query(ctx,
		`SELECT id, code_hash FROM recovery_codes WHERE user_id=$1 AND used_at IS NULL`, userID)
	if err != nil {
		return false, err
	}
	type rc struct {
		id   uuid.UUID
		hash string
	}
	var candidates []rc
	for rows.Next() {
		var c rc
		if err := rows.Scan(&c.id, &c.hash); err != nil {
			rows.Close()
			return false, err
		}
		candidates = append(candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	for _, c := range candidates {
		if _, verr := s.hasher.Verify(ctx, code, c.hash); verr == nil {
			// Atomic single-use: only the first updater wins.
			ct, err := st.Pool.Exec(ctx,
				`UPDATE recovery_codes SET used_at=now() WHERE id=$1 AND used_at IS NULL`, c.id)
			if err != nil {
				return false, err
			}
			return ct.RowsAffected() == 1, nil
		}
	}
	return false, nil
}

// CountUnused returns how many recovery codes remain.
func (s *RecoveryService) CountUnused(ctx context.Context, db store.DBTX, userID uuid.UUID) (int, error) {
	var n int
	err := db.QueryRow(ctx, `SELECT count(*) FROM recovery_codes WHERE user_id=$1 AND used_at IS NULL`, userID).Scan(&n)
	return n, err
}

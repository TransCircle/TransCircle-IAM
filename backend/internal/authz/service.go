package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"

	"github.com/transcircle/iam/internal/rbac"
	"github.com/transcircle/iam/internal/store"
)

// Service resolves a user's effective permissions with a Redis read-through
// cache whose correctness is anchored to the Postgres-authoritative perm_version
// (must-fix #3): a cache entry is only trusted when its version matches the DB.
type Service struct {
	st   *store.Store
	repo rbac.Repo
	sf   singleflight.Group
}

// New builds the authorization service.
func New(st *store.Store) *Service {
	return &Service{st: st}
}

type cachedPerms struct {
	Version int64               `json:"v"`
	Epoch   int64               `json:"e"`
	Apps    map[string][]string `json:"apps"` // appKey -> permission keys
}

func cacheKey(userID uuid.UUID) string { return "authz:eff:" + userID.String() }

// shortTTL is a safety-net only; the version check is the real correctness gate.
const shortTTL = 60 * time.Second

// effective returns a user's effective permissions, using the cache when its
// version matches the authoritative DB perm_version.
func (s *Service) effective(ctx context.Context, userID uuid.UUID) (cachedPerms, error) {
	curVer, curEpoch, err := s.repo.PermVersionAndEpoch(ctx, s.st.Pool, userID)
	if err != nil {
		return cachedPerms{}, err
	}

	if raw, err := s.st.Redis.Get(ctx, cacheKey(userID)).Bytes(); err == nil {
		var cp cachedPerms
		if json.Unmarshal(raw, &cp) == nil && cp.Version == curVer && cp.Epoch == curEpoch {
			return cp, nil
		}
	} else if !errors.Is(err, redis.Nil) {
		// Redis error: fall through to DB (fail-open on cache, not on authz).
	}

	v, err, _ := s.sf.Do(userID.String(), func() (any, error) {
		return s.recompute(ctx, userID, curVer, curEpoch)
	})
	if err != nil {
		return cachedPerms{}, err
	}
	return v.(cachedPerms), nil
}

func (s *Service) recompute(ctx context.Context, userID uuid.UUID, version, epoch int64) (cachedPerms, error) {
	perms, err := s.repo.EffectivePermissions(ctx, s.st.Pool, userID, nil)
	if err != nil {
		return cachedPerms{}, err
	}
	cp := cachedPerms{Version: version, Epoch: epoch, Apps: map[string][]string{}}
	for _, p := range perms {
		cp.Apps[p.AppKey] = append(cp.Apps[p.AppKey], p.PermKey)
	}
	if raw, err := json.Marshal(cp); err == nil {
		_ = s.st.Redis.Set(ctx, cacheKey(userID), raw, shortTTL).Err()
	}
	return cp, nil
}

// Has reports whether the user holds permKey within the named application.
func (s *Service) Has(ctx context.Context, userID uuid.UUID, appKey, permKey string) (bool, error) {
	cp, err := s.effective(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, k := range cp.Apps[appKey] {
		if k == permKey {
			return true, nil
		}
	}
	return false, nil
}

// HasSystem checks a permission in the built-in system application.
func (s *Service) HasSystem(ctx context.Context, userID uuid.UUID, permKey string) (bool, error) {
	return s.Has(ctx, userID, rbac.SystemAppKey, permKey)
}

// AppPermissions returns the user's roles + permissions for one application,
// shaped for OIDC claims and the permissions API.
func (s *Service) AppPermissions(ctx context.Context, userID, appID uuid.UUID, appKey string) (rbac.AppPermissions, error) {
	cp, err := s.effective(ctx, userID)
	if err != nil {
		return rbac.AppPermissions{}, err
	}
	roles, err := s.repo.EffectiveRoles(ctx, s.st.Pool, userID, appID)
	if err != nil {
		return rbac.AppPermissions{}, err
	}
	perms := cp.Apps[appKey]
	if perms == nil {
		perms = []string{}
	}
	if roles == nil {
		roles = []string{}
	}
	return rbac.AppPermissions{AppID: appID, AppKey: appKey, Roles: roles, Permissions: perms}, nil
}

// SystemPermissionSet returns the user's full system-app permission set (for /me).
func (s *Service) SystemPermissionSet(ctx context.Context, userID uuid.UUID) ([]string, error) {
	cp, err := s.effective(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := cp.Apps[rbac.SystemAppKey]
	if out == nil {
		out = []string{}
	}
	return out, nil
}

// AllPermissions returns the user's effective permissions across every app
// (appKey -> permission keys). Used by impersonation subset checks.
func (s *Service) AllPermissions(ctx context.Context, userID uuid.UUID) (map[string][]string, error) {
	cp, err := s.effective(ctx, userID)
	if err != nil {
		return nil, err
	}
	return cp.Apps, nil
}

// Invalidate drops a user's cached permissions. Register via store.AfterCommit so
// it only runs after the mutating transaction commits.
func (s *Service) Invalidate(ctx context.Context, userID uuid.UUID) {
	_ = s.st.Redis.Del(ctx, cacheKey(userID)).Err()
}

// VerifyCatalog asserts every Go permission constant exists in the DB seed,
// failing closed at startup if the seed and constants have drifted.
func (s *Service) VerifyCatalog(ctx context.Context) error {
	rows, err := s.st.Pool.Query(ctx,
		`SELECT key FROM permissions WHERE application_id=$1`, rbac.SystemAppID)
	if err != nil {
		return err
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return err
		}
		have[k] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, k := range Catalog {
		if !have[k] {
			return fmt.Errorf("authz: permission %q declared in code but missing from DB seed", k)
		}
	}
	return nil
}

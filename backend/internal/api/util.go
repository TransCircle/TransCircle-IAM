package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/transcircle/iam/internal/httpx"
)

func pathUUID(r *http.Request, key string) (uuid.UUID, error) {
	id, err := uuid.Parse(chi.URLParam(r, key))
	if err != nil {
		return uuid.Nil, httpx.ErrBadRequest.WithDetail("无效的标识符")
	}
	return id, nil
}

// pageParams parses and clamps list pagination. limit is bounded to
// [1, maxLimit] so a negative value can't crash Postgres ("LIMIT must not be
// negative") and a huge value can't force an unbounded scan/materialization;
// offset is floored at 0.
func pageParams(r *http.Request, defLimit, maxLimit int) (limit, offset int) {
	limit = queryInt(r, "limit", defLimit)
	if limit < 1 {
		limit = defLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	offset = queryInt(r, "offset", 0)
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// mapWriteError converts the Postgres constraint violations that user-supplied
// input can trigger into proper 4xx problems instead of a generic 500. Anything
// else is returned unchanged (rendered as 500 and logged).
func mapWriteError(err error) error {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return err
	}
	switch pg.Code {
	case "23505": // unique_violation
		return httpx.ErrConflict.WithDetail("资源已存在").WithInternal(err)
	case "23503": // foreign_key_violation
		return httpx.ErrBadRequest.WithDetail("引用的对象不存在").WithInternal(err)
	case "23502": // not_null_violation
		return httpx.ErrBadRequest.WithDetail("缺少必填字段").WithInternal(err)
	case "23514": // check_violation
		return httpx.ErrBadRequest.WithDetail("字段取值非法").WithInternal(err)
	default:
		return err
	}
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

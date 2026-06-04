// Package httpx holds HTTP helpers: RFC7807 problem responses, typed app errors,
// JSON encoding, and the shared middleware stack. Handlers return *AppError and
// never panic on expected failures.
package httpx

import (
	"errors"
	"net/http"
)

// AppError is a typed, HTTP-aware error rendered as RFC7807 problem+json.
type AppError struct {
	Status   int            `json:"-"`
	Code     string         `json:"code"`             // machine-readable, e.g. "invalid_credentials"
	Title    string         `json:"title"`            // short human summary (zh-CN)
	Detail   string         `json:"detail,omitempty"` // optional specifics
	Fields   map[string]any `json:"fields,omitempty"` // field-level validation errors
	internal error          // wrapped cause, never serialized
}

func (e *AppError) Error() string {
	if e.internal != nil {
		return e.Code + ": " + e.internal.Error()
	}
	return e.Code
}

func (e *AppError) Unwrap() error { return e.internal }

// WithInternal attaches a non-exposed cause for logging.
func (e *AppError) WithInternal(err error) *AppError {
	clone := *e
	clone.internal = err
	return &clone
}

// WithDetail returns a copy with a human detail message.
func (e *AppError) WithDetail(detail string) *AppError {
	clone := *e
	clone.Detail = detail
	return &clone
}

// NewError constructs an AppError.
func NewError(status int, code, title string) *AppError {
	return &AppError{Status: status, Code: code, Title: title}
}

// Common reusable errors.
var (
	ErrBadRequest   = NewError(http.StatusBadRequest, "bad_request", "请求无效")
	ErrUnauthorized = NewError(http.StatusUnauthorized, "unauthorized", "未认证")
	ErrForbidden    = NewError(http.StatusForbidden, "forbidden", "权限不足")
	ErrNotFound     = NewError(http.StatusNotFound, "not_found", "资源不存在")
	ErrConflict     = NewError(http.StatusConflict, "conflict", "资源冲突")
	ErrRateLimited  = NewError(http.StatusTooManyRequests, "rate_limited", "请求过于频繁")
	ErrInternal     = NewError(http.StatusInternalServerError, "internal", "服务器内部错误")
)

// AsAppError coerces any error into an *AppError (defaulting to 500).
func AsAppError(err error) *AppError {
	var ae *AppError
	if errors.As(err, &ae) {
		return ae
	}
	return ErrInternal.WithInternal(err)
}

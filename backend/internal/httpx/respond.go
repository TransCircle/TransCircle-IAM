package httpx

import (
	"encoding/json"
	"net/http"

	"github.com/transcircle/iam/internal/logging"
)

// JSON writes v as JSON with the given status.
func JSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if v == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logging.From(r.Context()).Error("encode response", "error", err)
	}
}

// NoContent writes a 204.
func NoContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

// Error renders err as an RFC7807 problem document and logs the internal cause.
func Error(w http.ResponseWriter, r *http.Request, err error) {
	ae := AsAppError(err)
	if ae.Status >= 500 {
		logging.From(r.Context()).Error("request failed",
			"code", ae.Code, "error", ae.Error())
	} else {
		logging.From(r.Context()).Warn("request rejected",
			"code", ae.Code, "status", ae.Status)
	}
	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(ae.Status)
	_ = json.NewEncoder(w).Encode(ae)
}

// DecodeJSON decodes the request body into v, rejecting unknown fields.
func DecodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrBadRequest.WithDetail("请求体解析失败").WithInternal(err)
	}
	return nil
}

// Handler is a handler that returns an error, centralizing error rendering.
type Handler func(w http.ResponseWriter, r *http.Request) error

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h(w, r); err != nil {
		Error(w, r, err)
	}
}

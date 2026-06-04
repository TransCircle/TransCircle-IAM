// Package logging configures the structured slog logger and request-scoped fields.
package logging

import (
	"context"
	"log/slog"
	"os"
)

type ctxKey struct{}

// New builds a JSON slog logger. In dev it stays at debug level.
func New(env string) *slog.Logger {
	level := slog.LevelInfo
	if env != "prod" {
		level = slog.LevelDebug
	}
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	return slog.New(h)
}

// WithContext stores a logger (carrying request-scoped attrs) in ctx.
func WithContext(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// From returns the request logger from ctx, falling back to the default.
func From(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

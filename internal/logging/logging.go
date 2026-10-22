package logging

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

type traceHandler struct {
	slog.Handler
}

func WithTraceID(h slog.Handler) slog.Handler {
	return traceHandler{h}
}

func (h traceHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return traceHandler{h.Handler.WithAttrs(attrs)}
}

func (h traceHandler) WithGroup(name string) slog.Handler {
	return traceHandler{h.Handler.WithGroup(name)}
}

func (h traceHandler) Handle(ctx context.Context, r slog.Record) error {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		r.AddAttrs(
			slog.String("traceId", sc.TraceID().String()),
			slog.String("spanId", sc.SpanID().String()),
		)
	}
	return h.Handler.Handle(ctx, r)
}

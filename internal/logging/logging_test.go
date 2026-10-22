package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

const (
	traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	spanID  = "00f067aa0ba902b7"
)

func newLogger(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return slog.New(WithTraceID(slog.NewTextHandler(&buf, nil))), &buf
}

func spanContext(t *testing.T) context.Context {
	t.Helper()
	tid, err := trace.TraceIDFromHex(traceID)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := trace.SpanIDFromHex(spanID)
	if err != nil {
		t.Fatal(err)
	}
	sc := trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled})
	return trace.ContextWithSpanContext(t.Context(), sc)
}

func TestWithTraceID(t *testing.T) {
	tests := []struct {
		name    string
		ctx     func(t *testing.T) context.Context
		with    []any
		group   string
		want    []string
		notWant []string
	}{
		{name: "a span in the context adds its ids", ctx: spanContext,
			want: []string{"traceId=" + traceID, "spanId=" + spanID}},
		{name: "no span, no ids", ctx: func(*testing.T) context.Context { return context.Background() },
			notWant: []string{"traceId=", "spanId="}},
		{name: "attributes from With are kept beside the ids", ctx: spanContext, with: []any{"k", "v"},
			want: []string{"k=v", "traceId=" + traceID}},
		{name: "a group keeps the ids, nested under it", ctx: spanContext, group: "g",
			want: []string{"g.traceId=" + traceID}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, buf := newLogger(t)
			if tt.with != nil {
				logger = logger.With(tt.with...)
			}
			if tt.group != "" {
				logger = logger.WithGroup(tt.group)
			}
			logger.InfoContext(tt.ctx(t), "hello")

			line := buf.String()
			for _, w := range tt.want {
				if !strings.Contains(line, w) {
					t.Errorf("log line %q lacks %q", line, w)
				}
			}
			for _, nw := range tt.notWant {
				if strings.Contains(line, nw) {
					t.Errorf("log line %q contains %q", line, nw)
				}
			}
		})
	}
}

func TestWithTraceIDKeepsTheLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(WithTraceID(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))

	logger.InfoContext(spanContext(t), "dropped")
	if buf.Len() != 0 {
		t.Errorf("an INFO line passed a WARN handler: %q", buf.String())
	}
}

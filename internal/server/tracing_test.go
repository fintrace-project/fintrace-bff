package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

const incomingTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"

func newRecordingProvider(t *testing.T) (*sdktrace.TracerProvider, *tracetest.SpanRecorder) {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	t.Cleanup(func() { _ = tp.Shutdown(t.Context()) })
	return tp, sr
}

func TestTracingStartsANewTraceAndOnlyLinksTheIncomingOne(t *testing.T) {
	tests := []struct {
		name        string
		traceparent string
		wantLink    bool
	}{
		{name: "a valid traceparent is linked", traceparent: "00-" + incomingTraceID + "-00f067aa0ba902b7-01", wantLink: true},
		{name: "no traceparent, no link"},
		{name: "an unknown version is ignored", traceparent: "ff-" + incomingTraceID + "-00f067aa0ba902b7-01"},
		{name: "an all-zero trace id is ignored", traceparent: "00-00000000000000000000000000000000-00f067aa0ba902b7-01"},
		{name: "an all-zero span id is ignored", traceparent: "00-" + incomingTraceID + "-0000000000000000-01"},
		{name: "garbage is ignored", traceparent: "nonsense"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tp, sr := newRecordingProvider(t)
			var seen trace.SpanContext
			handler := withTracing(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = trace.SpanContextFromContext(r.Context())
			}), tp)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/anything", nil)
			if tt.traceparent != "" {
				req.Header.Set("traceparent", tt.traceparent)
			}
			handler.ServeHTTP(httptest.NewRecorder(), req)

			spans := sr.Ended()
			if len(spans) != 1 {
				t.Fatalf("ended spans = %d, want 1", len(spans))
			}
			span := spans[0]
			if span.Parent().IsValid() {
				t.Errorf("span parent = %s, want a new root", span.Parent().SpanID())
			}
			if span.SpanContext().TraceID().String() == incomingTraceID {
				t.Error("span continues the caller's trace id, want a trace of its own")
			}
			if !seen.Equal(span.SpanContext()) {
				t.Errorf("handler saw span context %v, want the request's span %v", seen, span.SpanContext())
			}

			links := span.Links()
			if !tt.wantLink {
				if len(links) != 0 {
					t.Fatalf("links = %d, want none", len(links))
				}
				return
			}
			if len(links) != 1 {
				t.Fatalf("links = %d, want 1", len(links))
			}
			if got := links[0].SpanContext.TraceID().String(); got != incomingTraceID {
				t.Errorf("linked trace id = %s, want %s", got, incomingTraceID)
			}
		})
	}
}

func TestTracingSkipsHealthz(t *testing.T) {
	tp, sr := newRecordingProvider(t)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
	RoutesHandler(tp).ServeHTTP(httptest.NewRecorder(), req)

	if spans := sr.Ended(); len(spans) != 0 {
		t.Fatalf("ended spans = %d, want none for /healthz", len(spans))
	}
}

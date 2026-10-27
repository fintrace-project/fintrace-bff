package httperr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

const testTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"

func write(t *testing.T, r *http.Request, status int, code Code, detail string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	Write(rec, r, status, code, detail)
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body %q is not JSON: %v", rec.Body.String(), err)
	}
	return rec, got
}

func withSpan(t *testing.T, r *http.Request) *http.Request {
	t.Helper()
	traceID, err := trace.TraceIDFromHex(testTraceID)
	if err != nil {
		t.Fatal(err)
	}
	spanID, err := trace.SpanIDFromHex("00f067aa0ba902b7")
	if err != nil {
		t.Fatal(err)
	}
	sc := trace.NewSpanContext(trace.SpanContextConfig{TraceID: traceID, SpanID: spanID})
	return r.WithContext(trace.ContextWithSpanContext(r.Context(), sc))
}

func TestWriteAnswersAProblemDetail(t *testing.T) {
	r := withSpan(t, httptest.NewRequest(http.MethodGet, "/api/v1/workspaces?size=100", nil))

	rec, got := write(t, r, http.StatusUnauthorized, NoSession, "no session")

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	want := map[string]any{
		"type":     "about:blank",
		"title":    "Unauthorized",
		"status":   float64(http.StatusUnauthorized),
		"detail":   "no session",
		"instance": "/api/v1/workspaces",
		"code":     "NO_SESSION",
		"traceId":  testTraceID,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("body = %v, want exactly the fields %v", got, want)
	}
}

func TestWriteLeavesOutWhatItDoesNotHave(t *testing.T) {
	_, got := write(t, httptest.NewRequest(http.MethodGet, "/api/v1/workspaces", nil),
		http.StatusBadGateway, UpstreamUnavailable, "")

	for _, k := range []string{"traceId", "detail"} {
		if v, ok := got[k]; ok {
			t.Errorf("%s = %v, want it absent", k, v)
		}
	}
	if got["code"] != "UPSTREAM_UNAVAILABLE" || got["title"] != "Bad Gateway" {
		t.Errorf("body = %v, want code UPSTREAM_UNAVAILABLE and title Bad Gateway", got)
	}
}

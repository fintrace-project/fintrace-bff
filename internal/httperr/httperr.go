package httperr

import (
	"encoding/json"
	"net/http"

	"go.opentelemetry.io/otel/trace"
)

type Code string

const (
	NoSession           Code = "NO_SESSION"
	SessionUnavailable  Code = "SESSION_UNAVAILABLE"
	UpstreamUnavailable Code = "UPSTREAM_UNAVAILABLE"
	UpstreamTimeout     Code = "UPSTREAM_TIMEOUT"
	UploadTooLarge      Code = "UPLOAD_TOO_LARGE"
)

type body struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
	Code     Code   `json:"code"`
	TraceID  string `json:"traceId,omitempty"`
}

func Write(w http.ResponseWriter, r *http.Request, status int, code Code, detail string) {
	b := body{
		Type:     "about:blank",
		Title:    http.StatusText(status),
		Status:   status,
		Detail:   detail,
		Instance: r.URL.Path,
		Code:     code,
	}

	if sc := trace.SpanContextFromContext(r.Context()); sc.HasTraceID() {
		b.TraceID = sc.TraceID().String()
	}

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(b)
}

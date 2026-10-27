package proxy

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/fintrace-project/fintrace-bff/internal/httperr"
	"github.com/fintrace-project/fintrace-bff/internal/logging"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

var strippedRequestHeaders = []string{"Cookie", "Traceparent", "Tracestate", "Baggage"}

func NewProxy(target *url.URL, transport http.RoundTripper) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			for _, h := range strippedRequestHeaders {
				pr.Out.Header.Del(h)
			}
		},
		Transport:      transport,
		ModifyResponse: dropSetCookie,
		ErrorHandler:   upstreamFailed,
	}
}

func dropSetCookie(resp *http.Response) error {
	resp.Header.Del("Set-Cookie")
	return nil
}

func upstreamFailed(w http.ResponseWriter, r *http.Request, err error) {
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		httperr.Write(w, r, http.StatusRequestEntityTooLarge, httperr.UploadTooLarge, "upload too large")
		return
	}

	status, code, detail := http.StatusBadGateway, httperr.UpstreamUnavailable, "upstream unavailable"
	if ne, ok := errors.AsType[net.Error](err); ok && ne.Timeout() {
		status, code, detail = http.StatusGatewayTimeout, httperr.UpstreamTimeout, "upstream timed out"
	}
	slog.DebugContext(r.Context(), "Upstream unavailable", "path", r.URL.Path, "status", status, "error", err)
	httperr.Write(w, r, status, code, detail)
}

func NewTransport(tp trace.TracerProvider, responseHeaderTimeout time.Duration) http.RoundTripper {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.ResponseHeaderTimeout = responseHeaderTimeout

	return otelhttp.NewTransport(logging.NewCallLogger(base),
		otelhttp.WithTracerProvider(tp),
		otelhttp.WithPropagators(propagation.TraceContext{}),
	)
}

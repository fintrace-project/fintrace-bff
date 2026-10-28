package proxy

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/fintrace-project/fintrace-bff/internal/config"
	"github.com/fintrace-project/fintrace-bff/internal/httperr"
	"github.com/fintrace-project/fintrace-bff/internal/logging"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

var strippedRequestHeaders = []string{"Cookie", "Traceparent", "Tracestate", "Baggage"}

func NewProxy(target *url.URL, transport http.RoundTripper, cfg config.Config) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			for _, h := range strippedRequestHeaders {
				pr.Out.Header.Del(h)
			}
		},
		Transport:      transport,
		ModifyResponse: responseModifier(cfg, target),
		ErrorHandler:   upstreamFailed,
	}
}

func responseModifier(cfg config.Config, target *url.URL) func(*http.Response) error {
	return func(resp *http.Response) error {
		dropSetCookie(resp)
		adjustLocation(resp, cfg.PublicOrigin, target)
		return nil
	}
}

func dropSetCookie(resp *http.Response) {
	resp.Header.Del("Set-Cookie")
}

func adjustLocation(resp *http.Response, originURL *url.URL, target *url.URL) {
	lh := "Location"
	loc := resp.Header.Get(lh)
	if loc != "" {
		locURL, err := url.Parse(loc)
		if err != nil {
			slog.WarnContext(resp.Request.Context(), `Invalid "Location" header`, "error", err)
			return
		}
		if locURL.IsAbs() && locURL.Scheme == target.Scheme && strings.EqualFold(locURL.Host, target.Host) {
			locURL.Scheme, locURL.Host = originURL.Scheme, originURL.Host

			// The proxy joins the target's base path on the request, so drop it on the response.
			if base := strings.TrimSuffix(target.Path, "/"); base != "" {
				if rest, ok := strings.CutPrefix(locURL.Path, base); ok && (rest == "" || strings.HasPrefix(rest, "/")) {
					locURL.Path, locURL.RawPath = rest, ""
				}
			}
			resp.Header.Set("Location", locURL.String())
		}
	}
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

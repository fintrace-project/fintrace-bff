package proxy

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fintrace-project/fintrace-bff/internal/config"
	"github.com/fintrace-project/fintrace-bff/internal/csp"
	"github.com/fintrace-project/fintrace-bff/internal/httperr"
	"github.com/fintrace-project/fintrace-bff/internal/logging"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

var strippedRequestHeaders = []string{"Cookie", "Traceparent", "Tracestate", "Baggage"}

// SecurityHeaders are the headers the BFF sets on every response; an upstream's own are dropped.
var SecurityHeaders = []string{"X-Content-Type-Options", "Referrer-Policy", "Content-Security-Policy", "Strict-Transport-Security"}

const maxHTMLBytes = 1024 * 1024 // 1M

func NewProxy(target *url.URL, transport http.RoundTripper, cfg config.Config) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			for _, h := range strippedRequestHeaders {
				pr.Out.Header.Del(h)
			}
		},
		Transport:      transport,
		ModifyResponse: defaultResponseModifier(cfg, target),
		ErrorHandler:   upstreamFailed,
	}
}

func WithCSP(proxy *httputil.ReverseProxy) *httputil.ReverseProxy {
	originalResponseModifier := proxy.ModifyResponse
	proxy.ModifyResponse = func(resp *http.Response) error {
		if err := originalResponseModifier(resp); err != nil {
			return err
		}

		nonce, ok := csp.NonceFrom(resp.Request.Context())
		if !ok || !hasBody(resp) || !isHTML(resp) {
			return nil
		}

		body, err := readHTML(resp)
		if err != nil {
			slog.ErrorContext(resp.Request.Context(), "CSP nonce not written", "path", resp.Request.URL.Path, "error", err)
			return err
		}
		if !bytes.Contains(body, []byte(csp.Placeholder)) {
			slog.WarnContext(resp.Request.Context(), "HTML carries no CSP nonce placeholder", "path", resp.Request.URL.Path)
		}
		setBody(resp, bytes.ReplaceAll(body, []byte(csp.Placeholder), []byte(nonce)))

		// A revalidated 304 would reuse a page carrying an earlier response's nonce
		resp.Header.Del("ETag")
		resp.Header.Del("Last-Modified")
		resp.Header.Set("Cache-Control", "no-store")
		return nil
	}

	return proxy
}

func defaultResponseModifier(cfg config.Config, target *url.URL) func(*http.Response) error {
	return func(resp *http.Response) error {
		dropSetCookie(resp)
		dropSecurityHeaders(resp)
		adjustLocation(resp, cfg.PublicOrigin, target)
		return nil
	}
}

func dropSetCookie(resp *http.Response) {
	resp.Header.Del("Set-Cookie")
}

// ReverseProxy adds an upstream's headers to those already set, so a second copy would reach the browser.
func dropSecurityHeaders(resp *http.Response) {
	for _, h := range SecurityHeaders {
		resp.Header.Del(h)
	}
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

func NewTransport(tp trace.TracerProvider, responseHeaderTimeout time.Duration, logLevel slog.Level) http.RoundTripper {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.ResponseHeaderTimeout = responseHeaderTimeout

	return otelhttp.NewTransport(logging.NewCallLoggerAt(base, logLevel),
		otelhttp.WithTracerProvider(tp),
		otelhttp.WithPropagators(propagation.TraceContext{}),
	)
}

func hasBody(resp *http.Response) bool {
	return resp.Request.Method != http.MethodHead &&
		resp.StatusCode != http.StatusNoContent &&
		resp.StatusCode != http.StatusNotModified
}

func isHTML(resp *http.Response) bool {
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	return err == nil && mt == "text/html"
}

func readHTML(resp *http.Response) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()

	var r io.Reader = resp.Body
	switch enc := resp.Header.Get("Content-Encoding"); enc {
	case "", "identity":
	case "gzip":
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("unzip HTML: %w", err)
		}
		defer func() { _ = gz.Close() }()
		r = gz
	default:
		return nil, fmt.Errorf("HTML in unsupported encoding %q", enc)
	}

	body, err := io.ReadAll(io.LimitReader(r, maxHTMLBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read HTML: %w", err)
	}
	if len(body) > maxHTMLBytes {
		return nil, fmt.Errorf("HTML larger than %d bytes", maxHTMLBytes)
	}
	return body, nil
}

func setBody(resp *http.Response, body []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Del("Content-Encoding")
}

package logging

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const maxLoggedBody = 8 * 1024

var (
	secretHeaders   = []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie"}
	secretFormField = regexp.MustCompile(`(^|&)(client_secret|code|code_verifier|subject_token|actor_token|access_token|refresh_token|id_token)=[^&]*`)
	secretJSONField = regexp.MustCompile(`("(?:client_secret|subject_token|actor_token|access_token|refresh_token|id_token)"\s*:\s*")[^"]*`)
)

type callLogger struct {
	next  http.RoundTripper
	level slog.Level
}

func (c callLogger) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	debug := slog.Default().Enabled(ctx, slog.LevelDebug)
	if debug {
		slog.DebugContext(ctx, "outbound call request", "method", req.Method, "url", sanitizedURL(req.URL),
			"headers", maskedHeaders(req.Header), "body", requestBody(req))
	}

	startTime := time.Now()
	resp, err := c.next.RoundTrip(req)
	if err != nil {
		slog.WarnContext(ctx, "outbound call failed", "method", req.Method, "url", sanitizedURL(req.URL), "duration", time.Since(startTime), "error", sanitizedError(err, req.URL))
		return nil, err
	}
	slog.Log(ctx, c.level, "outbound call", "method", req.Method, "url", sanitizedURL(req.URL), "status", resp.StatusCode, "duration", time.Since(startTime))

	if debug {
		slog.DebugContext(ctx, "outbound call response", "method", req.Method, "url", sanitizedURL(req.URL),
			"headers", maskedHeaders(resp.Header), "body", responseBody(resp))
	}
	return resp, nil
}

func NewCallLogger(roundTripper http.RoundTripper) http.RoundTripper {
	return NewCallLoggerAt(roundTripper, slog.LevelInfo)
}

func NewCallLoggerAt(roundTripper http.RoundTripper, level slog.Level) http.RoundTripper {
	return callLogger{next: roundTripper, level: level}
}

func sanitizedURL(u *url.URL) string {
	c := *u
	c.User = nil
	c.RawQuery = ""
	c.ForceQuery = false
	c.Fragment = ""
	c.RawFragment = ""
	return c.String()
}

func sanitizedError(err error, u *url.URL) error {
	if uerr, ok := errors.AsType[*url.Error](err); ok {
		return &url.Error{Op: uerr.Op, URL: sanitizedURL(u), Err: uerr.Err}
	}
	return err
}

func maskedHeaders(h http.Header) http.Header {
	out := h.Clone()
	for _, k := range secretHeaders {
		if out.Get(k) != "" {
			out.Set(k, "***")
		}
	}
	return out
}

func requestBody(req *http.Request) string {
	switch {
	case req.Body == nil || req.Body == http.NoBody:
		return "<empty>"
	case strings.HasPrefix(req.Header.Get("Content-Type"), "multipart/"):
		return fmt.Sprintf("<multipart, %d bytes>", req.ContentLength)
	case req.GetBody == nil:
		return "<not replayable>"
	}
	body, err := req.GetBody()
	if err != nil {
		return "<unreadable>"
	}
	defer func() { _ = body.Close() }()
	head, err := io.ReadAll(io.LimitReader(body, maxLoggedBody+1))
	if err != nil {
		return "<unreadable>"
	}
	return excerpt(head)
}

func responseBody(resp *http.Response) string {
	if resp.Body == nil || resp.Body == http.NoBody {
		return "<empty>"
	}
	head, err := io.ReadAll(io.LimitReader(resp.Body, maxLoggedBody+1))
	resp.Body = readCloser{io.MultiReader(bytes.NewReader(head), resp.Body), resp.Body}
	if err != nil {
		return "<unreadable>"
	}
	return excerpt(head)
}

type readCloser struct {
	io.Reader
	io.Closer
}

func excerpt(head []byte) string {
	if len(head) == 0 {
		return "<empty>"
	}
	suffix := ""
	if len(head) > maxLoggedBody {
		head, suffix = head[:maxLoggedBody], "… (truncated)"
	}
	return mask(head) + suffix
}

func mask(body []byte) string {
	b := secretFormField.ReplaceAll(body, []byte("${1}${2}=***"))
	return string(secretJSONField.ReplaceAll(b, []byte("${1}***")))
}

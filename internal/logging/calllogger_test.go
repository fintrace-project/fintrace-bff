package logging

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const leakyURL = "https://user:pw@realm.example/path?code=secret#frag"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Swaps the default logger, so tests using it must not run in parallel.
func captureDefaultLog(t *testing.T, level slog.Level) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: level})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func assertRedacted(t *testing.T, line string) {
	t.Helper()
	if !strings.Contains(line, "https://realm.example/path") {
		t.Errorf("log line %q lacks the scheme, host and path", line)
	}
	for _, leak := range []string{"secret", "pw", "frag"} {
		if strings.Contains(line, leak) {
			t.Errorf("log line %q leaks %q", line, leak)
		}
	}
}

func assertMasked(t *testing.T, log string, leaks, kept []string) {
	t.Helper()
	for _, leak := range leaks {
		if strings.Contains(log, leak) {
			t.Errorf("log %q leaks %q", log, leak)
		}
	}
	for _, k := range kept {
		if !strings.Contains(log, k) {
			t.Errorf("log %q lacks %q", log, k)
		}
	}
}

func TestCallLoggerLogsAResponseAndPassesItBack(t *testing.T) {
	buf := captureDefaultLog(t, slog.LevelInfo)
	want := &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}
	logger := NewCallLogger(roundTripFunc(func(*http.Request) (*http.Response, error) { return want, nil }))

	got, err := logger.RoundTrip(httptest.NewRequestWithContext(t.Context(), http.MethodGet, leakyURL, nil))

	if err != nil || got != want {
		t.Fatalf("RoundTrip() = %v, %v; want the inner response and no error", got, err)
	}
	line := buf.String()
	if !strings.Contains(line, "level=INFO") || !strings.Contains(line, "status=204") {
		t.Errorf("log line %q, want INFO with status=204", line)
	}
	if strings.Contains(line, "level=DEBUG") {
		t.Errorf("log %q has DEBUG lines at INFO", line)
	}
	assertRedacted(t, line)
}

func TestCallLoggerLogsATransportFailureAndReturnsIt(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "a bare network error", err: errors.New("dial tcp: connection refused")},
		{name: "a url.Error naming the full URL", err: &url.Error{Op: "Get", URL: leakyURL, Err: errors.New("boom")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := captureDefaultLog(t, slog.LevelInfo)
			logger := NewCallLogger(roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, tt.err }))

			resp, err := logger.RoundTrip(httptest.NewRequestWithContext(t.Context(), http.MethodGet, leakyURL, nil))

			if resp != nil || err != tt.err {
				t.Fatalf("RoundTrip() = %v, %v; want nil and the inner error unchanged", resp, err)
			}
			line := buf.String()
			if !strings.Contains(line, "level=WARN") {
				t.Errorf("log line %q, want WARN", line)
			}
			assertRedacted(t, line)
		})
	}
}

func TestCallLoggerAtDebugKeepsACallOutOfTheInfoLogButNotAFailure(t *testing.T) {
	buf := captureDefaultLog(t, slog.LevelInfo)
	ok := NewCallLoggerAt(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	}), slog.LevelDebug)
	failing := NewCallLoggerAt(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial tcp: connection refused")
	}), slog.LevelDebug)

	if _, err := ok.RoundTrip(httptest.NewRequestWithContext(t.Context(), http.MethodGet, leakyURL, nil)); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("log %q, want a completed call kept out of an INFO log", buf.String())
	}
	_, _ = failing.RoundTrip(httptest.NewRequestWithContext(t.Context(), http.MethodGet, leakyURL, nil))
	if !strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("log %q, want the failure as a WARN whatever the level", buf.String())
	}
}

func TestCallLoggerReadsNoBodyBelowDebug(t *testing.T) {
	captureDefaultLog(t, slog.LevelInfo)
	body := io.NopCloser(strings.NewReader("untouched"))
	logger := NewCallLogger(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body}, nil
	}))

	resp, err := logger.RoundTrip(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://realm.example/", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != body {
		t.Error("the response body was wrapped although DEBUG is off")
	}
}

func TestCallLoggerMasksATokenExchangeAtDebug(t *testing.T) {
	buf := captureDefaultLog(t, slog.LevelDebug)
	form := "grant_type=authorization_code&code=the-code&code_verifier=the-verifier" +
		"&client_secret=the-secret&redirect_uri=http%3A%2F%2Flocalhost%3A8100%2Fauth%2Fcallback"
	tokens := `{"access_token":"the-access","id_token":"the-id","refresh_token":"the-refresh","token_type":"Bearer"}`

	var sent string
	logger := NewCallLogger(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		sent = string(b)
		h := http.Header{"Content-Type": {"application/json"}, "Set-Cookie": {"KC_SESSION=the-cookie"}}
		return &http.Response{StatusCode: http.StatusOK, Header: h, Body: io.NopCloser(strings.NewReader(tokens))}, nil
	}))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://realm.example/token", strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("fintrace-bff", "the-basic-secret")

	resp, err := logger.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	received, _ := io.ReadAll(resp.Body)

	if sent != form {
		t.Errorf("the transport was sent %q, want the whole form", sent)
	}
	if string(received) != tokens {
		t.Errorf("the caller read %q, want the whole response", received)
	}
	assertMasked(t, buf.String(),
		[]string{"the-code", "the-verifier", "the-secret", "the-basic-secret", "the-access", "the-id", "the-refresh", "the-cookie"},
		[]string{"grant_type=authorization_code", "redirect_uri=", "token_type", "Bearer", "outbound call request", "outbound call response"})
}

func TestCallLoggerKeepsCoresErrorCodeInJSON(t *testing.T) {
	buf := captureDefaultLog(t, slog.LevelDebug)
	problem := `{"code":"WORKSPACE_NOT_FOUND","status":404}`
	logger := NewCallLogger(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(problem))}, nil
	}))

	if _, err := logger.RoundTrip(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://core.example/", nil)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "WORKSPACE_NOT_FOUND") {
		t.Errorf("log %q masked Core's error code", buf.String())
	}
}

func TestCallLoggerTruncatesALongBodyButPassesItAllOn(t *testing.T) {
	buf := captureDefaultLog(t, slog.LevelDebug)
	long := strings.Repeat("x", maxLoggedBody+100)
	logger := NewCallLogger(roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(long))}, nil
	}))

	resp, err := logger.RoundTrip(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://realm.example/", nil))
	if err != nil {
		t.Fatal(err)
	}
	received, _ := io.ReadAll(resp.Body)

	if len(received) != len(long) {
		t.Errorf("the caller read %d bytes, want %d", len(received), len(long))
	}
	if !strings.Contains(buf.String(), "(truncated)") || strings.Contains(buf.String(), long) {
		t.Errorf("the logged body was not truncated")
	}
}

func TestCallLoggerDescribesBodiesItWillNotRead(t *testing.T) {
	tests := []struct {
		name string
		req  func(t *testing.T) *http.Request
		want string
	}{
		{name: "a multipart upload is logged by size", want: "<multipart, 4 bytes>", req: func(t *testing.T) *http.Request {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://realm.example/", strings.NewReader("dump"))
			r.Header.Set("Content-Type", "multipart/form-data; boundary=x")
			r.ContentLength = 4
			return r
		}},
		{name: "a body that cannot be read twice", want: "<not replayable>", req: func(t *testing.T) *http.Request {
			r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://realm.example/", io.NopCloser(strings.NewReader("once")))
			if err != nil {
				t.Fatal(err)
			}
			return r
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := captureDefaultLog(t, slog.LevelDebug)
			logger := NewCallLogger(roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
			}))

			if _, err := logger.RoundTrip(tt.req(t)); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(buf.String(), tt.want) {
				t.Errorf("log %q lacks %q", buf.String(), tt.want)
			}
		})
	}
}

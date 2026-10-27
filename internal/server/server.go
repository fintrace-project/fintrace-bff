package server

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/fintrace-project/fintrace-bff/internal/config"
	"github.com/fintrace-project/fintrace-bff/internal/session"
)

const healthzPath = "/healthz"
const authSignInPath = "/auth/sign-in"
const authCallbackPath = "/auth/callback"
const authSignOutPath = "/auth/sign-out"

func RoutesHandler(tp trace.TracerProvider, auth *session.Auth, cfg config.Config) (http.Handler, error) {
	mux := http.NewServeMux()

	// Registered routes
	registerHealth(mux)
	registerAuth(mux, auth)

	// Wrappers
	h, err := withCSRF(mux, cfg)
	if err != nil {
		return nil, err
	}

	return withTracing(h, tp), nil
}

func withCSRF(handler http.Handler, cfg config.Config) (http.Handler, error) {
	p := http.NewCrossOriginProtection()
	origin := cfg.PublicOrigin.String()
	err := p.AddTrustedOrigin(origin)
	if err != nil {
		return nil, fmt.Errorf("csrf: trust %s: %w", origin, err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := p.Check(r)
		if err == nil && isUnsafe(r.Method) && r.Header.Get("Origin") == "" {
			err = errors.New("missing Origin header")
		}
		if err != nil {
			slog.WarnContext(r.Context(), "cross-origin request refused",
				"method", r.Method, "path", r.URL.Path, "origin", r.Header.Get("Origin"), "error", err)
			http.Error(w, "cross-origin request refused", http.StatusForbidden)
			return
		}
		handler.ServeHTTP(w, r)
	}), nil
}

func withTracing(next http.Handler, tp trace.TracerProvider) http.Handler {
	return otelhttp.NewHandler(next, "fintrace-bff",
		otelhttp.WithPublicEndpointFn(func(*http.Request) bool { return true }),
		otelhttp.WithTracerProvider(tp),
		otelhttp.WithPropagators(propagation.TraceContext{}),
		otelhttp.WithFilter(func(r *http.Request) bool { return r.URL.Path != healthzPath }),
	)
}

func registerHealth(mux *http.ServeMux) {
	const path = http.MethodGet + " " + healthzPath

	healthzHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"UP"}`)
	}

	mux.HandleFunc(path, healthzHandler)
	slog.Info("route registered", "pattern", path)
}

func registerAuth(mux *http.ServeMux, auth *session.Auth) {
	registerAuthSignIn(mux, auth)
	registerAuthCallback(mux, auth)
	registerAuthSignOut(mux, auth)
}

func registerAuthSignIn(mux *http.ServeMux, auth *session.Auth) {
	const path = http.MethodGet + " " + authSignInPath
	mux.HandleFunc(path, auth.SignIn)
	slog.Info("route registered", "pattern", path)
}

func registerAuthCallback(mux *http.ServeMux, auth *session.Auth) {
	const path = http.MethodGet + " " + authCallbackPath
	mux.HandleFunc(path, auth.Callback)
	slog.Info("route registered", "pattern", path)
}

func registerAuthSignOut(mux *http.ServeMux, auth *session.Auth) {
	const path = http.MethodPost + " " + authSignOutPath
	mux.HandleFunc(path, auth.SignOut)
	slog.Info("route registered", "pattern", path)
}

func isUnsafe(s string) bool {
	return s != http.MethodGet && s != http.MethodOptions && s != http.MethodHead
}

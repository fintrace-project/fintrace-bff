package server

import (
	"io"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/fintrace-project/fintrace-bff/internal/session"
)

const healthzPath = "/healthz"
const authSignInPath = "/auth/sign-in"
const authCallbackPath = "/auth/callback"
const authSignOutPath = "/auth/sign-out"

func RoutesHandler(tp trace.TracerProvider, auth *session.Auth) http.Handler {
	mux := http.NewServeMux()

	// Registered routes
	registerHealth(mux)
	registerAuth(mux, auth)

	// Wrappers
	return withTracing(mux, tp)
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
	const path = "GET " + healthzPath

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
	const path = "GET " + authSignInPath
	mux.HandleFunc(path, auth.SignIn)
	slog.Info("route registered", "pattern", path)
}

func registerAuthCallback(mux *http.ServeMux, auth *session.Auth) {
	const path = "GET " + authCallbackPath
	mux.HandleFunc(path, auth.Callback)
	slog.Info("route registered", "pattern", path)
}

func registerAuthSignOut(mux *http.ServeMux, auth *session.Auth) {
	const path = "POST " + authSignOutPath
	mux.HandleFunc(path, auth.SignOut)
	slog.Info("route registered", "pattern", path)
}

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
const authLoginPath = "/auth/login"
const authCallbackPath = "/auth/callback"

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
	registerAuthLogin(mux, auth)
	registerAuthCallback(mux, auth)
}

func registerAuthLogin(mux *http.ServeMux, auth *session.Auth) {
	const path = "GET " + authLoginPath
	mux.HandleFunc(path, auth.Login)
	slog.Info("route registered", "pattern", path)
}

func registerAuthCallback(mux *http.ServeMux, auth *session.Auth) {
	const path = "GET " + authCallbackPath
	mux.HandleFunc(path, auth.Callback)
	slog.Info("route registered", "pattern", path)
}

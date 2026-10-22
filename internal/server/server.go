package server

import (
	"io"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

const healthzPath = "/healthz"

func RoutesHandler(tp trace.TracerProvider) http.Handler {
	mux := http.NewServeMux()

	// Registered routes
	registerHealth(mux)

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
	slog.Debug("route registered", "pattern", path)
}

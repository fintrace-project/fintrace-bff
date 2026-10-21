package server

import (
	"io"
	"log/slog"
	"net/http"
)

func RoutesHandler() http.Handler {
	mux := http.NewServeMux()
	registerHealth(mux)
	return mux
}

func registerHealth(mux *http.ServeMux) {
	const path = "GET /healthz"

	healthzHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"UP"}`)
	}

	mux.HandleFunc(path, healthzHandler)
	slog.Debug("route registered", "pattern", path)
}

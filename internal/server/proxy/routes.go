package proxy

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/fintrace-project/fintrace-bff/internal/httperr"
)

var coreRoutes = []string{
	"GET /api/v1/workspaces",
	"POST /api/v1/workspaces",
	"GET /api/v1/workspaces/{workspaceId}",
	"PUT /api/v1/workspaces/{workspaceId}",
	"DELETE /api/v1/workspaces/{workspaceId}",
	"POST /api/v1/workspaces/{workspaceId}/archive",
	"DELETE /api/v1/workspaces/{workspaceId}/archive",

	"GET /api/v1/workspaces/{workspaceId}/accounts",
	"POST /api/v1/workspaces/{workspaceId}/accounts",
	"GET /api/v1/workspaces/{workspaceId}/accounts/{accountId}",
	"PUT /api/v1/workspaces/{workspaceId}/accounts/{accountId}",
	"DELETE /api/v1/workspaces/{workspaceId}/accounts/{accountId}",
	"POST /api/v1/workspaces/{workspaceId}/accounts/{accountId}/restore",
	"GET /api/v1/workspaces/{workspaceId}/accounts/{accountId}/balance-anchors",
	"POST /api/v1/workspaces/{workspaceId}/accounts/{accountId}/balance-anchors",
	"GET /api/v1/workspaces/{workspaceId}/accounts/{accountId}/balance-anchors/{anchorId}",
	"DELETE /api/v1/workspaces/{workspaceId}/accounts/{accountId}/balance-anchors/{anchorId}",

	"GET /api/v1/workspaces/{workspaceId}/categories",
	"POST /api/v1/workspaces/{workspaceId}/categories",
	"GET /api/v1/workspaces/{workspaceId}/categories/{categoryId}",
	"PUT /api/v1/workspaces/{workspaceId}/categories/{categoryId}",
	"DELETE /api/v1/workspaces/{workspaceId}/categories/{categoryId}",
	"POST /api/v1/workspaces/{workspaceId}/categories/{categoryId}/restore",

	"POST /api/v1/workspaces/{workspaceId}/operations",
	"GET /api/v1/workspaces/{workspaceId}/operations/{operationId}",
	"PUT /api/v1/workspaces/{workspaceId}/operations/{operationId}",
	"DELETE /api/v1/workspaces/{workspaceId}/operations/{operationId}",

	"POST /api/v1/workspaces/{workspaceId}/transfers",
	"GET /api/v1/workspaces/{workspaceId}/transfers/{transferId}",
	"PUT /api/v1/workspaces/{workspaceId}/transfers/{transferId}",
	"DELETE /api/v1/workspaces/{workspaceId}/transfers/{transferId}",

	"GET /api/v1/workspaces/{workspaceId}/statistics/balances/accounts",
}

var mokImporterRoutes = []string{"POST /api/v1/workspaces/{workspaceId}/import"}

const (
	uploadMaxBytes      = 51 << 20 // the importer's 50 MiB plus room for multipart framing
	uploadReadDeadline  = 2 * time.Minute
	uploadWriteDeadline = 6 * time.Minute
)

func RegisterCoreRoutes(mux *http.ServeMux, bearer func(http.Handler) http.Handler, upstream http.Handler) {
	h := bearer(upstream)
	for _, pattern := range coreRoutes {
		register(mux, h, pattern, "core")
	}
}

func RegisterImporterRoutes(mux *http.ServeMux, bearer func(http.Handler) http.Handler, upstream http.Handler) {
	h := bearer(uploadLimit(upstream))
	for _, pattern := range mokImporterRoutes {
		register(mux, h, pattern, "mok-importer")
	}
}

func uploadLimit(next http.Handler) http.Handler {
	capped := http.MaxBytesHandler(next, uploadMaxBytes)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > uploadMaxBytes {
			httperr.Write(w, r, http.StatusRequestEntityTooLarge, httperr.UploadTooLarge, "upload too large")
			return
		}

		rc := http.NewResponseController(w)
		now := time.Now()
		if err := errors.Join(
			rc.SetReadDeadline(now.Add(uploadReadDeadline)),
			rc.SetWriteDeadline(now.Add(uploadWriteDeadline)),
		); err != nil {
			slog.WarnContext(r.Context(), "Upload deadlines not extended", "error", err)
		}

		capped.ServeHTTP(w, r)
	})
}

func register(mux *http.ServeMux, h http.Handler, pattern string, upstream string) {
	mux.Handle(pattern, h)
	slog.Info("route registered", "pattern", pattern, "upstream", upstream)
}

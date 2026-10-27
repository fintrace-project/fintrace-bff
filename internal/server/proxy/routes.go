package proxy

import (
	"log/slog"
	"net/http"
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

func RegisterCoreRoutes(mux *http.ServeMux, bearer func(http.Handler) http.Handler, upstream http.Handler) {
	h := bearer(upstream)
	for _, pattern := range coreRoutes {
		mux.Handle(pattern, h)
		slog.Info("route registered", "pattern", pattern, "upstream", "core")
	}
}

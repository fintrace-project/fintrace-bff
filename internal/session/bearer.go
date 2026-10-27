package session

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/fintrace-project/fintrace-bff/internal/httperr"
)

func BearerToken(r *http.Request) (string, bool) {
	scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	return strings.TrimSpace(token), true
}

func (a *Auth) VerifyBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _ := BearerToken(r)
		accessToken, err := a.oidc.AccessVerifier.Verify(r.Context(), token)
		if err != nil {
			slog.WarnContext(r.Context(), "Bearer token rejected", "error", err)
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			httperr.Write(w, r, http.StatusUnauthorized, httperr.InvalidToken, "invalid bearer token")
			return
		}

		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+token)

		var claims struct {
			Azp string `json:"azp"`
		}
		_ = accessToken.Claims(&claims)
		slog.DebugContext(r.Context(), "Bearer token accepted", "sub", accessToken.Subject, "azp", claims.Azp)

		next.ServeHTTP(w, r)
	})
}

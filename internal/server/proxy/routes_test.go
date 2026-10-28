package proxy

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

const testBearer = "Bearer test-token"

type upstreamRecorder struct {
	calls []*http.Request
}

func (u *upstreamRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.calls = append(u.calls, r)
	w.WriteHeader(http.StatusNoContent)
}

func stubBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Authorization", testBearer)
		next.ServeHTTP(w, r)
	})
}

func newCoreMux() (*http.ServeMux, *upstreamRecorder) {
	mux := http.NewServeMux()
	upstream := &upstreamRecorder{}
	RegisterCoreRoutes(mux, stubBearer, upstream)
	return mux, upstream
}

func serve(mux *http.ServeMux, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

var wildcard = regexp.MustCompile(`\{[^}]+\}`)

func requestFor(pattern string) (method, path string) {
	method, path, _ = strings.Cut(pattern, " ")
	return method, wildcard.ReplaceAllString(path, "id-1")
}

func TestEveryCoreRouteReachesTheUpstreamWithABearer(t *testing.T) {
	for _, pattern := range coreRoutes {
		t.Run(pattern, func(t *testing.T) {
			mux, upstream := newCoreMux()
			method, path := requestFor(pattern)

			rec := serve(mux, method, path)

			if len(upstream.calls) != 1 {
				t.Fatalf("upstream called %d times, status = %d; want once", len(upstream.calls), rec.Code)
			}
			got := upstream.calls[0]
			if got.Method != method || got.URL.Path != path {
				t.Errorf("upstream got %s %s, want %s %s", got.Method, got.URL.Path, method, path)
			}
			if a := got.Header.Get("Authorization"); a != testBearer {
				t.Errorf("Authorization = %q, want %q: the route is not behind the bearer", a, testBearer)
			}
		})
	}
}

func TestCoreRoutesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, pattern := range coreRoutes {
		if seen[pattern] {
			t.Errorf("%q is listed twice", pattern)
		}
		seen[pattern] = true
	}
}

func TestUnlistedRoutesNeverReachTheUpstream(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		wantStatus int
	}{
		{name: "the admin replay", method: http.MethodPost,
			path: "/admin/api/v1/workspaces/id-1/replay", wantStatus: http.StatusNotFound},
		{name: "actuator", method: http.MethodGet,
			path: "/actuator/health", wantStatus: http.StatusNotFound},
		{name: "Core's import API, which belongs to the importer", method: http.MethodPost,
			path: "/api/v1/workspaces/id-1/import", wantStatus: http.StatusNotFound},
		{name: "a dot-dot path out of /api", method: http.MethodPost,
			path: "/api/v1/workspaces/../../admin/api/v1/workspaces/id-1/replay", wantStatus: http.StatusTemporaryRedirect},
		{name: "one segment too many", method: http.MethodGet,
			path: "/api/v1/workspaces/id-1/accounts/id-2/extra", wantStatus: http.StatusNotFound},
		{name: "a trailing slash", method: http.MethodGet,
			path: "/api/v1/workspaces/", wantStatus: http.StatusNotFound},
		{name: "an unversioned path", method: http.MethodGet,
			path: "/api/workspaces", wantStatus: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux, upstream := newCoreMux()

			rec := serve(mux, tt.method, tt.path)

			if len(upstream.calls) != 0 {
				t.Errorf("upstream called with %s %s, want it never reached", tt.method, upstream.calls[0].URL.Path)
			}
			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestADotDotPathIsRedirectedToItsCleanFormWhichIsNotListed(t *testing.T) {
	mux, upstream := newCoreMux()

	rec := serve(mux, http.MethodPost, "/api/v1/workspaces/../../admin/api/v1/workspaces/id-1/replay")
	loc := rec.Header().Get("Location")
	if want := "/api/admin/api/v1/workspaces/id-1/replay"; loc != want {
		t.Fatalf("Location = %q, want %q", loc, want)
	}

	if rec := serve(mux, http.MethodPost, loc); rec.Code != http.StatusNotFound {
		t.Errorf("following the redirect: status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if len(upstream.calls) != 0 {
		t.Errorf("upstream called with %s, want it never reached", upstream.calls[0].URL.Path)
	}
}

// The Core routes alone; behind RoutesHandler the /api/ fallback answers 404 instead (server/web_test.go).
func TestAnUnlistedMethodOnAListedPathIs405OnTheCoreRoutesAlone(t *testing.T) {
	mux, upstream := newCoreMux()

	rec := serve(mux, http.MethodPatch, "/api/v1/workspaces/id-1")

	if len(upstream.calls) != 0 {
		t.Error("upstream reached with PATCH, which is not listed")
	}
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
	}
	if got, want := rec.Header().Get("Allow"), "DELETE, GET, HEAD, PUT"; got != want {
		t.Errorf("Allow = %q, want %q", got, want)
	}
}

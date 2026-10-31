package coreapi

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testUserID = "0192f3a0-0000-7000-8000-000000000001"

type coreCall struct {
	method, path, authorization, accept string
}

// A fake Core answering every request with status and body, and recording what it received.
func newFakeCore(t *testing.T, status int, body string) (*httptest.Server, *[]coreCall) {
	t.Helper()
	var calls []coreCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, coreCall{r.Method, r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Accept")})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func mustUsersAPI(t *testing.T, srv *httptest.Server, basePath string) *UsersAPI {
	t.Helper()
	base, err := url.Parse(srv.URL + basePath)
	if err != nil {
		t.Fatal(err)
	}
	return NewUsersAPI(base, srv.Client())
}

func TestUserIDAsksCoreForTheCallersOwnID(t *testing.T) {
	srv, calls := newFakeCore(t, http.StatusOK, `{"userId":"`+testUserID+`"}`)

	id, err := mustUsersAPI(t, srv, "").UserID(t.Context(), "access-1")

	if err != nil {
		t.Fatalf("UserID() error = %v", err)
	}
	if id != testUserID {
		t.Errorf("UserID() = %q, want %q", id, testUserID)
	}
	if len(*calls) != 1 {
		t.Fatalf("%d calls to Core, want 1", len(*calls))
	}
	want := coreCall{http.MethodGet, "/api/v1/users/current/id", "Bearer access-1", "application/json"}
	if got := (*calls)[0]; got != want {
		t.Errorf("call = %+v, want %+v", got, want)
	}
}

func TestUserIDKeepsTheBasePath(t *testing.T) {
	srv, calls := newFakeCore(t, http.StatusOK, `{"userId":"`+testUserID+`"}`)

	if _, err := mustUsersAPI(t, srv, "/core/").UserID(t.Context(), "access-1"); err != nil {
		t.Fatalf("UserID() error = %v", err)
	}
	if got, want := (*calls)[0].path, "/core/api/v1/users/current/id"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}

func TestUserIDFailsOnAnAnswerWithoutAnID(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{"unauthorized", http.StatusUnauthorized, `{"detail":"Not authenticated"}`, "401"},
		{"server error", http.StatusInternalServerError, `{}`, "500"},
		{"malformed body", http.StatusOK, `{"userId":`, "decode user id"},
		{"empty id", http.StatusOK, `{"userId":""}`, "no user id"},
		{"missing id", http.StatusOK, `{}`, "no user id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _ := newFakeCore(t, tt.status, tt.body)

			id, err := mustUsersAPI(t, srv, "").UserID(t.Context(), "access-1")

			if err == nil {
				t.Fatalf("UserID() = %q, want an error", id)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tt.wantErr)
			}
		})
	}
}

func TestUserIDFailsWhenCoreIsUnreachable(t *testing.T) {
	srv, _ := newFakeCore(t, http.StatusOK, `{"userId":"`+testUserID+`"}`)
	api := mustUsersAPI(t, srv, "")
	srv.Close()

	if _, err := api.UserID(t.Context(), "access-1"); err == nil || !strings.Contains(err.Error(), "call core") {
		t.Errorf("error = %v, want the failed call", err)
	}
}

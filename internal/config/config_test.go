package config

import (
	"log/slog"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
)

var required = []string{
	"FINTRACE_OAUTH2_ISSUER_URI",
	"BFF_PUBLIC_ORIGIN",
	"BFF_CORE_URL",
	"BFF_IMPORTER_URL",
	"BFF_WEB_URL",
	"BFF_OAUTH2_CLIENT_ID",
	"BFF_OAUTH2_CLIENT_SECRET",
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func fullEnv() map[string]string {
	return map[string]string{
		"BFF_LISTEN_ADDR":            ":9000",
		"BFF_LOG_LEVEL":              "DEBUG",
		"FINTRACE_OAUTH2_ISSUER_URI": "https://idp.example/realms/r",
		"BFF_PUBLIC_ORIGIN":          "https://fintrace.example",
		"BFF_CORE_URL":               "http://fintrace-core:8080",
		"BFF_IMPORTER_URL":           "http://fintrace-mok-importer:8080",
		"BFF_WEB_URL":                "http://fintrace-web:8080",
		"BFF_OAUTH2_CLIENT_ID":       "fintrace-bff",
		"BFF_OAUTH2_CLIENT_SECRET":   "s3cret",
	}
}

func lookup(env map[string]string) func(string) string {
	return func(name string) string { return env[name] }
}

func without(env map[string]string, names ...string) map[string]string {
	for _, n := range names {
		delete(env, n)
	}
	return env
}

func TestLoad(t *testing.T) {
	withDefaults := func(listenAddr string, level slog.Level) Config {
		return Config{
			ListenAddr:   listenAddr,
			LogLevel:     level,
			IssuerURI:    mustParse(t, "https://idp.example/realms/r"),
			PublicOrigin: mustParse(t, "https://fintrace.example"),
			CoreURL:      mustParse(t, "http://fintrace-core:8080"),
			ImporterURL:  mustParse(t, "http://fintrace-mok-importer:8080"),
			WebURL:       mustParse(t, "http://fintrace-web:8080"),
			ClientID:     "fintrace-bff",
			ClientSecret: "s3cret",
		}
	}
	tests := []struct {
		name string
		env  map[string]string
		want Config
	}{
		{
			name: "every variable set",
			env:  fullEnv(),
			want: withDefaults(":9000", slog.LevelDebug),
		},
		{
			name: "optional variables unset take their defaults",
			env:  without(fullEnv(), "BFF_LISTEN_ADDR", "BFF_LOG_LEVEL"),
			want: withDefaults(":8080", slog.LevelInfo),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(lookup(tt.env))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Load() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestLoadRejectsMissingRequired(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		missing []string
	}{
		{name: "nothing set", env: map[string]string{}, missing: required},
		{name: "one missing", env: without(fullEnv(), "BFF_CORE_URL"), missing: []string{"BFF_CORE_URL"}},
		{name: "set but empty", env: func() map[string]string {
			env := fullEnv()
			env["BFF_WEB_URL"] = ""
			return env
		}(), missing: []string{"BFF_WEB_URL"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(lookup(tt.env))
			if err == nil {
				t.Fatalf("Load() = %+v, want an error", got)
			}
			if got != (Config{}) {
				t.Errorf("Load() = %+v alongside an error, want the zero Config", got)
			}
			for _, name := range tt.missing {
				if strings.Count(err.Error(), name) != 1 {
					t.Errorf("error %q should name %s exactly once", err, name)
				}
			}
			for _, name := range required {
				if !slices.Contains(tt.missing, name) && strings.Contains(err.Error(), name) {
					t.Errorf("error %q names %s, which is set", err, name)
				}
			}
		})
	}
}

func TestLoadRejectsUnknownLogLevel(t *testing.T) {
	env := fullEnv()
	env["BFF_LOG_LEVEL"] = "loud"

	got, err := Load(lookup(env))
	if err == nil {
		t.Fatalf("Load() = %+v, want an error", got)
	}
	for _, want := range []string{"BFF_LOG_LEVEL", "loud"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should contain %q", err, want)
		}
	}
}

var urlVars = []string{
	"FINTRACE_OAUTH2_ISSUER_URI",
	"BFF_CORE_URL",
	"BFF_IMPORTER_URL",
	"BFF_WEB_URL",
}

func assertRejected(t *testing.T, env map[string]string, invalid map[string]string) {
	t.Helper()
	got, err := Load(lookup(env))
	if err == nil {
		t.Fatalf("Load() = %+v, want an error", got)
	}
	if got != (Config{}) {
		t.Errorf("Load() = %+v alongside an error, want the zero Config", got)
	}
	for name, value := range invalid {
		if strings.Count(err.Error(), name) != 1 {
			t.Errorf("error %q should name %s exactly once", err, name)
		}
		if !strings.Contains(err.Error(), value) {
			t.Errorf("error %q should quote the rejected value %q", err, value)
		}
	}
	for _, name := range required {
		if _, bad := invalid[name]; !bad && strings.Contains(err.Error(), name) {
			t.Errorf("error %q names %s, which is valid", err, name)
		}
	}
}

func TestLoadRejectsInvalidURL(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "no scheme", value: "fintrace-core"},
		{name: "host and port without a scheme", value: "fintrace-core:8080"},
		{name: "relative path", value: "/core"},
		{name: "scheme other than http(s)", value: "ftp://fintrace-core"},
		{name: "no host", value: "http://"},
		{name: "malformed", value: "http://[::1"},
		{name: "user info", value: "http://user:pw@fintrace-core"},
		{name: "query", value: "http://fintrace-core?x=1"},
		{name: "fragment", value: "http://fintrace-core#top"},
	}
	for _, tt := range tests {
		for _, name := range urlVars {
			t.Run(tt.name+"/"+name, func(t *testing.T) {
				env := fullEnv()
				env[name] = tt.value
				assertRejected(t, env, map[string]string{name: tt.value})
			})
		}
	}
}

func TestLoadRejectsInvalidPublicOrigin(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "no scheme", value: "fintrace.example"},
		{name: "scheme other than http(s)", value: "ftp://fintrace.example"},
		{name: "no host", value: "https://"},
		{name: "malformed", value: "https://[::1"},
		{name: "path", value: "https://fintrace.example/app"},
		{name: "trailing slash", value: "https://fintrace.example/"},
		{name: "query", value: "https://fintrace.example?x=1"},
		{name: "fragment", value: "https://fintrace.example#top"},
		{name: "user info", value: "https://user@fintrace.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := fullEnv()
			env["BFF_PUBLIC_ORIGIN"] = tt.value
			assertRejected(t, env, map[string]string{"BFF_PUBLIC_ORIGIN": tt.value})
		})
	}
}

func TestLoadAcceptsURLsWithPortAndPath(t *testing.T) {
	env := fullEnv()
	env["BFF_PUBLIC_ORIGIN"] = "http://localhost:8080"
	env["BFF_CORE_URL"] = "http://fintrace-core:8080/base"

	got, err := Load(lookup(env))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if want := mustParse(t, "http://localhost:8080"); !reflect.DeepEqual(got.PublicOrigin, want) {
		t.Errorf("PublicOrigin = %+v, want %+v", got.PublicOrigin, want)
	}
	if want := mustParse(t, "http://fintrace-core:8080/base"); !reflect.DeepEqual(got.CoreURL, want) {
		t.Errorf("CoreURL = %+v, want %+v", got.CoreURL, want)
	}
}

func TestLoadNamesEveryInvalidVariable(t *testing.T) {
	env := fullEnv()
	env["BFF_CORE_URL"] = "fintrace-core"
	env["BFF_WEB_URL"] = "ftp://fintrace-web"
	env["BFF_PUBLIC_ORIGIN"] = "https://fintrace.example/app"

	assertRejected(t, env, map[string]string{
		"BFF_CORE_URL":      "fintrace-core",
		"BFF_WEB_URL":       "ftp://fintrace-web",
		"BFF_PUBLIC_ORIGIN": "https://fintrace.example/app",
	})
}

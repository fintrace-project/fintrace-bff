package config

import (
	"log/slog"
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
	tests := []struct {
		name string
		env  map[string]string
		want Config
	}{
		{
			name: "every variable set",
			env:  fullEnv(),
			want: Config{
				ListenAddr:   ":9000",
				LogLevel:     slog.LevelDebug,
				IssuerURI:    "https://idp.example/realms/r",
				PublicOrigin: "https://fintrace.example",
				CoreURL:      "http://fintrace-core:8080",
				ImporterURL:  "http://fintrace-mok-importer:8080",
				WebURL:       "http://fintrace-web:8080",
			},
		},
		{
			name: "optional variables unset take their defaults",
			env:  without(fullEnv(), "BFF_LISTEN_ADDR", "BFF_LOG_LEVEL"),
			want: Config{
				ListenAddr:   ":8080",
				LogLevel:     slog.LevelInfo,
				IssuerURI:    "https://idp.example/realms/r",
				PublicOrigin: "https://fintrace.example",
				CoreURL:      "http://fintrace-core:8080",
				ImporterURL:  "http://fintrace-mok-importer:8080",
				WebURL:       "http://fintrace-web:8080",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(lookup(tt.env))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got != tt.want {
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

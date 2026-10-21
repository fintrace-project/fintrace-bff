package config

import (
	"errors"
	"fmt"
	"log/slog"
)

type Config struct {
	ListenAddr   string     // BFF_LISTEN_ADDR
	LogLevel     slog.Level // BFF_LOG_LEVEL
	IssuerURI    string     // FINTRACE_OAUTH2_ISSUER_URI
	PublicOrigin string     // BFF_PUBLIC_ORIGIN
	CoreURL      string     // BFF_CORE_URL
	ImporterURL  string     // BFF_IMPORTER_URL
	WebURL       string     // BFF_WEB_URL
}

type errorCollector struct {
	errs []error
}

func Load(getenv func(string) string) (Config, error) {
	ec := &errorCollector{}
	cfg := Config{
		ListenAddr:   getOptionalEnv(getenv, "BFF_LISTEN_ADDR", ":8080"),
		LogLevel:     asLogLevel(getOptionalEnv(getenv, "BFF_LOG_LEVEL", "INFO"), ec),
		IssuerURI:    getRequiredEnv(getenv, "FINTRACE_OAUTH2_ISSUER_URI", ec),
		PublicOrigin: getRequiredEnv(getenv, "BFF_PUBLIC_ORIGIN", ec),
		CoreURL:      getRequiredEnv(getenv, "BFF_CORE_URL", ec),
		ImporterURL:  getRequiredEnv(getenv, "BFF_IMPORTER_URL", ec),
		WebURL:       getRequiredEnv(getenv, "BFF_WEB_URL", ec),
	}

	if err := errors.Join(ec.errs...); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func asLogLevel(logLevel string, ec *errorCollector) slog.Level {
	var level slog.Level
	if err := level.UnmarshalText([]byte(logLevel)); err != nil {
		ec.errs = append(ec.errs, fmt.Errorf("BFF_LOG_LEVEL: %w", err))
	}
	return level
}

func getOptionalEnv(getenv func(string) string, envName, defValue string) string {
	env := getenv(envName)

	if env == "" {
		return defValue
	}

	return env
}

func getRequiredEnv(getenv func(string) string, envName string, ec *errorCollector) string {
	env := getenv(envName)

	if env == "" {
		ec.errs = append(ec.errs, errors.New(envName+" is not set"))
	}

	return env
}

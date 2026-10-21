package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
)

type Config struct {
	ListenAddr   string     // BFF_LISTEN_ADDR
	LogLevel     slog.Level // BFF_LOG_LEVEL
	IssuerURI    *url.URL   // FINTRACE_OAUTH2_ISSUER_URI
	CoreURL      *url.URL   // BFF_CORE_URL
	ImporterURL  *url.URL   // BFF_IMPORTER_URL
	WebURL       *url.URL   // BFF_WEB_URL
	PublicOrigin *url.URL   // BFF_PUBLIC_ORIGIN
	ClientID     string     // BFF_OAUTH2_CLIENT_ID
	ClientSecret string     // BFF_OAUTH2_CLIENT_SECRET
}

type errorCollector struct {
	errs []error
}

type urlRule func(*url.URL) error

func noPath(urlAddr *url.URL) error {
	if urlAddr.Path != "" {
		return errors.New("must not contain a path")
	}
	return nil
}

func Load(getenv func(string) string) (Config, error) {
	ec := &errorCollector{}

	cfg := Config{
		ListenAddr:   getOptionalEnv(getenv, "BFF_LISTEN_ADDR", ":8080"),
		LogLevel:     asLogLevel(getOptionalEnv(getenv, "BFF_LOG_LEVEL", "INFO"), ec),
		IssuerURI:    getRequiredEnvAsURL(getenv, "FINTRACE_OAUTH2_ISSUER_URI", ec),
		CoreURL:      getRequiredEnvAsURL(getenv, "BFF_CORE_URL", ec),
		ImporterURL:  getRequiredEnvAsURL(getenv, "BFF_IMPORTER_URL", ec),
		WebURL:       getRequiredEnvAsURL(getenv, "BFF_WEB_URL", ec),
		PublicOrigin: getRequiredEnvAsURL(getenv, "BFF_PUBLIC_ORIGIN", ec, noPath),
		ClientID:     getRequiredEnv(getenv, "BFF_OAUTH2_CLIENT_ID", ec),
		ClientSecret: getRequiredEnv(getenv, "BFF_OAUTH2_CLIENT_SECRET", ec),
	}

	if err := errors.Join(ec.errs...); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func getRequiredEnvAsURL(getenv func(string) string, envName string, ec *errorCollector, extraURLRules ...urlRule) *url.URL {
	env := getRequiredEnv(getenv, envName, ec)

	if env == "" {
		return nil
	}

	var errs []error

	urlAddr, err := url.Parse(env)

	if err != nil {
		ec.errs = append(ec.errs, fmt.Errorf("%s: %w", envName, err))
		return nil
	}

	if urlAddr.Scheme != "https" && urlAddr.Scheme != "http" {
		errs = append(errs, errors.New("scheme must be http or https"))
	}
	if urlAddr.Host == "" {
		errs = append(errs, errors.New("host must not be empty"))
	}
	if urlAddr.User != nil {
		errs = append(errs, errors.New("must not contain user info"))
	}

	if urlAddr.RawQuery != "" || urlAddr.ForceQuery {
		errs = append(errs, errors.New("must not contain a query"))
	}

	if urlAddr.Fragment != "" {
		errs = append(errs, errors.New("must not contain a fragment"))
	}

	for _, extraURLRule := range extraURLRules {
		if err := extraURLRule(urlAddr); err != nil {
			errs = append(errs, err)
		}
	}

	if err := errors.Join(errs...); err != nil {
		ec.errs = append(ec.errs, fmt.Errorf("%s: invalid URL %q: %w", envName, env, err))
		return nil
	}
	return urlAddr
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

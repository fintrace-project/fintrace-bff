package proxy

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/fintrace-project/fintrace-bff/internal/config"
	"go.opentelemetry.io/otel/trace"
)

type UpstreamTransports struct {
	Core        http.RoundTripper
	MOKImporter http.RoundTripper
	Web         http.RoundTripper
}

func MakeUpstreamTransports(tp trace.TracerProvider) UpstreamTransports {
	return UpstreamTransports{
		Core:        NewTransport(tp, 10*time.Second, slog.LevelInfo),
		MOKImporter: NewTransport(tp, 5*time.Minute, slog.LevelInfo),
		Web:         NewTransport(tp, 10*time.Second, slog.LevelDebug),
	}
}

type UpstreamProxies struct {
	Core        http.Handler
	MOKImporter http.Handler
	Web         http.Handler
}

func MakeUpstreamProxies(cfg config.Config, transports UpstreamTransports) UpstreamProxies {
	return UpstreamProxies{
		Core:        NewProxy(cfg.CoreURL, transports.Core, cfg),
		MOKImporter: NewProxy(cfg.MOKImporterURL, transports.MOKImporter, cfg),
		Web:         WithCSP(NewProxy(cfg.WebURL, transports.Web, cfg)),
	}
}

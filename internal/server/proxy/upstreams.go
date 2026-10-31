package proxy

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/fintrace-project/fintrace-bff/internal/config"
	"go.opentelemetry.io/otel/trace"
)

type UpstreamProxies struct {
	Core        http.Handler
	MOKImporter http.Handler
	Web         http.Handler
}

func MakeUpstreamProxies(cfg config.Config, tp trace.TracerProvider) UpstreamProxies {
	return UpstreamProxies{
		Core:        NewProxy(cfg.CoreURL, NewTransport(tp, 10*time.Second, slog.LevelInfo), cfg),
		MOKImporter: NewProxy(cfg.MOKImporterURL, NewTransport(tp, 5*time.Minute, slog.LevelInfo), cfg),
		Web:         NewProxy(cfg.WebURL, NewTransport(tp, 10*time.Second, slog.LevelDebug), cfg),
	}
}

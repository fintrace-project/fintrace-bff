package proxy

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/fintrace-project/fintrace-bff/internal/config"
	"go.opentelemetry.io/otel/trace"
)

type ExtClients struct {
	Core        http.Handler
	MOKImporter http.Handler
	Web         http.Handler
}

func MakeClients(cfg config.Config, tp trace.TracerProvider) ExtClients {
	return ExtClients{
		Core:        NewProxy(cfg.CoreURL, NewTransport(tp, 10*time.Second, slog.LevelInfo), cfg),
		MOKImporter: NewProxy(cfg.MOKImporterURL, NewTransport(tp, 5*time.Minute, slog.LevelInfo), cfg),
		Web:         NewProxy(cfg.WebURL, NewTransport(tp, 10*time.Second, slog.LevelDebug), cfg),
	}
}

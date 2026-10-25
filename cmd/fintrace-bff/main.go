package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/fintrace-project/fintrace-bff/internal/config"
	"github.com/fintrace-project/fintrace-bff/internal/logging"
	"github.com/fintrace-project/fintrace-bff/internal/server"
	"github.com/fintrace-project/fintrace-bff/internal/session"
	"github.com/fintrace-project/fintrace-bff/internal/session/memstore"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	initLogging(cfg)
	tp := newTracerProvider()
	defer shutdownTracingProvider(tp)

	// A context that is cancelled when SIGINT (Ctrl+C) or SIGTERM (docker stop) arrives
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store := memstore.New(time.Now)
	go store.RunEviction(ctx, time.Minute)

	auth, err := session.NewAuth(context.Background(), cfg, newOutboundClient(), store)
	if err != nil {
		return err
	}

	srv := newHTTPServer(cfg, tp, auth)

	ln, err := listen(srv)
	if err != nil {
		return err
	}

	return serve(ctx, srv, ln)
}

func newOutboundClient() *http.Client {
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: logging.NewCallLogger(http.DefaultTransport),
	}
}

func initLogging(cfg config.Config) {
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel})
	slog.SetDefault(slog.New(logging.WithTraceID(handler)))
	slog.Info("Logging initialised", "log_level", cfg.LogLevel)
}

func newTracerProvider() *sdktrace.TracerProvider {
	return sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
}

func shutdownTracingProvider(tp *sdktrace.TracerProvider) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tp.Shutdown(ctx); err != nil {
		slog.Warn("Tracer provider shutdown failed", "error", err)
	}
}

func newHTTPServer(cfg config.Config, tp trace.TracerProvider, auth *session.Auth) *http.Server {
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           server.RoutesHandler(tp, auth),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return srv
}

func listen(srv *http.Server) (net.Listener, error) {
	listener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err) // port taken, bad address, no permission
	}
	slog.Info("HTTP Server listening", "address", listener.Addr())
	return listener, nil
}

func serve(ctx context.Context, srv *http.Server, ln net.Listener) error {
	// Serve in the background; report how it ended
	errChannel := make(chan error, 1)
	go func() { // launch async gorutine
		errChannel <- srv.Serve(ln)
	}()

	select { // waiting signal from channel
	case err := <-errChannel:
		return fmt.Errorf("server: %w", err)
	case <-ctx.Done():
	}

	slog.Info("Shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	slog.Info("Process stopped")
	return nil
}

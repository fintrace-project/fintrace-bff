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

	"github.com/fintrace-project/fintrace-bff/internal/config"
	"github.com/fintrace-project/fintrace-bff/internal/server"
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
	srv := newHTTPServer(cfg)

	// A context that is cancelled when SIGINT (Ctrl+C) or SIGTERM (docker stop) arrives
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := listen(srv)
	if err != nil {
		return err
	}

	return serve(ctx, srv, ln)
}

func initLogging(cfg config.Config) {
	slog.SetLogLoggerLevel(cfg.LogLevel)
	slog.Info("Logging initialised", "log_level", cfg.LogLevel)
}

func newHTTPServer(cfg config.Config) *http.Server {
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           server.RoutesHandler(),
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

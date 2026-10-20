package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/fintrace-project/fintrace-bff/internal/config"
)

func configure() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	initLogging(cfg)

	return nil
}

func initLogging(cfg config.Config) {
	slog.SetLogLoggerLevel(cfg.LogLevel)
	slog.Info("Logging initialised", "log_level", cfg.LogLevel)
}

func main() {
	if err := configure(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

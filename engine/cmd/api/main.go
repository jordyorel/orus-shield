// Command api serves the dashboard's HTTP API.
//
// Configuration comes from environment variables (see loadConfig). It
// listens on 127.0.0.1 by default: exposing it means putting it behind a
// TLS-terminating reverse proxy, because session cookies are Secure.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jordyorel/orus-shield/engine/internal/api"
	"github.com/jordyorel/orus-shield/engine/internal/module"
	"github.com/jordyorel/orus-shield/engine/internal/modules/all"
	"github.com/jordyorel/orus-shield/engine/internal/store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("api exited", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.databaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}

	reg, err := all.Registry()
	if err != nil {
		return err
	}
	var modules []string
	var catalog []module.Info
	for _, m := range reg.All() {
		modules = append(modules, m.Info().ID)
		catalog = append(catalog, m.Info())
	}
	srv, err := api.New(st, api.Config{TrustedOrigins: cfg.trustedOrigins, Modules: modules, Catalog: catalog, MFAKey: cfg.mfaKey}, log)
	if err != nil {
		return err
	}
	handler, err := srv.Handler()
	if err != nil {
		return err
	}
	httpServer := &http.Server{
		Addr:    cfg.addr,
		Handler: handler,
		// Timeouts bound slow clients (rule 7 applies to our own clients
		// too: a connection that sends one byte a minute must not hold a
		// goroutine forever).
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("api listening", "addr", cfg.addr)
		errc <- httpServer.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("api stopping")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Command api serves the JSON API under /api/v1 and the web dashboard on
// every other path, on one origin: both share the session cookie, and the
// dashboard needs no cross-origin requests.
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

	"github.com/jordyorel/orus-shield/engine/internal/account"
	"github.com/jordyorel/orus-shield/engine/internal/api"
	"github.com/jordyorel/orus-shield/engine/internal/modules/all"
	"github.com/jordyorel/orus-shield/engine/internal/store"
	"github.com/jordyorel/orus-shield/engine/internal/web"
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
	for _, m := range reg.All() {
		modules = append(modules, m.Info().ID)
	}
	// One account service for both front ends: same sessions, same rules.
	acct, err := account.New(st.Auth(), account.Config{MFAKey: cfg.mfaKey})
	if err != nil {
		return err
	}
	srv, err := api.NewWithAccount(st, acct, api.Config{TrustedOrigins: cfg.trustedOrigins, Modules: modules}, log)
	if err != nil {
		return err
	}
	apiHandler, err := srv.Handler()
	if err != nil {
		return err
	}
	dashboard, err := web.New(acct, log)
	if err != nil {
		return err
	}
	handler := http.NewServeMux()
	handler.Handle("/api/", apiHandler)
	handler.Handle("/", dashboard.Handler())
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
		log.Info("api and dashboard listening", "addr", cfg.addr)
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

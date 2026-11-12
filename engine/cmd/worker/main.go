// Command worker runs scan jobs from the PostgreSQL queue.
//
// Configuration comes from environment variables; see loadConfig. Start as
// many workers as needed: they share the queue safely.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/jordyorel/orus-shield/engine/internal/modules/all"
	"github.com/jordyorel/orus-shield/engine/internal/notify"
	"github.com/jordyorel/orus-shield/engine/internal/ownership"
	"github.com/jordyorel/orus-shield/engine/internal/store"
	"github.com/jordyorel/orus-shield/engine/internal/threats"
	"github.com/jordyorel/orus-shield/engine/internal/worker"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("worker exited", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}

	// SIGINT (Ctrl-C) and SIGTERM (docker stop, Kubernetes) stop the worker
	// cleanly: the current scan is abandoned and retried by another worker.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.databaseURL)
	if err != nil {
		return err
	}
	defer st.Close()

	// Safe with several workers starting together: Migrate takes a lock.
	if err := st.Migrate(ctx); err != nil {
		return err
	}

	// One resolver for modules and ownership checks (ORUS_DNS_SERVER).
	registry, err := all.Registry(cfg.dns, all.Options{Nuclei: cfg.nuclei, ZAP: cfg.zap})
	if err != nil {
		return err
	}
	verifier := ownership.New(st, cfg.dns)

	// Email alerts: delivered from the outbox next to the scans. Without
	// mail they stay queued, and expire after a day.
	if cfg.smtp != nil {
		go notify.New(st, *cfg.smtp, cfg.publicURL, log.With("component", "notify")).Run(ctx, notify.DefaultInterval)
	} else {
		log.Warn("ORUS_SMTP_ADDR is not set: email alerts will not be sent")
	}
	if cfg.nuclei.Binary == "" {
		log.Warn("ORUS_NUCLEI_BIN is not set: the vulns module (known vulnerabilities) will fail")
	} else {
		// Emerging threats: new CVE templates of the installed release,
		// matched against what was detected on every verified domain.
		go threats.NewWatcher(st, cfg.nuclei.Templates, log.With("component", "threats")).Run(ctx, threats.DefaultInterval)
	}
	if cfg.zap.Image == "" {
		log.Warn("ORUS_ZAP_IMAGE is not set: deep web scans (zap module, deep profile) will fail")
	}
	return worker.New(st, registry, verifier, cfg.worker, log).Run(ctx)
}

// Command orus-agent scans a customer's internal network for Orus Shield
// (step J). The customer installs it on one machine of their network; it
// only calls out (HTTPS to the API) and opens no port.
//
//	orus-agent enroll -api https://app.example.com -code CODE [-config PATH]
//	orus-agent run [-config PATH]
//	orus-agent version
//
// enroll exchanges the one-time code shown in the dashboard for the
// agent's token, saved in the configuration file (mode 0600). run then
// asks the API for scans of the agent's internal network, runs them, and
// sends the results. It scans only the private ranges an admin declared,
// with the network's exclusions and rate: every connection goes through a
// gate, like the workers' modules.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

const usage = `usage:
  orus-agent enroll -api URL -code CODE [-config PATH]
  orus-agent run [-config PATH]
  orus-agent version`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "orus-agent:", err)
		if errors.Is(err, errUsage) {
			fmt.Fprintln(os.Stderr, usage)
			os.Exit(2)
		}
		os.Exit(1)
	}
}

var errUsage = errors.New("invalid usage")

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(out, "orus-agent %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
		return nil
	case "enroll":
		fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
		api := fs.String("api", "", "the Orus Shield address, e.g. https://app.orus-shield.com")
		code := fs.String("code", "", "the one-time enrolment code shown in the dashboard")
		path := fs.String("config", defaultConfigPath(), "configuration file")
		if err := fs.Parse(args[1:]); err != nil || *api == "" || *code == "" {
			return errUsage
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		cfg, err := enrol(ctx, newClient(*api, ""), *code)
		if err != nil {
			return err
		}
		cfg.API = *api
		if err := saveConfig(*path, cfg); err != nil {
			return err
		}
		fmt.Fprintf(out, "enrolled: agent %s, ranges %v\nconfiguration saved to %s; now run: orus-agent run\n", cfg.AgentID, cfg.Ranges, *path)
		return nil
	case "run":
		fs := flag.NewFlagSet("run", flag.ContinueOnError)
		path := fs.String("config", defaultConfigPath(), "configuration file")
		if err := fs.Parse(args[1:]); err != nil {
			return errUsage
		}
		cfg, err := loadConfig(*path)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
		return newAgent(newClient(cfg.API, cfg.Token), log).loop(ctx)
	}
	return errUsage
}

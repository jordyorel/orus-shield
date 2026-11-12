package zap

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Runner starts ZAP. Tests replace it so that no container runs.
type Runner interface {
	// Run executes ZAP with the plan and configuration of dir, and returns
	// when it has exited. ZAP writes its report in dir.
	Run(ctx context.Context, cfg Config, dir string) error
}

// Docker runs the pinned image with "docker run".
type Docker struct{}

// maxStderr bounds the error output kept for the error message.
const maxStderr = 4 << 10

// dockerArgs builds the command line. Hardening: no capabilities, no
// privilege escalation, bounded memory, CPUs and processes, removed after
// the run. Only the run's directory is mounted.
func dockerArgs(cfg Config, dir, name string) []string {
	args := []string{
		"run", "--rm", "--name", name,
		"--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--memory", "3g", "--cpus", "2", "--pids-limit", "512",
		"-v", dir + ":" + containerDir + ":rw",
	}
	if cfg.Network != "" {
		args = append(args, "--network", cfg.Network)
	} else if cfg.ProxyHost == "host.docker.internal" {
		// Docker Desktop defines this name; Docker Engine on Linux needs it.
		args = append(args, "--add-host", "host.docker.internal:host-gateway")
	}
	return append(args, cfg.Image,
		// -silent: ZAP makes no request of its own (update checks, news).
		"zap.sh", "-cmd", "-silent",
		"-configfile", containerDir+"/"+configFile,
		"-autorun", containerDir+"/"+planFile)
}

// Run implements Runner. The environment is not inherited beyond what the
// docker client needs to find its daemon.
func (Docker) Run(ctx context.Context, cfg Config, dir string) error {
	name := "orus-zap-" + randomHex(8)
	// cfg.Image is the operator's ORUS_ZAP_IMAGE (checked at startup); the
	// other arguments are built by this package. No shell is involved.
	cmd := exec.CommandContext(ctx, "docker", dockerArgs(cfg, dir, name)...) //nolint:gosec // G204: see comment above
	// ZAP writes its own errors on standard output: keep the end of both.
	stderr := &tail{max: maxStderr}
	cmd.Stdout = stderr
	cmd.Stderr = stderr
	cmd.Cancel = func() error {
		// Killing the docker client does not stop the container: ask the
		// daemon, then let CommandContext kill the client.
		kill := exec.Command("docker", "kill", name) //nolint:gosec // G204: our own container name
		_ = kill.Run()
		return cmd.Process.Kill()
	}
	cmd.WaitDelay = 30 * time.Second
	err := cmd.Run()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return fmt.Errorf("zap exited with status %d: %s", exit.ExitCode(), strings.TrimSpace(stderr.String()))
		}
		return fmt.Errorf("run zap: %w", err)
	}
	return nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// tail keeps the last max bytes written.
type tail struct {
	b   []byte
	max int
}

func (t *tail) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = t.b[len(t.b)-t.max:]
	}
	return len(p), nil
}

func (t *tail) String() string { return clean(string(t.b), t.max) }

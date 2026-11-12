package vulns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Runner starts Nuclei. Tests replace it so that no real program runs.
type Runner interface {
	// Run executes binary with args in dir, streams its standard output to
	// out, and returns when it has exited.
	Run(ctx context.Context, binary string, args []string, dir string, out *parser) error
}

// Exec runs the real binary.
type Exec struct{}

// maxStderr bounds the error output kept for the error message.
const maxStderr = 4 << 10

// Run implements Runner. The environment is not inherited: Nuclei gets a
// throwaway HOME (its config and caches die with the run) and nothing else,
// so no proxy, token or secret from the worker's environment reaches it.
func (Exec) Run(ctx context.Context, binary string, args []string, dir string, out *parser) error {
	// binary is the operator's ORUS_NUCLEI_BIN (absolute, checked at
	// startup); args are built by this package, never from scan data except
	// file paths in the run's own directory. No shell is involved.
	cmd := exec.CommandContext(ctx, binary, args...) //nolint:gosec // G204: see comment above
	cmd.Dir = dir
	cmd.Env = []string{"HOME=" + filepath.Join(dir, "home"), "PATH=/usr/bin:/bin"}
	cmd.Stdout = out
	stderr := &tail{max: maxStderr}
	cmd.Stderr = stderr
	cmd.WaitDelay = 10 * time.Second // after ctx ends: kill, then stop waiting for pipes
	err := cmd.Run()
	out.Flush()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return fmt.Errorf("exit status %d: %s", exit.ExitCode(), strings.TrimSpace(stderr.String()))
		}
		return err
	}
	return nil
}

// tail keeps the last max bytes written.
type tail struct {
	max int
	b   []byte
}

func (t *tail) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = t.b[len(t.b)-t.max:]
	}
	return len(p), nil
}

func (t *tail) String() string { return clean(string(t.b), t.max) }

var _ io.Writer = (*tail)(nil)

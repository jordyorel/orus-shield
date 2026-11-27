//go:build unix

package zap

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestInputsReadableUnderStrictUmask: the worker's systemd unit sets
// UMask=0077. ZAP's container runs as another uid: its plan and
// configuration must still be readable by it, or ZAP refuses to start
// ("File not readable: /zap/wrk/zap.conf", seen on a test server).
func TestInputsReadableUnderStrictUmask(t *testing.T) {
	old := syscall.Umask(0o077) // process-wide: this test is not parallel
	defer syscall.Umask(old)
	dir := t.TempDir()
	if err := writeInputs(dir, "example.com", []string{"https://example.com"}, proxyAddr{Host: "h", Port: "1"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{planFile, configFile} {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o644 {
			t.Errorf("%s: mode %v, want 0644", name, fi.Mode().Perm())
		}
	}
}

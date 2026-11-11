//go:build e2e

package main

// End-to-end driver against a real sshd on a throwaway test machine.
// It runs the same call() the MCP tool runs; only the password dialog is
// replaced, by one that answers every prompt from a file.
//
//	SSH_MCP_E2E_HOST=10.0.0.5 SSH_MCP_E2E_USER=mcptest \
//	SSH_MCP_E2E_PASSFILE=/path/to/pw SSH_MCP_E2E_CALLS=calls.json \
//	go test -tags e2e -count=1 -run TestE2E -v .
//
// calls.json is a JSON array of tool inputs, e.g.
// [{"host":"t","command":"ss","args":["-tlnp"]}]. The host alias is "t".
// Optional: SSH_MCP_E2E_PORT (22), SSH_MCP_E2E_SUDO_DIRS (comma-separated),
// SSH_MCP_E2E_SUDO_PASSFILE (answer for the sudo dialog, if different).
// The host key is taken from ssh-keyscan and trusted: test machines only.

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestE2E(t *testing.T) {
	host, user := os.Getenv("SSH_MCP_E2E_HOST"), os.Getenv("SSH_MCP_E2E_USER")
	if host == "" || user == "" {
		t.Skip("SSH_MCP_E2E_HOST and SSH_MCP_E2E_USER not set")
	}
	port := os.Getenv("SSH_MCP_E2E_PORT")
	if port == "" {
		port = "22"
	}
	pw, err := os.ReadFile(os.Getenv("SSH_MCP_E2E_PASSFILE"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(os.Getenv("SSH_MCP_E2E_CALLS"))
	if err != nil {
		t.Fatal(err)
	}
	var calls []input
	if err := json.Unmarshal(raw, &calls); err != nil {
		t.Fatal(err)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	keys, err := exec.Command("ssh-keyscan", "-p", port, host).Output()
	if err != nil || len(keys) == 0 {
		t.Fatalf("ssh-keyscan %s: %v", host, err)
	}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(home, ".ssh"), 0o700))
	must(os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), keys, 0o600))
	dirs := `"/var/log"`
	if d := os.Getenv("SSH_MCP_E2E_SUDO_DIRS"); d != "" {
		dirs = `"` + strings.Join(strings.Split(d, ","), `", "`) + `"`
	}
	must(os.MkdirAll(filepath.Join(home, ".config", "ssh-mcp"), 0o700))
	must(os.WriteFile(filepath.Join(home, ".config", "ssh-mcp", "config.json"), []byte(fmt.Sprintf(
		`{"hosts": {"t": {"host": %q, "user": %q, "port": %s}}, "sudo_read_dirs": [%s]}`, host, user, port, dirs)), 0o600))

	prompts := 0
	old := dialog
	dialog = func(prompt string, hidden bool) (string, error) {
		prompts++
		t.Logf("DIALOG #%d hidden=%v: %q", prompts, hidden, prompt)
		if f := os.Getenv("SSH_MCP_E2E_SUDO_PASSFILE"); f != "" && strings.Contains(prompt, "sudo password") {
			b, err := os.ReadFile(f)
			return strings.TrimSpace(string(b)), err
		}
		return strings.TrimSpace(string(pw)), nil
	}
	t.Cleanup(func() { dialog = old; conns = map[string]*hostConn{} })

	for i, in := range calls {
		start := time.Now()
		out, err := call(in)
		took := time.Since(start).Round(time.Millisecond)
		a, _ := json.Marshal(in)
		if err != nil {
			t.Logf("#%d %s (%s, dialogs so far %d)\n  ERROR: %v", i, a, took, prompts, err)
			continue
		}
		if len(out) > 1500 {
			out = out[:1500] + fmt.Sprintf("\n  ...[%d more bytes]", len(out)-1500)
		}
		t.Logf("#%d %s (%s, dialogs so far %d)\n%s", i, a, took, prompts, out)
	}
	if b, err := os.ReadFile(filepath.Join(home, ".local", "state", "ssh-mcp", "audit.log")); err == nil {
		t.Logf("audit.log has %d lines", strings.Count(string(b), "\n"))
		if strings.Contains(string(b), strings.TrimSpace(string(pw))) {
			t.Error("the password appears in the audit log")
		}
	}
}

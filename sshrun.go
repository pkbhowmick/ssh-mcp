package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skeema/knownhosts"
	"golang.org/x/crypto/ssh"
)

const (
	maxOut = 32 << 10 // what the agent gets back
	rawMax = 4 << 20  // what is captured for local grep/tail before the 32 KB cut
)

// Variables so tests can replace them.
var (
	localTimeout = 45 * time.Second
	dialog       = osaDialog
)

type hostConn struct {
	alias    string
	cfg      hostCfg
	client   *ssh.Client
	sudoPass string // in memory only; the login password is never kept
}

// ponytail: one global lock around every call, so calls are serialized
// (including while a password dialog is open); per-host locks if parallelism matters.
var (
	mu    sync.Mutex
	conns = map[string]*hostConn{}
)

// result is one remote command's outcome. Every string is redacted.
type result struct {
	out       string // stdout and stderr merged in order, cut to the capture limit
	stdout    string // stdout only, first 8 KB (for parsing realpath and stat)
	stderr    string // stderr only, first 8 KB
	code      int
	trunc     bool // out was cut
	gotStdout bool // stdout produced at least one byte
}

const sideMax = 8 << 10

// execute runs a validated command, capturing at most limit bytes of output.
// sudo comes from needSudo; when it is set, the paths in v.pathIdx are
// resolved on the host (and, for content reads, type-checked) first.
func execute(alias string, h hostCfg, v checked, sudo bool, dirs []string, limit int) (result, error) {
	mu.Lock()
	defer mu.Unlock()
	c := conns[alias]
	if c != nil && c.cfg != h {
		if c.client != nil {
			c.client.Close()
		}
		c = nil
	}
	if c == nil {
		c = &hostConn{alias: alias, cfg: h}
		conns[alias] = c
	}
	if !sudo {
		return c.run(remoteCmd(v.argv, false), "", limit)
	}

	if c.client == nil {
		// Log in (and check the host key) before asking for the sudo password.
		if err := c.dial(); err != nil {
			return result{}, err
		}
	}
	if c.sudoPass == "" {
		p, err := dialog(fmt.Sprintf("ssh-mcp: sudo password for %s@%s (%s)", h.User, h.Host, alias), true)
		if err != nil {
			return result{}, err
		}
		c.sudoPass = p
	}
	argv := slices.Clone(v.argv)
	if len(v.pathIdx) > 0 {
		paths := make([]string, len(v.pathIdx))
		for k, i := range v.pathIdx {
			paths[k] = argv[i]
		}
		resolved, err := c.sudoLines(append([]string{"realpath", "-e", "--"}, paths...), len(paths))
		if err != nil {
			return result{}, err
		}
		for k, r := range resolved {
			if !path.IsAbs(r) || path.Clean(r) != r || !within(r, dirs) || secret(r) {
				return result{}, fmt.Errorf("%s resolves to %q, which is outside sudo_read_dirs or on the secret denylist",
					paths[k], sanitize(r))
			}
			argv[v.pathIdx[k]] = r
		}
		if v.regular {
			// A FIFO or device read as root can block or consume data.
			types, err := c.sudoLines(append([]string{"stat", "-c", "%F", "--"}, resolved...), len(resolved))
			if err != nil {
				return result{}, err
			}
			for k, ty := range types {
				if ty != "regular file" && ty != "regular empty file" {
					return result{}, fmt.Errorf("%s is not a regular file (the host says %q); only regular files are read under sudo",
						resolved[k], sanitize(ty))
				}
			}
		}
	}
	return c.sudo(argv, limit)
}

// sudoLines runs a helper under sudo and returns its stdout as exactly n lines.
func (c *hostConn) sudoLines(argv []string, n int) ([]string, error) {
	r, err := c.sudo(argv, maxOut)
	if err != nil {
		return nil, err
	}
	if r.code != 0 {
		return nil, fmt.Errorf("%s failed on the host (exit %d); host output, untrusted: %s",
			argv[0], r.code, clip(sanitize(strings.TrimSpace(r.out)), 300))
	}
	lines := strings.Split(strings.TrimSpace(r.stdout), "\n")
	if len(r.stdout) >= sideMax || len(lines) != n {
		return nil, fmt.Errorf("%s printed %d lines for %d paths; refusing", argv[0], len(lines), n)
	}
	return lines, nil
}

var sudoFailures = []string{"incorrect password", "sorry, try again", "authentication failed",
	"a password is required", "no password was provided", "incorrect authentication"}

// sudo runs argv under sudo with the cached password on stdin. On an auth
// failure the password is dropped and nothing is retried (no lockout).
// When sudo rejects the password the command never runs, so an auth failure
// is only: non-zero exit, no stdout at all, and a failure phrase on stderr.
// Host output that merely mentions such a phrase is not one.
func (c *hostConn) sudo(argv []string, limit int) (result, error) {
	r, err := c.run(remoteCmd(argv, true), c.sudoPass+"\n", limit)
	if err != nil {
		return r, err
	}
	r.out = strings.TrimPrefix(r.out, "\n") // sudo-rs: blank line on stderr after reading the password
	if r.code != 0 && !r.gotStdout {
		low := strings.ToLower(r.stderr)
		for _, m := range sudoFailures {
			if strings.Contains(low, m) {
				c.sudoPass = ""
				return result{}, fmt.Errorf("sudo authentication failed on %s; the cached sudo password was cleared and nothing was retried. Host stderr, untrusted: %s",
					c.alias, clip(sanitize(strings.TrimSpace(r.stderr)), 300))
			}
		}
	}
	return r, nil
}

// run executes one remote command string with the given stdin.
func (c *hostConn) run(cmd, stdin string, limit int) (result, error) {
	if c.client == nil {
		if err := c.dial(); err != nil {
			return result{}, err
		}
	}
	// ponytail: NewSession has no deadline of its own, so a half-dead cached
	// connection can stall here (behind the global lock) until TCP gives up;
	// wrap it in the local timeout if that shows up in practice.
	s, err := c.client.NewSession()
	if err != nil {
		c.client.Close()
		c.client = nil
		if err := c.dial(); err != nil {
			return result{}, err
		}
		if s, err = c.client.NewSession(); err != nil {
			c.client.Close()
			c.client = nil
			return result{}, fmt.Errorf("ssh session to %s: %s", c.alias, sanitize(err.Error()))
		}
	}
	defer s.Close()
	// Each buffer keeps len(password) extra bytes, so a password straddling a
	// cap is still redacted before the cut.
	extra := len(c.sudoPass)
	all := &capWriter{limit: limit + extra}
	outW := &capWriter{limit: sideMax + extra}
	errW := &capWriter{limit: sideMax + extra}
	s.Stdout = io.MultiWriter(all, outW)
	s.Stderr = io.MultiWriter(all, errW)
	s.Stdin = strings.NewReader(stdin)
	done := make(chan error, 1)
	go func() { done <- s.Run(cmd) }()
	select {
	case err = <-done:
	case <-time.After(localTimeout):
		// Drop the whole connection: it may be dead, and the next call must not stall on it.
		c.client.Close()
		c.client = nil
		return result{}, fmt.Errorf("no result from %s within %s; the connection was closed", c.alias, localTimeout)
	}
	var r result
	r.out, r.trunc = all.result(c.sudoPass, limit)
	r.stdout, _ = outW.result(c.sudoPass, sideMax)
	r.stderr, _ = errW.result(c.sudoPass, sideMax)
	r.gotStdout = outW.seen > 0
	if err != nil {
		var ee *ssh.ExitError
		if !errors.As(err, &ee) {
			return result{}, fmt.Errorf("ssh to %s: %s", c.alias, sanitize(err.Error()))
		}
		r.code = ee.ExitStatus()
	}
	return r, nil
}

func (c *hostConn) dial() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	kh := filepath.Join(home, ".ssh", "known_hosts")
	db, err := knownhosts.NewDB(kh)
	if err != nil {
		return fmt.Errorf("reading %s: %w", kh, err)
	}
	addr := net.JoinHostPort(c.cfg.Host, strconv.Itoa(c.cfg.Port))
	who := c.cfg.User + "@" + addr

	// After one cancelled dialog, fail every later prompt of this login, so
	// x/crypto falling through to the next auth method does not ask again.
	cancelled := false
	ask := func(prompt string, hidden bool) (string, error) {
		if cancelled {
			return "", errors.New("login cancelled")
		}
		a, err := dialog(prompt, hidden)
		if err != nil {
			cancelled = true
		}
		return a, err
	}
	check := db.HostKeyCallback()
	cfg := &ssh.ClientConfig{
		User: c.cfg.User,
		Auth: []ssh.AuthMethod{
			ssh.PasswordCallback(func() (string, error) {
				return ask("ssh-mcp: SSH login password for "+who, true)
			}),
			ssh.KeyboardInteractive(func(name, instruction string, qs []string, echos []bool) ([]string, error) {
				answers := make([]string, len(qs))
				for i, q := range qs {
					text := strings.TrimSpace(strings.Join([]string{name, instruction, q}, "\n"))
					a, err := ask("ssh-mcp: login to "+who+"\n\n"+text, i >= len(echos) || !echos[i])
					if err != nil {
						return nil, err
					}
					answers[i] = a
				}
				return answers, nil
			}),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			err := check(hostname, remote, key)
			switch {
			case knownhosts.IsHostKeyChanged(err):
				return fmt.Errorf("the host key of %s does not match %s; refusing to connect. Check the key and fix known_hosts by hand", addr, kh)
			case knownhosts.IsHostUnknown(err):
				return fmt.Errorf("%s is not in %s; run `ssh -p %d %s` once by hand to verify and record its key", addr, kh, c.cfg.Port, c.cfg.User+"@"+c.cfg.Host)
			}
			return err
		},
		HostKeyAlgorithms: db.HostKeyAlgorithms(addr),
		Timeout:           20 * time.Second,
	}
	cl, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		if cancelled {
			return fmt.Errorf("login to %s cancelled or timed out", who)
		}
		// x/crypto errors can carry server-sent text (disconnect reasons).
		return fmt.Errorf("ssh to %s: %s", who, sanitize(err.Error()))
	}
	c.client = cl
	return nil
}

// The prompt is passed as an argv item, never interpolated into the script:
// keyboard-interactive prompts are server-controlled text.
const dialogScript = `on run argv
	set r to display dialog (item 1 of argv) default answer "" with title "ssh-mcp"%s giving up after 120
	if gave up of r then error "no answer within 2 minutes"
	return text returned of r
end run`

// osaDialog asks the user in a macOS dialog. prompt must start with fixed
// text, so osascript never parses it as an option.
func osaDialog(prompt string, hidden bool) (string, error) {
	h := ""
	if hidden {
		h = " with hidden answer"
	}
	out, err := exec.Command("/usr/bin/osascript", "-e", fmt.Sprintf(dialogScript, h), prompt).Output()
	if err != nil {
		return "", errors.New("the password dialog was cancelled or timed out")
	}
	return strings.TrimSuffix(string(out), "\n"), nil
}

// capWriter keeps the first limit bytes written to it and discards the rest.
type capWriter struct {
	mu    sync.Mutex
	limit int
	buf   []byte
	trunc bool
	seen  int // bytes offered, kept or not
}

func (w *capWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seen += len(p)
	if room := w.limit - len(w.buf); len(p) > room {
		w.buf = append(w.buf, p[:room]...)
		w.trunc = true
	} else {
		w.buf = append(w.buf, p...)
	}
	return len(p), nil
}

// result redacts secret (if 4+ bytes), then cuts to max.
func (w *capWriter) result(secret string, max int) (string, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	s, trunc := string(w.buf), w.trunc
	if len(secret) >= 4 {
		s = strings.ReplaceAll(s, secret, "[redacted]")
	}
	if len(s) > max {
		s, trunc = s[:max], true
	}
	return s, trunc
}

// sanitize makes host output safe to show: terminal controls and invisible or
// bidi format characters become '?', and the tool's own header marker cannot
// be forged.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f,
			r >= 0x200b && r <= 0x200f, r >= 0x202a && r <= 0x202e,
			r >= 0x2060 && r <= 0x2069, r == 0xfeff:
			return '?'
		}
		return r
	}, s)
	return strings.ReplaceAll(s, "[ssh-mcp]", "[ssh-mcp*]")
}

// clip cuts s to at most n bytes without splitting a UTF-8 sequence.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "..."
}

package main

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// row is one allowed command. Anything a row does not list is refused.
type row struct {
	sudo       bool            // run under sudo on the host
	sudoFlag   string          // run under sudo when this flag is given (ss -p: other users' processes)
	sudoHint   string          // rerun under sudo when unprivileged output contains this text
	word       bool            // flags are whole words (ip, bridge, virsh); otherwise getopt clusters
	flags      map[string]bool // allowed flag -> takes a value
	pre        []string        // forced args, placed right after the command name
	verbs      []string        // if set, the first caller arg must be one of these
	flagsFirst bool            // no flag may follow the first positional (ip, bridge)
	files      bool            // positionals are file paths; options are emitted before them
	regular    bool            // reads file content: under sudo, every path must be a regular file
	follow     string          // flag that follows symlinks inside directories (refused under sudo)
	pattern    bool            // grep: the first positional is the pattern, emitted as -e <pattern>
	pathFlag   string          // the value of this flag is a path checked like a file path
	check      func(p parsed) error
	rule       string // what check enforces, for the README
}

// parsed is what a row's check sees. flags maps each flag as written (no
// aliasing between short and long forms, so checks name rows' only spelling)
// to one entry per occurrence: the value, or "" for a flag without one.
type parsed struct {
	pos   []string
	flags map[string][]string
}

// checked is a validated command, ready to be quoted and run.
type checked struct {
	argv      []string // command name, forced args, then the normalized caller args
	sudo      bool     // the row itself needs sudo
	pathIdx   []int    // argv indexes holding file paths
	recursive bool     // -r or -R on a file row
	deref     bool     // the row's follow flag was given
	regular   bool     // see row.regular
	sudoHint  string   // see row.sudoHint
}

var (
	virshVerbs = []string{"list", "dominfo", "domstate", "dumpxml", "domiflist", "domblklist",
		"domifaddr", "domstats", "net-list", "net-info", "net-dumpxml", "pool-list", "pool-info",
		"vol-list", "nodeinfo", "capabilities", "version"}
	systemctlVerbs = []string{"status", "show", "cat", "is-active", "is-enabled", "is-failed",
		"list-units", "list-unit-files", "list-timers", "list-sockets", "list-dependencies"}
	ipObjects     = []string{"addr", "address", "link", "route", "rule", "neigh", "netns"}
	ipActions     = []string{"show", "list", "get"}
	bridgeObjects = []string{"link", "fdb", "vlan", "mdb"}
	nftObjects    = []string{"ruleset", "tables", "table", "chains", "chain", "sets", "set",
		"maps", "map", "counters", "flowtables"}
	iptTables = []string{"filter", "nat", "mangle", "raw", "security"}
	chActions = []string{"info", "counters", "ping"}

	positionalRe = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)
	valueRe      = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./ -]*$`)
	pingCountRe  = regexp.MustCompile(`^[1-5]$`)
	psBSDRe      = regexp.MustCompile(`^[auxwfjl]+$`)
)

var iptablesRow = row{
	sudo:  true,
	flags: flagSet("-L -S -n -v -x -t= --line-numbers"),
	check: func(p parsed) error {
		for _, t := range p.flags["-t"] {
			if !slices.Contains(iptTables, t) {
				return fmt.Errorf("table %q is not one of %s", t, strings.Join(iptTables, " "))
			}
		}
		return maxPos(1)(p)
	},
	rule: "at most one argument (a chain name); -t one of " + strings.Join(iptTables, "/"),
}

var table = map[string]row{
	// libvirt: -r makes libvirtd itself refuse every write.
	"virsh": {
		word: true,
		pre:  []string{"-r", "-c", "qemu:///system"},
		flags: flagSet("--all --inactive --persistent --transient --autostart --no-autostart " +
			"--name --uuid --title --table --state-running --state-paused --state-shutoff " +
			"--state-other --with-snapshot --without-snapshot --managed-save --details --reason " +
			"--full --daemon --state --cpu-total --balloon --vcpu --interface --block --perf " +
			"--iothread --memory --list-active --list-inactive --list-running --list-paused " +
			"--list-shutoff --list-other"),
		verbs: virshVerbs,
		rule:  "first argument one of " + strings.Join(virshVerbs, " "),
	},
	"ch-remote": {
		sudo:     true,
		flags:    flagSet("--api-socket="),
		pathFlag: "--api-socket",
		check: func(p parsed) error {
			if len(p.flags["--api-socket"]) != 1 {
				return errors.New("ch-remote needs --api-socket <path> exactly once")
			}
			if len(p.pos) != 1 || !slices.Contains(chActions, p.pos[0]) {
				return fmt.Errorf("ch-remote needs exactly one of: %s", strings.Join(chActions, " "))
			}
			return nil
		},
		rule: "--api-socket required (path, resolved and checked like a sudo file read); exactly one of " +
			strings.Join(chActions, "/"),
	},
	"journalctl": {
		flags: flagSet("-u= -n= -b= -k -p= -o= -r -x --since= --until="),
		pre:   []string{"--no-pager"},
		// Without journal access, journalctl prints this and shows only the login user's own entries.
		sudoHint: "Hint: You are currently not seeing messages from other users",
		check:    maxPos(0),
		rule:     "no arguments other than flags; -b needs a value (-b 0 is the current boot)",
	},
	"systemctl": {
		flags: flagSet("-a --all -l --full -n= --lines= -t= --type= --state= -p= --property= " +
			"--value --no-legend --plain --failed --reverse --before --after -q"),
		pre:   []string{"--no-pager"},
		verbs: systemctlVerbs,
		rule:  "first argument one of " + strings.Join(systemctlVerbs, " "),
	},
	"ip": {
		word:       true,
		flags:      flagSet("-br -d -s -j -p -4 -6 -o"),
		flagsFirst: true,
		check: func(p parsed) error {
			if len(p.pos) == 0 || !slices.Contains(ipObjects, p.pos[0]) {
				return fmt.Errorf("ip needs an object, one of: %s", strings.Join(ipObjects, " "))
			}
			if len(p.pos) > 1 && !slices.Contains(ipActions, p.pos[1]) {
				return fmt.Errorf("ip %s: the action must be one of %s (exact), or absent with nothing after it",
					p.pos[0], strings.Join(ipActions, " "))
			}
			return nil
		},
		rule: "object " + strings.Join(ipObjects, "/") + "; then nothing, or " +
			strings.Join(ipActions, "/") + " and its selectors; flags only before the object",
	},
	"bridge": {
		word:       true,
		flags:      flagSet("-s -d -j -p"),
		flagsFirst: true,
		check: func(p parsed) error {
			if len(p.pos) == 0 || !slices.Contains(bridgeObjects, p.pos[0]) {
				return fmt.Errorf("bridge needs an object, one of: %s", strings.Join(bridgeObjects, " "))
			}
			if len(p.pos) > 1 && p.pos[1] != "show" {
				return errors.New("bridge: the action must be show, or absent with nothing after it")
			}
			return nil
		},
		rule: "object " + strings.Join(bridgeObjects, "/") + "; then nothing, or show and its selectors; " +
			"flags only before the object",
	},
	"ss": {
		flags:    flagSet("-t -u -l -n -p -a -4 -6 -H -o -i -m"),
		sudoFlag: "-p",
		rule:     "filter expression words",
	},
	"ping": {
		flags: flagSet("-c= -n -q -W= -4 -6"),
		check: func(p parsed) error {
			if len(p.flags["-c"]) == 0 {
				return errors.New("ping needs -c <count>")
			}
			for _, c := range p.flags["-c"] {
				if !pingCountRe.MatchString(c) {
					return fmt.Errorf("ping -c %q: count must be 1 to 5", c)
				}
			}
			if len(p.pos) != 1 {
				return errors.New("ping needs exactly one host")
			}
			return nil
		},
		rule: "-c required, 1 to 5 (every occurrence); exactly one host",
	},
	"nft": {
		sudo:  true,
		flags: flagSet("-a -j -n -s -t -y"),
		check: func(p parsed) error {
			if len(p.pos) < 2 || p.pos[0] != "list" || !slices.Contains(nftObjects, p.pos[1]) {
				return fmt.Errorf("nft needs: list <%s> [family] [names]", strings.Join(nftObjects, "|"))
			}
			if len(p.pos) > 5 {
				return errors.New("nft: too many arguments")
			}
			return nil
		},
		rule: "list, then one of " + strings.Join(nftObjects, "/") + ", then up to 3 words (family, table, name)",
	},
	"iptables":  iptablesRow,
	"ip6tables": iptablesRow,

	"df":      {flags: flagSet("-a -h -H -i -k -l -P -T -t= -x="), rule: "paths or devices"},
	"du":      {flags: flagSet("-a -c -h -k -m -s -x -d="), rule: "paths"},
	"free":    {flags: flagSet("-b -g -h -k -l -m -t -w"), check: maxPos(0), rule: "none"},
	"lsblk":   {flags: flagSet("-a -b -d -f -J -l -m -n -p -S -t -o="), rule: "devices"},
	"findmnt": {flags: flagSet("-A -D -J -k -l -m -n -r -s -o= -t="), rule: "source or target"},
	"ps": {
		flags: flagSet("-e -A -f -F -l -H -w -L -T -o= -p= -C= -u= -U= --sort="),
		check: func(p parsed) error {
			for _, s := range p.pos {
				if !psBSDRe.MatchString(s) {
					return fmt.Errorf("ps: %q is not a BSD option word made of a u x w f j l", s)
				}
			}
			return nil
		},
		rule: "BSD option words of the letters a u x w f j l (e.g. aux)",
	},
	"uptime":   {flags: flagSet("-p -s"), check: maxPos(0), rule: "none"},
	"uname":    {flags: flagSet("-a -s -n -r -v -m -p -i -o"), check: maxPos(0), rule: "none"},
	"hostname": {flags: flagSet("-f -s -d -i -I -A"), check: maxPos(0), rule: "none (an argument would set the name)"},
	"id":       {flags: flagSet("-u -g -G -n -r"), check: maxPos(1), rule: "at most one user"},
	"lscpu":    {flags: flagSet("-J -x"), check: maxPos(0), rule: "none"},
	"lsmod":    {flags: flagSet(""), check: maxPos(0), rule: "none"},
	"sysctl": {
		flags: flagSet("-a -n"),
		check: func(p parsed) error {
			for _, s := range p.pos {
				if strings.Contains(s, "=") {
					return fmt.Errorf("sysctl %q: '=' would set a value", s)
				}
			}
			return nil
		},
		rule: "keys without =",
	},

	"cat":      {files: true, regular: true, flags: flagSet("-A -b -E -n -s -T -v"), rule: "one or more paths"},
	"ls":       {files: true, follow: "-L", flags: flagSet("-1 -a -A -d -F -h -i -l -L -n -r -R -S -t"), rule: "one or more paths"},
	"stat":     {files: true, follow: "-L", flags: flagSet("-f -L -t -c="), rule: "one or more paths"},
	"head":     {files: true, regular: true, flags: flagSet("-q -v -c= -n="), rule: "one or more paths"},
	"tail":     {files: true, regular: true, flags: flagSet("-q -v -c= -n="), rule: "one or more paths"},
	"wc":       {files: true, regular: true, flags: flagSet("-c -l -L -m -w"), rule: "one or more paths"},
	"readlink": {files: true, flags: flagSet("-e -f -m -n"), rule: "one or more paths"},
	"grep": {
		files:   true,
		regular: true,
		pattern: true,
		flags:   flagSet("-c -E -F -h -H -i -l -L -n -o -r -s -v -w -x -A= -B= -C= -m="),
		rule:    "a pattern (any text without a line break; sent as -e PATTERN), then one or more paths",
	},
}

// flagSet parses "-a -n= --since=": a trailing = means the flag takes a value.
func flagSet(spec string) map[string]bool {
	m := map[string]bool{}
	for _, f := range strings.Fields(spec) {
		name, takes := strings.CutSuffix(f, "=")
		m[name] = takes
	}
	return m
}

func maxPos(n int) func(parsed) error {
	return func(p parsed) error {
		if len(p.pos) > n {
			return fmt.Errorf("at most %d non-flag arguments allowed, got %d", n, len(p.pos))
		}
		return nil
	}
}

func commandNames() []string {
	names := make([]string, 0, len(table))
	for n := range table {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// validate checks command+args against the table and returns the argv to run.
func validate(command string, args []string) (checked, error) {
	r, ok := table[command]
	if !ok {
		return checked{}, fmt.Errorf("command %q is not allowed; allowed: %s", command, strings.Join(commandNames(), " "))
	}
	for _, a := range args {
		if strings.ContainsAny(a, "\x00\n\r") {
			return checked{}, fmt.Errorf("argument %q contains NUL or a line break", a)
		}
	}
	if len(r.verbs) > 0 && (len(args) == 0 || !slices.Contains(r.verbs, args[0])) {
		return checked{}, fmt.Errorf("%s: the first argument must be one of: %s", command, strings.Join(r.verbs, " "))
	}

	type tok struct {
		s    string
		path bool // its argv index goes into pathIdx
		pos  bool // positional; emitted after the options on file rows
	}
	var toks []tok
	p := parsed{flags: map[string][]string{}}
	havePattern := false
	addFlag := func(name, val string, takes bool) error {
		if !takes {
			toks = append(toks, tok{s: name})
			p.flags[name] = append(p.flags[name], "")
			return nil
		}
		if err := checkValue(name, val); err != nil {
			return err
		}
		toks = append(toks, tok{s: name}, tok{s: val, path: name == r.pathFlag && r.pathFlag != ""})
		p.flags[name] = append(p.flags[name], val)
		return nil
	}

	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return checked{}, errors.New("a bare -- is not allowed")
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			if r.pattern && !havePattern {
				// grep's pattern: any text, exempt from the charset and ';' rules.
				havePattern = true
				toks = append(toks, tok{s: "-e"}, tok{s: a})
				continue
			}
			if err := checkPositional(a); err != nil {
				return checked{}, err
			}
			p.pos = append(p.pos, a)
			toks = append(toks, tok{s: a, pos: true, path: r.files})
			continue
		}
		if r.flagsFirst && len(p.pos) > 0 {
			return checked{}, fmt.Errorf("%s: flag %q must come before the object", command, a)
		}
		if r.word || strings.HasPrefix(a, "--") {
			name, val, hasVal := a, "", false
			if strings.HasPrefix(a, "--") {
				name, val, hasVal = strings.Cut(a, "=")
			}
			takes, ok := r.flags[name]
			if !ok {
				return checked{}, fmt.Errorf("%s: flag %q is not allowed", command, name)
			}
			if !takes && hasVal {
				return checked{}, fmt.Errorf("%s: flag %s takes no value", command, name)
			}
			if takes && !hasVal {
				if i+1 == len(args) {
					return checked{}, fmt.Errorf("%s: flag %s needs a value", command, name)
				}
				i++
				val = args[i]
			}
			if err := addFlag(name, val, takes); err != nil {
				return checked{}, err
			}
			continue
		}
		// getopt cluster: -abc, -n20, -n 20
		for j := 1; j < len(a); j++ {
			name := "-" + a[j:j+1]
			takes, ok := r.flags[name]
			if !ok {
				return checked{}, fmt.Errorf("%s: flag %s (in %q) is not allowed", command, name, a)
			}
			val := ""
			if takes {
				val = a[j+1:]
				if val == "" {
					if i+1 == len(args) {
						return checked{}, fmt.Errorf("%s: flag %s needs a value", command, name)
					}
					i++
					val = args[i]
				}
			}
			if err := addFlag(name, val, takes); err != nil {
				return checked{}, err
			}
			if takes {
				break
			}
		}
	}

	if r.pattern && !havePattern {
		return checked{}, fmt.Errorf("%s needs a pattern and at least one path", command)
	}
	if r.files && len(p.pos) == 0 {
		return checked{}, fmt.Errorf("%s needs at least one absolute path", command)
	}
	if r.check != nil {
		if err := r.check(p); err != nil {
			return checked{}, err
		}
	}

	v := checked{argv: append([]string{command}, r.pre...), sudoHint: r.sudoHint,
		sudo: r.sudo || (r.sudoFlag != "" && len(p.flags[r.sudoFlag]) > 0)}
	v.recursive = r.files && (len(p.flags["-r"]) > 0 || len(p.flags["-R"]) > 0)
	v.deref = r.follow != "" && len(p.flags[r.follow]) > 0
	v.regular = r.regular
	emit := func(t tok) {
		if t.path {
			v.pathIdx = append(v.pathIdx, len(v.argv))
		}
		v.argv = append(v.argv, t.s)
	}
	for _, t := range toks {
		if !(r.files && t.pos) {
			emit(t)
		}
	}
	for _, t := range toks {
		if r.files && t.pos {
			emit(t)
		}
	}
	return v, nil
}

func checkPositional(a string) error {
	if strings.Contains(a, ";") {
		return fmt.Errorf("argument %q contains ';'", a)
	}
	if strings.HasPrefix(a, "-") || !positionalRe.MatchString(a) {
		return fmt.Errorf("argument %q has characters outside [A-Za-z0-9_@%%+=:,./-] or starts with -", a)
	}
	return nil
}

// checkValue: a flag value may start with '-' only before a digit (-1h, -5),
// so a value the real tool might read as a flag is never passed.
func checkValue(flag, v string) error {
	if strings.Contains(v, ";") {
		return fmt.Errorf("value %q for %s contains ';'", v, flag)
	}
	if !valueRe.MatchString(v) {
		return fmt.Errorf("value %q for %s has characters outside [A-Za-z0-9_@%%+=:,./ -]", v, flag)
	}
	if strings.HasPrefix(v, "-") && (len(v) < 2 || v[1] < '0' || v[1] > '9') {
		return fmt.Errorf("value %q for %s looks like a flag", v, flag)
	}
	return nil
}

func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// remoteCmd is the exact string the remote login shell runs.
func remoteCmd(argv []string, sudo bool) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = quote(a)
	}
	if sudo {
		// LC_ALL=C.UTF-8 keeps sudo's own messages (and stat -c %F) in English.
		return "env LC_ALL=C.UTF-8 sudo -S -k -p '' -- timeout 30 " + strings.Join(q, " ")
	}
	return "env PATH=/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin timeout 30 " + strings.Join(q, " ")
}

func within(p string, dirs []string) bool {
	for _, d := range dirs {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// secret reports paths that are never read, even inside sudo_read_dirs.
func secret(p string) bool {
	if slices.Contains(strings.Split(p, "/"), ".ssh") || within(p, []string{"/etc/libvirt/secrets"}) {
		return true
	}
	base := strings.ToLower(path.Base(p))
	if strings.HasPrefix(base, "shadow") || strings.HasPrefix(base, "gshadow") ||
		strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") ||
		(strings.HasPrefix(base, "id_") && !strings.HasSuffix(base, ".pub")) {
		return true
	}
	ok, _ := path.Match("ssh_host_*_key", base)
	return ok
}

// needSudo applies the path rules that need no host: every path absolute,
// clean and not secret; either all paths are inside dirs (sudo) or none are.
// A sudo row's paths (the ch-remote socket) must all be inside dirs.
func needSudo(v checked, dirs []string) (bool, error) {
	in := 0
	for _, i := range v.pathIdx {
		p := v.argv[i]
		if !path.IsAbs(p) || path.Clean(p) != p {
			return false, fmt.Errorf("path %q must be absolute and clean (no .., //, or trailing /)", p)
		}
		if secret(p) {
			return false, fmt.Errorf("path %q is on the secret denylist", p)
		}
		if within(p, dirs) {
			in++
		}
	}
	if in == 0 && !v.sudo {
		return false, nil
	}
	if in != len(v.pathIdx) {
		return false, fmt.Errorf("paths must be all inside or all outside sudo_read_dirs (%s); a sudo command's paths must be inside",
			strings.Join(dirs, " "))
	}
	if v.recursive || v.deref {
		return false, errors.New("recursive reads (-r/-R) and following symlinks (-L) are refused under sudo")
	}
	return true, nil
}

package cli

// cmd_exec: `webv2 exec <campaign> --command CMD [--profile P] [--dry-run]
// [--workdir W] [--finding F] [--timeout N] [--env K=V ...]` — run a
// sandboxed command through this framework and write the EXEC record (the
// CLI form of Sandbox(c, profile).run(...)). The exec ledger is the only
// thing E4+ evidence may trace to; `webv2 execs` lists it, `webv2 mint`
// mints evidence from a record.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// pyNegativeNumberRe is argparse's _negative_number_matcher: a token that
// looks like a negative number is still a usable value.
var pyNegativeNumberRe = regexp.MustCompile(`^-\d+$|^-\d*\.\d+$`)

// looksLikeOption is argparse's "would this token be parsed as an option?"
// test: anything starting with '-' except a bare "-" and a negative number.
// argparse refuses to consume such a token as an option's value, so
// `--command --help` is "expected one argument", not a help request.
func looksLikeOption(s string) bool {
	return strings.HasPrefix(s, "-") && s != "-" &&
		!pyNegativeNumberRe.MatchString(s)
}

// flagValue is the space-separated value of an option: the next token when
// argparse would accept it as a value, else ok=false.
func flagValue(args []string, i int) (string, bool) {
	if i+1 >= len(args) || looksLikeOption(args[i+1]) {
		return "", false
	}
	return args[i+1], true
}

// execHelp is argparse's `webv2 exec --help` output, byte-exact.
const execHelp = `usage: webv2 exec [-h] [--profile PROFILE] [--dry-run] --command COMMAND
                  [--workdir WORKDIR] [--finding FINDING] [--timeout TIMEOUT]
                  [--env K=V]
                  campaign

positional arguments:
  campaign

options:
  -h, --help         show this help message and exit
  --profile PROFILE  execution profile: host-readonly (host shell — can NEVER
                     back E4+ evidence) or a container profile (docker-
                     networkless, docker-gvisor, vm-snapshot, fork-runner —
                     required for E4+ evidence)
  --dry-run          print the exact container argv, env keys, network and
                     workdir mode, then exit — no execution, no EXEC record,
                     works even when the runtime is absent
  --command COMMAND
  --workdir WORKDIR  working directory (bind-mounted)
  --finding FINDING  finding this exec is for
  --timeout TIMEOUT
  --env K=V          environment variable for the container (repeatable);
                     recorded by key in the EXEC ledger
`

// envKeyRe is Python's re.match(r"[A-Za-z_][A-Za-z0-9_]*", k) — a PREFIX
// match, so "A B" passes exactly as it does upstream.
var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)

func runExec(root string, args []string, r *Runner) int {
	ensureSeams()
	var pos []string
	command, profile, workdir, finding := "", "host-readonly", "", ""
	timeout, haveTimeout := 300, false
	dryRun := false
	var env []sandbox.EnvVar
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, hasVal := splitFlag(a)
		switch {
		case a == "--dry-run":
			dryRun = true
		case name == "--command" || name == "--profile" || name == "--workdir" ||
			name == "--finding" || name == "--timeout" || name == "--env":
			if !hasVal {
				next, ok := flagValue(args, i)
				if !ok {
					return r.fail(root, argErrf("exec",
						"argument %s: expected one argument", name))
				}
				val, hasVal = next, true
				i++
			}
			switch name {
			case "--command":
				command = val
			case "--profile":
				profile = val
			case "--workdir":
				workdir = val
			case "--finding":
				finding = val
			case "--timeout":
				n, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
				if err != nil {
					return r.fail(root, argErrf("exec",
						"argument --timeout: invalid int value: %s",
						validation.PyReprStr(val)))
				}
				timeout, haveTimeout = int(n), true
			case "--env":
				env = append(env, sandbox.EnvVar{Key: val})
			}
		case a == "-h" || a == "--help":
			fmt.Fprint(r.Out, execHelp)
			return 0
		case strings.HasPrefix(a, "-"):
			return r.fail(root, usageErrf("unrecognized arguments: %s", a))
		default:
			pos = append(pos, a)
		}
	}
	_ = haveTimeout
	if len(pos) > 1 {
		return r.fail(root, usageErrf("unrecognized arguments: %s", pos[1]))
	}
	missing := []string{}
	if len(pos) < 1 {
		missing = append(missing, "campaign")
	}
	if !haveFlag(args, "--command") {
		missing = append(missing, "--command")
	}
	if len(missing) > 0 {
		return r.fail(root, requiredErrf("exec", missing...))
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	parsedEnv, err := parseEnvSpecs(env)
	if err != nil {
		fmt.Fprintf(r.Err, "exec failed: %s\n", err)
		return 2
	}
	if dryRun {
		return execPreview(r, profile, command, workdir, parsedEnv)
	}
	return execRun(c, pos[0], profile, command, workdir, finding, timeout,
		parsedEnv, r)
}

// haveFlag reports whether an option appeared at all (argparse's required
// check is presence, not a non-empty value).
func haveFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag || strings.HasPrefix(a, flag+"=") {
			return true
		}
	}
	return false
}

// parseEnvSpecs is cmd_exec_run's --env loop: K=V, K matching
// [A-Za-z_][A-Za-z0-9_]*.
func parseEnvSpecs(specs []sandbox.EnvVar) ([]sandbox.EnvVar, error) {
	out := make([]sandbox.EnvVar, 0, len(specs))
	for _, spec := range specs {
		raw := spec.Key
		k, v, ok := strings.Cut(raw, "=")
		if !ok {
			return nil, fmt.Errorf("--env expects K=V (got %s)",
				validation.PyReprStr(raw))
		}
		if k == "" || !envKeyRe.MatchString(k) {
			return nil, fmt.Errorf("--env key %s is not a valid environment "+
				"name (K must match [A-Za-z_][A-Za-z0-9_]*)",
				validation.PyReprStr(k))
		}
		out = append(out, sandbox.EnvVar{Key: k, Value: v})
	}
	return out, nil
}

// execPreview is cmd_exec_run's --dry-run branch.
func execPreview(r *Runner, profile, command, workdir string,
	env []sandbox.EnvVar) int {
	if !isKnownProfile(profile) {
		fmt.Fprintf(r.Err, "exec failed: unknown profile %s\n",
			validation.PyReprStr(profile))
		return 2
	}
	var wd *string
	if workdir != "" {
		wd = &workdir
	}
	pv, err := sandbox.Preview(profile, command, wd, env)
	if err != nil {
		fmt.Fprintf(r.Err, "exec failed: %s\n", err)
		return 2
	}
	avail := "yes"
	if !(objAt(pv, "available").Kind == validation.Bool &&
		objAt(pv, "available").B) {
		avail = "NO — install the runtime to execute this profile"
	}
	fmt.Fprintf(r.Out, "exec preview [%s]  available: %s\n",
		objStr(pv, "profile"), avail)
	if objStr(pv, "profile") != "host-readonly" {
		fmt.Fprintf(r.Out, "  network: %s\n", objStr(pv, "network"))
		wdText := objStr(pv, "workdir")
		if wdText == "" {
			wdText = "(sandbox tmpfs)"
		}
		fmt.Fprintf(r.Out, "  workdir: %s (%s)\n", wdText,
			objStr(pv, "workdir_mode"))
		keys := objAt(pv, "env_keys")
		if len(keys.A) > 0 {
			fmt.Fprintf(r.Out, "  env keys: %s\n", joinScalars(keys))
		}
		if m := objAt(pv, "svm_mount"); m.Kind == validation.Str {
			fmt.Fprintf(r.Out, "  svm mount: %s -> /home/foundry/.svm\n", m.S)
		}
		parts := []string{}
		for _, a := range objAt(pv, "argv").A {
			parts = append(parts, shlexQuote(scalarStr(a)))
		}
		fmt.Fprintf(r.Out, "  $ %s\n", strings.Join(parts, " "))
	} else {
		cwd := objStr(pv, "workdir")
		if cwd == "" {
			cwd = "(current directory)"
		}
		fmt.Fprintf(r.Out, "  command (host shell, cwd %s): %s\n", cwd,
			objStr(pv, "command"))
		keys := objAt(pv, "env_keys")
		if len(keys.A) > 0 {
			fmt.Fprintf(r.Out, "  extra env keys: %s\n", joinScalars(keys))
		}
	}
	fmt.Fprintf(r.Out, "  note: %s\n", objStr(pv, "note"))
	return 0
}

// execSandbox is the Sandbox surface execRun needs. The Python twin
// monkeypatches SB.Sandbox to assert what the CLI hands the sandbox, so the
// Go twin keeps the same seam (newExecSandbox).
type execSandbox interface {
	Run(command string, opts sandbox.RunOpts) (validation.Value, error)
}

// newExecSandbox is the sandbox factory seam (tests substitute a stub).
var newExecSandbox = func(c *state.Campaign,
	profile string) (execSandbox, error) {
	return sandbox.NewSandbox(c, profile)
}

// execRun is the preflight + Sandbox.run + result block.
func execRun(c *state.Campaign, campaignID, profile, command, workdir,
	finding string, timeout int, env []sandbox.EnvVar, r *Runner) int {
	var wd *string
	if workdir != "" {
		wd = &workdir
	}
	pre, err := sandbox.SandboxPreflight(c, wd, &profile)
	if err != nil {
		return r.withErr(c.Dir, func() error { return err })
	}
	if issues := objAt(pre, "issues"); len(issues.A) > 0 {
		for _, i := range issues.A {
			fmt.Fprintf(r.Err, "exec preflight FAIL: %s\n", scalarStr(i))
		}
		fmt.Fprintln(r.Err, "environment problem, not hypothesis problem — "+
			"fix the above and re-run (re-check: webv2 doctor "+campaignID+" / "+
			"webv2 env doctor "+campaignID+")")
		return 2
	}
	for _, w := range objAt(pre, "warnings").A {
		fmt.Fprintf(r.Err, "exec preflight warn: %s\n", scalarStr(w))
	}
	sb, err := newExecSandbox(c, profile)
	if err != nil {
		fmt.Fprintf(r.Err, "exec failed: %s\n", err)
		return 2
	}
	opts := sandbox.RunOpts{Timeout: timeout}
	if wd != nil {
		opts.Workdir = wd
	}
	if finding != "" {
		opts.FindingID = &finding
	}
	if len(env) > 0 {
		opts.Env = env
	}
	rec, err := sb.Run(command, opts)
	if err != nil {
		fmt.Fprintf(r.Err, "exec failed: %s\n", err)
		return 2
	}
	fmt.Fprintf(r.Out, "%s  [%s] exit=%s %s\n", objStr(rec, "exec_id"),
		objStr(rec, "profile"), scalarStr(objAt(rec, "exit_status")),
		pyHead(objStr(rec, "command"), 70))
	fmt.Fprintf(r.Out, "output: %s / %s (mint with `webv2 mint ... --exec %s`)\n",
		objStr(rec, "stdout_path"), objStr(rec, "stderr_path"),
		objStr(rec, "exec_id"))
	if objStr(rec, "profile") == "host-readonly" &&
		objAt(rec, "exit_status").Kind == validation.Int &&
		objAt(rec, "exit_status").I == 0 {
		fmt.Fprintln(r.Out, "  (host-readonly ran on the host — this exec can "+
			"NEVER back E4+ evidence; use a container profile for that)")
	}
	exit := objAt(rec, "exit_status")
	if exit.Kind == validation.Int && exit.I != 0 {
		res := sandbox.ClassifyFailure(rec)
		class := objStr(res, "class")
		if class == "environment" || class == "setup" || class == "unknown" {
			fmt.Fprintf(r.Out, "  classified: %s — %s (re-check: webv2 "+
				"classify %s %s)\n", strings.ToUpper(class),
				objStr(res, "note"), campaignID, objStr(rec, "exec_id"))
		}
	}
	return 0
}

// isKnownProfile reports whether the name is one of the sandbox profiles.
func isKnownProfile(profile string) bool {
	for _, p := range sandbox.Profiles {
		if p == profile {
			return true
		}
	}
	return false
}

// joinScalars is Python's ", ".join(list-of-strings).
func joinScalars(items validation.Value) string {
	parts := make([]string, 0, len(items.A))
	for _, it := range items.A {
		parts = append(parts, scalarStr(it))
	}
	return strings.Join(parts, ", ")
}

// shlexQuote is Python's shlex.quote.
func shlexQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
			r >= '0' && r <= '9' || strings.ContainsRune("_@%+=:,./-", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func init() {
	register(command{ord: 40, name: "exec",
		line: "exec <campaign> --command CMD [--profile P] [--dry-run]",
		run:  runExec})
}

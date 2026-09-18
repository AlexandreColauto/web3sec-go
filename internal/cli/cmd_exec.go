package cli

// cmd_exec: `webv2 exec <campaign> --command CMD [--profile P] [--dry-run]
// [--workdir W] [--finding F] [--timeout N] [--env K=V ...]` — run a
// sandboxed command through this framework and write the EXEC record (the
// CLI form of Sandbox(c, profile).run(...)). The exec ledger is the only
// thing E4+ evidence may trace to; `webv2 execs` lists it, `webv2 mint`
// mints evidence from a record.

import (
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"websec/internal/findings"

	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// maxTimeoutSeconds is the largest --timeout the sandbox can honor without
// lying: execute() builds the kill timer as time.Duration(secs) *
// time.Second, and a second count past MaxInt64/1e9 wraps that duration
// (a negative or near-zero timer would kill the command instantly while
// the record claimed a timeout of absurd length). The CLI refuses the
// value instead of letting the sandbox fabricate such a record.
const maxTimeoutSeconds = math.MaxInt64 / int64(time.Second)

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

// execArgs carries the parsed argv of the exec verb.
type execArgs struct {
	command     string
	profile     string
	workdir     string
	finding     string
	timeout     int
	haveTimeout bool
	dryRun      bool
	env         []sandbox.EnvVar
	pos         []string
	helpSeen    bool
}

// execTimeoutSecs parses and range-checks one --timeout value.
func execTimeoutSecs(val string) (int, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
	if err != nil {
		return 0, argErrf("exec",
			"argument --timeout: invalid int value: %s",
			validation.PyReprStr(val))
	}
	// A zero or negative timeout cannot be honored: the
	// sandbox clamps it to its 300s default, so the operator
	// would silently get the opposite of what they asked
	// (and the record would carry no trace of the request).
	// Refuse at the boundary, name the state and the fix.
	if n <= 0 {
		return 0, argErrf("exec",
			"argument --timeout: must be a positive number of "+
				"seconds (got %d) — the sandbox cannot honor a "+
				"zero or negative timeout; re-run with --timeout N "+
				"where N >= 1", n)
	}
	// Absurdly large: past this bound the sandbox's kill
	// timer wraps and the run would be killed instantly while
	// the record claimed a timeout of the requested length —
	// a lying record. Refuse the value instead.
	if n > maxTimeoutSeconds || n > int64(^uint(0)>>1) {
		return 0, argErrf("exec",
			"argument --timeout: %d seconds exceeds the largest "+
				"timeout the sandbox can honor (%d) — re-run with "+
				"a smaller --timeout", n, int64(min(
				maxTimeoutSeconds, int64(^uint(0)>>1))))
	}
	return int(n), nil
}

// execParseArgs parses the flag loop, printing the help block and flagging
// it when -h/--help appears mid-argv.
func execParseArgs(args []string, r *Runner) (*execArgs, error) {
	pa := &execArgs{profile: "host-readonly", timeout: 300}
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, hasVal := splitFlag(a)
		switch {
		case a == "--dry-run":
			pa.dryRun = true
		case name == "--command" || name == "--profile" || name == "--workdir" ||
			name == "--finding" || name == "--timeout" || name == "--env":
			if !hasVal {
				next, ok := flagValue(args, i)
				if !ok {
					return nil, argErrf("exec",
						"argument %s: expected one argument", name)
				}
				val, hasVal = next, true
				i++
			}
			switch name {
			case "--command":
				pa.command = val
			case "--profile":
				pa.profile = val
			case "--workdir":
				pa.workdir = val
			case "--finding":
				pa.finding = val
			case "--timeout":
				n, err := execTimeoutSecs(val)
				if err != nil {
					return nil, err
				}
				pa.timeout, pa.haveTimeout = n, true
			case "--env":
				pa.env = append(pa.env, sandbox.EnvVar{Key: val})
			}
		case a == "-h" || a == "--help":
			fmt.Fprint(r.Out, execHelp)
			pa.helpSeen = true
			return pa, nil
		case strings.HasPrefix(a, "-"):
			return nil, usageErrf("unrecognized arguments: %s", a)
		default:
			pa.pos = append(pa.pos, a)
		}
	}
	return pa, nil
}

// execCheckArgs applies argparse's post-loop checks: the positional overflow,
// then the required campaign and --command.
func execCheckArgs(args []string, pa *execArgs) error {
	_ = pa.haveTimeout
	if len(pa.pos) > 1 {
		return usageErrf("unrecognized arguments: %s", pa.pos[1])
	}
	missing := []string{}
	if len(pa.pos) < 1 {
		missing = append(missing, "campaign")
	}
	if !haveFlag(args, "--command") {
		missing = append(missing, "--command")
	}
	if len(missing) > 0 {
		return requiredErrf("exec", missing...)
	}
	return nil
}

func runExec(root string, args []string, r *Runner) int {
	ensureSeams()
	pa, err := execParseArgs(args, r)
	if err != nil {
		return r.fail(root, err)
	}
	if pa.helpSeen {
		return 0
	}
	if err := execCheckArgs(args, pa); err != nil {
		return r.fail(root, err)
	}
	c, err := state.Open(root, pa.pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	parsedEnv, err := parseEnvSpecs(pa.env)
	if err != nil {
		fmt.Fprintf(r.Err, "exec failed: %s\n", err)
		return 2
	}
	if pa.dryRun {
		return execPreview(r, pa.profile, pa.command, pa.workdir, parsedEnv)
	}
	return execRun(c, pa.pos[0], pa.profile, pa.command, pa.workdir, pa.finding,
		pa.timeout, parsedEnv, r)
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
	if !(validation.ObjAt(pv, "available").Kind == validation.Bool &&
		validation.ObjAt(pv, "available").B) {
		avail = "NO — install the runtime to execute this profile"
	}
	fmt.Fprintf(r.Out, "exec preview [%s]  available: %s\n",
		validation.ObjStr(pv, "profile"), avail)
	if validation.ObjStr(pv, "profile") != "host-readonly" {
		fmt.Fprintf(r.Out, "  network: %s\n", validation.ObjStr(pv, "network"))
		wdText := validation.ObjStr(pv, "workdir")
		if wdText == "" {
			wdText = "(sandbox tmpfs)"
		}
		fmt.Fprintf(r.Out, "  workdir: %s (%s)\n", wdText,
			validation.ObjStr(pv, "workdir_mode"))
		keys := validation.ObjAt(pv, "env_keys")
		if len(keys.A) > 0 {
			fmt.Fprintf(r.Out, "  env keys: %s\n", joinScalars(keys))
		}
		if m := validation.ObjAt(pv, "svm_mount"); m.Kind == validation.Str {
			fmt.Fprintf(r.Out, "  svm mount: %s -> /home/foundry/.svm\n", m.S)
		}
		parts := []string{}
		for _, a := range validation.ObjAt(pv, "argv").A {
			parts = append(parts, shlexQuote(scalarStr(a)))
		}
		fmt.Fprintf(r.Out, "  $ %s\n", strings.Join(parts, " "))
	} else {
		cwd := validation.ObjStr(pv, "workdir")
		if cwd == "" {
			cwd = "(current directory)"
		}
		fmt.Fprintf(r.Out, "  command (host shell, cwd %s): %s\n", cwd,
			validation.ObjStr(pv, "command"))
		keys := validation.ObjAt(pv, "env_keys")
		if len(keys.A) > 0 {
			fmt.Fprintf(r.Out, "  extra env keys: %s\n", joinScalars(keys))
		}
	}
	fmt.Fprintf(r.Out, "  note: %s\n", validation.ObjStr(pv, "note"))
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

// execSandboxPreflight runs the sandbox preflight, printing the FAIL issues
// and the warnings; a non-zero code stops the run. The preflight may rewrite
// the profile through its pointer, so the profile is passed by value and
// the (possibly rewritten) value is returned.
func execSandboxPreflight(c *state.Campaign, campaignID string, wd *string,
	profile string, r *Runner) (string, int) {
	pre, err := sandbox.SandboxPreflight(c, wd, &profile)
	if err != nil {
		return "", r.withErr(c.Dir, func() error { return err })
	}
	if issues := validation.ObjAt(pre, "issues"); len(issues.A) > 0 {
		for _, i := range issues.A {
			fmt.Fprintf(r.Err, "exec preflight FAIL: %s\n", scalarStr(i))
		}
		fmt.Fprintln(r.Err, "environment problem, not hypothesis problem — "+
			"fix the above and re-run (re-check: webv2 doctor "+campaignID+" / "+
			"webv2 env doctor "+campaignID+")")
		return "", 2
	}
	for _, w := range validation.ObjAt(pre, "warnings").A {
		fmt.Fprintf(r.Err, "exec preflight warn: %s\n", scalarStr(w))
	}
	return profile, 0
}

// execReport prints the exec record's summary lines and, on a non-zero
// exit, the failure notes (the sandbox note, the capture note and the
// failure classification).
func execReport(rec validation.Value, campaignID string, r *Runner) {
	fmt.Fprintf(r.Out, "%s  [%s] exit=%s %s\n", validation.ObjStr(rec, "exec_id"),
		validation.ObjStr(rec, "profile"), scalarStr(validation.ObjAt(rec, "exit_status")),
		pyHead(validation.ObjStr(rec, "command"), 70))
	fmt.Fprintf(r.Out, "output: %s / %s (mint with `webv2 mint ... --exec %s`)\n",
		validation.ObjStr(rec, "stdout_path"), validation.ObjStr(rec, "stderr_path"),
		validation.ObjStr(rec, "exec_id"))
	if validation.ObjStr(rec, "profile") == "host-readonly" &&
		validation.ObjAt(rec, "exit_status").Kind == validation.Int &&
		validation.ObjAt(rec, "exit_status").I == 0 {
		fmt.Fprintln(r.Out, "  (host-readonly ran on the host — this exec can "+
			"NEVER back E4+ evidence; use a container profile for that)")
	}
	exit := validation.ObjAt(rec, "exit_status")
	if exit.Kind == validation.Int && exit.I != 0 {
		// r36 F1/F6 at the CLI boundary: the operator hears the sandbox's
		// own account of a failed run, not just "exit=-1". The note is
		// forwarded VERBATIM from the record's stderr log (or not at all
		// — absence stays inconclusive); the capture note repeats only
		// what the record's output_capture object actually states.
		if note, ok := sandboxNote(rec); ok {
			fmt.Fprintf(r.Out, "  %s\n", note)
		}
		if msg := captureNote(rec); msg != "" {
			fmt.Fprintf(r.Out, "  %s\n", msg)
		}
		res := sandbox.ClassifyFailure(rec)
		class := validation.ObjStr(res, "class")
		if class == "environment" || class == "setup" || class == "unknown" {
			fmt.Fprintf(r.Out, "  classified: %s — %s (re-check: webv2 "+
				"classify %s %s)\n", strings.ToUpper(class),
				validation.ObjStr(res, "note"), campaignID, validation.ObjStr(rec, "exec_id"))
		}
	}
}

// execRun is the preflight + Sandbox.run + result block.
func execRun(c *state.Campaign, campaignID, profile, command, workdir,
	finding string, timeout int, env []sandbox.EnvVar, r *Runner) int {
	// r4 (critic) / r5 issue 4: the binding check FIRST — it is a cheap
	// findings-dir read, and a dead binding must not be discovered only
	// after the operator fixes an unrelated environment problem. A ledger
	// row is forever; binding one to a finding that does not exist — or is
	// dead (mint would then refuse it, leaving inert bookkeeping that looks
	// like coverage) — is the lie the terminal-row law refuses everywhere.
	if code, msg := execFindingBindingRefused(c, finding); code != 0 {
		fmt.Fprint(r.Err, msg)
		return code
	}
	var wd *string
	if workdir != "" {
		wd = &workdir
	}
	profile, code := execSandboxPreflight(c, campaignID, wd, profile, r)
	if code != 0 {
		return code
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
	execReport(rec, campaignID, r)
	return 0
}

// sandboxNote returns the sandbox's own note from the exec record's stderr
// log: execute() appends exactly one "sandbox: " line (the timeout / kill
// / never-ran account) as the LAST line of stderr, so only a bounded tail
// of the file is read and only a final line carrying that prefix is
// forwarded — a command cannot forge the note by printing "sandbox: "
// mid-stream, and a log with no such line (a twin-era or
// externally-reported record) forwards nothing rather than an invention.
func sandboxNote(rec validation.Value) (string, bool) {
	p := validation.ObjStr(rec, "stderr_path")
	if p == "" {
		return "", false
	}
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() == 0 {
		return "", false
	}
	f, err := os.Open(p)
	if err != nil {
		return "", false
	}
	defer f.Close()
	const tailBytes = 8 << 10
	if fi.Size() > tailBytes {
		if _, err := f.Seek(fi.Size()-tailBytes, io.SeekStart); err != nil {
			return "", false
		}
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return "", false
	}
	last := strings.TrimRight(string(raw), "\n")
	if i := strings.LastIndexByte(last, '\n'); i >= 0 {
		last = last[i+1:]
	}
	if !strings.HasPrefix(last, "sandbox: ") {
		return "", false
	}
	return last, true
}

// captureNote renders what the record's output_capture object says about a
// capped or withheld capture (r36 F6): the operator learns at run time
// that the log on disk is incomplete, with the counts the record actually
// carries — never a fabricated total, never a promise mint has not made.
func captureNote(rec validation.Value) string {
	oc := validation.ObjAt(rec, "output_capture")
	if oc.Kind != validation.Obj {
		return ""
	}
	parts := []string{}
	for _, stream := range []struct{ name, flag, total string }{
		{"stdout", "stdout_truncated", "stdout_total_bytes"},
		{"stderr", "stderr_truncated", "stderr_total_bytes"},
	} {
		if f := validation.ObjAt(oc, stream.flag); f.Kind != validation.Bool || !f.B {
			continue
		}
		total := validation.ObjAt(oc, stream.total)
		capV := validation.ObjAt(oc, "cap_bytes")
		if total.Kind == validation.Int && capV.Kind == validation.Int {
			parts = append(parts, fmt.Sprintf(
				"%s truncated: the run wrote %d bytes and the capture keeps "+
					"at most %d — the log on disk is marked truncated",
				stream.name, total.I, capV.I))
			continue
		}
		parts = append(parts, stream.name+
			" truncated: the true byte count is not in the record")
	}
	if w := validation.ObjAt(oc, "output_withheld"); w.Kind == validation.Bool && w.B {
		parts = append(parts, "output totals unknown: the capture was "+
			"withheld (output_withheld in the record)")
	}
	return strings.Join(parts, "; ")
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

// execFindingBindingRefused is the hoisted guard: (0,"") when the binding
// is legal or absent; (2, message) when --finding names a ghost or a dead
// row.
func execFindingBindingRefused(c *state.Campaign, finding string) (int, string) {
	if finding == "" {
		return 0, ""
	}
	f, ferr := findings.LoadFinding(c, finding)
	if ferr != nil {
		return 2, "exec refused: --finding " + finding + " is not in " +
			"this campaign (" + ferr.Error() + ")\n"
	}
	if findings.IsTerminal(validation.ObjStr(f, "status")) {
		return 2, "exec refused: --finding " + finding + " is " +
			validation.ObjStr(f, "status") + " — an exec bound to a dead row can " +
			"never mint against it; run against the live successor\n"
	}
	return 0, ""
}

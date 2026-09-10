// Package cli is the webv2 P0 command surface (Task 14): init, status,
// snap, log, audit, verify, plus help. Port of webv2/cli.py's P0
// commands, message-for-message.
//
// PYTHON WINS — divergences from the plan's §Task-14 interface block
// (all forced by cli.py, the source of truth):
//   - init is `init --program PROG` (no positional program, no
//     [campaignId], no --budget). Prints `initialized {id} at {dir}` plus
//     the `next: webv2 snap ...` line — NOT `campaign {id} initialized
//     in {root}`.
//   - status is `status <campaign> [--verbose]` and ALWAYS prints the
//     orchestrator status dict as indent-2 JSON (insertion order, NOT
//     canonical-sorted). There is no `status --json` flag.
//   - snap is `snap <campaign> <target> [--deployment F] [--chain F]
//     [--exclude ...]` (positionals, NOT --target/--name/--no-pin/--json/
//     --foundry-on-disk). The toolchain line is
//     `  toolchain: foundry — solc 0.8.24 (detected from the pinned tree)`.
//   - log is `log <campaign> [--tail N]` (no --json).
//   - audit is `audit <campaign> [--json]`; the summary line goes to
//     STDOUT (not stderr), then `  [{section}] {problem}` lines.
//   - verify is `verify <campaign>` (no --exit-code flag; exit is 1 when
//     the log is not ok, 0 when ok) and prints the verify_log dict as
//     indent-2 JSON — there is NO `log OK: ...` line in cli.py.
//   - exit codes are 0 ok / 1 handled error / 2 usage error (argparse
//     uses 2; the plan's "0/1" omits it).
//   - `help` is additive (cli.py has no help subcommand; argparse --help
//     lists every command). No-arg usage exits 2, like argparse.
//   - --root is accepted leading (`webv2 --root W status C-x`, the only
//     form cli.py accepts) or trailing; cli.py rejects the trailing form
//     with exit 2, this CLI accepts it. On cli.py-valid invocations the
//     behavior is identical.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"websec/internal/validation"
)

// Runner carries the captured writers so tests capture output without
// exec'ing the binary.
type Runner struct {
	Out io.Writer
	Err io.Writer
}

// Run dispatches argv (without the program name) and returns the process
// exit code.
func Run(argv []string, stdout, stderr io.Writer) int {
	r := &Runner{Out: stdout, Err: stderr}
	return r.run(argv)
}

// command is one registered subcommand. Each cmd_*.go file registers its
// command from an init() so new commands never touch this file (the P1 CLI
// waves add files only).
type command struct {
	ord  int    // registration order in cli.py main() — usage display order
	name string // subcommand name
	line string // usage-block text after the padded name
	run  func(root string, args []string, r *Runner) int
}

// registered collects the subcommands in init() order; usageText sorts by
// ord (Python's add_parser order) before rendering.
var registered []command

// register adds a subcommand. Called from init() in each cmd_*.go.
func register(c command) { registered = append(registered, c) }

func commandByName(name string) (command, bool) {
	for _, c := range registered {
		if c.name == name {
			return c, true
		}
	}
	return command{}, false
}

// usageText renders the usage block: the implemented commands in
// cli.py registration order, then help. (Go lists only the implemented
// commands; cli.py's argparse usage lists every registered command —
// D11, a documented deviation.)
func usageText() string {
	cmds := make([]command, len(registered))
	copy(cmds, registered)
	sort.Slice(cmds, func(i, j int) bool { return cmds[i].ord < cmds[j].ord })
	width := 0
	for _, c := range cmds {
		if len(c.name) > width {
			width = len(c.name)
		}
	}
	var b strings.Builder
	b.WriteString("usage: webv2 [--root DIR] <command> [args]\n\n")
	b.WriteString("Commands (in fixed order):\n")
	cont := strings.Repeat(" ", 2+width+2)
	for _, c := range cmds {
		// Continuation lines of a wrapped usage entry re-pad to the
		// current column (the stored padding may target a wider set).
		for i, ln := range strings.Split(c.line, "\n") {
			if i > 0 {
				ln = strings.TrimLeft(ln, " ")
			}
			if i == 0 {
				fmt.Fprintf(&b, "  %-*s  %s", width, c.name, ln)
			} else {
				fmt.Fprintf(&b, "\n%s%s", cont, ln)
			}
		}
		b.WriteString("\n")
	}
	b.WriteString("  help  this usage\n")
	return b.String()
}

func (r *Runner) run(argv []string) int {
	root, rest := splitRoot(argv)
	if len(rest) == 0 {
		fmt.Fprint(r.Err, usageText())
		return 2
	}
	cmd, args := rest[0], rest[1:]
	if cmd == "help" || cmd == "--help" || cmd == "-h" {
		fmt.Fprint(r.Out, usageText())
		return 0
	}
	if c, ok := commandByName(cmd); ok {
		return c.run(root, args, r)
	}
	fmt.Fprintf(r.Err, "error: unknown command %q\n%s", cmd, usageText())
	return 2
}

// --- help surface ----------------------------------------------------------
//
// argparse prints a command's usage block and exits 0 for `-h`/`--help`,
// *before* it validates a single argument. Most verbs reproduce that in their
// own parser; the 23 whose parsers predate the argSpec help path (recorded in
// docs/runbook-go-notes.md 3a) did not, so `webv2 <cmd> -h` either rejected the
// flag or exited 2 on a missing required argument. This helper is the shared
// entry guard for those verbs; `TestEveryCommandAnswersHelp` keeps the whole
// surface honest.

// verbUsageConstants are the verbs whose usage text is a package constant
// rather than an argparse block.
var verbUsageConstants = map[string]string{
	"ack":      ackUsage,
	"exploit":  exploitUsage,
	"immunize": t21ImmunizeUsage,
	"move":     moveUsage,
	"rank":     rankUsage,
}

// helpRequested writes cmd's usage block for -h/--help and reports whether the
// caller must stop with success (exit 0). It must be the first thing a verb
// entry does: argparse answers help before it looks at anything else.
func helpRequested(out io.Writer, cmd string, args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			fmt.Fprint(out, helpUsageText(cmd))
			return true
		}
	}
	return false
}

// helpUsageText is the block `webv2 <cmd> -h` prints: the captured argparse
// block when the verb has one, its usage constant otherwise, and for the few
// verbs with neither, a usage line derived from the command registry — so the
// text can never drift from the registered signature.
func helpUsageText(cmd string) string {
	if b, ok := argparseUsageBlocks[cmd]; ok {
		return b
	}
	if b, ok := verbUsageConstants[cmd]; ok {
		return b
	}
	c, ok := commandByName(cmd)
	if !ok {
		return "usage: webv2 " + cmd + " [-h]\n"
	}
	// The registry line is "<name> <args>   <description>", possibly wrapped;
	// the usage line takes the first line only, minus the name and description.
	rest := strings.Split(c.line, "\n")[0]
	rest = strings.TrimPrefix(rest, cmd+" ")
	if i := strings.Index(rest, "   "); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimRight(rest, " ")
	if rest == "" {
		return "usage: webv2 " + cmd + " [-h]\n"
	}
	return "usage: webv2 " + cmd + " [-h] " + rest + "\n"
}

// splitRoot pulls --root/--root=DIR out of argv (leading or trailing;
// the trailing form is an accepted superset of cli.py). Default ".".
func splitRoot(argv []string) (string, []string) {
	root := "."
	var rest []string
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--root" && i+1 < len(argv) {
			root = argv[i+1]
			i++
			continue
		}
		if strings.HasPrefix(a, "--root=") {
			root = strings.TrimPrefix(a, "--root=")
			continue
		}
		rest = append(rest, a)
	}
	return root, rest
}

// withErr maps a command error to stderr + exit code, mirroring cli.py
// main's handler: `error: {e}` + exit 1, plus the self-correcting
// workspace hint for "no such campaign" when root has no campaigns/.
// Usage errors exit 2 with the usage text (argparse); failSilent exits 1
// with no further output (verify/audit check failure, like sys.exit(1)).
func (r *Runner) withErr(root string, fn func() error) int {
	err := fn()
	if err == nil {
		return 0
	}
	var ue *usageError
	if errors.As(err, &ue) {
		fmt.Fprintf(r.Err, "error: %s\n%s", ue.msg, usageText())
		return 2
	}
	var fs failSilent
	if errors.As(err, &fs) {
		return 1
	}
	return mapRunError(root, err, r.Err)
}

// failSilent marks check/gate failure: exit 1, no further output.
type failSilent struct{}

func (failSilent) Error() string { return "check failed" }

// mapRunError prints `error: {e}` (exit 1), with the workspace hint when
// the campaign is missing because the directory is wrong. Exported for
// the duplicate-init mapping test.
func mapRunError(root string, err error, stderr io.Writer) int {
	msg := err.Error()
	fmt.Fprintf(stderr, "error: %s\n", msg)
	if strings.Contains(msg, "no such campaign") &&
		!isDir(filepath.Join(root, "campaigns")) {
		fmt.Fprintf(stderr, "hint: no campaigns/ under %s — you are not in "+
			"the workspace. Run from the workspace directory (where "+
			"campaigns/ lives), or pass --root WORKSPACE.\n", root)
	}
	return 1
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// usageError reports a CLI usage problem (argparse exit 2).
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// runFn adapters convert usage errors to exit 2 with a usage line.
func usageErrf(format string, args ...any) error {
	return &usageError{msg: fmt.Sprintf(format, args...)}
}

func parseTail(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, usageErrf("invalid --tail %q", s)
	}
	return n, nil
}

// --- value helpers (cli-local; state's objAt is private) ------------------

func objAt(v validation.Value, key string) validation.Value {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

func objStr(v validation.Value, key string) string {
	if f := objAt(v, key); f.Kind == validation.Str {
		return f.S
	}
	return ""
}

func objInt(v validation.Value, key string) int64 {
	if f := objAt(v, key); f.Kind == validation.Int {
		if f.Big != "" {
			n, _ := strconv.ParseInt(f.Big, 10, 64)
			return n
		}
		return f.I
	}
	return 0
}

// scalarStr renders a JSON scalar the way Python f"{v}" does for the int
// and string shapes the CLI prints (chain ids, block numbers).
func scalarStr(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return v.S
	case validation.Int:
		return validation.IntText(v)
	case validation.Bool:
		if v.B {
			return "True"
		}
		return "False"
	case validation.Null:
		return "None"
	case validation.Flt:
		return validation.PythonFloat(v.F)
	default:
		return validation.CanonCompact(v)
	}
}

// --- prettyASCII: json.dumps(v, indent=2) byte-exact ----------------------
// Insertion order, 2-space indent, ensure_ascii=True escaping (CPython
// indent mode uses item separator ',' + newline and key separator ': ').

func prettyASCII(v validation.Value) string {
	var b strings.Builder
	writePretty(&b, v, 0)
	return b.String()
}

func writePretty(b *strings.Builder, v validation.Value, depth int) {
	pad := strings.Repeat("  ", depth)
	inner := pad + "  "
	switch v.Kind {
	case validation.Null:
		b.WriteString("null")
	case validation.Bool:
		if v.B {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case validation.Int:
		b.WriteString(validation.IntText(v))
	case validation.Flt:
		b.WriteString(validation.PythonFloat(v.F))
	case validation.Str:
		b.WriteByte('"')
		writeASCIIEscape(b, v.S)
		b.WriteByte('"')
	case validation.Arr:
		if len(v.A) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, e := range v.A {
			if i > 0 {
				b.WriteString(",\n")
			}
			b.WriteString(inner)
			writePretty(b, e, depth+1)
		}
		b.WriteString("\n" + pad + "]")
	case validation.Obj:
		if len(v.O) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, kv := range v.O {
			if i > 0 {
				b.WriteString(",\n")
			}
			b.WriteString(inner)
			b.WriteByte('"')
			writeASCIIEscape(b, kv.K)
			b.WriteString("\": ")
			writePretty(b, kv.V, depth+1)
		}
		b.WriteString("\n" + pad + "}")
	}
}

const hexd = "0123456789abcdef"

func writeU4(b *strings.Builder, r rune) {
	b.WriteString("\\u")
	b.WriteByte(hexd[(r>>12)&0xf])
	b.WriteByte(hexd[(r>>8)&0xf])
	b.WriteByte(hexd[(r>>4)&0xf])
	b.WriteByte(hexd[r&0xf])
}

// writeASCIIEscape is CPython ensure_ascii=True string escaping (matches
// validation's canonical escaper; DEL 0x7f is escaped, unlike the raw
// indented dump).
func writeASCIIEscape(b *strings.Builder, s string) {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '"':
			b.WriteString("\\\"")
		case r == '\\':
			b.WriteString("\\\\")
		case r == '\b':
			b.WriteString("\\b")
		case r == '\f':
			b.WriteString("\\f")
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteString("\\t")
		case r < 0x20 || r == 0x7f:
			writeU4(b, r)
		case r <= 0x7e:
			b.WriteRune(r)
		default:
			if r > 0xffff {
				r2 := r - 0x10000
				writeU4(b, 0xd800+rune(r2>>10&0x3ff))
				writeU4(b, 0xdc00+rune(r2&0x3ff))
			} else {
				writeU4(b, r)
			}
		}
		i += size
	}
}

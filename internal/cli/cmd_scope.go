package cli

// cmd_scope: `webv2 scope <campaign> [--policy F]` — load the bounty policy
// into the campaign (program identity for the shared store + the gate's
// scope/exclusions). Without --policy it records the 'no policy' state
// (cli.py cmd_scope verbatim).
//
// This file also owns the T14 shared helpers: the command-level exit shapes
// (cli.py handlers print their own message and sys.exit(N)), the
// argparse-exact failure text, Python-style file errors, and the JSON
// dump convention the T14 verbs share. They are prefixed t14 so the
// concurrent P1b wave cannot collide with them.

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"websec/internal/orchestrator"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- shared T14 helpers ---------------------------------------------------

// t14Exit is a handler-level exit: cli.py prints its own message (stdout or
// stderr) and calls sys.exit(code). It bypasses the generic `error: {e}`
// mapper because the message IS the whole output.
type t14Exit struct {
	code  int
	text  string
	toErr bool
}

func (e *t14Exit) Error() string { return e.text }

// t14ExitErr is `print(..., file=sys.stderr); sys.exit(code)`.
func t14ExitErr(code int, format string, args ...any) error {
	return &t14Exit{code: code, text: fmt.Sprintf(format, args...), toErr: true}
}

// t14ExitOut is `print(...); sys.exit(code)` (the stdout half).
func t14ExitOut(code int, format string, args ...any) error {
	return &t14Exit{code: code, text: fmt.Sprintf(format, args...)}
}

// t14Argparse is an argparse-level failure: the exact usage block plus the
// `webv2 <prog>: error: ...` line argparse writes to stderr before exit 2.
// The text is pinned from the live Python CLI (COLUMNS=80).
type t14Argparse struct{ text string }

func (e *t14Argparse) Error() string { return e.text }

// t14ArgparseErr renders `usage\nwebv2 <prog>: error: <msg>\n`.
func t14ArgparseErr(usage, prog, format string, args ...any) error {
	return &t14Argparse{text: usage + "webv2 " + prog + ": error: " +
		fmt.Sprintf(format, args...) + "\n"}
}

// t14Unrecognized is argparse's top-level "unrecognized arguments" failure:
// the message is reported by the ROOT parser, so the usage shown is the
// top-level one (pinned verbatim from cli.py).
func t14Unrecognized(arg string) error {
	return &t14Argparse{text: t14TopUsage + "webv2: error: unrecognized arguments: " +
		arg + "\n"}
}

// t14Dispatch runs one command body and maps the port's error shapes onto
// cli.py's exit contract (handler exit / argparse exit 2 / generic error).
func t14Dispatch(root string, r *Runner, fn func() error) int {
	err := fn()
	if err == nil {
		return 0
	}
	var ex *t14Exit
	if errors.As(err, &ex) {
		w := r.Out
		if ex.toErr {
			w = r.Err
		}
		fmt.Fprint(w, ex.text)
		return ex.code
	}
	var ae *t14Argparse
	if errors.As(err, &ae) {
		fmt.Fprint(r.Err, ae.text)
		return 2
	}
	return r.withErr(root, func() error { return err })
}

// t14Open is cli.py's `_campaign(root, cid)`: Campaign.open, whose missing-
// campaign error text the generic mapper already renders byte-exactly.
func t14Open(root, cid string) (*state.Campaign, error) {
	return state.Open(root, cid)
}

// t14OSError is CPython's OSError str() for the two shapes a CLI file read
// actually produces: ENOENT and EISDIR.
func t14OSError(path string, err error) error {
	info, statErr := os.Stat(path)
	if statErr == nil && info.IsDir() {
		return fmt.Errorf("[Errno 21] Is a directory: %s",
			validation.PyReprStr(path))
	}
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("[Errno 2] No such file or directory: %s",
			validation.PyReprStr(path))
	}
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("[Errno 13] Permission denied: %s",
			validation.PyReprStr(path))
	}
	return err
}

// t14ReadText is Path(p).read_text(encoding="utf-8") with CPython's error
// text (a malformed payload's JSONDecodeError text is NOT reproduced — see
// the port note in cmd_ingest.go).
func t14ReadText(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", t14OSError(path, err)
	}
	return string(raw), nil
}

// t14LoadJSON is json.loads(Path(p).read_text()).
func t14LoadJSON(path string) (validation.Value, error) {
	text, err := t14ReadText(path)
	if err != nil {
		return validation.VNull(), err
	}
	return t14ParseJSON(text)
}

// t14ParseJSON is json.loads(text) for the object/array payloads the CLI
// takes. A malformed document reports CPython's JSONDecodeError text (the
// CLI's error lines are Python's), so the message stays byte-identical.
func t14ParseJSON(text string) (validation.Value, error) {
	v, err := validation.ParseOrdered([]byte(text))
	if err != nil {
		if msg := t14PyJSONError(text); msg != "" {
			return validation.VNull(), errors.New(msg)
		}
	}
	return v, err
}

// t14PyLen is len(x or []): the element count of a list field, 0 otherwise.
func t14PyLen(v validation.Value) int {
	if v.Kind == validation.Arr {
		return len(v.A)
	}
	return 0
}

// t14Exists is Path(p).exists().
func t14Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// t14SetOrAppend is the dict assignment `o[key] = v`: replace in place when
// the key exists (position kept), append otherwise.
func t14SetOrAppend(o []validation.KV, key string,
	v validation.Value) []validation.KV {
	for i := range o {
		if o[i].K == key {
			o[i].V = v
			return o
		}
	}
	return append(o, validation.KV{K: key, V: v})
}

// t14List is `v.get(key) or []` for list-valued fields.
func t14List(v validation.Value, key string) validation.Value {
	got := objAt(v, key)
	if got.Kind != validation.Arr {
		return validation.VArr()
	}
	return got
}

// t14Join is `", ".join(items)` over the string rendering of each item.
func t14Join(v validation.Value) string {
	if v.Kind != validation.Arr {
		return ""
	}
	parts := make([]string, 0, len(v.A))
	for _, it := range v.A {
		parts = append(parts, scalarStr(it))
	}
	return strings.Join(parts, ", ")
}

// t14Truthy is Python's bool(): null/false/0/""/[]/{} are falsy.
func t14Truthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		return v.I != 0
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return false
}

// t14Truncate is s[:n] over code points.
func t14Truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}

// t14PrintJSON is `print(json.dumps(v, indent=2, default=str))`.
func t14PrintJSON(w io.Writer, v validation.Value) {
	fmt.Fprintln(w, prettyASCII(v))
}

// ---- pinned argparse text -------------------------------------------------
//
// Captured from the live Python CLI with COLUMNS=80 (a non-tty argparse
// falls back to 80 columns). The usage blocks are the subparser's own; the
// top-level block is what argparse prints for "unrecognized arguments",
// which the ROOT parser reports.

const t14TopUsage = `usage: webv2 [-h] [--root ROOT]
             {init,status,doctor,complete,dedup,prioritize,repro-queue,chains,terminals,privileged,cost,yields,relations,resemble,index,sinks,prescreen,forkdiff,recency,baseline,brief,invariant-verify,artifact-register,artifact-list,invariant-contradict,publish,globalize,corpus-surface,shared,report,memory,ingest,model,plan,answered,probes,floors,execs,budget,exec,scope,move,mint,sequence,verdict,recall,impact,snap,run,log,verify,audit,ladder,waive,prove,gate,price,price-basis,env,classify,shield,precondition,immunize,resolve-candidate,hint,sft} ...
`

const t14ScopeUsage = `usage: webv2 scope [-h] [--policy POLICY] campaign
`

const t14ScopeHelp = `usage: webv2 scope [-h] [--policy POLICY] campaign

positional arguments:
  campaign

options:
  -h, --help       show this help message and exit
  --policy POLICY  path to a bounty-policy JSON
`

// ---- cmd_scope ------------------------------------------------------------

func runScope(root string, args []string, r *Runner) error {
	var pos []string
	policy := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			fmt.Fprint(r.Out, t14ScopeHelp)
			return nil
		case a == "--policy" && i+1 < len(args):
			policy = args[i+1]
			i++
		case strings.HasPrefix(a, "--policy="):
			policy = strings.TrimPrefix(a, "--policy=")
		case a == "--policy":
			return t14ArgparseErr(t14ScopeUsage, "scope",
				"argument --policy: expected one argument")
		case strings.HasPrefix(a, "-"):
			return t14Unrecognized(a)
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) < 1 {
		return t14ArgparseErr(t14ScopeUsage, "scope",
			"the following arguments are required: campaign")
	}
	if len(pos) > 1 {
		return t14Unrecognized(strings.Join(pos[1:], " "))
	}
	c, err := t14Open(root, pos[0])
	if err != nil {
		return err
	}
	if policy != "" {
		// cli.py opens the campaign FIRST (_campaign), so a missing campaign
		// outranks a missing policy file; surface CPython's FileNotFoundError
		// text for the policy read before the orchestrator's own read.
		if _, err := t14ReadText(policy); err != nil {
			return err
		}
	}
	res, err := orchestrator.New(c).Scope(policy)
	if err != nil {
		return err
	}
	if policy != "" {
		fmt.Fprintf(r.Out, "policy loaded from %s — %d scope entries, "+
			"%d exclusions\n", policy, t14PyLen(objAt(res, "scope")),
			t14PyLen(objAt(res, "exclusions")))
		return nil
	}
	fmt.Fprintln(r.Out, "no policy provided (load one before BOUNTY_GATE "+
		"with `webv2 scope C-xxx --policy p.json`)")
	return nil
}

func init() {
	register(command{ord: 41, name: "scope",
		line: `scope <campaign> [--policy F]       load the bounty policy ` +
			`(program identity + gate scope)`,
		run: func(root string, args []string, r *Runner) int {
			return t14Dispatch(root, r, func() error {
				return runScope(root, args, r)
			})
		}})
}

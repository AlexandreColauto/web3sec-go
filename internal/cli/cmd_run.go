package cli

// cmd_run: `webv2 run <campaign> [--until UNTIL] [--max-stages N]` — walk the
// pipeline; code runs the deterministic stages and halts, honestly, at the
// first stage that needs a model (cli.py cmd_run verbatim).

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"

	"websec/internal/adapter"
	"websec/internal/orchestrator"
	"websec/internal/pipeline"
	"websec/internal/validation"
)

const t30RunUsage = `usage: webv2 run [-h] [--until UNTIL] [--max-stages MAX_STAGES] campaign
`

const t30RunHelp = `usage: webv2 run [-h] [--until UNTIL] [--max-stages MAX_STAGES] campaign

positional arguments:
  campaign

options:
  -h, --help            show this help message and exit
  --until UNTIL
  --max-stages MAX_STAGES
`

func runRun(root string, args []string, r *Runner) error {
	// Every command handler installs the cross-module seams (main.go does the
	// same for the binary); without it the pipeline's structural-index stage
	// reports the absent-module refusal.
	ensureSeams()
	sp := &argSpec{
		prog:  "run",
		usage: t30RunUsage,
		vals: []*valOpt{
			{name: "--until"},
			{name: "--max-stages"},
		},
		pos: []*posOpt{{name: "campaign"}},
	}
	if err := sp.parse(args); err != nil {
		return err
	}
	if sp.helpSeen {
		fmt.Fprint(r.Out, t30RunHelp)
		return nil
	}
	var until *string
	if sp.vals[0].seen {
		v := sp.vals[0].val
		until = &v
	}
	var maxStages *int64
	haltDigits := ""
	if sp.vals[1].seen {
		n, digits, err := parsePyInt(sp.vals[1].val, "--max-stages")
		if err != nil {
			return err
		}
		maxStages = &n
		haltDigits = digits
	}
	c, err := t14Open(root, sp.pos[0].val)
	if err != nil {
		return err
	}
	// The real adapter is installed here: cmd_run is the only caller of the
	// model-bundle path in the Go port (Python imports adapter directly).
	pipeline.SetAdapter(adapter.PipelineAdapter{})
	p := pipeline.New(c, orchestrator.PipelineAdapter{O: orchestrator.New(c)}, nil)
	summary, err := p.Run(pipeline.RunOpts{Until: until, MaxStages: maxStages})
	if err != nil {
		return err
	}
	restoreMaxStagesHalt(summary, maxStages, haltDigits)
	return emitRunSummary(r, summary)
}

// restoreMaxStagesHalt rewrites the halt text a clamped budget produced.
// Python's max_stages is an unbounded int and its halt message echoes the
// exact value; a budget beyond int64 can only be consumed after 2**63 stages,
// so the clamped stand-in never changes the run, only the digits.
func restoreMaxStagesHalt(summary validation.Value, clamped *int64,
	digits string) {
	if digits == "" || clamped == nil || validation.ObjStr(summary, "halt") !=
		"max_stages="+strconv.FormatInt(*clamped, 10) {
		return
	}
	for i := range summary.O {
		if summary.O[i].K == "halt" {
			summary.O[i].V = validation.VStr("max_stages=" + digits)
			return
		}
	}
}

// emitRunSummary prints the run summary (needs_model stripped) and the
// HALTED block, then maps the outcome to the verb's exit code: 3 when a model
// stage blocks the run, 2 when the scheduler halted, 0 otherwise.
func emitRunSummary(r *Runner, summary validation.Value) error {
	fmt.Fprintln(r.Out, validation.DumpIndentedASCII(withoutKey(summary, "needs_model")))
	if nm := validation.ObjAt(summary, "needs_model"); nm.Kind == validation.Obj {
		fmt.Fprintf(r.Out, "\nHALTED at model stage: %s\n", validation.ObjStr(nm, "stage"))
		fmt.Fprintf(r.Out, "  prompt:  %s\n", scalarStr(validation.ObjAt(nm, "prompt_path")))
		fmt.Fprintf(r.Out, "  budget:  %s\n", scalarStr(validation.ObjAt(nm, "budget_class")))
		blocks := []string{}
		if b := validation.ObjAt(nm, "blocks"); b.Kind == validation.Arr {
			for _, x := range b.A {
				blocks = append(blocks, scalarStr(x))
			}
		}
		fmt.Fprintf(r.Out, "  context: %s\n", strings.Join(blocks, ", "))
		fmt.Fprintln(r.Out, "  feed results back through the ingest APIs, "+
			"then run again.")
		return &t14Exit{code: 3}
	}
	if validation.ObjStr(summary, "status") == "halted" {
		return t14ExitErr(2, "\nHALTED: %s\n", scalarStr(validation.ObjAt(summary, "halt")))
	}
	return nil
}

// parsePyInt is argparse's type=int over a Python int: unbounded, whitespace
// tolerant, and underscore separators between digits are legal literals. The
// second result is the normalized decimal text Python's f-string would print
// when the value does not fit int64 (empty otherwise); the value handed to the
// pipeline is clamped to the int64 extremes, which is observationally
// identical — a budget beyond 2**63 stages can never be consumed.
func parsePyInt(val, name string) (int64, string, error) {
	bad := func() error {
		return t14ArgparseErr(t30RunUsage, "run",
			"argument %s: invalid int value: %s", name,
			validation.PyReprStr(val))
	}
	s := strings.TrimSpace(val)
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	if !pyDigits(s) {
		return 0, "", bad()
	}
	n := new(big.Int)
	if _, ok := n.SetString(strings.ReplaceAll(s, "_", ""), 10); !ok {
		return 0, "", bad()
	}
	if neg {
		n.Neg(n)
	}
	if n.IsInt64() {
		return n.Int64(), "", nil
	}
	if n.Sign() > 0 {
		return math.MaxInt64, n.String(), nil
	}
	return math.MinInt64, n.String(), nil
}

// pyDigits is Python's decimal literal shape: digits, with single underscores
// only between digits ("1_000" legal, "_1", "1_", "1__0" not).
func pyDigits(s string) bool {
	if s == "" {
		return false
	}
	prevDigit := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= '0' && ch <= '9':
			prevDigit = true
		case ch == '_':
			if !prevDigit || i+1 >= len(s) || s[i+1] < '0' || s[i+1] > '9' {
				return false
			}
			prevDigit = false
		default:
			return false
		}
	}
	return prevDigit
}

// withoutKey is `{k: v for k, v in summary.items() if k != key}`.
func withoutKey(v validation.Value, key string) validation.Value {
	out := validation.VObj()
	for _, kv := range v.O {
		if kv.K != key {
			out.O = append(out.O, kv)
		}
	}
	return out
}

func init() {
	register(command{ord: 49, name: "run",
		line: `run <campaign> [--until UNTIL] [--max-stages N]   walk the pipeline; halt at the first model stage`,
		run: func(root string, args []string, r *Runner) int {
			return t14Dispatch(root, r, func() error {
				return runRun(root, args, r)
			})
		}})
}

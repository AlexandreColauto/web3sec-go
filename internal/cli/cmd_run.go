package cli

// cmd_run: `webv2 run <campaign> [--until UNTIL] [--max-stages N]` — walk the
// pipeline; code runs the deterministic stages and halts, honestly, at the
// first stage that needs a model (cli.py cmd_run verbatim).

import (
	"fmt"
	"math"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"

	"websec/internal/adapter"
	"websec/internal/feed"
	"websec/internal/orchestrator"
	"websec/internal/pipeline"
	"websec/internal/state"
	"websec/internal/validation"
)

const t30RunUsage = `usage: webv2 run [-h] [--until UNTIL] [--max-stages MAX_STAGES] [--feed FEED] campaign
`

const t30RunHelp = `usage: webv2 run [-h] [--until UNTIL] [--max-stages MAX_STAGES] [--feed FEED] campaign

positional arguments:
  campaign

options:
  -h, --help            show this help message and exit
  --until UNTIL
  --max-stages MAX_STAGES
  --feed FEED           ingest one model-stage drop file (campaigns/<C>/inbox/<stage>.json)
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
			{name: "--feed"},
		},
		pos: []*posOpt{{name: "campaign", optional: true}},
	}
	if err := sp.parse(args); err != nil {
		return err
	}
	if sp.helpSeen {
		fmt.Fprint(r.Out, t30RunHelp)
		return nil
	}
	// `--feed` is resolved BY NAME: a positional index into sp.vals is a bug
	// waiting for the next flag insertion. `--feed ""` must not fall through
	// to the normal run path either — a malformed invocation would silently
	// become a full pipeline run.
	for _, v := range sp.vals {
		if v.name == "--feed" && v.seen {
			if v.val == "" {
				return t14ExitErr(2, "--feed requires a path\n")
			}
			return runFeed(root, sp.pos[0].val, v.val, r)
		}
	}
	// The campaign positional is optional only because `--feed` names its
	// campaign through the drop file's path; without the flag it is required,
	// with argparse's own error text.
	if !sp.pos[0].seen {
		return t14ArgparseErr(t30RunUsage, "run",
			"the following arguments are required: campaign")
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

// runFeed is `run --feed FILE`: the non-interactive model-stage handoff (v1.6
// Part 1). The file's STEM names the pipeline stage; the file must live in the
// campaign's own inbox (a drop file from anywhere else is not a handoff); the
// drop carries the stage's request record — so the input-artifact declaration
// is validated, and a violation refused AND recorded — plus the output
// payload; a stage with no wired ingest path is refused by name.
//
// The drop file's PATH names its campaign (campaigns/<C>/inbox/<stage>.json),
// so the campaign positional is optional here; when it is given it must agree
// with the path, and a path outside the convention is refused.
//
// Exit codes: 0 ingested, 1 handled error (unreadable file, ingest or
// input-set refusal), 2 usage (unwired stage, drop outside the inbox). Exit 3
// belongs to the run path's model-stage halt and is never returned here.
func runFeed(root, cid, path string, r *Runner) error {
	stage := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	fs, ok := feed.FeedStageFor(stage)
	if !ok {
		return t14ExitErr(2, "no ingest path for stage %q (drop file %s): %s; "+
			"wired stages: %s\n", stage, path, unwiredReason(stage),
			strings.Join(feed.FeedStageIDs(), ", "))
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return t14ExitErr(1, "feed %s: %v\n", path, err)
	}
	c, err := feedCampaign(root, cid, abs)
	if err != nil {
		return err
	}
	doc, err := validation.ReadJson(abs)
	if err != nil {
		return t14ExitErr(1, "feed %s: %v\n", path, err)
	}
	fid, err := fs.Ingest(c, doc)
	if err != nil {
		return t14ExitErr(1, "feed %s: %v\n", path, err)
	}
	_, _ = fmt.Fprintf(r.Out, "ingested %s from %s (stage %s, contract %s)\n",
		fid, abs, fs.Stage, fs.Schema)
	return nil
}

// feedCampaign opens the campaign a drop file belongs to. The drop lives in
// <root>/campaigns/<C>/inbox/<stage>.json (docs/CRITICAL_HUNTING_PLAN.md §0.2),
// so its path IS its campaign; a path outside that convention is not a
// handoff, and an explicit campaign positional that disagrees with the path is
// an operator mistake, not a second source of truth.
func feedCampaign(root, cid, abs string) (*state.Campaign, error) {
	derived, ok := feedCampaignID(root, abs)
	if !ok {
		return nil, t14ExitErr(2, "drop file must live in the campaign inbox "+
			"(campaigns/<campaign>/inbox/<stage>.json under %s), got %s\n",
			root, abs)
	}
	if cid != "" && cid != derived {
		return nil, t14ExitErr(2,
			"drop file belongs to campaign %s, not %s\n", derived, cid)
	}
	return t14Open(root, derived)
}

// feedCampaignID reads the campaign id out of a drop file's path.
func feedCampaignID(root, abs string) (string, bool) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(rootAbs, abs)
	if err != nil {
		return "", false
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) != 4 || parts[0] != "campaigns" || parts[2] != "inbox" {
		return "", false
	}
	return parts[1], parts[1] != ""
}

// unwiredReason is the declared reason a stage has no ingest path (the drop
// file's stem named something the handoff does not carry).
func unwiredReason(stage string) string {
	if why := feed.FeedUnwired[stage]; why != "" {
		return why
	}
	return "unknown stage"
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

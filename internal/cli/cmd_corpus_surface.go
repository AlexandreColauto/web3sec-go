package cli

// cmd_corpus_surface: `webv2 corpus-surface <campaign>` — the deterministic
// corpus sweep (class exposure + PoC shape matches). Advisory: it never sets
// status, mints hypotheses, or blocks the pipeline (cli.py cmd_corpus_surface
// verbatim).
//
// Seam note: corpus.LoadSharedMemory (internal/sharedmem), corpus.ListEvalCases
// (internal/evalstore) and corpus.LoadPocRecords (the datasets.defihacklabs
// port) default to Python's absent-store behavior until those packages land;
// the wiring one-liners belong in ensureSeams() beside the other Set* calls.
// Cross-twin parity is otherwise byte-identical over the real DeFiHackLabs
// corpus (.scratch/t27/cross_twin.py).

import (
	"fmt"
	"path/filepath"
	"strconv"

	"websec/internal/backtest"
	"websec/internal/corpus"
	"websec/internal/evalstore"
	"websec/internal/validation"
)

const corpusSurfaceUsage = `usage: webv2 corpus-surface [-h] [--backtest] [--top TOP] [--baseline NAME]
                            campaign
`

// corpusSurfaceHelp is argparse's `webv2 corpus-surface --help` output.
// I2b added --baseline NAME, which lengthens the option column: argparse
// re-pads every option to the new help position and re-wraps the usage
// block, so the whole block is re-pinned (generated with CPython 3.14's
// argparse at COLUMNS=80 and pasted verbatim).
const corpusSurfaceHelp = `usage: webv2 corpus-surface [-h] [--backtest] [--top TOP] [--baseline NAME]
                            campaign

positional arguments:
  campaign

options:
  -h, --help       show this help message and exit
  --backtest       rank held-out eval cases severity-only vs with dev priors
                   (campaign is still required but ignored); the backtest
                   measures the RANKING SIGNALS THE STORE ACTUALLY CARRIES
  --top TOP        top-K precision window for --backtest (default: 10)
  --baseline NAME  run a detector baseline alongside the backtest; repeatable;
                   NAME ∈ {always, never, slither, aderyn}
`

func runCorpusSurface(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		backtestFlag := &boolOpt{name: "--backtest"}
		topFlag := &valOpt{name: "--top"}
		// --baseline is repeatable (argparse action="append"): every
		// occurrence accumulates in multi while val keeps the last one.
		baselineFlag := &valOpt{name: "--baseline", append: true}
		sp := &argSpec{
			prog:  "corpus-surface",
			usage: corpusSurfaceUsage,
			pos:   []*posOpt{{name: "campaign"}},
			flags: []*boolOpt{backtestFlag},
			vals:  []*valOpt{topFlag, baselineFlag},
		}
		if err := sp.parse(args); err != nil {
			return err
		}
		if sp.helpSeen {
			fmt.Fprint(r.Out, corpusSurfaceHelp)
			return nil
		}
		top := 10
		if topFlag.seen {
			n, err := strconv.Atoi(topFlag.val)
			if err != nil {
				return t14ArgparseErr(corpusSurfaceUsage,
					"corpus-surface",
					"argument --top: invalid int value: %s",
					quoteSingle(topFlag.val))
			}
			if n <= 0 {
				return t14ArgparseErr(corpusSurfaceUsage,
					"corpus-surface",
					"argument --top: must be >= 1 (got %d)", n)
			}
			top = n
		}
		// The choices check is parse-time in argparse, so it runs before
		// the post-parse dependency checks below: a bad NAME is reported
		// even when a prerequisite flag is missing too. The message reuses
		// the --from family's exact shape (PyReprStr + quotedList).
		for _, name := range baselineFlag.multi {
			if !backtest.IsBaseline(name) {
				return t14ArgparseErr(corpusSurfaceUsage, "corpus-surface",
					"argument --baseline: invalid choice: %s "+
						"(choose from %s)", validation.PyReprStr(name),
					quotedList(backtest.BaselineRoster))
			}
		}
		// --top is a --backtest window, not a sweep option: accepting it
		// beside the plain sweep would silently ignore it, so it is an
		// argparse usage error (exit 2) instead.
		if topFlag.seen && !backtestFlag.set {
			return t14ArgparseErr(corpusSurfaceUsage,
				"corpus-surface", "--top requires --backtest")
		}
		// The floors need the held-out set, which only --backtest has.
		if baselineFlag.seen && !backtestFlag.set {
			return t14ArgparseErr(corpusSurfaceUsage, "corpus-surface",
				"--baseline requires --backtest")
		}
		if backtestFlag.set {
			return runCorpusBacktest(r, root, top, baselineFlag.multi)
		}
		c, err := t14Open(root, sp.pos[0].val)
		if err != nil {
			return err
		}
		report, err := corpus.BuildReport(c, nil)
		if err != nil {
			return err
		}
		out := filepath.Join(c.ArtifactsDir, corpus.CorpusSurfaceFile)
		if err := validation.WriteJson(out, report, ""); err != nil {
			return err
		}
		if _, err := c.RegisterOrRefresh("corpus-surface", out, "", nil,
			"corpus sweep: class exposure + shape matches"); err != nil {
			return err
		}
		exposure := listAtCLI(report, "class_exposure")
		matches := listAtCLI(report, "shape_matches")
		fmt.Fprintf(r.Out, "corpus surface for %s: %d classes probed, "+
			"%d PoC files with signal, %d records without a resolvable PoC\n",
			c.CampaignID, len(exposure), len(matches),
			objInt(report, "poc_missing"))
		fmt.Fprint(r.Out, "class exposure (top 10):\n")
		for _, row := range firstRowsCLI(exposure, 10) {
			flag := "-"
			if boolAtCLI(row, "exposed") {
				flag = "EXPOSED"
			}
			fmt.Fprintf(r.Out, "  [%s] %-24s score=%.3f (w=%s, conf=%s)\n",
				flag, validation.ObjStr(row, "bug_class"), floatAtCLI(row, "score"),
				scalarStr(validation.ObjAt(row, "corpus_weight")),
				validation.ObjStr(row, "confidence"))
		}
		if len(matches) > 0 {
			fmt.Fprint(r.Out, "PoC shape matches (top 5):\n")
			for _, m := range firstRowsCLI(matches, 5) {
				fmt.Fprintf(r.Out, "  %s  exact=%d near=%d %s\n",
					validation.ObjStr(m, "file"), len(listAtCLI(m, "exact_hits")),
					len(listAtCLI(m, "near_misses")), validation.ObjStr(m, "bug_class"))
			}
		}
		return nil
	})
}

// runCorpusBacktest is `webv2 corpus-surface <campaign> --backtest`:
// the G3 prior scorecard over the repo-level eval store. The campaign
// positional stays required (the argparse shape is unchanged) but its
// value is ignored — the backtest never opens the campaign, it reads
// evalstore.LoadCases() and ranks pseudo-findings through
// backtest.Run, which owns the verdict rule.
//
// I2b: when --baseline names are present the scorecard string is composed
// with backtest.BaselineBlock, which scores the SAME held-out slice
// (backtest.HeldOut — Run's selection, I1b exclusions included) against
// the requested baselines. Run itself is untouched: the block is appended
// after its last line, it never changes the verdict or the exit code, and
// with no --baseline the bytes are exactly what they were before this
// flag existed.
//
// The tool runner is spawned with os/exec DIRECTLY (backtest.RealToolRunner)
// — never through internal/sandbox, whose RegisterExec mints
// sandbox_execution records on a campaign. A baseline is an eval-side
// measurement: it must not append artifacts or move a single byte of the
// campaign it reports beside. An empty resolved root means "this CLI's
// root", the checkout internal:// repos' gold paths are relative to.
func runCorpusBacktest(r *Runner, root string, top int, baselines []string) error {
	cases, err := evalstore.LoadCases()
	if err != nil {
		return err
	}
	out, code := backtest.Run(cases, top)
	if code != 0 {
		return t14ExitErr(code, "%s", out)
	}
	if len(baselines) > 0 {
		out += backtest.BaselineBlock(baselines, backtest.HeldOut(cases),
			func(tool, toolRoot string) ([]validation.Value, error) {
				if toolRoot == "" {
					toolRoot = root
				}
				return backtest.RealToolRunner(tool, toolRoot)
			})
	}
	fmt.Fprint(r.Out, out)
	return nil
}

func init() {
	register(command{ord: 28, name: "corpus-surface",
		line: "corpus-surface <campaign>       deterministic corpus sweep (advisory)",
		run:  runCorpusSurface})
}

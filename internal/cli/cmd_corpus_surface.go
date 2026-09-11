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

const corpusSurfaceUsage = "usage: webv2 corpus-surface [-h] [--backtest] [--top TOP] campaign\n"

// corpusSurfaceHelp is argparse's `webv2 corpus-surface --help` output.
const corpusSurfaceHelp = `usage: webv2 corpus-surface [-h] [--backtest] [--top TOP] campaign

positional arguments:
  campaign

options:
  -h, --help  show this help message and exit
  --backtest  rank held-out eval cases severity-only vs with dev priors
              (campaign is still required but ignored); the backtest
              measures the RANKING SIGNALS THE STORE ACTUALLY CARRIES
  --top TOP   top-K precision window for --backtest (default: 10)
`

func runCorpusSurface(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		backtestFlag := &boolOpt{name: "--backtest"}
		topFlag := &valOpt{name: "--top"}
		sp := &argSpec{
			prog:  "corpus-surface",
			usage: corpusSurfaceUsage,
			pos:   []*posOpt{{name: "campaign"}},
			flags: []*boolOpt{backtestFlag},
			vals:  []*valOpt{topFlag},
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
		// --top is a --backtest window, not a sweep option: accepting it
		// beside the plain sweep would silently ignore it, so it is an
		// argparse usage error (exit 2) instead.
		if topFlag.seen && !backtestFlag.set {
			return t14ArgparseErr(corpusSurfaceUsage,
				"corpus-surface", "--top requires --backtest")
		}
		if backtestFlag.set {
			return runCorpusBacktest(r, top)
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
				flag, objStr(row, "bug_class"), floatAtCLI(row, "score"),
				scalarStr(objAt(row, "corpus_weight")),
				objStr(row, "confidence"))
		}
		if len(matches) > 0 {
			fmt.Fprint(r.Out, "PoC shape matches (top 5):\n")
			for _, m := range firstRowsCLI(matches, 5) {
				fmt.Fprintf(r.Out, "  %s  exact=%d near=%d %s\n",
					objStr(m, "file"), len(listAtCLI(m, "exact_hits")),
					len(listAtCLI(m, "near_misses")), objStr(m, "bug_class"))
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
func runCorpusBacktest(r *Runner, top int) error {
	cases, err := evalstore.LoadCases()
	if err != nil {
		return err
	}
	out, code := backtest.Run(cases, top)
	if code != 0 {
		return t14ExitErr(code, "%s", out)
	}
	fmt.Fprint(r.Out, out)
	return nil
}

func init() {
	register(command{ord: 28, name: "corpus-surface",
		line: "corpus-surface <campaign>       deterministic corpus sweep (advisory)",
		run:  runCorpusSurface})
}

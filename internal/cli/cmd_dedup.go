package cli

// cmd_dedup: `webv2 dedup <campaign>` — the deterministic dedup sweep,
// report printed as indent-2 JSON (cli.py cmd_dedup verbatim: it calls
// dedup.run_dedup directly, NOT the orchestrator's phase-setting wrapper).
//
// This file also carries the shared helpers the P1b command files use
// (Python float formatting, padding, the argparse error surface) and the
// findings<->invariants seam wiring the CLI needs: Python connects those at
// import time (findings imports invariants), and cmd/webv2/main.go wires the
// rest. The CLI is driven directly by tests, so the connections live here
// too — idempotent, same targets.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"websec/internal/bounty"
	"websec/internal/corpus"
	"websec/internal/costs"
	"websec/internal/dedup"
	"websec/internal/envgo"
	"websec/internal/findings"
	"websec/internal/forkdiff"
	"websec/internal/forkpoc"
	"websec/internal/histmining"
	"websec/internal/invariants"
	"websec/internal/orchestrator"
	"websec/internal/pipeline"
	"websec/internal/report"
	"websec/internal/reproduction"
	"websec/internal/sandbox"
	"websec/internal/sequencepoc"
	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

func runDedup(root string, args []string, r *Runner) int {
	if helpRequested(r.Out, "dedup", args) {
		return 0
	}

	ensureSeams()
	pos, err := plainPositionals(args, "dedup", 1, "campaign")
	if err != nil {
		return r.fail(root, err)
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	report, err := dedup.RunDedup(c, true)
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	fmt.Fprintln(r.Out, validation.DumpIndentedASCII(report))
	return 0
}

func init() {
	register(command{ord: 5, name: "dedup",
		line: "dedup <campaign>                    deterministic dedup sweep",
		run:  runDedup})
}

// --- shared helpers (P1b wave) ---------------------------------------------

// plainPositionals rejects any flag and requires exactly n positionals. A
// missing required positional is an argparse error (per-subcommand usage
// block); an unexpected flag or extra positional is raised by Python's ROOT
// parser, so it keeps the D11 global-usage rendering.
func plainPositionals(args []string, cmd string, n int, names ...string) ([]string, error) {
	var pos []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			return nil, usageErrf("unrecognized arguments: %s", a)
		}
		pos = append(pos, a)
		if len(pos) > n {
			return nil, usageErrf("unrecognized arguments: %s", pos[n])
		}
	}
	if len(pos) != n {
		return nil, requiredErrf(cmd, names...)
	}
	return pos, nil
}

// --- argparse error surface (D11 refinement) --------------------------------

// cli.py's usage errors come from argparse: the subcommand's usage block,
// then `webv2 <cmd>: error: <message>`. The P0 commands render Go's own
// usage block instead (D11); the P1b commands reproduce argparse's block
// byte-for-byte — every block below is captured from the Python reference
// by .scratch/t15/usage_blocks.py — for the errors argparse raises INSIDE a
// subparser (missing required arguments, invalid choice, expected one
// argument). An unrecognized extra positional is raised by the ROOT parser
// in Python (`webv2: error: unrecognized arguments: X` + a usage block
// listing every command); that one keeps the D11 rendering, because Go's
// global usage deliberately lists only the implemented commands.
var argparseUsageBlocks = map[string]string{
	"dedup":       "usage: webv2 dedup [-h] campaign\n",
	"prioritize":  "usage: webv2 prioritize [-h] campaign\n",
	"repro-queue": "usage: webv2 repro-queue [-h] campaign\n",
	"invariant-verify": "usage: webv2 invariant-verify [-h] " +
		"[--artifact ARTIFACT] [--exec EXEC-*]\n" +
		"                              campaign inv_id\n",
	"artifact-register": "usage: webv2 artifact-register [-h] [--kind KIND] " +
		"[--note NOTE] campaign path\n",
	"artifact-list": "usage: webv2 artifact-list [-h] [--kind KIND] campaign\n",
	"invariant-contradict": "usage: webv2 invariant-contradict [-h] " +
		"--evidence EVIDENCE campaign inv_id\n",
	"verdict": "usage: webv2 verdict [-h]\n" +
		"                     --verdict {pending,confirmed,possible,disproved," +
		"duplicate,out_of_scope,informational}\n" +
		"                     --reason REASON\n" +
		"                     campaign finding\n",
	"recall": "usage: webv2 recall [-h] --finding FINDING " +
		"[--mode {negative,comparative}]\n" +
		"                    [--note NOTE]\n" +
		"                    campaign\n",
	"waive": "usage: webv2 waive [-h] [--subject SUBJECT] --reason REASON " +
		"--actor ACTOR\n" +
		"                   campaign stage\n",
	"prove": "usage: webv2 prove [-h] [--stage STAGE] campaign\n",
	"gate":  "usage: webv2 gate [-h] [--explain CHECK] [campaign] [finding]\n",
	"resolve-candidate": "usage: webv2 resolve-candidate [-h] --verdict " +
		"{same,distinct} [--note NOTE]\n" +
		"                               [--actor ACTOR]\n" +
		"                               campaign finding of_finding\n",
	"execs": "usage: webv2 execs [-h] [--id ID] [--json] campaign\n",
	"exec": "usage: webv2 exec [-h] [--profile PROFILE] [--dry-run] " +
		"--command COMMAND\n" +
		"                  [--workdir WORKDIR] [--finding FINDING] " +
		"[--timeout TIMEOUT]\n" +
		"                  [--env K=V]\n" +
		"                  campaign\n",
	"mint": "usage: webv2 mint [-h] --exec EXEC_ID --description DESCRIPTION\n" +
		"                  [--tier {T1,T2,T3,T4}]\n" +
		"                  [--type {balance-delta,differential,fork-test," +
		"foundry-test,fuzz,historical-analog,invariant-test,manual," +
		"reachability,reasoning,static-analysis,symbolic-witness,trace," +
		"unit-test}]\n" +
		"                  campaign finding\n",
	"classify": "usage: webv2 classify [-h] campaign exec_id\n",
}

// argparseError is a usage error whose rendering is argparse's.
type argparseError struct{ cmd, msg string }

func (e *argparseError) Error() string { return e.msg }

func argErrf(cmd, format string, a ...any) error {
	return &argparseError{cmd: cmd, msg: fmt.Sprintf(format, a...)}
}

// requiredErrf is argparse's "the following arguments are required: a, b"
// (the names appear in the parser's action order: positionals first).
func requiredErrf(cmd string, names ...string) error {
	return argErrf(cmd, "the following arguments are required: %s",
		strings.Join(names, ", "))
}

// fail renders an argparse usage error byte-for-byte, or falls back to the
// shared error handler for every other error.
func (r *Runner) fail(root string, err error) int {
	var ae *argparseError
	if errors.As(err, &ae) {
		fmt.Fprint(r.Err, argparseUsageBlocks[ae.cmd])
		fmt.Fprintf(r.Err, "webv2 %s: error: %s\n", ae.cmd, ae.msg)
		return 2
	}
	return r.withErr(root, func() error { return err })
}

// --- value helpers ---------------------------------------------------------

// pyFixed2 is Python's f"{x:.2f}": two decimals, correctly rounded (Go's
// strconv and CPython both round the exact binary value to nearest-even).
func pyFixed2(f float64) string {
	return strconv.FormatFloat(f, 'f', 2, 64)
}

// pyRight is Python's f"{s:>{width}}" for strings (pad only, never cut).
func pyRight(s string, width int) string {
	if n := width - len([]rune(s)); n > 0 {
		return strings.Repeat(" ", n) + s
	}
	return s
}

// pyScore2 renders a JSON number the way f"{x:.2f}" does.
func pyScore2(v validation.Value) string {
	switch v.Kind {
	case validation.Int:
		if v.Big != "" {
			f, _ := strconv.ParseFloat(v.Big, 64)
			return pyFixed2(f)
		}
		return pyFixed2(float64(v.I))
	case validation.Flt:
		return pyFixed2(v.F)
	default:
		return pyFixed2(0)
	}
}

// pyHead is Python's s[:n]: the first n RUNES (never splitting a code point).
func pyHead(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}

// pyFloatOf is Python's float(x) for the JSON shapes the CLI formats.
func pyFloatOf(v validation.Value) float64 {
	switch v.Kind {
	case validation.Flt:
		return v.F
	case validation.Int:
		if v.Big != "" {
			f, _ := strconv.ParseFloat(v.Big, 64)
			return f
		}
		return float64(v.I)
	default:
		return 0
	}
}

// ensureSeams installs the cross-module connections the CLI's commands read
// through (Python: import-time). Idempotent; every setter simply replaces
// the seam target.
var seamsInstalled bool

func ensureSeams() {
	if seamsInstalled {
		return
	}
	seamsInstalled = true
	dedup.SetMarkDuplicate(findings.MarkDuplicate)
	dedup.SetFlagPossibleDuplicate(findings.FlagPossibleDuplicate)
	dedup.SetFoldIntoLineage(findings.FoldIntoLineage)
	taxonomy.SetCompatClasses(func() []string {
		out := []string{}
		for _, g := range dedup.EconomicCompatGroups {
			out = append(out, g...)
		}
		for _, names := range dedup.AssetClassHints {
			out = append(out, names...)
		}
		return out
	})
	findings.SetInvariantGuard(invariants.AssertInvariantsVerified)
	findings.SetNormalizeInvID(invariants.NormalizeInvID)
	findings.SetLoadInvariantLinks(invariants.LoadLinks)
	findings.SetDocumentedInvariants(docMapSeam)
	findings.SetInvariantVerified(invariants.IsVerified)
	findings.SetIntentClaims(intentMapSeam)
	findings.SetReproductionTierOrder(func() []string {
		return reproduction.TierOrder
	})
	orchestrator.SetReproduction(orchestrator.ReproductionAPI{
		TierOf:                  reproduction.TierOf,
		NextTier:                reproduction.NextTier,
		MintIndependentEvidence: reproduction.MintIndependentEvidence,
	})
	// sequence_poc: the CONFIRMED gate (findings), the fork-PoC evidence
	// floor (forkpoc) and the reproduction queue (orchestrator) all read the
	// same predicate/verifier. One implementation, three seams.
	findings.SetOnchainSequenceRequired(sequencepoc.OnchainSequenceRequired)
	findings.SetVerifySequenceCoverage(sequencepoc.VerifySequenceCoverage)
	forkpoc.SetOnchainSequenceRequired(sequencepoc.OnchainSequenceRequired)
	forkpoc.SetVerifySequenceCoverage(sequencepoc.VerifySequenceCoverage)
	orchestrator.SetSequencePOC(orchestrator.SequencePOCAPI{
		IsSequenceRequired: sequencepoc.IsSequenceRequired,
	})
	// D17: the env port (internal/envgo) now backs the sandbox seams — the
	// transcription in envseam.go stays as the seam default.
	sandbox.SetClassifyFailure(envgo.ClassifyFailure)
	sandbox.SetSandboxPreflight(envgo.SandboxPreflight)
	sandbox.SetDockerImageProbe(envgo.DockerImageProbe)
	// costs: the pipeline's budget gate reads costs.jsonl.
	pipeline.SetCosts(costs.API{})
	// D2: the pipeline's report stage reads this seam. Without it `webv2 run`
	// walks every deterministic stage and then fails the LAST one with
	// "report module not wired: cannot run stage 'report'" — the seam was
	// never installed (cmd_report bypasses the pipeline and calls the module
	// directly). The other deterministic stages need no handler: they are
	// owned by the orchestrator the runner passes to pipeline.New.
	pipeline.SetReport(reportAdapter{})
	// structidx: the structural index seams (Python: import-time module
	// access). Idempotent; Wire covers orchestrator/coverage/reproduction/
	// planner, the two calls below cover histmining's recency seam.
	structidx.Wire()
	histmining.SetIndexAPI(histmining.IndexAPI{
		EnsureFreshIndex: structidx.EnsureFreshIndex,
		SinkFunctions:    structidx.SinkFunctions,
		WritersOf:        structidx.WritersOf,
	})
	// B4: the scope check (bounty) resolves a finding's contract name to its
	// source path via the structural index, so a path-based scope entry can
	// match a name-carrying finding. Wired here (the top module) because the
	// structidx→orchestrator→bounty import cycle bars a direct dependency;
	// empty when there is no active snapshot or no matching contract node.
	bounty.SetContractPathResolver(func(c *state.Campaign, name string) string {
		root, err := corpus.ActiveSnapshotRoot(c)
		if err != nil || root == "" {
			return ""
		}
		idx, err := structidx.EnsureFreshIndex(c, root)
		if err != nil || idx.Kind != validation.Obj {
			return ""
		}
		return structidx.ContractPath(idx, name)
	})
	// forkdiff: the baselines audit section (audit.py section 10) reads the
	// baselines directory and the T0-parser fingerprint from here.
	forkdiff.Wire()
	// T28: the learning/relations/shared_memory seams (D15/D18 closure).
	wireT28Seams()
	// T33: the eval_store seams (trajectory/metrics case_partition and
	// corpus.class_inventory).
	wireT33Seams()
	// T34: the dataset record loader (corpus_surface attribution).
	wireT34Seams()
}

// reportAdapter adapts report.Generate to pipeline.ReportAPI (D2).
type reportAdapter struct{}

func (reportAdapter) Generate(c *state.Campaign) (string, error) {
	return report.Generate(c)
}

// docMapSeam adapts invariants.DocumentedInvariants to findings' seam shape.
func docMapSeam(c *state.Campaign) (map[string]validation.Value, error) {
	doc, err := invariants.DocumentedInvariants(c, nil)
	if err != nil {
		return nil, err
	}
	out := make(map[string]validation.Value, len(doc.O))
	for _, e := range doc.O {
		out[e.K] = e.V
	}
	return out, nil
}

// intentMapSeam adapts invariants.IntentClaims to findings' seam shape.
func intentMapSeam(c *state.Campaign) (map[string]validation.Value, error) {
	claims, err := invariants.IntentClaims(c, nil)
	if err != nil {
		return nil, err
	}
	out := make(map[string]validation.Value, len(claims.O))
	for _, e := range claims.O {
		out[e.K] = e.V
	}
	return out, nil
}

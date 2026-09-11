package backtest

// baseline.go: the I2b baseline roster and comparator.
//
// WHY this exists: a recall number quoted alone is a claim nobody can
// price. `corpus-surface --backtest` scores the framework's RANKING
// SIGNALS over the held-out partition, but nothing in that scorecard says
// what a plain detector baseline would have scored over the SAME cases.
// This file adds the floor pair (`always` flags everything, `never` flags
// nothing) plus the two real tools Task 5 taught the framework to read
// (Slither, Aderyn), so a recall can never be read without its precision
// and the always-floor's price.
//
// Purity: BaselineBlock is a pure function of (names, held, run) — no
// clock, no store, no I/O. The one impure thing in this file is
// RealToolRunner, which spawns a SAST binary; it is opt-in (the caller
// passes it in as the ToolRunner seam) and the integration test is the
// only place that reaches for it.
//
// Why the scored universe is not recomputed here as "the store": the
// held-out slice is backtest.Run's, AFTER I1b's temporal/near-dup
// exclusions (Task 2 owns exclusion; this file consumes it through
// HeldOut, which mirrors Run's selection and is locked to Run's own output
// by TestHeldOutMirrorsRunHeldSlice). Run itself is deliberately NOT
// modified: the CLI composes Run's string with this block.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"websec/internal/datasets/aderyn"
	"websec/internal/datasets/slither"
	"websec/internal/evalstore"
	"websec/internal/risk"
	"websec/internal/validation"
	"websec/internal/wilson"
)

// BaselineRoster is the FIXED baseline roster in canonical output order.
// The CLI's `--baseline` choice list and its `choose from` message read
// this slice, and BaselineBlock prints in this order regardless of argv
// order — argv order is accepted by argparse but must never reach output.
var BaselineRoster = []string{"always", "never", "slither", "aderyn"}

// IsBaseline reports whether name is a roster baseline.
func IsBaseline(name string) bool {
	for _, r := range BaselineRoster {
		if r == name {
			return true
		}
	}
	return false
}

// ToolRunner runs one SAST tool over a root and returns its parsed
// payloads. It is the seam that keeps every comparator test offline: the
// real implementation is RealToolRunner, the tests inject tables.
//
// root is a source tree the tool can be pointed at. The EMPTY root means
// "the runner's own default root" — the comparator resolves `internal://`
// repos to it because that layout's gold paths are relative to the CLI's
// root (the repo the operator is standing in), and the CLI's closure
// substitutes its own root for "".
type ToolRunner func(tool, root string) ([]validation.Value, error)

// HeldOut is the scored universe: every adjudicated case in the held-out
// partition that I1b's exclusion discipline (Task 2, through
// evalstore.PartitionHealthFull) did not drop, in input order.
//
// It mirrors backtest.Run's own selection exactly — Run is not modified to
// expose its slice (the CLI composes Run's string with the baseline block,
// and Run's contract stays as shipped), so the two are locked together by
// TestHeldOutMirrorsRunHeldSlice, which checks this function against the
// only observable handle on Run's slice: the --top clamp count and the
// accepted count Run prints.
func HeldOut(cases []validation.Value) []validation.Value {
	excluded := map[string]bool{}
	for _, e := range evalstore.PartitionHealthFull(cases).Excluded {
		if orStr(objAt(e.Case, "partition")) != "held-out" {
			continue
		}
		excluded[orStr(objAt(e.Case, "case_id"))] = true
	}
	var held []validation.Value
	for _, c := range cases {
		if !risk.IsAdjudicated(orStr(objAt(objAt(c, "gold"), "outcome"))) {
			continue
		}
		if orStr(objAt(c, "partition")) != "held-out" {
			continue
		}
		if excluded[orStr(objAt(c, "case_id"))] {
			continue
		}
		held = append(held, c)
	}
	return held
}

// BaselineBlock renders the requested baselines over the held-out slice,
// in the FIXED roster order and with duplicate names collapsed (a baseline
// run is idempotent; printing the same block twice is noise). Names
// outside the roster are ignored — the CLI rejects them before this point
// — so a caller can never smuggle a second parser in through the back
// door.
//
// Every metric line comes from wilson.Format, the framework's only
// interval source:
//
//	recall    = flagged / scored        (did the baseline flag the case?)
//	precision = flagged-and-accepted / flagged
//
// "accepted" is gold.outcome == "confirmed-exploitable" — the SAME
// definition backtest.Run uses, not a second one. Note what recall counts
// here: whether the baseline FLAGGED a case, not whether the case was
// accepted. The roster's own pinned floors force that reading (`always`
// flags every case and prints recall n/n beside precision accepted/n);
// the accepted definition governs precision's numerator.
//
// A not-computable case (no local checkout for its repo, or no
// gold.locations to anchor a tool file against) is NEVER a miss: it is
// excluded from n and disclosed by the `skipped: k/n cases (no local
// checkout)` line, because treating it as unflagged would manufacture a
// false-negative rate out of thin air.
func BaselineBlock(names []string, held []validation.Value,
	run ToolRunner) string {
	var b strings.Builder
	for _, name := range rosterOrder(names) {
		switch name {
		case "always":
			writeFloor(&b, "always", len(held), len(held), acceptedCount(held))
		case "never":
			writeFloor(&b, "never", 0, len(held), 0)
		case "slither", "aderyn":
			b.WriteString(toolBaseline(name, held, run))
		}
	}
	return b.String()
}

// rosterOrder is requested ∩ roster, deduplicated, in roster order.
func rosterOrder(names []string) []string {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	out := make([]string, 0, len(want))
	for _, n := range BaselineRoster {
		if want[n] {
			out = append(out, n)
		}
	}
	return out
}

// writeFloor renders one of the two floor baselines. `always` prints
// flagged == len(held) (it flags everything) and `never` prints 0 flagged
// with a 0/0 precision denominator — wilson.Format's literal
// "0/0 (95% CI n/a)", never a fabricated 0%.
func writeFloor(b *strings.Builder, name string, flagged, n, flaggedAccepted int) {
	fmt.Fprintf(b, "baseline %s:\n%s\n%s\n", name,
		wilson.Format(flagged, n, "recall"),
		wilson.Format(flaggedAccepted, flagged, "precision"))
}

// acceptedCount counts the gold-accepted rows — the one accepted
// definition this file uses.
func acceptedCount(cases []validation.Value) int {
	n := 0
	for _, c := range cases {
		if isAccepted(c) {
			n++
		}
	}
	return n
}

// isAccepted is `gold.outcome == "confirmed-exploitable"`.
func isAccepted(c validation.Value) bool {
	return orStr(objAt(objAt(c, "gold"), "outcome")) == "confirmed-exploitable"
}

// toolBaseline renders one SAST comparator: resolve the distinct roots,
// run the tool ONCE per root, flag a case iff some admitted payload's file
// basename equals the basename of one of that case's gold locations, and
// score with wilson.Format.
//
// The failure posture is the honesty law of this block:
//
//   - binary absent (exec.LookPath's error, surfaced by the runner) ⇒ one
//     SKIPPED line, no metric lines, exit 0;
//   - the tool fails on EVERY resolved root ⇒ one SKIPPED line naming the
//     root count;
//   - the tool fails on SOME roots ⇒ score over the cases whose root ran,
//     and disclose the failures on the accounting line. Cases under a
//     failed root leave the denominators for the same reason an
//     uncheckable case does: a case nobody could check is not a miss.
//
// With no checkable case at all the tool is never spawned, so its absence
// cannot be observed; the `skipped: n/n` line is what discloses that run.
func toolBaseline(tool string, held []validation.Value,
	run ToolRunner) string {
	roots := map[string][]int{}
	var order []string
	notComputable := 0
	for i, c := range held {
		if len(locations(c)) == 0 {
			notComputable++ // no anchor to match a tool file against
			continue
		}
		root, ok := baselineRoot(c)
		if !ok {
			notComputable++
			continue
		}
		if _, seen := roots[root]; !seen {
			order = append(order, root)
		}
		roots[root] = append(roots[root], i)
	}
	if len(order) == 0 {
		lines := []string{"baseline " + tool + ":"}
		if notComputable > 0 {
			lines = append(lines, skippedLine(notComputable, len(held)))
		}
		lines = append(lines,
			wilson.Format(0, 0, "recall"),
			wilson.Format(0, 0, "precision"))
		return strings.Join(lines, "\n") + "\n"
	}
	sort.Strings(order) // deterministic spawn order and accounting order
	flagged := make([]bool, len(held))
	var scored []int
	failed := 0
	for _, root := range order {
		payloads, err := run(tool, root)
		if err != nil {
			if errors.Is(err, exec.ErrNotFound) {
				return fmt.Sprintf(
					"baseline %s: SKIPPED (%s not on PATH)\n", tool, tool)
			}
			failed++
			continue
		}
		names := payloadBasenames(payloads)
		for _, i := range roots[root] {
			scored = append(scored, i)
			flagged[i] = caseFlagged(held[i], names)
		}
	}
	if failed == len(order) {
		return fmt.Sprintf(
			"baseline %s: SKIPPED (tool failed on %d/%d roots)\n",
			tool, failed, len(order))
	}
	flaggedN, flaggedAccepted := 0, 0
	for _, i := range scored {
		if !flagged[i] {
			continue
		}
		flaggedN++
		if isAccepted(held[i]) {
			flaggedAccepted++
		}
	}
	lines := []string{"baseline " + tool + ":"}
	if notComputable > 0 {
		line := skippedLine(notComputable, len(held))
		if failed > 0 {
			line += fmt.Sprintf("; tool errors: %d roots", failed)
		}
		lines = append(lines, line)
	} else if failed > 0 {
		lines = append(lines, fmt.Sprintf("tool errors: %d roots", failed))
	}
	lines = append(lines,
		wilson.Format(flaggedN, len(scored), "recall"),
		wilson.Format(flaggedAccepted, flaggedN, "precision"))
	return strings.Join(lines, "\n") + "\n"
}

// skippedLine is the locked not-computable accounting string: k cases of
// the n scored-universe rows had no local checkout.
func skippedLine(k, n int) string {
	return fmt.Sprintf("skipped: %d/%d cases (no local checkout)", k, n)
}

// baselineRoot resolves one case's tool root (locked, no new flag):
//
//	code.repo internal://…          ⇒ "" (the runner's default root, i.e.
//	                                  the CLI's root: the suite's gold
//	                                  paths are relative to it)
//	code.repo an existing abs dir   ⇒ that directory
//	anything else (URL, owner/name,
//	commit-pinned external repo)    ⇒ not computable
func baselineRoot(c validation.Value) (string, bool) {
	repo := orStr(objAt(objAt(c, "code"), "repo"))
	if strings.HasPrefix(repo, "internal://") {
		return "", true
	}
	if filepath.IsAbs(repo) {
		if st, err := os.Stat(repo); err == nil && st.IsDir() {
			return repo, true
		}
	}
	return "", false
}

// locations is gold.locations (an empty list for an absent key).
func locations(c validation.Value) []validation.Value {
	locs := objAt(objAt(c, "gold"), "locations")
	if locs.Kind != validation.Arr {
		return nil
	}
	return locs.A
}

// caseFlagged reports whether any payload basename matches any of the
// case's gold location basenames. The basename is deliberate: the tool's
// path is relative to whatever checkout it ran in, and the same contract
// reached through two layouts is the same anchor.
func caseFlagged(c validation.Value, payloads map[string]bool) bool {
	for _, loc := range locations(c) {
		f := objStr(loc, "file")
		if f == "" {
			continue
		}
		if payloads[filepath.Base(f)] {
			return true
		}
	}
	return false
}

// payloadBasenames collects the basenames of every location an admitted
// payload carries (affected[].path — the field both Task 5 loaders fill
// with the tool's own path).
func payloadBasenames(payloads []validation.Value) map[string]bool {
	out := map[string]bool{}
	for _, p := range payloads {
		aff := objAt(p, "affected")
		if aff.Kind != validation.Arr {
			continue
		}
		for _, a := range aff.A {
			if f := objStr(a, "path"); f != "" {
				out[filepath.Base(f)] = true
			}
		}
	}
	return out
}

// realToolTimeout bounds one tool invocation: a SAST run over a fixture
// suite takes seconds, and the bound exists so a wedged compiler cannot
// hang a scorecard forever.
const realToolTimeout = 10 * time.Minute

// RealToolRunner is the real ToolRunner: it spawns the SAST binary over
// root with os/exec DIRECTLY.
//
// It must NOT go through internal/sandbox: RegisterExec/NewSandbox are
// campaign-scoped — they policy-check the command and MINT
// sandbox_execution records on a campaign. A baseline is an eval-side
// measurement, not a campaign execution; routing it through the sandbox
// would append artifacts and move bytes on a read-only scorecard. What is
// copied from internal/sandbox/exec.go is the ARGV DISCIPLINE only:
// explicit argv (no shell string interpolation, and no shell at all), a
// fixed cwd, and a cleaned temp dir for the tool's JSON.
//
// The EXIT CODE is not the signal: slither 0.11.6 exits 255 on a run that
// still writes `success: true` JSON (observed over the shipped suite), and
// aderyn exits 0 with findings. The signal is whether a parsable JSON
// document appeared; a missing or unparsable one is a root failure, which
// the comparator reports as a coverage failure rather than as zero flags.
func RealToolRunner(tool, root string) ([]validation.Value, error) {
	bin, err := exec.LookPath(tool)
	if err != nil {
		return nil, err // errors.Is(err, exec.ErrNotFound) ⇒ the SKIPPED gate
	}
	var toPayloads func(validation.Value) ([]validation.Value, error)
	outFlag := ""
	switch tool {
	case "slither":
		toPayloads, outFlag = slither.ToPayloads, "--json"
	case "aderyn":
		toPayloads, outFlag = aderyn.ToPayloads, "--output"
	default:
		return nil, fmt.Errorf("baseline: no loader for tool %q", tool)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "webv2-baseline-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	out := filepath.Join(tmp, tool+".json")
	ctx, cancel := context.WithTimeout(context.Background(), realToolTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, abs, outFlag, out)
	cmd.Dir = abs
	var logs strings.Builder
	cmd.Stdout, cmd.Stderr = &logs, &logs
	runErr := cmd.Run()
	doc, err := validation.ReadJson(out)
	if err != nil {
		reason := "no output file"
		if runErr != nil {
			reason = runErr.Error()
		}
		return nil, fmt.Errorf("%s: no parsable JSON from %s (%s)%s",
			tool, abs, reason, logTail(logs.String()))
	}
	return toPayloads(doc)
}

// logTail appends the tail of a tool's captured output to a failure
// message, bounded so an error can never carry a whole compiler dump.
func logTail(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) > 200 {
		s = s[len(s)-200:]
	}
	return ": " + s
}

// objStr is objAt(v, key).S with "" for an absent or non-string value.
func objStr(v validation.Value, key string) string { return orStr(objAt(v, key)) }

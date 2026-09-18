// task12_coverage_parity_test.go — Task 12 follow-up, from the independent
// Phase C review (docs/sdd/task-10-12-review.md, Task 12 "the
// coverage-ledger read-by-path" section).
//
// The queue score reads the coverage ledger by PATH instead of importing
// internal/coverage (that import closes an import cycle through the coverage
// test binary: coverage -> audit/sections -> completion -> planner), so
// planner.coverageSwept is a second copy of coverage's "has this been worked"
// predicate. The copies already diverge at the edges, and a future
// coverage-side change to the predicate would NOT break this reader at
// compile time. This pin is the tripwire: it runs coverage's own
// RefreshGaps over the fixture ledger and asserts the classification of every
// known row — the two documented divergent rows included — so a change on
// either side turns the test red instead of silently re-ranking the queue.
package planner

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/coverage"
	"websec/internal/state"
	"websec/internal/validation"
)

// task12CoverageRow is one fixture ledger row: the status/trajectory-counts
// shape under test plus what each side says about it.
type task12CoverageRow struct {
	path    string
	status  string
	counts  validation.Value
	swept   bool   // planner.coverageSwept
	gapKind string // coverage.RefreshGaps: "" = no gap raised
	gapDesc string // the gap's own words, "" when no gap
	note    string
}

// task12CoverageRows is the parity table. The first two rows are the known
// divergences the review named; the last two are rows where the two copies
// agree, so the pin cannot be satisfied by a predicate that simply returns
// false.
var task12CoverageRows = []task12CoverageRow{
	{path: "src/Swept.sol", status: "swept",
		// coverage counts trajectory KEYS, not the sum of their counts:
		// one key with count 2 is still "swept from only 1 trajectory".
		counts: validation.VObj(kv("code", validation.VInt(2)),
			kv("math", validation.VInt(1))),
		swept: true, gapKind: "",
		note: "a swept row with >=2 trajectories: both say worked"},
	{path: "src/Thin.sol", status: "swept",
		counts: validation.VObj(),
		swept:  false, gapKind: "thin-trajectory",
		gapDesc: "swept from only 0 trajectory(ies)",
		note: "DIVERGENT: coverage's own words say the row WAS swept " +
			"(thinly); the queue score calls it untouched (conservative — " +
			"it ranks higher)"},
	{path: "src/Excluded.sol", status: "excluded",
		counts: validation.VObj(),
		swept:  false, gapKind: "",
		note: "DIVERGENT: coverage's gaps never mention an excluded row " +
			"(invisible, so treated as worked); the queue score calls it " +
			"untouched (conservative)"},
	{path: "src/Unknown.sol", status: "unknown",
		counts: validation.VObj(kv("code", validation.VInt(1))),
		swept:  false, gapKind: "unswept-contract",
		gapDesc: "has never been swept",
		note:    "never swept: both agree, in different words"},
}

// task12CoverageLedger writes the fixture ledger and returns the campaign.
func task12CoverageLedger(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Coverage Parity Program",
		state.InitOpts{})
	if err != nil {
		t.Fatalf("init campaign: %v", err)
	}
	rows := []validation.Value{}
	for _, r := range task12CoverageRows {
		rows = append(rows, validation.VObj(
			kv("path", validation.VStr(r.path)),
			kv("status", validation.VStr(r.status)),
			kv("trajectory_counts", r.counts)))
	}
	ledger := validation.VObj(
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("snapshot_id", validation.VStr("unpinned")),
		kv("updated_at", validation.VStr("2026-09-17T00:00:00Z")),
		kv("contracts", validation.VArr(rows...)))
	if err := validation.WriteJson(
		filepath.Join(c.ArtifactsDir, "coverage.json"), ledger, ""); err != nil {
		t.Fatalf("write coverage ledger: %v", err)
	}
	return c
}

// task12CoverageGaps runs coverage's authoritative RefreshGaps and returns the
// first gap per component path (a zero Value when the path raised none).
func task12CoverageGaps(t *testing.T, c *state.Campaign) map[string]validation.Value {
	t.Helper()
	gaps, err := coverage.RefreshGaps(c, validation.VObj())
	if err != nil {
		t.Fatalf("coverage.RefreshGaps: %v", err)
	}
	out := map[string]validation.Value{}
	for _, g := range gaps {
		path := validation.ObjStr(g, "component")
		if path == "" {
			continue
		}
		if _, ok := out[path]; !ok {
			out[path] = g
		}
	}
	return out
}

// TestCoverageSweptParityWithRefreshGaps is the parity pin: every known row's
// classification is asserted on BOTH sides, so either copy drifting turns
// this red.
func TestCoverageSweptParityWithRefreshGaps(t *testing.T) {
	c := task12CoverageLedger(t)
	ledger, err := validation.ReadJson(
		filepath.Join(c.ArtifactsDir, "coverage.json"))
	if err != nil {
		t.Fatalf("read coverage ledger: %v", err)
	}
	byPath := map[string]validation.Value{}
	for _, row := range listOf(ledger, "contracts") {
		byPath[validation.ObjStr(row, "path")] = row
	}
	gaps := task12CoverageGaps(t, c)
	// the reader the pin protects: the queue signals read the ledger by path
	signals, err := buildQueueSignals(c, validation.VObj())
	if err != nil {
		t.Fatalf("buildQueueSignals: %v", err)
	}

	for _, tc := range task12CoverageRows {
		row, ok := byPath[tc.path]
		if !ok {
			t.Fatalf("fixture ledger lost %s", tc.path)
		}
		if got := coverageSwept(row); got != tc.swept {
			t.Errorf("%s (%s): coverageSwept = %v, want %v — %s",
				tc.path, tc.status, got, tc.swept, tc.note)
		}
		gap := gaps[tc.path]
		if got := validation.ObjStr(gap, "kind"); got != tc.gapKind {
			t.Errorf("%s (%s): coverage.RefreshGaps kind = %q, want %q "+
				"— coverage's predicate moved; re-check planner's copy "+
				"against it (%s)", tc.path, tc.status, got, tc.gapKind,
				tc.note)
		}
		if tc.gapDesc != "" {
			if desc := validation.ObjStr(gap, "description"); !strings.Contains(desc,
				tc.gapDesc) {
				t.Errorf("%s: coverage gap description = %q, want it to "+
					"contain %q — coverage's own words about the row are "+
					"part of this pin", tc.path, desc, tc.gapDesc)
			}
		}
		if got := signals.touched[tc.path]; got != tc.swept {
			t.Errorf("%s: queue signal touched = %v, want coverageSwept "+
				"= %v — the reader stopped using the pinned predicate",
				tc.path, got, tc.swept)
		}
	}

	// Divergence 1 (named by the review): a row coverage's gaps are SILENT
	// about while the queue score calls it untouched. Exactly one row may
	// be in that state — a second one means the drift risk grew, and
	// someone has to write it down here.
	silent := []string{}
	for _, tc := range task12CoverageRows {
		if tc.gapKind == "" && !tc.swept {
			silent = append(silent, tc.path)
		}
	}
	if len(silent) != 1 || silent[0] != "src/Excluded.sol" {
		t.Fatalf("rows invisible to coverage's gaps but untouched to the "+
			"queue score = %v, want [src/Excluded.sol]", silent)
	}
	// Divergence 2 (named by the review) is pinned above by coverage's own
	// gap description on src/Thin.sol: coverage says the row was swept
	// (thinly), the queue score says untouched.
	if task12CoverageRows[1].path != "src/Thin.sol" {
		t.Fatalf("the thin-row fixture moved: %s",
			task12CoverageRows[1].path)
	}
}

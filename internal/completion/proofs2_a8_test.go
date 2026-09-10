// A8 regression: the report-freshness proof used to compare the report's
// state-head stamp against the ABSOLUTE log head with strict equality — but
// generate() stamps the head it read and THEN logs its own events
// (artifact refresh + report.generated), so the equality could never pass
// and the proof sat permanently red after every real report.
package completion

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// doneIs reports whether the proof's "done" field equals want.
func doneIs(p validation.Value, want bool) bool {
	v := objAt(p, "done")
	return v.Kind == validation.Bool && v.B == want
}

// a8ReportLikeGenerate mirrors generate()'s tail: write report.md stamped
// with the head as it is NOW, then log the two events generate() logs after
// stamping (the artifact event first, report.generated last).
func a8ReportLikeGenerate(t *testing.T, c *state.Campaign) {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	headHash := ""
	if len(events) > 0 {
		headHash = objAt(events[len(events)-1], "event_hash").S
	}
	body := "<!-- state-head: " + headHash + " -->\n# Security Research Report\n"
	if err := os.WriteFile(filepath.Join(c.Dir, "report.md"),
		[]byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	data := validation.VObj(validation.KV{K: "path",
		V: validation.VStr(filepath.Join(c.Dir, "report.md"))})
	if _, err := c.Log("artifact.refreshed", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Log("report.generated", nil, &data); err != nil {
		t.Fatal(err)
	}
}

// TestProofReportFreshWhenHeadIsItsOwnGeneration pins A8: right after
// generate() the log head IS the report.generated event, and the proof must
// pass (it never could under the old strict-equality check).
func TestProofReportFreshWhenHeadIsItsOwnGeneration(t *testing.T) {
	c, err := state.Init(t.TempDir(), "A8 Program",
		state.InitOpts{CampaignID: "C-a8a8a8a8"})
	if err != nil {
		t.Fatal(err)
	}
	a8ReportLikeGenerate(t, c)

	p, err := proofReport(c)
	if err != nil {
		t.Fatal(err)
	}
	if !doneIs(p, true) {
		t.Fatalf("proof = %s, want done", validation.DumpIndented(p))
	}
	if got := objStr(p, "note"); got != "report fresh" {
		t.Fatalf("note = %q", got)
	}
}

// TestProofReportStaleWhenSomethingLogsAfterGeneration: any event logged
// after the report's own generation (new evidence, a new stage, ...) makes
// the report visibly stale — the semantics the stamp was always meant to
// carry.
func TestProofReportStaleWhenSomethingLogsAfterGeneration(t *testing.T) {
	c, err := state.Init(t.TempDir(), "A8 Program",
		state.InitOpts{CampaignID: "C-a8b8b8b8"})
	if err != nil {
		t.Fatal(err)
	}
	a8ReportLikeGenerate(t, c)
	if _, err := c.Log("evidence.minted", nil, nil); err != nil {
		t.Fatal(err)
	}

	p, err := proofReport(c)
	if err != nil {
		t.Fatal(err)
	}
	if !doneIs(p, false) {
		t.Fatalf("proof = %s, want not done", validation.DumpIndented(p))
	}
	missing := objAt(p, "missing")
	if len(missing.A) != 1 || !strings.Contains(missing.A[0].S,
		"report.md is stale") {
		t.Fatalf("missing = %s", validation.DumpIndented(missing))
	}
}

// TestProofReportStaleMessageKeepsTheStampRepr: the stale message still
// names the stamp the report was generated at (None when absent) and the
// current head.
func TestProofReportStaleMessageKeepsTheStampRepr(t *testing.T) {
	c, err := state.Init(t.TempDir(), "A8 Program",
		state.InitOpts{CampaignID: "C-a8c8c8c8"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.Dir, "report.md"),
		[]byte("# hand-written report, no stamp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Log("stage.changed", nil, nil); err != nil {
		t.Fatal(err)
	}

	p, err := proofReport(c)
	if err != nil {
		t.Fatal(err)
	}
	if !doneIs(p, false) {
		t.Fatalf("proof = %s, want not done", validation.DumpIndented(p))
	}
	missing := objAt(p, "missing")
	if len(missing.A) != 1 ||
		!strings.Contains(missing.A[0].S,
			"generated at log head None") {
		t.Fatalf("missing = %s", validation.DumpIndented(missing))
	}
}

// TestProofReportWithoutGenerationEventIsStale pins the Go fail-closed rule:
// a log that never carried a report.generated (a hand-written report) is
// stale even when its stamp equals the current head — freshness is proven by
// the log head being the report's own generation, never by the stamp alone.
func TestProofReportWithoutGenerationEventIsStale(t *testing.T) {
	c, err := state.Init(t.TempDir(), "A8 Program",
		state.InitOpts{CampaignID: "C-a8d8d8d8"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Log("stage.changed", nil, nil); err != nil {
		t.Fatal(err)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	headHash := objAt(events[len(events)-1], "event_hash").S
	body := "<!-- state-head: " + headHash + " -->\n# hand report\n"
	if err := os.WriteFile(filepath.Join(c.Dir, "report.md"),
		[]byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	p, err := proofReport(c)
	if err != nil {
		t.Fatal(err)
	}
	if !doneIs(p, false) {
		t.Fatalf("proof = %s, want stale", validation.DumpIndented(p))
	}
	missing := objAt(p, "missing")
	if len(missing.A) != 1 || !strings.Contains(missing.A[0].S,
		"report.md is stale") {
		t.Fatalf("missing = %s", validation.DumpIndented(missing))
	}
}

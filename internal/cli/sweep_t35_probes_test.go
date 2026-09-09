package cli

// T35 testmap re-triage: tests/test_probes_cli.py's brief/report rows — the
// brief prints the probe-surface line (and marks it stale), and a campaign
// without a surface is untouched.

import (
	"os"
	"strings"
	"testing"

	"websec/internal/audit"
	"websec/internal/planner"
	"websec/internal/probes"
	"websec/internal/report"
	"websec/internal/state"
	"websec/internal/validation"
)

func TestBriefPrintsTheSurfaceLineAndCountsDispositions(t *testing.T) {
	ws, c, _, surface := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	code, out, errS := run(t, "--root", ws, "brief", t29CID)
	if code != 0 {
		t.Fatalf("brief exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "probe surface: 10 rows (0 dispositioned, 10 open)") {
		t.Fatalf("brief lacks the surface line:\n%s", out)
	}
	if strings.Contains(out, "— stale?") {
		t.Fatalf("a fresh surface must not read stale:\n%s", out)
	}
	row := t29Row(t, surface, "")
	pid := objStr(t29ProbePriority(t, c, objStr(row, "row_id")), "id")
	code, _, errS = run(t, "--root", ws, "answered", t29CID, pid,
		"deprioritized", "--anchor", "concept", "--reason",
		"the join itself is not the bug")
	if code != 0 {
		t.Fatalf("answered exit %d: err=%q", code, errS)
	}
	code, out, errS = run(t, "--root", ws, "brief", t29CID)
	if code != 0 {
		t.Fatalf("brief exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "probe surface: 10 rows (1 dispositioned, 9 open)") {
		t.Fatalf("brief does not count the disposition:\n%s", out)
	}
}

func TestBriefMarksAStaleSurface(t *testing.T) {
	ws, c, idx, _ := t29Setup(t, t29Ranking, true)
	t29Emit(t, ws)
	t29BumpIndexLine(t, c, idx)
	code, out, errS := run(t, "--root", ws, "brief", t29CID)
	if code != 0 {
		t.Fatalf("brief exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out,
		"probe surface: 10 rows (0 dispositioned, 10 open) — stale?") {
		t.Fatalf("brief does not mark the surface stale:\n%s", out)
	}
}

func TestACampaignWithoutASurfaceIsUnaffected(t *testing.T) {
	probes.Wire()
	audit.Setup()
	ws := t.TempDir()
	c, err := state.Init(ws, "Probe CLI", state.InitOpts{CampaignID: t29CID})
	if err != nil {
		t.Fatal(err)
	}
	t29Plan(t, c)
	code, out, errS := run(t, "--root", ws, "brief", t29CID)
	if code != 0 {
		t.Fatalf("brief exit %d: out=%q err=%q", code, out, errS)
	}
	if strings.Contains(out, "probe surface:") ||
		strings.Contains(out, "probe row") {
		t.Fatalf("a surface-less brief mentions probes:\n%s", out)
	}
	path, err := report.Generate(c)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "Mechanical candidate surface") {
		t.Fatalf("a surface-less report gained the section:\n%s", raw)
	}
	aud, err := audit.AuditCampaign(c)
	if err != nil {
		t.Fatal(err)
	}
	sec := objAt(objAt(aud, "sections"), "probe_surface")
	if v := objAt(sec, "ok"); v.Kind != validation.Bool || !v.B {
		t.Fatalf("audit probe_surface not ok: %v", sec)
	}
	if got := objInt(sec, "checked"); got != 0 {
		t.Fatalf("audit checked = %d, want 0", got)
	}
	plan, err := planner.LoadPlanReadonly(c)
	if err != nil {
		t.Fatal(err)
	}
	div, err := planner.DivergenceStatusFor(c, plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range objListAt(div, "missing") {
		if strings.Contains(objStr(m, "what"), "probe") {
			t.Fatalf("divergence names a probe: %v", m)
		}
	}
}

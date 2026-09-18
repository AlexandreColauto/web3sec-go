// lens_batting_test.go (G17 tactic batting average): the NextActions
// advisory render is policy-gated OFF plus presence-gated — flag off (or
// no lens data) emits zero batting lines, flag on with verdict-resolved
// lens rows renders one pinned line per lens (L-id order, never
// "unattributed").
package briefing

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// batPrio is one batting-fixture plan priority.
func batPrio(id, status, rowID, ref string) validation.Value {
	p := validation.VObj(
		kv("id", validation.VStr(id)),
		kv("question", validation.VStr("probe the sweep ("+id+")")),
		kv("risk", validation.VFloat(0.9)),
		kv("trajectories", validation.VArr(validation.VStr("A-code"))),
		kv("budget_class", validation.VStr("cheap")),
		kv("status", validation.VStr(status)),
	)
	if rowID != "" {
		p.O = append(p.O, kv("probe", validation.VObj(
			kv("row_id", validation.VStr(rowID)),
			kv("probe_id", validation.VStr("p")),
			kv("axis", validation.VStr("liveness")))))
	}
	if ref != "" {
		p.O = append(p.O, kv("closed_ref", validation.VStr(ref)))
	}
	return p
}

// batFinding writes a billed confirmation (the costs T22 shape).
func batFinding(t *testing.T, c *state.Campaign, fid string) {
	t.Helper()
	f := validation.VObj(
		kv("finding_id", validation.VStr(fid)),
		kv("created_at", validation.VStr("2026-01-01T00:00:00+00:00")),
		kv("status", validation.VStr("CONFIRMED")),
		kv("trajectory", validation.VStr("code")),
		kv("verification", validation.VObj(
			kv("critic_verdict", validation.VStr("confirmed")))),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("description", validation.VStr("unguarded sweep")))),
		kv("evidence", validation.VArr(validation.VObj(
			kv("evidence_id", validation.VStr("EV-bat-1")),
			kv("level", validation.VStr("E4")),
			kv("type", validation.VStr("foundry-test"))))),
		kv("economic_impact", validation.VObj(
			kv("extractable_usd", validation.VFloat(1000)))),
	)
	if err := os.MkdirAll(c.FindingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(
		filepath.Join(c.FindingsDir, fid+".json"), f, ""); err != nil {
		t.Fatal(err)
	}
}

// batFixture writes plan + surface for the two-lens batting campaign:
// L-01 0/40 open (trips the queue gate), L-02 5/12 (5 answered-confirmed,
// 7 open — never parks).
func batFixture(t *testing.T, c *state.Campaign) {
	t.Helper()
	surface := map[string]string{}
	prios := []validation.Value{}
	for i := 1; i <= 40; i++ {
		rid := fmt.Sprintf("rA-%03d", i)
		surface[rid] = "L-01"
		prios = append(prios, batPrio(fmt.Sprintf("Q-A-%03d", i),
			"open", rid, ""))
	}
	for i := 1; i <= 12; i++ {
		rid := fmt.Sprintf("rB-%03d", i)
		surface[rid] = "L-02"
		qid := fmt.Sprintf("Q-B-%03d", i)
		if i <= 5 {
			fid := fmt.Sprintf("F-bat%06d", i)
			batFinding(t, c, fid)
			prios = append(prios, batPrio(qid, "answered", rid, fid))
			continue
		}
		prios = append(prios, batPrio(qid, "open", rid, ""))
	}
	lenses := validation.VArr(
		validation.VObj(
			kv("id", validation.VStr("L-01")),
			kv("lens", validation.VStr("liveness")),
			kv("surface", validation.VStr("protocol")),
			kv("question", validation.VStr("lens q?")),
			kv("status", validation.VStr("open"))),
		validation.VObj(
			kv("id", validation.VStr("L-02")),
			kv("lens", validation.VStr("incentive-inversion")),
			kv("surface", validation.VStr("protocol")),
			kv("question", validation.VStr("lens q?")),
			kv("status", validation.VStr("open"))))
	plan := validation.VObj(
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("created_at", validation.VStr("2026-01-01T00:00:00+00:00")),
		kv("priorities", validation.VArr(prios...)),
		kv("lenses", lenses))
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"campaign_plan.json"), plan, ""); err != nil {
		t.Fatal(err)
	}
	rows := []validation.Value{}
	for rid, lens := range surface {
		rows = append(rows, validation.VObj(
			kv("row_id", validation.VStr(rid)),
			kv("lens", validation.VStr(lens))))
	}
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"probe_surface.json"),
		validation.VObj(kv("rows", validation.VArr(rows...))), ""); err != nil {
		t.Fatal(err)
	}
}

// batSetPolicy writes the minimal bounty policy carrying the flag.
func batSetPolicy(t *testing.T, c *state.Campaign, on bool) {
	t.Helper()
	flag := "false"
	if on {
		flag = "true"
	}
	if err := os.WriteFile(filepath.Join(c.Dir, "bounty_policy.json"),
		[]byte(`{"auto_tune": `+flag+`}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

// batLines extracts the batting-average advisory lines.
func batLines(b validation.Value) []string {
	out := []string{}
	for _, a := range strListOf(validation.ObjAt(b, "next_actions")) {
		if strings.Contains(a, "batting average") {
			out = append(out, a)
		}
	}
	return out
}

// TestLensBattingFlagOffAbsent is the briefing half of the byte law:
// lens data with no flag renders zero batting lines (this is the path
// every golden campaign takes).
func TestLensBattingFlagOffAbsent(t *testing.T) {
	camp := newCamp(t, "Batting Program")
	batFixture(t, camp)
	b := build(t, camp, false)
	if lines := batLines(b); len(lines) != 0 {
		t.Fatalf("flag-off batting lines = %v, want none", lines)
	}
}

// TestLensBattingFlagOnRenders pins both advisory rows exactly: the 0/40
// lens cites its 8.8% upper, the 5/12 lens its 19.3–68.0% interval —
// L-id order, no unattributed row.
func TestLensBattingFlagOnRenders(t *testing.T) {
	camp := newCamp(t, "Batting Program")
	batFixture(t, camp)
	batSetPolicy(t, camp, true)
	b := build(t, camp, false)
	lines := batLines(b)
	// Task 7 fix round 1 (I-2): the advisory stat rides its lens's
	// mechanical-table command (webv2 run when the lens has no table
	// verb), and the reason is paren-free — the wilson CI brackets.
	cid := camp.CampaignID
	want := []string{
		"webv2 enforce " + cid + " <cursor-variable>  # lens L-01 " +
			"batting average — precision: 0/40 [95% CI 0.0–8.8%]",
		"webv2 run " + cid + "  # lens L-02 batting average — " +
			"precision: 5/12 [95% CI 19.3–68.0%]",
	}
	if len(lines) != len(want) {
		t.Fatalf("batting lines = %v, want %v", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Fatalf("batting line[%d] = %q, want %q", i, lines[i],
				want[i])
		}
	}
}

// TestLensBattingPresenceGate pins the presence half: flag on but no
// lens data anywhere (fresh campaign) renders nothing — no key, no
// line, no empty section.
func TestLensBattingPresenceGate(t *testing.T) {
	camp := newCamp(t, "No Lens Program")
	batSetPolicy(t, camp, true)
	b := build(t, camp, false)
	if lines := batLines(b); len(lines) != 0 {
		t.Fatalf("no-data batting lines = %v, want none", lines)
	}
}

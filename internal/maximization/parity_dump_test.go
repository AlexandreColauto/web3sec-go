package maximization

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"websec/internal/findings"
	"websec/internal/reproduction"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// TestParityDump is the cross-twin parity driver: it runs the same scripted
// ladder flow as .scratch/parity_py.py and writes masked canonical JSON for
// comparison. Skipped unless MAX_PARITY_OUT is set.
func TestParityDump(t *testing.T) {
	out := os.Getenv("MAX_PARITY_OUT")
	if out == "" {
		t.Skip("MAX_PARITY_OUT not set")
	}
	t.Setenv("WEBV2_NOW", "2026-09-06T12:00:00.000000+00:00")
	dir := t.TempDir()
	if d := os.Getenv("MAX_PARITY_DIR"); d != "" {
		os.RemoveAll(d)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		dir = d
	}
	c, fid := parityCampaign(t, dir)
	parityFlow(t, c, fid)
	doc := parityDoc(t, c, fid)
	body, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, body, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s (finding %s)", out, fid)
}

// parityCampaign is the scripted fixture .scratch/parity_py.py builds.
func parityCampaign(t *testing.T, dir string) (*state.Campaign, string) {
	t.Helper()
	c, err := state.Init(dir, "Acme", state.InitOpts{
		CampaignID: "C-abc1234567"})
	if err != nil {
		t.Fatal(err)
	}
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr("Rounding loss")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("logic-error")),
			kv("description", validation.VStr(
				"test fixture: rounding loss on deposit")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("deposit"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
		kv("capabilities", validation.VObj(
			kv("granted", validation.VArr(validation.VStr("drain_treasury"))),
			kv("required", validation.VArr()))),
	), "attacker", "06", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "triage",
		"", false); err != nil {
		t.Fatal(err)
	}
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless", Command: "forge test --match-test test_x",
		ReportedBy: "test-harness", FindingID: &fid,
		StdoutText: "PASS: test_x\n"})
	if err != nil {
		t.Fatal(err)
	}
	tier := "T2"
	if _, err := reproduction.RecordAttempt(c, fid, "reproduced",
		reproduction.RecordOpts{ExecID: strp(objStr(rec, "exec_id")),
			Tier: &tier}); err != nil {
		t.Fatal(err)
	}
	if _, err := reproduction.MintReproEvidence(c, fid, objStr(rec, "exec_id"),
		"sandboxed unit PoC", &tier, nil); err != nil {
		t.Fatal(err)
	}
	return c, fid
}

// parityFlow drives the same ladder script the Python twin runs.
func parityFlow(t *testing.T, c *state.Campaign, fid string) {
	t.Helper()
	lad, err := StartLadder(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	again, err := StartLadder(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if objStr(again, "ladder_id") != objStr(lad, "ladder_id") {
		t.Fatal("not idempotent")
	}
	cap1, ratio := 1.0, 1.0
	r1, err := AddVariant(c, fid, "dust", "dust the pool with one wei",
		[]string{"capital-minimization"}, &cap1, &ratio,
		[]string{"victim stakes"}, []string{"hold until oracle"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExploreAxis(c, fid, "cap-saturation",
		"  no payout cap in this code path  "); err != nil {
		t.Fatal(err)
	}
	r2, err := AddVariant(c, fid, "sandwich",
		"sandwich the accounting update", []string{"ordering-permutation"},
		nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DisproveRung(c, fid, objStr(r2, "rung_id"),
		"  the pool rejects 1 wei deposits (MIN_DEPOSIT)  "); err != nil {
		t.Fatal(err)
	}
	rec2, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless", Command: "forge test --match-test test_dust",
		ReportedBy: "test-harness", FindingID: &fid,
		StdoutText: "PASS: test_dust\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReproduceRung(c, fid, objStr(r1, "rung_id"),
		objStr(rec2, "exec_id"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := SetMaximal(c, fid, objStr(r1, "rung_id")); err != nil {
		t.Fatal(err)
	}
	if _, err := ExploreAxis(c, fid, "precondition-removal",
		"the deposit precondition is enforced by the code"); err != nil {
		t.Fatal(err)
	}
	if _, err := ExploreAxis(c, fid, "role-conflation",
		"victim role is not open to the attacker here"); err != nil {
		t.Fatal(err)
	}
	if _, err := CompleteLadder(c, fid, "operator"); err != nil {
		t.Fatal(err)
	}
}

// parityDoc is the masked canonical artifact the Python twin writes.
func parityDoc(t *testing.T, c *state.Campaign, fid string) map[string]any {
	t.Helper()
	rep, err := LadderReport(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	lad2, err := LoadLadder(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{}
	for name, v := range map[string]validation.Value{"ladder": *lad2,
		"finding": f2, "report": rep} {
		var anyv any
		if err := json.Unmarshal([]byte(maskParity(validation.CanonCompact(v))),
			&anyv); err != nil {
			t.Fatal(err)
		}
		doc[name] = anyv
	}
	doc["events"] = parityEvents(t, c)
	return doc
}

// parityEvents masks the event log the way the Python twin does.
func parityEvents(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	evs := []string{}
	for _, e := range events {
		evs = append(evs, maskParity(validation.CanonCompact(validation.VObj(
			kv("type", objAt(e, "type")),
			kv("ref", objAt(e, "ref")),
			kv("data", objAt(e, "data"))))))
	}
	return evs
}

func strp(s string) *string { return &s }

var parityMasks = []struct {
	rx  *regexp.Regexp
	rep string
}{
	{regexp.MustCompile(`F-[a-z0-9]{6,}`), "F-X"},
	{regexp.MustCompile(`EXEC-[A-Za-z0-9-]+`), "EXEC-X"},
	{regexp.MustCompile(`EV-[A-Za-z0-9-]+`), "EV-X"},
	{regexp.MustCompile(`LAD-[a-z0-9]{6,}`), "LAD-X"},
	{regexp.MustCompile(`R-[a-z0-9]{4,}`), "R-X"},
	{regexp.MustCompile(`C-[a-z0-9]{6,}`), "C-X"},
	{regexp.MustCompile(`MEM-[A-Za-z0-9-]+`), "MEM-X"},
	{regexp.MustCompile(`ART-[A-Za-z0-9-]+`), "ART-X"},
}

func maskParity(s string) string {
	for _, m := range parityMasks {
		s = m.rx.ReplaceAllString(s, m.rep)
	}
	return s
}

package cli

// R43A (P1) end to end, through the real verbs — the critic's repro:
//
//	init + ingest; plant 'not json' as findings/F-zzz.json -> audit rc=1 (red)
//	chmod 000 findings/ -> audit used to print PASS with findings=0 problem(s)
//
// and the same store drove `prove` to certify maximal-exploitation [DONE,
// authoritative] plus every OTHER findings-dependent stage, while `status`
// printed "findings": {} for a store it never read. The required behaviour:
// audit refuses and NAMES the error, prove leaves those stages open with the
// proof error, status refuses, and the honest shapes (a fresh campaign with no
// findings/ or chains/ directory, or genuinely empty ones) stay green.

import (
	"os"
	"strings"
	"testing"

	"websec/internal/state"
)

func r43aChmod(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod 000 %s: %v", dir, err)
	}
	// t.TempDir's RemoveAll cannot descend into a mode-000 directory, and
	// cleanups run newest-first, so restoring here runs before it.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if _, err := os.ReadDir(dir); err == nil {
		t.Skipf("cannot create an unreadable directory here (%s stayed readable)", dir)
	}
}

// r43aCampaign is init + state.Open, with the campaign at hand for its dirs.
func r43aCampaign(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	root := t.TempDir()
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatalf("open campaign: %v", err)
	}
	return c, root
}

// r43aFindingsStages are the stages whose proofs run over the findings store.
var r43aFindingsStages = []string{
	"maximal-exploitation", "hostile-review", "independent-verification",
	"mainnet-fork-poc", "reproduction", "bounty-gate", "dedup",
	"risk-calibration", "learning",
}

func TestR43aUnreadableFindingsStoreRefusesAuditProveStatus(t *testing.T) {
	c, root := r43aCampaign(t)
	r43aChmod(t, c.FindingsDir)

	// audit: not PASS, and the refusal names the path and the OS error.
	code, out, errS := run(t, "--root", root, "audit", c.CampaignID)
	if code != 1 {
		t.Fatalf("audit exit %d (out %q err %q); want 1", code, out, errS)
	}
	if strings.Contains(out, "PASS") {
		t.Fatalf("audit certified an unreadable findings store: %q", out)
	}
	if !strings.Contains(errS, c.FindingsDir) ||
		!strings.Contains(errS, "cannot be listed") ||
		!strings.Contains(errS, "permission denied") {
		t.Fatalf("audit must name the error: %q", errS)
	}

	// prove --stage: open (rc 1), naming the proof error.
	code, out, errS = run(t, "--root", root, "prove", c.CampaignID,
		"--stage", "maximal-exploitation")
	if code != 1 {
		t.Fatalf("prove --stage exit %d (out %q err %q); want 1", code, out, errS)
	}
	if strings.Contains(out, "DONE") {
		t.Fatalf("maximal-exploitation certified DONE: %q", out)
	}
	if !strings.Contains(out, "open") || !strings.Contains(out, "proof error") ||
		!strings.Contains(out, "cannot be listed") {
		t.Fatalf("prove must report the proof error: %q", out)
	}

	// prove (all stages): none of the findings-dependent stages is DONE.
	code, out, errS = run(t, "--root", root, "prove", c.CampaignID)
	if code != 0 {
		t.Fatalf("prove exit %d: %q", code, errS)
	}
	for _, line := range strings.Split(out, "\n") {
		for _, stage := range r43aFindingsStages {
			if strings.HasPrefix(line, stage) && strings.Contains(line, "DONE") {
				t.Errorf("%s certified DONE with an unreadable findings store: %q",
					stage, line)
			}
		}
	}

	// status: refuse, and never print a findings map.
	code, out, errS = run(t, "--root", root, "status", c.CampaignID)
	if code != 1 {
		t.Fatalf("status exit %d (out %q err %q); want 1", code, out, errS)
	}
	if strings.Contains(out, "\"findings\"") {
		t.Fatalf("status printed a findings map for an unreadable store: %q", out)
	}
	if !strings.Contains(errS, "cannot be listed") {
		t.Fatalf("status must name the refusal: %q", errS)
	}
}

// TestR43aHandPlantedFindingIsRedThenRefused is the first half of the critic's
// repro: the planted non-JSON finding reds the audit (rc 1) while the store is
// readable, and once it is chmod 000 the audit still does not pass — now with
// the store named instead of a JSON parse line.
func TestR43aHandPlantedFindingIsRedThenRefused(t *testing.T) {
	c, root := r43aCampaign(t)
	planted := c.FindingsDir + "/F-zzz.json"
	if err := os.WriteFile(planted, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "audit", c.CampaignID)
	if code != 1 {
		t.Fatalf("planted non-JSON: audit exit %d (out %q err %q)", code, out, errS)
	}
	if strings.Contains(out, "PASS") {
		t.Fatalf("audit passed a planted non-JSON finding: %q", out)
	}

	r43aChmod(t, c.FindingsDir)
	code, out, errS = run(t, "--root", root, "audit", c.CampaignID)
	if code != 1 || strings.Contains(out, "PASS") {
		t.Fatalf("audit exit %d out %q; want a refusal", code, out)
	}
	if !strings.Contains(errS, "cannot be listed") ||
		!strings.Contains(errS, c.FindingsDir) {
		t.Fatalf("audit must name the unreadable store: %q", errS)
	}
}

// TestR43aUnreadableChainStoreRefusesAudit: the chains/ half of the repro — a
// hand-planted chain reds the projection; with chains/ chmod 000 the audit
// must refuse rather than lose the premise of both projection directions.
func TestR43aUnreadableChainStoreRefusesAudit(t *testing.T) {
	c, root := r43aCampaign(t)
	planted := c.ChainsDir + "/CHAIN-zzz.json"
	if err := os.WriteFile(planted, []byte(`{"chain_id":"CHAIN-zzz"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := run(t, "--root", root, "audit", c.CampaignID)
	if code != 1 || !strings.Contains(out, "hand-planted chains") {
		t.Fatalf("planted chain: exit %d out %q; want the projection problem", code, out)
	}
	if err := os.Remove(planted); err != nil {
		t.Fatal(err)
	}

	r43aChmod(t, c.ChainsDir)
	code, out, errS := run(t, "--root", root, "audit", c.CampaignID)
	if code != 1 || strings.Contains(out, "PASS") {
		t.Fatalf("audit exit %d out %q; want a refusal", code, out)
	}
	if !strings.Contains(errS, c.ChainsDir) ||
		!strings.Contains(errS, "cannot be listed") {
		t.Fatalf("audit must name the unreadable chain store: %q", errS)
	}
}

// TestR43aHonestShapesStayGreen: the distinction the refactor must preserve —
// a campaign that has NOT produced findings/ or chains/ yet, and a campaign
// whose directories are genuinely empty, still audit green and status/ prove
// unchanged.
func TestR43aHonestShapesStayGreen(t *testing.T) {
	// (a) directories absent entirely.
	c, root := r43aCampaign(t)
	for _, d := range []string{c.FindingsDir, c.ChainsDir, c.MemoryDir, c.ExecsDir} {
		if err := os.RemoveAll(d); err != nil {
			t.Fatal(err)
		}
	}
	code, out, errS := run(t, "--root", root, "audit", c.CampaignID)
	if code != 0 || !strings.Contains(out, "audit PASS") {
		t.Fatalf("absent dirs: exit %d out %q err %q", code, out, errS)
	}
	code, out, errS = run(t, "--root", root, "status", c.CampaignID)
	if code != 0 || !strings.Contains(out, "\"findings\": {}") {
		t.Fatalf("absent findings dir: status exit %d out %q err %q", code, out, errS)
	}
	code, _, errS = run(t, "--root", root, "prove", c.CampaignID)
	if code != 0 {
		t.Fatalf("absent dirs: prove exit %d err %q", code, errS)
	}

	// (b) directories present and empty (the shape init writes).
	c2, root2 := r43aCampaign(t)
	code, out, errS = run(t, "--root", root2, "audit", c2.CampaignID)
	if code != 0 || !strings.Contains(out, "audit PASS") {
		t.Fatalf("empty dirs: exit %d out %q err %q", code, out, errS)
	}
}

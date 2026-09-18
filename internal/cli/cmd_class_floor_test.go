package cli

// Wave N, T6 — the class→floor advisory at ingest, and re-file parity.
//
// What these tests pin:
//
//   - the accepted `ingested …` line names the CONFIRMED floor the chosen class
//     pins, read through findings.RequiredLevelForCampaign — the SAME lookup
//     the CONFIRMED gate runs — so an instance floor override shows up on the
//     line exactly as it shows up in the gate;
//   - re-filing a finding to a class with a LOOSER floor (E6 -> E4) does not
//     retroactively bless anything: the same evidence, re-read on the next gate
//     read, passes the evidence clause that was failing before — evidence
//     untouched, status untouched;
//   - the reverse re-file (E4 -> E6) RAISES the bar with the evidence untouched
//     — a re-file can never silently lower what a finding must prove.
//
// No child tool is executed: the exec ledger record is registered through
// sandbox.RegisterExec (externally-reported), exactly like the T2 fixture.

import (
	"encoding/json"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// t6PayloadJSON is a schema-valid hypothesis payload for one class, carrying
// ONE E4 evidence item that cites an existing exec. E4 is reachable with a
// local (non-fork) profile, so the only variable under test is the class floor.
func t6PayloadJSON(class, ref string) string {
	return `{"title":"Unguarded rescue moves protocol-held tokens",` +
		`"root_cause":{"class":"` + class + `","description":` +
		`"rescue has no role check at all"},"affected":[{"path":"V.sol"}],` +
		`"attacker":{"profile":"arbitrary EOA","capabilities":[]},` +
		`"evidence":[{"evidence_id":"EV-floor1","level":"E4",` +
		`"type":"foundry-test","description":"the sandboxed PoC drained it",` +
		`"exec_ref":"` + ref + `"}]}`
}

// t6Ingest files payload into a fresh campaign and returns the finding id.
func t6Ingest(t *testing.T, root, cid, jsonBody string) (string, string) {
	t.Helper()
	p := t2Write(t, root, "t6-payload.json", jsonBody)
	code, out, errS := run(t, "--root", root, "ingest", cid, "--json-file", p)
	if code != 0 {
		t.Fatalf("ingest exit %d: %q", code, errS)
	}
	return t2IngestedID(t, out), out
}

// t6Evidence is the finding's evidence array as canonical JSON — the byte
// witness that re-filing rewrites the class and nothing else.
func t6Evidence(t *testing.T, c *state.Campaign, fid string) string {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatalf("load %s: %v", fid, err)
	}
	return validation.CanonCompact(validation.ObjAt(f, "evidence"))
}

// t6Status is the finding's status — amend never moves it.
func t6Status(t *testing.T, c *state.Campaign, fid string) string {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatalf("load %s: %v", fid, err)
	}
	return validation.ObjStr(f, "status")
}

// t6GateRead runs the read-only per-finding gate dry-run.
func t6GateRead(t *testing.T, root, cid, fid string) string {
	t.Helper()
	code, out, errS := run(t, "--root", root, "gate", cid, fid)
	if code != 1 && code != 0 {
		t.Fatalf("gate exit %d: %q", code, errS)
	}
	return out
}

// TestIngestLineNamesConfirmedFloor: the accepted line names the CONFIRMED
// floor for a known class (from the floor table), the conservative default for
// an unknown class, and the E6 wall the example class pins.
func TestIngestLineNamesConfirmedFloor(t *testing.T) {
	c, root, cid := t2Campaign(t)
	execID := t2RegisterExec(t, c, "")
	for _, tc := range []struct {
		class string
		floor string
	}{
		{"share-price-inflation", "E6"}, // floor-table entry
		{"access-control", "E4"},        // loosest floor in the table
		{"bridge-message", "E6"},
		{"quantum-decoherence", "E5"}, // unknown -> conservative default
	} {
		_, out := t6Ingest(t, root, cid, t6PayloadJSON(tc.class, execID))
		want := "(class " + tc.class + ", CONFIRMED floor " + tc.floor + ")"
		if !strings.Contains(out, want) {
			t.Errorf("ingested line for %q is missing %q:\n%s",
				tc.class, want, out)
		}
	}
}

// TestIngestLineFloorFollowsTheGateRead: the line reads the floor through the
// SAME campaign-aware lookup the gate runs, so an instance override moves both
// or neither. (A copy of the class table would show E4 here while the gate
// demanded E6.)
func TestIngestLineFloorFollowsTheGateRead(t *testing.T) {
	c, root, cid := t2Campaign(t)
	execID := t2RegisterExec(t, c, "")
	code, out, errS := run(t, "--root", root, "floors", cid, "set",
		"access-control", "E6", "--actor", "operator",
		"--reason", "this target has no local harness, only a fork")
	if code != 0 {
		t.Fatalf("floors set exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "E6") {
		t.Fatalf("floors set output = %q", out)
	}
	fid, line := t6Ingest(t, root, cid, t6PayloadJSON("access-control", execID))
	if !strings.Contains(line, "(class access-control, CONFIRMED floor E6)") {
		t.Fatalf("ingested line ignored the instance override:\n%s", line)
	}
	gate := t6GateRead(t, root, cid, fid)
	if !strings.Contains(gate,
		"evidence-floor: evidence level E4 < required E6 for CONFIRMED") {
		t.Fatalf("gate read disagrees with the ingested line:\n%s", gate)
	}
}

// TestAmendClassRefileRecomputesGateFloor is the T6 parity pin: a finding filed
// under an E6-floor class with E4-only evidence is refused at the CONFIRMED
// gate; re-filing it to an E4-floor class makes the SAME evidence satisfy the
// evidence clause on the NEXT gate read (no retroactive promotion, no stale
// blessing, evidence and status untouched).
func TestAmendClassRefileRecomputesGateFloor(t *testing.T) {
	c, root, cid := t2Campaign(t)
	execID := t2RegisterExec(t, c, "")
	fid, line := t6Ingest(t, root, cid,
		t6PayloadJSON("bridge-message", execID))
	if !strings.Contains(line, "(class bridge-message, CONFIRMED floor E6)") {
		t.Fatalf("ingested line = %q", line)
	}
	evidenceBefore := t6Evidence(t, c, fid)

	// gate read 1: E6 floor, E4 evidence — refused, and the brief says why.
	gate := t6GateRead(t, root, cid, fid)
	if !strings.Contains(gate,
		"evidence-floor: evidence level E4 < required E6 for CONFIRMED") {
		t.Fatalf("pre-amend gate read = %q", gate)
	}
	code, brief, errS := run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("brief exit %d: %q", code, errS)
	}
	if !strings.Contains(brief, fid+" stuck at E4 (floor E6)") {
		t.Fatalf("pre-amend brief does not name the stuck floor:\n%s", brief)
	}

	// re-file by true root cause: the evidence was always an access-control PoC.
	code, out, errS := run(t, "--root", root, "amend", cid, fid,
		"--class", "access-control",
		"--note", "true root cause is a missing role check, not a bridge message")
	if code != 0 {
		t.Fatalf("amend exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "amended "+fid) {
		t.Fatalf("amend output = %q", out)
	}

	// gate read 2: the new class's floor governs; the same evidence passes.
	gate = t6GateRead(t, root, cid, fid)
	if !strings.Contains(gate, "\u2713 evidence-floor") {
		t.Fatalf("post-amend evidence clause still fails:\n%s", gate)
	}
	if strings.Contains(gate, "required E6") {
		t.Fatalf("post-amend gate still reads the old class floor:\n%s", gate)
	}
	code, brief, errS = run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("brief exit %d: %q", code, errS)
	}
	if strings.Contains(brief, "stuck at E4 (floor E6)") {
		t.Fatalf("post-amend brief still reports the old floor:\n%s", brief)
	}

	// nothing else moved: the evidence bytes and the status are the SAME.
	if after := t6Evidence(t, c, fid); after != evidenceBefore {
		t.Errorf("amend rewrote the evidence:\nbefore %s\nafter  %s",
			evidenceBefore, after)
	}
	if st := t6Status(t, c, fid); st != "HYPOTHESIS" {
		t.Errorf("amend moved the status: %s", st)
	}
}

// TestAmendClassRefileToStricterRaisesTheBar is the other polarity: re-filing
// to a STRICTER class raises what the finding must prove, with the evidence
// untouched — a re-file never silently lowers a bar, and never blesses.
//
// The class used is bridge-message (E6, not one of ECONOMIC_CONFIRMATION_CLASSES)
// so the raise shows up as the same single evidence clause at a higher floor;
// an economic class raises it twice over (the three-clause economic gate plus
// its E7 quantification clause), which the gate renders as different text.
func TestAmendClassRefileToStricterRaisesTheBar(t *testing.T) {
	c, root, cid := t2Campaign(t)
	execID := t2RegisterExec(t, c, "")
	fid, line := t6Ingest(t, root, cid,
		t6PayloadJSON("access-control", execID))
	if !strings.Contains(line, "(class access-control, CONFIRMED floor E4)") {
		t.Fatalf("ingested line = %q", line)
	}
	evidenceBefore := t6Evidence(t, c, fid)
	if gate := t6GateRead(t, root, cid, fid); !strings.Contains(gate,
		"\u2713 evidence-floor") {
		t.Fatalf("E4 class with E4 evidence must pass the clause:\n%s", gate)
	}

	code, _, errS := run(t, "--root", root, "amend", cid, fid,
		"--class", "bridge-message",
		"--note", "the failure crosses a bridge message, not a role check")
	if code != 0 {
		t.Fatalf("amend exit %d: %q", code, errS)
	}

	gate := t6GateRead(t, root, cid, fid)
	if !strings.Contains(gate,
		"evidence-floor: evidence level E4 < required E6 for CONFIRMED") {
		t.Fatalf("stricter re-file did not raise the bar:\n%s", gate)
	}
	code, brief, errS := run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("brief exit %d: %q", code, errS)
	}
	if !strings.Contains(brief, fid+" stuck at E4 (floor E6)") {
		t.Fatalf("stricter re-file is not surfaced as stuck:\n%s", brief)
	}
	if after := t6Evidence(t, c, fid); after != evidenceBefore {
		t.Errorf("amend rewrote the evidence:\nbefore %s\nafter  %s",
			evidenceBefore, after)
	}
	if st := t6Status(t, c, fid); st != "HYPOTHESIS" {
		t.Errorf("amend moved the status: %s", st)
	}
}

// TestIngestJSONCarriesConfirmedFloor pins review defect D1: the JSON
// acceptance envelope gained "confirmed_floor" so --json consumers and the
// text line can never disagree about what the class costs.
func TestIngestJSONCarriesConfirmedFloor(t *testing.T) {
	c, root, cid := t2Campaign(t)
	p := t2Write(t, root, "d1.json", t6PayloadJSON("bridge-message",
		t2RegisterExec(t, c, "")))
	code, out, errS := run(t, "--root", root, "ingest", cid, "--json",
		"--json-file", p)
	if code != 0 {
		t.Fatalf("ingest --json exit %d: %q", code, errS)
	}
	var d struct {
		Finding struct {
			FindingID string `json:"finding_id"`
		} `json:"finding"`
		ConfirmedFloor string `json:"confirmed_floor"`
	}
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("ingest --json envelope: %v", err)
	}
	if d.ConfirmedFloor != "E6" {
		t.Fatalf("confirmed_floor = %q, want E6 (the class's CONFIRMED floor)",
			d.ConfirmedFloor)
	}
}

// TestAdvisoryFollowsFloorOverride pins critic I-2: after `floors set`
// relaxes the class to the loosest floor, the ingest output carries NO
// stricter-than-necessary advisory — the warning reads the campaign-aware
// floor, the same lookup the line and the gate use.
func TestAdvisoryFollowsFloorOverride(t *testing.T) {
	c, root, cid := t2Campaign(t)
	execID := t2RegisterExec(t, c, "")
	code, _, errS := run(t, "--root", root, "floors", cid, "set",
		"bridge-message", "E4", "--actor", "operator",
		"--reason", "this target has no fork, E4 is the bar")
	if code != 0 {
		t.Fatalf("floors set: %q %q", errS, "")
	}
	_, out2, errS2 := run(t, "--root", root, "ingest", cid, "--json-file",
		t2Write(t, root, "ovr.json", t6PayloadJSON("bridge-message", execID)))
	if errS2 != "" {
		t.Fatalf("ingest after override: %q", errS2)
	}
	if !strings.Contains(out2, "CONFIRMED floor E4") {
		t.Fatalf("line must show the overridden floor: %q", out2)
	}
	if strings.Contains(out2, "ADVISORY") {
		t.Fatalf("no stricter-floor advisory may survive an override: %q", out2)
	}
}

// TestAdvisoryAttributesOverrideToItsSource pins critic r2 (R2-3): when a
// campaign floor policy RAISES a class, the advisory says so and offers the
// undo — never "the class pins" for the operator's own recorded floor.
func TestAdvisoryAttributesOverrideToItsSource(t *testing.T) {
	_, root, cid := t2Campaign(t)
	code, _, errS := run(t, "--root", root, "floors", cid, "set",
		"reentrancy", "E6", "--actor", "operator",
		"--reason", "this target's reentrancy bar is a fork")
	if code != 0 {
		t.Fatalf("floors set: %q", errS)
	}
	code, out, errS := run(t, "--root", root, "ingest", cid, "--json-file",
		t2Write(t, root, "ov.json",
			`{"title":"Reentrancy in withdraw() drains the pool",`+
				`"root_cause":{"class":"reentrancy",`+
				`"description":"external call precedes the balance update"},`+
				`"affected":[{"path":"A.sol"}],`+
				`"attacker":{"profile":"any EOA","capabilities":[]}}`))
	if code != 0 {
		t.Fatalf("ingest: %q", errS)
	}
	_ = out
	if !strings.Contains(out, "in THIS campaign") ||
		!strings.Contains(out, "floors <campaign> unset reentrancy") ||
		strings.Contains(out, "class 'reentrancy' pins a CONFIRMED floor of E6") {
		t.Fatalf("override must be attributed to the policy, not the class: %q", out)
	}
}

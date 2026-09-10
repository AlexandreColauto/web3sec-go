package chainengine

// unproven_test.go — IMPROVEMENTS B3: chain materialization at HYPOTHESIS
// (--unproven). A hypothesis-level chain is a DOCUMENT, never a finding: it
// carries provenance "unproven", per-link evidence levels, its own event,
// and no super-finding, so nothing downstream can count it as confirmed.

import (
	"errors"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// upPair is the two-member freeze chain at HYPOTHESIS: the first finding
// grants the pause capability, the second needs it and grants the liveness
// terminal. Nothing is confirmed.
func upPair(t *testing.T, c *state.Campaign) (f1, f2 validation.Value) {
	t.Helper()
	f1 = hypo(t, c, "access-control",
		[]string{"control_protocol_pause"}, nil,
		"pause gate reachable by arbitrary EOA")
	f2 = hypo(t, c, "chain-freeze",
		[]string{"liveness_loss"},
		[]string{"control_protocol_pause"},
		"pause with no timelock freezes all withdrawals")
	return f1, f2
}

func upIDs(f1, f2 validation.Value) []string {
	return []string{objStr(f1, "finding_id"), objStr(f2, "finding_id")}
}

// setSourcePin rewrites a finding's source pin (the schema wants >= 8 chars).
func setSourcePin(t *testing.T, c *state.Campaign, fid, pin string) {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	sp := asObj(objAt(f, "snapshot_ids"))
	sp.O = setOrAppend(sp.O, "source", validation.VStr(pin))
	f.O = setOrAppend(f.O, "snapshot_ids", sp)
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
}

// TestUnprovenChainMaterializesWithoutSuperFinding is the core B3 claim: a
// hypothesis-level chain materializes as a doc, stamped and linked, with no
// CHAIN super-finding anywhere and its own event type.
func TestUnprovenChainMaterializesWithoutSuperFinding(t *testing.T) {
	c := newCampaign(t, "Unproven Program")
	f1, f2 := upPair(t, c)
	ids := upIDs(f1, f2)
	ch, err := MaterializeChainOpts(c, ids,
		"Freeze chain without a recovery path",
		"EOA pauses; nobody can unpause; every withdrawal stops", nil, nil,
		MaterializeOpts{Unproven: true})
	if err != nil {
		t.Fatalf("unproven materialize: %v", err)
	}
	if got := objStr(ch, "provenance"); got != "unproven" {
		t.Errorf("provenance = %q, want unproven", got)
	}
	if got := objStr(ch, "evidence_floor"); got != "E0" {
		t.Errorf("evidence_floor = %q, want E0", got)
	}
	if got := objStr(ch, "status"); got != "proposed" {
		t.Errorf("status = %q, want proposed", got)
	}
	links := listOf(ch, "capability_links").A
	if len(links) != 1 {
		t.Fatalf("links = %d, want 1", len(links))
	}
	if got := objStr(links[0], "link_evidence"); got != "E0" {
		t.Errorf("link_evidence = %q, want E0", got)
	}
	if got := objStr(links[0], "granted"); got != "control_protocol_pause" {
		t.Errorf("link granted = %q", got)
	}
	// the terminal is DERIVED from the hypothesis-mode search (no caller
	// annotation), and verified against the via_finding.
	term := objAt(ch, "terminal")
	if got := objStr(term, "capability"); got != "liveness_loss" {
		t.Fatalf("derived terminal = %q, want liveness_loss", got)
	}
	if got := objStr(term, "via_finding"); got != ids[1] {
		t.Errorf("derived terminal via = %q, want %q", got, ids[1])
	}
	// no super-finding: both findings are still HYPOTHESIS, and no CHAIN
	// finding exists at all.
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("findings = %d, want 2 (no super-finding)", len(all))
	}
	for _, f := range all {
		if st := objStr(f, "status"); st != "HYPOTHESIS" {
			t.Errorf("%s status = %q, want HYPOTHESIS",
				objStr(f, "finding_id"), st)
		}
	}
	// the event is distinct and carries the provenance, not a super-finding.
	evts, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(evts) == 0 {
		t.Fatal("no events")
	}
	last := evts[len(evts)-1]
	if got := objStr(last, "type"); got != "chain.materialized_unproven" {
		t.Errorf("event type = %q, want chain.materialized_unproven", got)
	}
	if got := objStr(last, "ref"); got != objStr(ch, "chain_id") {
		t.Errorf("event ref = %q, want %q", got, objStr(ch, "chain_id"))
	}
	data := objAt(last, "data")
	if got := objStr(data, "provenance"); got != "unproven" {
		t.Errorf("event provenance = %q, want unproven", got)
	}
	if hasKey(data, "super_finding") {
		t.Errorf("unproven event must not name a super-finding: %v", data)
	}
}

// TestUnprovenChainSpansSnapshots: a hypothesis-level chain may span the
// snapshots its members were filed against; the same member set fails the
// proven gate. The proof constraint stays where it belongs.
func TestUnprovenChainSpansSnapshots(t *testing.T) {
	c := newCampaign(t, "Cross-snapshot Program")
	f1, f2 := upPair(t, c)
	ids := upIDs(f1, f2)
	setSourcePin(t, c, ids[0], "snapshot-aaaa")
	setSourcePin(t, c, ids[1], "snapshot-bbbb")
	// Both members are CONFIRMED, so the status gate cannot mask the pin
	// gate: the proven refusal below is the shared-pin rule itself.
	confirm(t, c, ids[0], "E5", "T3")
	confirm(t, c, ids[1], "E5", "T3")

	if _, err := MaterializeChain(c, ids, "Cross-snapshot freeze chain", "",
		nil, nil); err == nil {
		t.Fatal("proven materialization accepted a mixed pin set")
	} else if !strings.Contains(err.Error(), "pinned to different/missing") {
		t.Errorf("proven error = %v", err)
	}
	ch, err := MaterializeChainOpts(c, ids, "Cross-snapshot freeze chain", "",
		nil, nil, MaterializeOpts{Unproven: true})
	if err != nil {
		t.Fatalf("unproven materialize: %v", err)
	}
	if got := objStr(ch, "provenance"); got != "unproven" {
		t.Errorf("provenance = %q, want unproven", got)
	}
}

// TestProvenChainStillRefusesHypothesisMembers: the hard gate is untouched
// by B3 — and the proven path writes neither provenance nor link_evidence
// (the byte-compat guarantee for every chain materialized before B3).
func TestProvenChainStillRefusesHypothesisMembers(t *testing.T) {
	c := newCampaign(t, "Proven Program")
	f1, f2 := upPair(t, c)
	ids := upIDs(f1, f2)
	_, err := MaterializeChain(c, ids, "Freeze chain without a recovery path",
		"", nil, nil)
	if err == nil {
		t.Fatal("proven materialization accepted HYPOTHESIS members")
	}
	var it *findings.IllegalTransition
	if !errors.As(err, &it) {
		t.Fatalf("error = %T %v, want *findings.IllegalTransition", err, err)
	}
	if !strings.Contains(err.Error(), "must each be CONFIRMED first") {
		t.Errorf("error = %v", err)
	}
	if docs, derr := chainDocs(c, false); derr != nil || len(docs) != 0 {
		t.Errorf("a refused materialization must write no chain doc: %v %v",
			docs, derr)
	}

	// now confirm both: the proven path materializes with a super-finding,
	// and its doc carries no B3 fields.
	confirm(t, c, ids[0], "E5", "T3")
	confirm(t, c, ids[1], "E5", "T3")
	ch, err := MaterializeChain(c, ids, "Freeze chain without a recovery path",
		"EOA pauses; nobody can unpause; every withdrawal stops", nil, nil)
	if err != nil {
		t.Fatalf("proven materialize: %v", err)
	}
	if hasKey(ch, "provenance") {
		t.Error("proven chain doc carries provenance (B3 changed proven bytes)")
	}
	if got := objStr(listOf(ch, "capability_links").A[0], "link_evidence"); got != "" {
		t.Errorf("proven link carries link_evidence %q", got)
	}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		t.Fatal(err)
	}
	supers := 0
	for _, f := range all {
		if objStr(f, "status") == "CHAIN" {
			supers++
		}
	}
	if supers != 1 {
		t.Errorf("proven chain super-findings = %d, want 1", supers)
	}
}

// TestCheckPinsMode is the gate table: the proven rule is unchanged, the
// unproven rule accepts a mixed (cross-snapshot) pin set and still refuses a
// member with no pin at all.
func TestCheckPinsMode(t *testing.T) {
	same := []validation.Value{validation.VStr("src-aaaa"), validation.VStr("src-aaaa")}
	mixed := []validation.Value{validation.VStr("src-aaaa"), validation.VStr("src-bbbb")}
	unpinned := []validation.Value{validation.VStr("src-aaaa"), validation.VNull()}
	if err := checkPinsMode(same, false); err != nil {
		t.Errorf("proven shared pin: %v", err)
	}
	if err := checkPinsMode(same, true); err != nil {
		t.Errorf("unproven shared pin: %v", err)
	}
	if err := checkPinsMode(mixed, false); err == nil {
		t.Error("proven gate accepted a mixed pin set")
	}
	if err := checkPinsMode(mixed, true); err != nil {
		t.Errorf("unproven mixed pin set: %v", err)
	}
	if err := checkPinsMode(unpinned, false); err == nil {
		t.Error("proven gate accepted an unpinned member")
	}
	if err := checkPinsMode(unpinned, true); err == nil {
		t.Error("unproven gate accepted an unpinned member")
	}
}

// TestUnprovenChainDuplicateRejected: the idempotence guard is shared — a
// second materialization of the same member set is refused whatever the
// provenance.
func TestUnprovenChainDuplicateRejected(t *testing.T) {
	c := newCampaign(t, "Duplicate Program")
	f1, f2 := upPair(t, c)
	ids := upIDs(f1, f2)
	if _, err := MaterializeChainOpts(c, ids, "Freeze chain duplicate guard",
		"", nil, nil, MaterializeOpts{Unproven: true}); err != nil {
		t.Fatalf("first materialize: %v", err)
	}
	_, err := MaterializeChainOpts(c, ids, "Freeze chain duplicate guard", "",
		nil, nil, MaterializeOpts{Unproven: true})
	if err == nil {
		t.Fatal("second materialize of the same member set was accepted")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %v", err)
	}
}

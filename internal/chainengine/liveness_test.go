package chainengine

// liveness_test.go — IMPROVEMENTS B1: the non-economic liveness terminal.
// A chain whose last finding grants liveness_loss is a terminal path (the
// protocol stops serving), priced at the blast-radius floor — no USD figure
// is defensible for a freeze.

import (
	"strings"
	"testing"

	"websec/internal/capabilities"
	"websec/internal/findings"
	"websec/internal/risk"
	"websec/internal/state"
	"websec/internal/validation"
)

// lvPair is the two-member liveness chain: the first finding grants the
// pause capability the second needs; the second grants the liveness
// terminal. Both are CONFIRMED (the materialization gate).
func lvPair(t *testing.T, c *state.Campaign) (f1, f2 validation.Value) {
	t.Helper()
	f1 = hypo(t, c, "access-control",
		[]string{"control_protocol_pause"}, nil,
		"pause gate reachable by arbitrary EOA")
	f2 = hypo(t, c, "chain-freeze",
		[]string{"liveness_loss"},
		[]string{"control_protocol_pause"},
		"pause with no timelock freezes all withdrawals")
	confirm(t, c, objStr(f1, "finding_id"), "E5", "T3")
	confirm(t, c, objStr(f2, "finding_id"), "E5", "T3")
	return f1, f2
}

// TestLivenessChainMaterializes: a chain ending in liveness_loss materializes
// with the liveness terminal annotation and the B1 non-USD pricing.
func TestLivenessChainMaterializes(t *testing.T) {
	c := newCampaign(t, "Liveness Program")
	f1, f2 := lvPair(t, c)
	ids := []string{objStr(f1, "finding_id"), objStr(f2, "finding_id")}
	term := validation.VObj(
		kv("capability", validation.VStr("liveness_loss")),
		kv("via_finding", validation.VStr(objStr(f2, "finding_id"))))
	ch, err := MaterializeChain(c, ids, "Chain freeze with no recovery path",
		"EOA pauses; nobody can unpause; every withdrawal stops", nil, &term)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	// the terminal annotation
	if got := objStr(objAt(ch, "terminal"), "capability"); got != "liveness_loss" {
		t.Fatalf("terminal.capability = %q, want liveness_loss", got)
	}
	if got := objStr(objAt(ch, "terminal"), "via_finding"); got != objStr(f2, "finding_id") {
		t.Fatalf("terminal.via_finding = %q", got)
	}
	// the B1 pricing on the CHAIN super-finding
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		t.Fatal(err)
	}
	var chainFinding validation.Value
	for _, f := range all {
		if objStr(f, "status") == "CHAIN" {
			chainFinding = f
		}
	}
	if chainFinding.Kind == validation.Null {
		t.Fatal("no CHAIN super-finding")
	}
	impact := objAt(chainFinding, "economic_impact")
	if got := objStr(impact, "blast_radius"); got != "protocol-solvency" {
		t.Errorf("blast_radius = %q, want protocol-solvency", got)
	}
	if got := objStr(impact, "kind"); got != "liveness" {
		t.Errorf("kind = %q, want liveness", got)
	}
	if pb := objAt(impact, "priceable"); pb.Kind != validation.Bool || pb.B {
		t.Errorf("priceable = %v, want false", pb)
	}
	if got := objStr(impact, "ceiling"); got == "" ||
		got != "liveness terminal: no USD figure is defensible — a frozen "+
			"chain freezes every user's funds; the blast radius is the price" {
		t.Errorf("ceiling = %q", got)
	}
	if hasKey(impact, "max_loss_usd") || hasKey(impact, "extractable_usd") {
		t.Errorf("liveness impact must carry no USD figures: %v", impact)
	}
}

// TestLivenessChainKeepsBridgeCanonical: a member already claiming
// bridge-canonical keeps its 8.0 weight — the floor never downgrades.
func TestLivenessChainKeepsBridgeCanonical(t *testing.T) {
	c := newCampaign(t, "Bridge Liveness")
	f1, f2 := lvPair(t, c)
	f2r, err := findings.LoadFinding(c, objStr(f2, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	ei := objAt(f2r, "economic_impact")
	if ei.Kind != validation.Obj {
		ei = validation.VObj()
	}
	ei.O = validation.SetOrAppend(ei.O, "blast_radius",
		validation.VStr("bridge-canonical"))
	f2r.O = validation.SetOrAppend(f2r.O, "economic_impact", ei)
	if err := findings.SaveFinding(c, &f2r); err != nil {
		t.Fatal(err)
	}
	term := validation.VObj(
		kv("capability", validation.VStr("liveness_loss")),
		kv("via_finding", validation.VStr(objStr(f2, "finding_id"))))
	_, err = MaterializeChain(c,
		[]string{objStr(f1, "finding_id"), objStr(f2, "finding_id")},
		"Bridged capital frozen by the chain", "", nil, &term)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range all {
		if objStr(f, "status") != "CHAIN" {
			continue
		}
		impact := objAt(f, "economic_impact")
		if got := objStr(impact, "blast_radius"); got != "bridge-canonical" {
			t.Fatalf("blast_radius = %q, want bridge-canonical", got)
		}
		if got := objStr(impact, "kind"); got != "liveness" {
			t.Fatalf("kind = %q, want liveness", got)
		}
	}
}

// TestLivenessTerminalWithoutAnnotationIsUnpriced: the B1 pricing is gated on
// the terminal annotation — the same members without one keep the plain
// (empty) economic impact. Golden-safe: no new fields appear unless the
// operator names the liveness terminal.
func TestLivenessTerminalWithoutAnnotationIsUnpriced(t *testing.T) {
	c := newCampaign(t, "Liveness Unannotated")
	f1, f2 := lvPair(t, c)
	ch, err := MaterializeChain(c,
		[]string{objStr(f1, "finding_id"), objStr(f2, "finding_id")},
		"Unannotated pair over the same members", "", nil, nil)
	if err != nil {
		t.Fatalf("materialize: %v", err)
	}
	if hasKey(ch, "terminal") {
		t.Fatalf("terminal must be absent without an annotation: %v", ch)
	}
	all, _ := findings.LoadAllFindings(c)
	for _, f := range all {
		if objStr(f, "status") != "CHAIN" {
			continue
		}
		impact := objAt(f, "economic_impact")
		if got := objStr(impact, "kind"); got != "" {
			t.Fatalf("kind = %q, want absent", got)
		}
		if got := objStr(impact, "blast_radius"); got != "" {
			t.Fatalf("blast_radius = %q, want absent", got)
		}
	}
}

// TestFindTerminalChainsFindsLivenessTerminal: the liveness terminal is a
// terminal for the search (default mode, CONFIRMED findings).
func TestFindTerminalChainsFindsLivenessTerminal(t *testing.T) {
	c := newCampaign(t, "Liveness Search")
	_, f2 := lvPair(t, c)
	paths, err := FindTerminalChains(c, nil, 5, 1)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, p := range paths {
		if objStr(p, "terminal_capability") == "liveness_loss" {
			found++
			if got := objStr(p, "terminal_finding"); got != objStr(f2, "finding_id") {
				t.Errorf("terminal_finding = %q", got)
			}
		}
	}
	if found != 1 {
		t.Fatalf("liveness terminal paths = %d, want 1: %v", found, paths)
	}
}

// TestFindTerminalChainsModeIncludesHypothesis: the B1/B3 mode admits
// unconfirmed findings as nodes — a HYPOTHESIS liveness finding ends a path
// in mode, and never in default mode.
func TestFindTerminalChainsModeIncludesHypothesis(t *testing.T) {
	c := newCampaign(t, "Liveness Unproven")
	// f1 is CONFIRMED and grants the capability f2 needs; f2 is a HYPOTHESIS
	// that grants the liveness terminal.
	f1 := hypo(t, c, "access-control", []string{"control_protocol_pause"}, nil,
		"pause gate reachable by arbitrary EOA")
	confirm(t, c, objStr(f1, "finding_id"), "E5", "T3")
	hypo(t, c, "chain-freeze", []string{"liveness_loss"},
		[]string{"control_protocol_pause"},
		"pause with no timelock freezes all withdrawals")

	defaultPaths, err := FindTerminalChains(c, nil, 5, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range defaultPaths {
		if objStr(p, "terminal_capability") == "liveness_loss" {
			t.Fatalf("default mode must not surface a hypothesis terminal: %v",
				p)
		}
	}
	modePaths, err := FindTerminalChainsMode(c, nil, 5, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, p := range modePaths {
		if objStr(p, "terminal_capability") == "liveness_loss" {
			found++
		}
	}
	if found != 1 {
		t.Fatalf("mode liveness paths = %d, want 1: %v", found, modePaths)
	}
}

// TestTerminalReportNotePresenceGated: the liveness sentence in the report
// note appears only when a liveness terminal surfaced (the additive
// convention — a campaign without one keeps its exact note bytes).
func TestTerminalReportNotePresenceGated(t *testing.T) {
	const baseNote = "terminal paths search CONFIRMED findings only; " +
		"terminal = asset-kind capability granted by the last finding"

	// without a liveness terminal: the note is byte-identical to pre-B1
	c1 := newCampaign(t, "Asset Only")
	f1 := hypo(t, c1, "oracle-manipulation",
		[]string{"drain_treasury"}, nil,
		"price manipulation drains the treasury")
	confirm(t, c1, objStr(f1, "finding_id"), "E5", "T3")
	rep, err := TerminalReport(c1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(rep, "note"); got != baseNote {
		t.Fatalf("note = %q, want the pre-B1 bytes\n%s", got, baseNote)
	}

	// with a liveness terminal: the sentence is appended
	c2 := newCampaign(t, "Asset Plus Liveness")
	lvPair(t, c2)
	rep2, err := TerminalReport(c2, nil)
	if err != nil {
		t.Fatal(err)
	}
	note2 := objStr(rep2, "note")
	if note2 != baseNote+"; liveness terminal (B1) = liveness_loss granted "+
		"by the last finding — non-economic: the freeze itself is the impact" {
		t.Fatalf("note = %q", note2)
	}
}

// TestLivenessCapabilityVectors pins the registry side of B1.
func TestLivenessCapabilityVectors(t *testing.T) {
	if !capabilities.IsTerminal("liveness_loss") {
		t.Fatal("liveness_loss must be a terminal")
	}
	if !capabilities.IsLivenessTerminal("liveness_loss") {
		t.Fatal("liveness_loss must be a liveness terminal")
	}
	if capabilities.IsLivenessTerminal("drain_treasury") {
		t.Fatal("drain_treasury is economic, not liveness")
	}
	if !capabilities.IsEconomicTerminal("drain_treasury") {
		t.Fatal("drain_treasury must be economic")
	}
	if capabilities.IsEconomicTerminal("liveness_loss") {
		t.Fatal("liveness_loss is non-economic")
	}
	if capabilities.IsTerminal("control_protocol_pause") {
		t.Fatal("a state capability is not a terminal")
	}
}

// TestLivenessChainRiskCalibration: the risk stage picks the liveness
// blast_radius up automatically (the spec's "no new factor" clause) — a
// frozen chain scores at the protocol-solvency weight with no USD figure.
func TestLivenessChainRiskCalibration(t *testing.T) {
	c := newCampaign(t, "Liveness Risk")
	f1, f2 := lvPair(t, c)
	term := validation.VObj(
		kv("capability", validation.VStr("liveness_loss")),
		kv("via_finding", validation.VStr(objStr(f2, "finding_id"))))
	if _, err := MaterializeChain(c,
		[]string{objStr(f1, "finding_id"), objStr(f2, "finding_id")},
		"Chain freeze, priced", "", nil, &term); err != nil {
		t.Fatalf("materialize: %v", err)
	}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		t.Fatal(err)
	}
	var chainFinding validation.Value
	for _, f := range all {
		if objStr(f, "status") == "CHAIN" {
			chainFinding = f
		}
	}
	if chainFinding.Kind == validation.Null {
		t.Fatal("no CHAIN super-finding")
	}
	r, err := risk.ValidatedRisk(chainFinding)
	if err != nil {
		t.Fatal(err)
	}
	rationale := objStr(r, "rationale")
	if !strings.Contains(rationale, "blast_radius(protocol-solvency)=") {
		t.Fatalf("rationale = %q, want the protocol-solvency weight",
			rationale)
	}
	if strings.Contains(rationale, "extractable") {
		t.Fatalf("rationale = %q, must carry NO extractable line (non-USD)",
			rationale)
	}
}

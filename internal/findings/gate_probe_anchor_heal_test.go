package findings_test

// gate_probe_anchor_heal_test.go: the operator-facing copy guard for the
// B10(a) heal line, plus the pin that keeps the copied B4 risk predicate in
// step with the planner's.
//
// WHY THE HEAL IS NOT IN GATE_REMEDIATION. The catalog is a static
// check-id -> template map, and bounty's TestGateExplainCatalogByteExact pins
// it to the Python catalog's exact 11 ids. B10(a)'s heal cannot be a static
// template anyway: it names the ROW'S OWN Q-* priority (or, when the surface
// row was never emitted, the emit that mints one), so it is rendered per
// clause by AnchorBlindSpot.Heal. That makes the existing catalog guard blind
// to it — which is exactly why the guard below is run over the heal text
// directly, using the same segment/flag scanner the catalog guard uses
// (remediationSegments / flagToken, gate_remediation_guard_test.go).

import (
	"strings"
	"testing"

	"websec/internal/cli"
	"websec/internal/findings"
	"websec/internal/planner"
	"websec/internal/validation"
)

// probeAnchorHealFlags is the accepted `--flag` vocabulary of the two verbs
// the heal names, read off cmd_answered_args.go and cmd_probes.go — never
// guessed from a usage line.
var probeAnchorHealFlags = map[string][]string{
	"answered": {"--reason", "--reason-all", "--ref", "--families",
		"--symmetry", "--reconcile", "--anchor", "--override-reason",
		"--override-dismissal", "--passes", "--interim", "--finding",
		"--actor", "--help"},
	"probes": {"--emit", "--per-axis", "--total", "--all", "--json",
		"--axis", "--anchor-blind", "--reason", "--actor", "--help"},
}

// TestProbeAnchorHealNamesRealCommand is the non-vacuous guard: every `webv2
// <verb>` the heal prints must be a dispatched command, and every `--flag` it
// prints must be one that verb's parser accepts.
func TestProbeAnchorHealNamesRealCommand(t *testing.T) {
	dispatched := map[string]bool{}
	for _, name := range cli.CommandNames() {
		dispatched[name] = true
	}
	if len(dispatched) == 0 {
		t.Fatal("CLI dispatch registry is empty — this guard would pass vacuously")
	}
	spots := []findings.AnchorBlindSpot{
		{RowID: "34589e8588", PriorityID: "Q-008"}, // emitted: answer the row
		{RowID: "a047e6509f"},                      // unemitted: emit first
	}
	verbs, flags := 0, 0
	for _, spot := range spots {
		heal := spot.Heal("C-f4e27261f7")
		if !strings.Contains(heal, spot.RowID) {
			t.Errorf("heal %q does not name its row %s", heal, spot.RowID)
		}
		segs := remediationSegments(heal)
		if len(segs) == 0 {
			t.Fatalf("heal %q names no `webv2` command", heal)
		}
		for _, seg := range segs {
			if seg.verb == "" {
				t.Errorf("heal %q has a segment with no verb: %v", heal,
					seg.tokens)
				continue
			}
			verbs++
			if !dispatched[seg.verb] {
				t.Errorf("heal %q tells the operator to run %q, which the CLI "+
					"does not dispatch", heal, seg.verb)
			}
			allowed := probeAnchorHealFlags[seg.verb]
			if allowed == nil {
				t.Errorf("no flag table entry for verb %q — seed "+
					"probeAnchorHealFlags from the parser", seg.verb)
				continue
			}
			for _, tok := range seg.tokens {
				flag := flagToken(tok)
				if flag == "" {
					continue
				}
				flags++
				if !probeAnchorFlagAllowed(allowed, flag) {
					t.Errorf("heal %q tells the operator to run `webv2 %s ... "+
						"%s`, which %s does not accept (accepted: %s)", heal,
						seg.verb, flag, seg.verb, strings.Join(allowed, " "))
				}
			}
		}
	}
	if verbs == 0 || flags == 0 {
		t.Fatalf("guard checked %d verb(s) and %d flag(s) — it has gone blind",
			verbs, flags)
	}
	// The disposition form itself: a probe-row closure needs a reason AND the
	// anchor field it claims is safe (planner.checkAnchorless), and the
	// closing status is one the answered verb really closes rows with.
	emitted := spots[0].Heal("C-f4e27261f7")
	for _, want := range []string{" answered --reason ", " --anchor "} {
		if !strings.Contains(emitted, want) {
			t.Errorf("heal %q misses %q", emitted, want)
		}
	}
	if !strings.Contains(emitted, " Q-008 answered ") {
		t.Errorf("heal %q must answer the row's own priority", emitted)
	}
	if !strings.Contains(spots[1].Heal("C-f4e27261f7"),
		"probes C-f4e27261f7 run --emit") {
		t.Errorf("an unemitted row must be minted first: %q",
			spots[1].Heal("C-f4e27261f7"))
	}
}

// probeAnchorFlagAllowed is membership in the local accepted-flag table.
func probeAnchorFlagAllowed(allowed []string, flag string) bool {
	for _, a := range allowed {
		if a == flag {
			return true
		}
	}
	return false
}

// TestProbeAnchorCatalogStaysPinned documents the deliberate decision above:
// GATE_REMEDIATION keeps its pinned 11 ids and B10(a) is NOT one of them,
// because bounty's TestGateExplainCatalogByteExact pins the catalog's size to
// the Python catalog. If catalog coverage for this check is ever wanted, that
// bounty golden has to move in the SAME commit — this test is the reminder.
func TestProbeAnchorCatalogStaysPinned(t *testing.T) {
	if rem, ok := findings.GATE_REMEDIATION[findings.ProbeAnchorCheckID]; ok {
		t.Fatalf("GATE_REMEDIATION gained %q = %q — that breaks bounty's "+
			"pinned catalog size; if catalog coverage is wanted, update "+
			"confirmedRemediationGolden/explainGolden in the same commit and "+
			"delete this test",
			findings.ProbeAnchorCheckID, rem)
	}
	if len(findings.GATE_REMEDIATION) == 0 {
		t.Fatal("GATE_REMEDIATION is empty — this pin would pass vacuously")
	}
}

// probeAnchorRiskVectors is the B4 predicate's vector table. The internal
// firing-rules test drives the CHECKER with these same coordinates (tier 0,
// assertion_gap 3, tier 1/gap 2, a missing tier, tier 5/gap 10) and the test
// below pins planner.HighRiskRow to the same answers — so if B4's rule moves,
// this fails and the copy in gate_probe_anchor.go is updated in the same
// commit instead of silently re-labelling rows.
func probeAnchorRiskVectors() []struct {
	name string
	row  validation.Value
	want bool
} {
	return []struct {
		name string
		row  validation.Value
		want bool
	}{
		{"tier0", validation.VObj(validation.KV{K: "tier", V: validation.VInt(0)}), true},
		{"gap3", validation.VObj(validation.KV{K: "tier", V: validation.VInt(2)},
			validation.KV{K: "assertion_gap", V: validation.VInt(3)}), true},
		{"low", validation.VObj(validation.KV{K: "tier", V: validation.VInt(1)},
			validation.KV{K: "assertion_gap", V: validation.VInt(2)}), false},
		{"missing tier reads as 0", validation.VObj(), true},
		{"tier5 gap10", validation.VObj(validation.KV{K: "tier", V: validation.VInt(5)},
			validation.KV{K: "assertion_gap", V: validation.VInt(10)}), true},
	}
}

// TestProbeAnchorHighRiskSourceMatchesVectors pins planner.HighRiskRow (the
// source of truth) against the vector table; the COPY (gateHighRiskRow) is
// pinned against the same table in gate_probe_anchor_copy_test.go — the
// internal test package, where it is reachable (round-2 review, B10a
// finding 1: a test that only exercised planner never looked at the copy).
func TestProbeAnchorHighRiskSourceMatchesVectors(t *testing.T) {
	checked := 0
	for _, v := range probeAnchorRiskVectors() {
		checked++
		if got := planner.HighRiskRow(v.row); got != v.want {
			t.Errorf("planner.HighRiskRow(%s) = %v, want %v — B4's rule moved; "+
				"update gateHighRiskRow in gate_probe_anchor.go and this vector "+
				"table in the same commit", v.name, got, v.want)
		}
	}
	if checked < 5 {
		t.Fatalf("only %d vectors checked", checked)
	}
}

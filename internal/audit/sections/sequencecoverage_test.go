// Port of tests/test_audit_sequence_coverage.py — audit §12 must use the
// gate's campaign-aware predicate. Run-3 bug: the audit flagged "sequence
// PoC coverage missing" for a 2-step exploit_sequence on a campaign with NO
// fork target — while the CONFIRMED gate (onchain_sequence_required)
// declares it not-applicable. Audit and gate must agree.
//
// The section is exercised directly (the sections package cannot import the
// audit package without an import cycle); the whole-report ok/summary parity
// is pinned by internal/audit's own tests.
package sections

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// seqPayload is SEQ_PAYLOAD.
func seqPayload(t *testing.T) validation.Value {
	t.Helper()
	v, err := validation.ParseOrdered([]byte(`{
      "title": "two-step drain",
      "root_cause": {"class": "reentrancy-drain",
                     "description": "two-step reentrancy drain across calls"},
      "attacker": {"profile": "arbitrary EOA", "capabilities": ["drain"]},
      "exploit_sequence": [
        {"step": 1, "actor": "attacker", "action": "drain()"},
        {"step": 2, "actor": "attacker", "action": "drain() again"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// campaignWithTree is _campaign_with_tree: a source-only pin.
func campaignWithTree(t *testing.T, name string) *state.Campaign {
	t.Helper()
	root := t.TempDir()
	c, err := state.Init(root, name, state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "src")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "C.sol"), []byte("// c"),
		0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.PinSourceSnapshot(c, target, nil, nil); err != nil {
		t.Fatal(err)
	}
	return c
}

// sectionValue runs the section and fails on the degraded entry.
func sectionValue(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	v, err := SequenceCoverage(c)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(v, "required").Kind == validation.Null {
		t.Fatalf("degraded section: %s", validation.DumpIndented(v))
	}
	return v
}

func TestNoForkTargetRowNotApplicableAndSectionOK(t *testing.T) {
	c := campaignWithTree(t, "seqcov")
	if _, err := findings.IngestHypothesis(c, seqPayload(t), "code", "t", ""); err != nil {
		t.Fatal(err)
	}
	sec := sectionValue(t, c)
	if intOfSection(sec, "required") != 1 || intOfSection(sec, "applicable") != 0 ||
		intOfSection(sec, "not_applicable") != 1 {
		t.Fatalf("counts = %s", validation.DumpIndented(sec))
	}
	row := validation.ObjAt(sec, "rows").A[0]
	if av := validation.ObjAt(row, "applicable"); av.Kind != validation.Bool || av.B {
		t.Errorf("applicable = %v, want false", av)
	}
	if p := validation.ObjAt(row, "problem"); p.Kind != validation.Null {
		t.Errorf("problem = %v, want null", p)
	}
	if n := len(validation.ObjAt(sec, "problems").A); n != 0 {
		t.Errorf("problems = %d, want 0", n)
	}
	if ok := validation.ObjAt(sec, "ok"); ok.Kind != validation.Bool || !ok.B {
		t.Errorf("ok = %v, want true", ok)
	}
}

func TestForkTargetRowApplicableAndFlagged(t *testing.T) {
	c := campaignWithTree(t, "seqcov2")
	sid, err := c.ActiveSnapshotIDOrNone()
	if err != nil || sid == nil {
		t.Fatalf("no active snapshot: %v", err)
	}
	chain, err := validation.ParseOrdered([]byte(
		`{"chain_id": 1, "fork_block": 1000, "rpc": "local-anvil"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot.AttachChainPin(c, *sid, chain); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.IngestHypothesis(c, seqPayload(t), "code", "t", ""); err != nil {
		t.Fatal(err)
	}
	sec := sectionValue(t, c)
	if intOfSection(sec, "applicable") != 1 ||
		intOfSection(sec, "not_applicable") != 0 {
		t.Fatalf("counts = %s", validation.DumpIndented(sec))
	}
	row := validation.ObjAt(sec, "rows").A[0]
	if av := validation.ObjAt(row, "applicable"); av.Kind != validation.Bool || !av.B {
		t.Errorf("applicable = %v, want true", av)
	}
	prob := validation.ObjStr(row, "problem")
	if !strings.Contains(prob, "sequence PoC coverage missing") {
		t.Errorf("problem = %q", prob)
	}
	if ok := validation.ObjAt(sec, "ok"); ok.Kind != validation.Bool || ok.B {
		t.Errorf("ok = %v, want false", ok)
	}
}

func TestNonSequenceFindingAbsentFromSection(t *testing.T) {
	c := campaignWithTree(t, "seqcov3")
	p := seqPayload(t)
	for i, kv := range p.O {
		if kv.K == "exploit_sequence" {
			p.O[i].V = validation.VArr(validation.VObj(
				KV("step", validation.VInt(1)),
				KV("actor", validation.VStr("attacker")),
				KV("action", validation.VStr("drain()"))))
		}
	}
	if _, err := findings.IngestHypothesis(c, p, "code", "t", ""); err != nil {
		t.Fatal(err)
	}
	sec := sectionValue(t, c)
	if intOfSection(sec, "required") != 0 {
		t.Errorf("required = %v, want 0", validation.ObjAt(sec, "required"))
	}
	if rows := validation.ObjAt(sec, "rows"); rows.Kind != validation.Arr || len(rows.A) != 0 {
		t.Errorf("rows = %v, want []", rows)
	}
}

// intOfSection reads a section counter (Int).
func intOfSection(v validation.Value, key string) int64 {
	got := validation.ObjAt(v, key)
	if got.Kind == validation.Int {
		if got.Big != "" {
			n := int64(0)
			for _, ch := range got.Big {
				n = n*10 + int64(ch-'0')
			}
			return n
		}
		return got.I
	}
	return -1
}

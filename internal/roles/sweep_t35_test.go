package roles

import (
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// t35SeqFinding is test_sequence_guidance.py::_mk: ingest through the real
// path, move to POSSIBLE, then attach the declared exploit_sequence.
func t35SeqFinding(t *testing.T, c *state.Campaign,
	seq []validation.Value) string {
	t.Helper()
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr("multi-tx sequence bug")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("description", validation.VStr(
				"missing check across two calls")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("contract", validation.VStr("V")),
			kv("function", validation.VStr("claim"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()))),
	), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "", "",
		false); err != nil {
		t.Fatal(err)
	}
	lf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if seq != nil {
		lf = setKey(lf, "exploit_sequence", validation.VArr(seq...))
	}
	if err := findings.SaveFinding(c, &lf); err != nil {
		t.Fatal(err)
	}
	return fid
}

func t35SeqRow(step int64, actor, action string) validation.Value {
	return validation.VObj(
		kv("step", validation.VInt(step)),
		kv("actor", validation.VStr(actor)),
		kv("action", validation.VStr(action)))
}

// Port of tests/test_sequence_guidance.py::test_roles_parity_shared_helper.
func TestRolesParitySharedHelper(t *testing.T) {
	c := newCamp(t)
	fidSeq := t35SeqFinding(t, c, []validation.Value{
		t35SeqRow(1, "alice", "deposit"), t35SeqRow(2, "bob", "drain")})
	fidSolo := t35SeqFinding(t, c, nil)

	prop, err := BuildProposerContext(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	crit, err := BuildCriticContext(c, fidSeq)
	if err != nil {
		t.Fatal(err)
	}
	var entry validation.Value
	for _, r := range objAt(prop, "sequence_requirements").A {
		if objStr(r, "finding_id") == fidSeq {
			entry = r
		}
	}
	if entry.Kind != validation.Obj {
		t.Fatalf("proposer row for %s missing: %s", fidSeq,
			validation.CanonCompact(objAt(prop, "sequence_requirements")))
	}
	sr := objAt(crit, "sequence_requirement")
	if objStr(sr, "finding_id") != objStr(entry, "finding_id") {
		t.Errorf("finding_id = %q", objStr(sr, "finding_id"))
	}
	if objAt(sr, "steps").I != objAt(entry, "steps").I {
		t.Errorf("steps = %v, want %v", objAt(sr, "steps"),
			objAt(entry, "steps"))
	}
	if objAt(sr, "n_actors").I != int64(len(objAt(entry, "actors").A)) {
		t.Errorf("n_actors = %v, want %d", objAt(sr, "n_actors"),
			len(objAt(entry, "actors").A))
	}
	if objStr(sr, "note") != objStr(entry, "note") {
		t.Errorf("note = %q, want %q", objStr(sr, "note"),
			objStr(entry, "note"))
	}
	if objAt(entry, "steps").I != 2 {
		t.Errorf("steps = %v, want 2", objAt(entry, "steps"))
	}
	if got := t35StrList(objAt(entry, "actors")); strings.Join(got, ",") !=
		"alice,bob" {
		t.Errorf("actors = %v, want [alice bob]", got)
	}
	if objAt(sr, "n_actors").I != 2 {
		t.Errorf("n_actors = %v, want 2", objAt(sr, "n_actors"))
	}
	soloCrit, err := BuildCriticContext(c, fidSolo)
	if err != nil {
		t.Fatal(err)
	}
	if objAt(soloCrit, "sequence_requirement").Kind != validation.Null {
		t.Errorf("solo sequence_requirement = %v, want null",
			objAt(soloCrit, "sequence_requirement"))
	}
	for _, r := range objAt(prop, "sequence_requirements").A {
		if objStr(r, "finding_id") == fidSolo {
			t.Error("the solo finding must not appear in the proposer rows")
		}
	}
	// value-level isolation: distinctive actor strings must not reach the
	// critic bundle even though the key-level check stays clean.
	blob := blob(crit)
	if strings.Contains(blob, "alice") || strings.Contains(blob, "bob") {
		t.Error("critic bundle leaks proposer-controlled actor strings")
	}
}

// Port of tests/test_sequence_guidance.py::test_critic_bundle_hides_distinctive_actor_values.
func TestCriticBundleHidesDistinctiveActorValues(t *testing.T) {
	c := newCamp(t)
	fid := t35SeqFinding(t, c, []validation.Value{
		t35SeqRow(1, "EVIL_ACTOR_ZZ9", "deposit"),
		t35SeqRow(2, "VICTIM_XYZ_QQ", "drain")})
	crit, err := BuildCriticContext(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	blob := blob(crit)
	if strings.Contains(blob, "EVIL_ACTOR_ZZ9") ||
		strings.Contains(blob, "VICTIM_XYZ_QQ") {
		t.Fatal("hostile actor marker survived into the critic bundle")
	}
	sr := objAt(crit, "sequence_requirement")
	if objAt(sr, "steps").I != 2 {
		t.Errorf("steps = %v, want 2", objAt(sr, "steps"))
	}
	if objAt(sr, "n_actors").I != 2 {
		t.Errorf("n_actors = %v, want 2", objAt(sr, "n_actors"))
	}
	// the proposer leg still sees the full row (it wrote the sequence).
	prop, err := BuildProposerContext(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	var entry validation.Value
	for _, r := range objAt(prop, "sequence_requirements").A {
		if objStr(r, "finding_id") == fid {
			entry = r
		}
	}
	if entry.Kind != validation.Obj {
		t.Fatalf("proposer row for %s missing", fid)
	}
	got := strings.Join(t35StrList(objAt(entry, "actors")), ",")
	if got != "EVIL_ACTOR_ZZ9,VICTIM_XYZ_QQ" {
		t.Errorf("proposer actors = %q", got)
	}
}

// t35StrList reads an array value of strings.
func t35StrList(v validation.Value) []string {
	out := []string{}
	for _, e := range v.A {
		out = append(out, e.S)
	}
	return out
}

// Port of tests/test_tier1_minor_sweep.py::test_s2_critic_bundle_renders_zero_padded_citation.
func TestS2CriticBundleRendersZeroPaddedCitation(t *testing.T) {
	c := newCamp(t)
	writeSource(t, c, "contract V {}\n")
	if _, err := invariants.SeedFromModel(c, validation.VObj(
		kv("invariants", validation.VArr(validation.VObj(
			kv("id", validation.VStr("INV-1")),
			kv("statement", validation.VStr(
				"totalAssets never decreases except via withdraw")),
			kv("severity_if_broken", validation.VStr("critical"))))))); err != nil {
		t.Fatal(err)
	}
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr("sweep drains the pool")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("description", validation.VStr(
				"unguarded setter lets anyone drain the pool")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("sweep"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr())))), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	f = setKey(f, "security_invariants", validation.VArr(validation.VObj(
		kv("id", validation.VStr("INV-001")),
		kv("statement", validation.VStr(
			"totalAssets never decreases except via withdraw")))))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	b, err := BuildCriticContext(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	iv := objAt(b, "invariant_verification")
	if len(iv.A) != 1 {
		t.Fatalf("invariant_verification = %s", validation.CanonCompact(iv))
	}
	if got := objStr(iv.A[0], "statement"); got !=
		"totalAssets never decreases except via withdraw" {
		t.Errorf("statement = %q", got)
	}
	if got := objStr(iv.A[0], "status"); got != "UNVERIFIED" {
		t.Errorf("status = %q, want UNVERIFIED", got)
	}
}

// Port of tests/test_bundle_corpus_keys.py::test_bundle_still_clean_asserts.
func TestBundleStillCleanAsserts(t *testing.T) {
	c := newCamp(t)
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", filepath.Join(t.TempDir(), "gmem"))
	seedGlobalMemoryRow(t, "MEM-b0001", "Reentrancy Attack")
	cls := "logic-error"
	b, err := BuildProposerContext(c, &cls)
	if err != nil {
		t.Fatal(err)
	}
	// the bundle must stay plain JSON (canonical serialization never panics
	// and round-trips through the parser).
	blob := validation.CanonCompact(b)
	round, err := validation.ParseOrdered([]byte(blob))
	if err != nil {
		t.Fatalf("bundle is not plain JSON: %v", err)
	}
	if objAt(round, "negative_memory").Kind != validation.Obj {
		t.Errorf("negative_memory = %s",
			validation.CanonCompact(objAt(round, "negative_memory")))
	}
	if blob == "" {
		t.Error("bundle serialized to an empty document")
	}
}

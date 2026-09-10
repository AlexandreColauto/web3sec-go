package briefing

// Port of tests/test_work_order.py's brief-side half: every rendered
// work-list uses risk.work_order_key (blast rank desc, unprivileged first,
// band desc, finding_id), including within the E6 view's groups.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/bounty"

	"websec/internal/findings"
	"websec/internal/floors"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// t35WorkHypo is test_work_order.py::hypo: an ingest carrying blast_radius
// and required_privileges.
func t35WorkHypo(t *testing.T, c *state.Campaign, title, blast, cls string,
	privs []string) validation.Value {
	t.Helper()
	privList := []validation.Value{}
	for _, p := range privs {
		privList = append(privList, validation.VStr(p))
	}
	f, err := findings.IngestHypothesis(c, validation.VObj(
		kv("title", validation.VStr(title)),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr(cls)),
			kv("description", validation.VStr("mechanism described in detail here")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Vault.sol")),
			kv("contract", validation.VStr("Vault")),
			kv("function", validation.VStr("f"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()),
			kv("required_privileges", validation.VArr(privList...)))),
		kv("capabilities", validation.VObj(
			kv("granted", validation.VArr(
				validation.VStr("withdraw_unbacked_assets"))),
			kv("required", validation.VArr()))),
		kv("economic_impact", validation.VObj(
			kv("blast_radius", validation.VStr(blast)))),
	), "code", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// t35SetID is test_work_order.py::_set_id: rename a finding to a chosen
// (schema-valid) id so an order that id-sorting would get wrong is testable.
func t35SetID(t *testing.T, c *state.Campaign, fid, newID string) validation.Value {
	t.Helper()
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(findings.FindingPath(c, fid)); err != nil {
		t.Fatal(err)
	}
	f.O = validation.SetOrAppend(f.O, "finding_id", validation.VStr(newID))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// t35LowFirstPair is _low_first_pair: ids sort OPPOSITE to consequence.
func t35LowFirstPair(t *testing.T, c *state.Campaign,
	prefix string) (validation.Value, validation.Value) {
	t.Helper()
	low := t35SetID(t, c, objStr(t35WorkHypo(t, c, prefix+" low",
		"single-user", "access-control", nil), "finding_id"),
		"F-000000000001")
	high := t35SetID(t, c, objStr(t35WorkHypo(t, c, prefix+" high",
		"bridge-canonical", "access-control", nil), "finding_id"),
		"F-ffffffffffff")
	return low, high
}

// Port of tests/test_work_order.py::test_gate_deficits_are_work_ordered.
func TestGateDeficitsAreWorkOrdered(t *testing.T) {
	c := newCamp(t, "Acme Program")
	low, high := t35LowFirstPair(t, c, "deficit")
	b := build(t, c, false)
	order := t35IDs(listAt(objAt(b, "findings"), "gate_deficits"))
	want := []string{objStr(high, "finding_id"), objStr(low, "finding_id")}
	if !sameStringSet(order, want) || len(order) != len(want) ||
		order[0] != want[0] {
		t.Errorf("gate_deficits order = %v, want %v", order, want)
	}
}

// Port of tests/test_work_order.py::test_structurally_unreachable_is_work_ordered.
func TestStructurallyUnreachableIsWorkOrdered(t *testing.T) {
	c := newCamp(t, "Acme Program")
	low := t35SetID(t, c, objStr(t35WorkHypo(t, c, "stuck low finding",
		"single-user", "cross-chain-replay", nil), "finding_id"),
		"F-000000000001")
	high := t35SetID(t, c, objStr(t35WorkHypo(t, c, "stuck high finding",
		"protocol-solvency", "cross-chain-replay", nil), "finding_id"),
		"F-ffffffffffff")
	b := build(t, c, false)
	order := t35IDs(listAt(objAt(b, "findings"), "structurally_unreachable"))
	want := []string{objStr(high, "finding_id"), objStr(low, "finding_id")}
	if len(order) != len(want) || order[0] != want[0] {
		t.Errorf("structurally_unreachable order = %v, want %v", order, want)
	}
}

// t35ReproducedPossible is the memory_recall_pending fixture: POSSIBLE with a
// confirmed critic verdict and a reproduced E4 run, no memory check yet.
func t35ReproducedPossible(t *testing.T, c *state.Campaign,
	f validation.Value) {
	t.Helper()
	fid := objStr(f, "finding_id")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "", "",
		false); err != nil {
		t.Fatal(err)
	}
	rec, err := sandbox.RegisterExec(c, sandbox.RegisterOpts{
		Profile: "docker-networkless",
		Command: "forge test --match-test test_exploit", FindingID: &fid,
		ReportedBy: "pytest-harness", StdoutText: "PASS: test_exploit\n"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := findings.AddEvidence(c, fid, validation.VObj(
		kv("evidence_id", validation.VStr("EV-"+tail(fid))),
		kv("level", validation.VStr("E4")),
		kv("type", validation.VStr("foundry-test")),
		kv("description", validation.VStr("repro under sandbox")),
		kv("sandbox_profile", objAt(rec, "profile")),
		kv("artifact_id", objAt(rec, "exec_id")))); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.SetCriticVerdict(c, fid, "confirmed", "ok"); err != nil {
		t.Fatal(err)
	}
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := objAt(vf, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "reproduction", validation.VObj(
		kv("status", validation.VStr("reproduced")),
		kv("tier_reached", validation.VStr("T3")),
		kv("attempts", validation.VArr())))
	vf.O = validation.SetOrAppend(vf.O, "verification", ver)
	if err := findings.SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
}

// Port of tests/test_work_order.py::test_memory_recall_pending_is_work_ordered.
func TestMemoryRecallPendingIsWorkOrdered(t *testing.T) {
	c := newCamp(t, "Acme Program")
	low := t35SetID(t, c, objStr(t35WorkHypo(t, c, "recall low",
		"single-user", "access-control", []string{"owner"}), "finding_id"),
		"F-000000000001")
	high := t35SetID(t, c, objStr(t35WorkHypo(t, c, "recall high",
		"protocol-solvency", "access-control", []string{"owner"}),
		"finding_id"), "F-ffffffffffff")
	t35ReproducedPossible(t, c, low)
	t35ReproducedPossible(t, c, high)
	b := build(t, c, false)
	order := strListOf(objAt(objAt(b, "findings"), "memory_recall_pending"))
	want := []string{objStr(high, "finding_id"), objStr(low, "finding_id")}
	if len(order) != len(want) || order[0] != want[0] {
		t.Errorf("memory_recall_pending order = %v, want %v", order, want)
	}
}

// Port of tests/test_work_order.py::test_e6_view_keeps_mandatory_work_first.
func TestE6ViewKeepsMandatoryWorkFirst(t *testing.T) {
	c := newCamp(t, "Acme Program")
	opt := t35SetID(t, c, objStr(t35WorkHypo(t, c, "optional high-blast",
		"protocol-solvency", "access-control", nil), "finding_id"),
		"F-ffffffffffff")
	man := t35SetID(t, c, objStr(t35WorkHypo(t, c, "mandatory low-blast",
		"single-user", "reentrancy", nil), "finding_id"), "F-000000000001")
	confirmSimple(t, c, objStr(opt, "finding_id"))
	confirmSimple(t, c, objStr(man, "finding_id"))
	// raise the reentrancy floor AFTER confirmation: the low-blast finding's
	// verification becomes mandatory, the high-blast one stays optional.
	if _, err := floors.SetFloorPolicy(c, "reentrancy", "E6", "pytest",
		"mandatory independent reproduction"); err != nil {
		t.Fatal(err)
	}
	b := build(t, c, false)
	got := []string{}
	for _, x := range listAt(b, "independent_verification_queue") {
		got = append(got, objStr(x, "finding_id")+"/"+
			pyBool(objAt(x, "mandatory")))
	}
	want := []string{objStr(man, "finding_id") + "/True",
		objStr(opt, "finding_id") + "/False"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("verification queue = %v, want %v", got, want)
	}
	manLine := "independently verify " + objStr(man, "finding_id")
	optLine := "independently verify " + objStr(opt, "finding_id")
	manI, optI := -1, -1
	for i, a := range objAt(b, "next_actions").A {
		if hasPrefix(a.S, manLine) {
			manI = i
		}
		if hasPrefix(a.S, optLine) {
			optI = i
		}
	}
	if manI < 0 || optI < 0 || manI >= optI {
		t.Errorf("next_actions mandatory index %d vs optional %d", manI, optI)
	}
}

// t35IDs reads the finding_id of each row.
func t35IDs(rows []validation.Value) []string {
	out := []string{}
	for _, r := range rows {
		out = append(out, objStr(r, "finding_id"))
	}
	return out
}

// pyBool renders a bool value the Python way.
func pyBool(v validation.Value) string {
	if v.Kind == validation.Bool && v.B {
		return "True"
	}
	return "False"
}

// hasPrefix is strings.HasPrefix for the test file.
func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// Port of tests/test_work_order.py::test_confirmed_queue_and_bounty_list_are_work_ordered.
func TestConfirmedQueueAndBountyListAreWorkOrdered(t *testing.T) {
	c := newCamp(t, "Acme Program")
	policyPath := filepath.Join(t.TempDir(), "policy.json")
	if _, err := bounty.SavePolicy(c, testPolicy, &policyPath); err != nil {
		t.Fatal(err)
	}
	doc, err := validation.ReadJson(c.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	doc.O = validation.SetOrAppend(doc.O, "policy_path", validation.VStr(policyPath))
	if err := validation.WriteJson(c.StatePath, doc, "campaign_state"); err != nil {
		t.Fatal(err)
	}
	low := t35SetID(t, c, objStr(t35WorkHypo(t, c, "confirmed low",
		"single-user", "access-control", []string{"owner"}), "finding_id"),
		"F-000000000001")
	high := t35SetID(t, c, objStr(t35WorkHypo(t, c, "confirmed high",
		"protocol-solvency", "access-control", []string{"owner"}),
		"finding_id"), "F-ffffffffffff")
	confirmSimple(t, c, objStr(low, "finding_id"))
	confirmSimple(t, c, objStr(high, "finding_id"))
	b := build(t, c, false)
	want := []string{objStr(high, "finding_id"), objStr(low, "finding_id")}
	if got := t35IDs(listAt(b, "independent_verification_queue")); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("verification queue = %v, want %v", got, want)
	}
	if got := t35IDs(listAt(objAt(b, "bounty"), "evaluated")); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("bounty.evaluated = %v, want %v", got, want)
	}
}

package risk

// PORT-NOTE tests/test_work_order.py: the pure key half (risk.work_order_key).
// The brief-rendering half of that suite drives webv2.briefing, which is
// unported — those cases are listed as unresolved.

import (
	"fmt"
	"sort"
	"strconv"
	"testing"

	"websec/internal/validation"
)

// woFinding parses one finding document.
func woFinding(t *testing.T, doc string) validation.Value {
	t.Helper()
	f, err := validation.ParseOrdered([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// fnd is the Python fixture fnd(): a minimal finding dict carrying exactly
// the three recorded inputs the key reads.
func fnd(fid, blast string, privs []string, level string) validation.Value {
	privArr := validation.VArr()
	for _, p := range privs {
		privArr.A = append(privArr.A, validation.VStr(p))
	}
	return validation.VObj(
		kv("finding_id", validation.VStr(fid)),
		kv("title", validation.VStr(fid)),
		kv("status", validation.VStr("POSSIBLE")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("description", validation.VStr("mechanism")))),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("contract", validation.VStr("V")),
			kv("function", validation.VStr("f"))))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("required_privileges", privArr))),
		kv("economic_impact", validation.VObj(
			kv("blast_radius", validation.VStr(blast)))),
		kv("evidence", validation.VArr(validation.VObj(
			kv("level", validation.VStr(level))))),
	)
}

func woKey(t *testing.T, f validation.Value) WorkOrderKey {
	t.Helper()
	k, err := WorkOrderKeyFor(f)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// woRepr renders the key exactly as CPython's tuple repr does.
func woRepr(k WorkOrderKey) string {
	b := "True"
	if !k.Privileged {
		b = "False"
	}
	return "(" + validation.PythonFloat(k.BlastRank) + ", " + b + ", " +
		strconv.Itoa(k.BandRank) + ", " +
		validation.PyReprStr(k.FindingID) + ")"
}

// workOrderVectors are generated from the live Python (webv2.risk.work_order_key
// repr, CPython 3.14) — see work_order.json [untracked].
var workOrderVectors = []struct {
	doc  string
	want string
}{
	{`{"finding_id":"F-aaaaaaaaaaa1","status":"POSSIBLE","root_cause":` +
		`{"class":"access-control","description":"mechanism"},"affected":` +
		`[{"path":"src/V.sol","contract":"V","function":"f"}],"attacker":` +
		`{"profile":"arbitrary EOA","required_privileges":["owner"]},` +
		`"economic_impact":{"blast_radius":"protocol-solvency"},` +
		`"evidence":[{"level":"E2"}]}`,
		"(-7.0, True, -3, 'F-aaaaaaaaaaa1')"},
	{`{"finding_id":"F-bbbbbbbbbbb2","status":"POSSIBLE","root_cause":` +
		`{"class":"access-control","description":"mechanism"},"affected":` +
		`[{"path":"src/V.sol","contract":"V","function":"f"}],"attacker":` +
		`{"profile":"arbitrary EOA","required_privileges":[]},` +
		`"economic_impact":{"blast_radius":"subset-of-users"},` +
		`"evidence":[{"level":"E5"}]}`,
		"(-3.0, False, -3, 'F-bbbbbbbbbbb2')"},
	{`{"finding_id":"F-ccccccccccc3","status":"POSSIBLE","root_cause":` +
		`{"class":"access-control","description":"mechanism"},"affected":` +
		`[{"path":"src/V.sol","contract":"V","function":"f"}],"attacker":` +
		`{"profile":"arbitrary EOA","required_privileges":["owner"]},` +
		`"economic_impact":{"blast_radius":"subset-of-users"},` +
		`"evidence":[{"level":"E5"}]}`,
		"(-3.0, True, -2, 'F-ccccccccccc3')"},
	{`{"finding_id":"F-000000000007","status":"POSSIBLE","root_cause":` +
		`{"class":"access-control","description":"mechanism"},"affected":` +
		`[{"path":"src/V.sol","contract":"V","function":"f"}],"attacker":` +
		`{"profile":"arbitrary EOA","required_privileges":[]},` +
		`"economic_impact":{"blast_radius":"bridge-canonical"},` +
		`"evidence":[{"level":"E0"}]}`,
		"(-8.0, False, -4, 'F-000000000007')"},
	{`{"finding_id":"F-000000000008","status":"POSSIBLE","root_cause":` +
		`{"class":"access-control","description":"mechanism"},"affected":` +
		`[{"path":"src/V.sol","contract":"V","function":"f"}],"attacker":` +
		`{"profile":"arbitrary EOA","required_privileges":[]},` +
		`"economic_impact":{"blast_radius":"all-users"},"evidence":` +
		`[{"level":"E2"}]}`,
		"(-5.0, False, -3, 'F-000000000008')"},
	// an unknown blast falls back to the unknown-blast default 2.0
	{`{"finding_id":"F-000000000009","status":"POSSIBLE","root_cause":` +
		`{"class":"access-control","description":"mechanism"},"affected":` +
		`[{"path":"src/V.sol","contract":"V","function":"f"}],"attacker":` +
		`{"profile":"arbitrary EOA","required_privileges":[]},` +
		`"economic_impact":{"blast_radius":"bogus-blast"},"evidence":` +
		`[{"level":"E7"}]}`,
		"(-2.0, False, -2, 'F-000000000009')"},
	// ROLE wins over OWNER (the identifier contains both signals)
	{`{"finding_id":"F-00000000000a","status":"POSSIBLE","root_cause":` +
		`{"class":"access-control","description":"mechanism"},"affected":` +
		`[{"path":"src/V.sol","contract":"V","function":"f"}],"attacker":` +
		`{"profile":"arbitrary EOA","required_privileges":` +
		`["DEFAULT_ADMIN_ROLE"]},"economic_impact":{"blast_radius":` +
		`"single-user"},"evidence":[{"level":"E0"}]}`,
		"(-1.0, True, 0, 'F-00000000000a')"},
	// a keeper-style actor matches neither pattern -> semi-privileged
	{`{"finding_id":"F-00000000000b","status":"POSSIBLE","root_cause":` +
		`{"class":"access-control","description":"mechanism"},"affected":` +
		`[{"path":"src/V.sol","contract":"V","function":"f"}],"attacker":` +
		`{"profile":"arbitrary EOA","required_privileges":` +
		`["keeper-set via governance queue"]},"economic_impact":` +
		`{"blast_radius":"single-user"},"evidence":[{"level":"E0"}]}`,
		"(-1.0, True, 0, 'F-00000000000b')"},
	// no attacker / no evidence: still ranks (band from recorded fields)
	{`{"finding_id":"F-00000000000c","economic_impact":` +
		`{"blast_radius":"all-users"}}`,
		"(-5.0, False, -2, 'F-00000000000c')"},
	// an empty finding_id renders as ''
	{`{"finding_id":"","economic_impact":{"blast_radius":"all-users"},` +
		`"evidence":[{"level":"E5"}]}`,
		"(-5.0, False, -4, '')"},
}

func TestWorkOrderKeyVectors(t *testing.T) {
	if len(workOrderVectors) < 10 {
		t.Fatalf("vector table too small: %d", len(workOrderVectors))
	}
	for _, v := range workOrderVectors {
		got := woRepr(woKey(t, woFinding(t, v.doc)))
		if got != v.want {
			t.Errorf("work_order_key = %s, want %s", got, v.want)
		}
	}
}

// Port of test_blast_rank_dominates_higher_blast_first.
func TestBlastRankDominatesHigherBlastFirst(t *testing.T) {
	ownerKey := fnd("F-aaaaaaaaaaa1", "protocol-solvency", []string{"owner"}, "E2")
	subset := fnd("F-bbbbbbbbbbb2", "subset-of-users", nil, "E5")
	// premise: the two are in the same band, so band cannot order them
	if b := bandOf(t, ownerKey); b != "high" {
		t.Fatalf("owner band = %q, want high", b)
	}
	if b := bandOf(t, subset); b != "high" {
		t.Fatalf("subset band = %q, want high", b)
	}
	rows := []validation.Value{subset, ownerKey}
	got, err := SortByWorkOrder(rows)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(got[0], "finding_id") != "F-aaaaaaaaaaa1" ||
		validation.ObjStr(got[1], "finding_id") != "F-bbbbbbbbbbb2" {
		t.Fatalf("order = %s, %s", validation.ObjStr(got[0], "finding_id"),
			validation.ObjStr(got[1], "finding_id"))
	}
}

// Port of test_unprivileged_beats_privileged_at_equal_blast_and_band.
func TestUnprivilegedBeatsPrivilegedAtEqualBlastAndBand(t *testing.T) {
	privileged := fnd("F-aaaaaaaaaaa1", "subset-of-users", []string{"owner"}, "E5")
	unprivileged := fnd("F-bbbbbbbbbbb2", "subset-of-users", nil, "E4")
	if b := bandOf(t, privileged); b != "medium" {
		t.Fatalf("privileged band = %q", b)
	}
	if b := bandOf(t, unprivileged); b != "medium" {
		t.Fatalf("unprivileged band = %q", b)
	}
	// id order would put the privileged one first; the key must not
	rows, err := SortByWorkOrder([]validation.Value{privileged, unprivileged})
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(rows[0], "finding_id") != "F-bbbbbbbbbbb2" {
		t.Fatalf("order = %v", rows)
	}
}

// Port of test_band_breaks_ties_after_blast_and_privilege.
func TestBandBreaksTiesAfterBlastAndPrivilege(t *testing.T) {
	weak := fnd("F-aaaaaaaaaaa1", "subset-of-users", nil, "E1")
	strong := fnd("F-bbbbbbbbbbb2", "subset-of-users", nil, "E5")
	if b := bandOf(t, weak); b != "medium" {
		t.Fatalf("weak band = %q", b)
	}
	if b := bandOf(t, strong); b != "high" {
		t.Fatalf("strong band = %q", b)
	}
	rows, err := SortByWorkOrder([]validation.Value{weak, strong})
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(rows[0], "finding_id") != "F-bbbbbbbbbbb2" ||
		validation.ObjStr(rows[1], "finding_id") != "F-aaaaaaaaaaa1" {
		t.Fatalf("order = %v", rows)
	}
}

// Port of test_exact_ties_keep_finding_id_order.
func TestExactTiesKeepFindingIDOrder(t *testing.T) {
	a := fnd("F-aaaaaaaaaaa1", "subset-of-users", nil, "E4")
	b := fnd("F-bbbbbbbbbbb2", "subset-of-users", nil, "E4")
	ka, kb := woKey(t, a), woKey(t, b)
	if ka.BlastRank != kb.BlastRank || ka.Privileged != kb.Privileged ||
		ka.BandRank != kb.BandRank {
		t.Fatalf("the first three components must tie: %+v %+v", ka, kb)
	}
	rows, err := SortByWorkOrder([]validation.Value{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(rows[0], "finding_id") != "F-aaaaaaaaaaa1" {
		t.Fatalf("order = %v", rows)
	}
}

// Port of test_key_is_total_and_deterministic_across_runs.
func TestWorkOrderKeyIsTotalAndDeterministic(t *testing.T) {
	specs := []struct {
		blast, level string
	}{
		{"single-user", "E0"}, {"single-user", "E0"},
		{"subset-of-users", "E4"}, {"all-users", "E2"},
		{"protocol-solvency", "E1"}, {"bridge-canonical", "E0"},
		{"subset-of-users", "E5"}, {"all-users", "E5"},
	}
	findings := make([]validation.Value, 0, len(specs))
	for i, s := range specs {
		findings = append(findings,
			fnd(fmt.Sprintf("F-%012x", i), s.blast, nil, s.level))
	}
	seen := map[string]bool{}
	for _, f := range findings {
		k := woKey(t, f)
		r := woRepr(k)
		if seen[r] {
			t.Fatalf("the key is not total: %s repeated", r)
		}
		seen[r] = true
	}
	first, err := SortByWorkOrder(findings)
	if err != nil {
		t.Fatal(err)
	}
	reversed := make([]validation.Value, 0, len(findings))
	for i := len(findings) - 1; i >= 0; i-- {
		reversed = append(reversed, findings[i])
	}
	again, err := SortByWorkOrder(reversed)
	if err != nil {
		t.Fatal(err)
	}
	for i := range first {
		if validation.ObjStr(first[i], "finding_id") != validation.ObjStr(again[i], "finding_id") {
			t.Fatalf("run order differs at %d: %s vs %s", i,
				validation.ObjStr(first[i], "finding_id"), validation.ObjStr(again[i], "finding_id"))
		}
	}
	// every component is a plain sortable scalar (no dicts/objects)
	if len(seen) != len(findings) {
		t.Fatalf("keys = %d, findings = %d", len(seen), len(findings))
	}
}

// TestWorkOrderKeyLessMatchesTupleOrdering pins the Less contract directly:
// Python compares the four components left to right, False before True.
func TestWorkOrderKeyLessMatchesTupleOrdering(t *testing.T) {
	keys := []WorkOrderKey{
		{BlastRank: -3, Privileged: true, BandRank: -2, FindingID: "b"},
		{BlastRank: -7, Privileged: true, BandRank: -3, FindingID: "a"},
		{BlastRank: -3, Privileged: false, BandRank: -2, FindingID: "c"},
		{BlastRank: -3, Privileged: false, BandRank: -3, FindingID: "d"},
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Less(keys[j]) })
	want := []string{"a", "d", "c", "b"}
	for i, w := range want {
		if keys[i].FindingID != w {
			t.Fatalf("order[%d] = %q, want %q", i, keys[i].FindingID, w)
		}
	}
}

func bandOf(t *testing.T, finding validation.Value) string {
	t.Helper()
	v, err := ValidatedRisk(finding)
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(v, "band")
}

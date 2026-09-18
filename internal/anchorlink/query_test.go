package anchorlink

import (
	"slices"
	"testing"

	"websec/internal/validation"
)

// queryStore is the shared Query fixture: one Rollup row, one open priority
// naming Rollup by component, one closed priority naming it, and one finding
// on the repo-prefixed Rollup path.
func queryStore(t *testing.T) (*Store, []validation.Value, []validation.Value, []validation.Value) {
	t.Helper()
	s := mustOpen(t, miniModel())
	rows := []validation.Value{
		surfaceRow("34589e8588", "Rollup", "commitBatch", 204,
			"finalizeBatch", 496, 0, sibling("Rollup", 204)),
	}
	open := priority("Q-008", "Rollup")
	closed := priority("Q-999", "Rollup")
	closed.O = validation.SetOrAppend(closed.O, "status", validation.VStr("closed"))
	prios := []validation.Value{open, closed}
	findings := []validation.Value{
		finding("F-g01", "contracts/l1/rollup/Rollup.sol", "commitBatch", 204, 320),
	}
	return s.Index(rows, prios, findings), rows, prios, findings
}

func TestQueryPatternForms(t *testing.T) {
	s, _, _, _ := queryStore(t)
	cases := []struct {
		pattern    string
		wantRows   int
		wantPrios  []string
		wantFinder []string
	}{
		{"Rollup.sol", 1, []string{"Q-008"}, []string{"F-g01"}},
		{"l1/rollup/Rollup.sol", 1, []string{"Q-008"}, []string{"F-g01"}},
		{"rollup/Rollup.sol", 1, []string{"Q-008"}, []string{"F-g01"}},
		// fn/line-qualified patterns keep the PATH-matched OPEN priorities as
		// members (a question about Rollup is a question about its commitBatch;
		// round-2 review finding 1); only a path-less pattern excludes them.
		{"l1/rollup/Rollup.sol#commitBatch", 1, []string{"Q-008"}, []string{"F-g01"}},
		{"l1/rollup/Rollup.sol#commitBatch:204", 1, []string{"Q-008"}, []string{"F-g01"}},
		{"Rollup.sol:204", 1, []string{"Q-008"}, []string{"F-g01"}},
		{"Rollup.sol#finalizeBatch", 1, []string{"Q-008"}, nil},
		{"Rollup.sol:496", 1, []string{"Q-008"}, nil}, // the finding's range is 204-320
		{"#commitBatch", 1, nil, []string{"F-g01"}},
		{"NoSuchThing.sol", 0, nil, nil},
		{"", 0, nil, nil},
		{"#", 0, nil, nil},
	}
	for _, c := range cases {
		m := s.Query(c.pattern)
		if len(m.Rows) != c.wantRows {
			t.Errorf("Query(%q).Rows = %+v, want %d rows", c.pattern, m.Rows, c.wantRows)
		}
		if len(m.Priorities) != len(c.wantPrios) {
			t.Errorf("Query(%q).Priorities = %v, want %v", c.pattern, m.Priorities, c.wantPrios)
		}
		if len(m.Findings) != len(c.wantFinder) {
			t.Errorf("Query(%q).Findings = %v, want %v", c.pattern, m.Findings, c.wantFinder)
		}
		if c.wantRows > 0 && m.Rows[0].RowID != "34589e8588" {
			t.Errorf("Query(%q) row id = %q", c.pattern, m.Rows[0].RowID)
		}
	}
}

// TestQueryDoesNotMatchUnrelatedPaths: the unrelated gateway row is never in a
// Rollup answer, and a gateway query never returns the Rollup row.
func TestQueryDoesNotMatchUnrelatedPaths(t *testing.T) {
	s, rows, prios, findings := queryStore(t)
	gw := surfaceRow("a047e6509f", "L1MessageQueueWithGasPriceOracle",
		"popCrossDomainMessage", 12, "", 0, 0)
	rows = append(rows, gw)
	s.Index(rows, prios, findings)

	m := s.Query("#commitBatch")
	if len(m.Rows) != 1 || m.Rows[0].RowID != "34589e8588" {
		t.Fatalf("#commitBatch rows = %+v", m.Rows)
	}
	m = s.Query("L1MessageQueueWithGasPriceOracle.sol")
	if len(m.Rows) != 1 || m.Rows[0].RowID != "a047e6509f" {
		t.Fatalf("queue query rows = %+v", m.Rows)
	}
	if len(m.Priorities) != 0 || len(m.Findings) != 0 {
		t.Fatalf("queue query leaked other stores: %+v", m)
	}
}

func TestQueryRowTierAndDisposition(t *testing.T) {
	s, rows, prios, findings := queryStore(t)
	m := s.Query("Rollup.sol")
	if len(m.Rows) != 1 {
		t.Fatalf("rows = %+v", m.Rows)
	}
	if m.Rows[0].Tier != 0 || m.Rows[0].Disposition != "undispositioned" ||
		m.Rows[0].Dispositioned {
		t.Fatalf("undispositioned row = %+v", m.Rows[0])
	}
	// A disposition is a plan priority that claims the row through
	// probe.row_id, with a terminal status.
	disposed := validation.VObj(
		kv("id", validation.VStr("Q-disposed")),
		kv("status", validation.VStr("answered")),
		kv("probe", validation.VObj(
			kv("row_id", validation.VStr("34589e8588")),
			kv("tier", validation.VInt(0)),
			kv("assertion_gap", validation.VInt(4)))))
	s.Index(rows, append(prios, disposed), findings)
	m = s.Query("Rollup.sol")
	if m.Rows[0].Disposition != "answered" || !m.Rows[0].Dispositioned {
		t.Fatalf("dispositioned row = %+v", m.Rows[0])
	}
}

func TestQueryRequiresIndex(t *testing.T) {
	s := mustOpen(t, miniModel())
	m := s.Query("Rollup.sol")
	if len(m.Rows) != 0 || len(m.Priorities) != 0 || len(m.Findings) != 0 {
		t.Fatalf("un-indexed store answered: %+v", m)
	}
}

func TestConvergencesNeedTwoStores(t *testing.T) {
	s := mustOpen(t, miniModel())
	rows := []validation.Value{
		surfaceRow("r1", "Rollup", "commitBatch", 204, "", 0, 0),
	}
	findings := []validation.Value{
		finding("F-a", "contracts/l1/rollup/Rollup.sol", "commitBatch", 204),
		finding("F-b", "contracts/l1/rollup/Rollup.sol", "commitBatch", 300),
	}
	// Two findings are ONE store: no convergence.
	if got := s.Convergences(nil, nil, findings); len(got) != 0 {
		t.Fatalf("single store converged: %+v", got)
	}
	got := s.Convergences(rows, nil, findings)
	byKey := map[string]Anchor{}
	for _, a := range got {
		byKey[a.Key] = a
	}
	path, ok := byKey["l1/rollup/Rollup.sol"]
	if !ok {
		t.Fatalf("path anchor missing: %+v", got)
	}
	if !slices.Equal(path.Stores, []string{StoreFindings, StoreSurface}) {
		t.Fatalf("path stores = %v", path.Stores)
	}
	if !slices.Equal(path.Rows, []string{"r1"}) ||
		!slices.Equal(path.Findings, []string{"F-a", "F-b"}) {
		t.Fatalf("path members = %+v", path)
	}
	fn, ok := byKey["l1/rollup/Rollup.sol#commitBatch"]
	if !ok || !slices.Equal(fn.Stores, []string{StoreFindings, StoreSurface}) {
		t.Fatalf("function anchor = %+v", fn)
	}
}

// TestConvergencesIgnoreUncitableMembers: a store with no id to cite is not a
// lead, so it must not manufacture a convergence.
func TestConvergencesIgnoreUncitableMembers(t *testing.T) {
	s := mustOpen(t, miniModel())
	row := surfaceRow("", "Rollup", "commitBatch", 204, "", 0, 0)
	findings := []validation.Value{finding("", "contracts/l1/rollup/Rollup.sol", "commitBatch", 204)}
	if got := s.Convergences([]validation.Value{row}, nil, findings); len(got) != 0 {
		t.Fatalf("uncitable members converged: %+v", got)
	}
}

func TestPathMatchesIsSegmentBoundary(t *testing.T) {
	cases := []struct {
		pattern, target string
		want            bool
	}{
		{"Rollup.sol", "l1/rollup/Rollup.sol", true},
		{"rollup/Rollup.sol", "l1/rollup/Rollup.sol", true},
		{"l1/rollup/Rollup.sol", "l1/rollup/Rollup.sol", true},
		{"contracts/l1/rollup/Rollup.sol", "l1/rollup/Rollup.sol", true},
		{"Rollup.sol", "l1/rollup/NotRollup.sol", false},
		{"ollup.sol", "l1/rollup/Rollup.sol", false},
		{"l2/rollup/Rollup.sol", "l1/rollup/Rollup.sol", false},
		{"", "anything", true},
	}
	for _, c := range cases {
		if got := pathMatches(c.pattern, c.target); got != c.want {
			t.Errorf("pathMatches(%q, %q) = %v, want %v", c.pattern, c.target, got, c.want)
		}
	}
}

func TestParsePattern(t *testing.T) {
	cases := []struct {
		in   string
		want pattern
		ok   bool
	}{
		{"l1/rollup/Rollup.sol#commitBatch:204",
			pattern{path: "l1/rollup/Rollup.sol", fn: "commitBatch", line: 204}, true},
		{"Rollup.sol:496", pattern{path: "Rollup.sol", line: 496}, true},
		{"#finalizeBatch", pattern{fn: "finalizeBatch"}, true},
		{"Rollup.sol", pattern{path: "Rollup.sol"}, true},
		{"", pattern{}, false},
		{"#", pattern{}, false},
	}
	for _, c := range cases {
		got, ok := parsePattern(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("parsePattern(%q) = %+v, %v; want %+v, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

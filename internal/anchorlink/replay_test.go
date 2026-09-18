package anchorlink

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"websec/internal/validation"
)

// replayDir holds the reduced REAL-structure fixture: the G-01 shape (a tier-0
// surface row with consumer commitBatch@204 / asserter finalizeBatch@496 and
// no disposition, the open LC-008 lifecycle priority, and a finding whose
// affected file is the repo-prefixed Rollup.sol), the unrelated G-02-style
// gateway row, and a model with the L1ERC20Gateway name collision. Shapes are
// copied from ../morph/campaigns/C-f4e27261f7/artifacts; the data is not.
const replayDir = "testdata/replay_g01"

func loadArtifact(t *testing.T, parts ...string) validation.Value {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{replayDir}, parts...)...))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	v, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return v
}

// replay is the loaded fixture: the store plus the three artifact stores.
type replay struct {
	store    *Store
	rows     []validation.Value
	prios    []validation.Value
	findings []validation.Value
}

func loadReplay(t *testing.T) replay {
	t.Helper()
	model := loadArtifact(t, "protocol_model.json")
	surface := loadArtifact(t, "probe_surface.json")
	plan := loadArtifact(t, "campaign_plan.json")
	finding := loadArtifact(t, "findings", "F-000000000001.json")
	rows := valueList(surface, "rows")
	prios := valueList(plan, "priorities")
	findings := []validation.Value{finding}
	if len(rows) != 2 || len(prios) != 3 || len(findings) != 1 {
		t.Fatalf("fixture shapes: rows=%d prios=%d findings=%d", len(rows), len(prios), len(findings))
	}
	s := mustOpen(t, model)
	return replay{store: s.Index(rows, prios, findings), rows: rows, prios: prios, findings: findings}
}

func (r replay) byKey(t *testing.T) map[string]Anchor {
	t.Helper()
	out := map[string]Anchor{}
	for _, a := range r.store.Convergences(r.rows, r.prios, r.findings) {
		out[a.Key] = a
	}
	return out
}

// TestReplayG01Convergences is the §5 replay in Go: both stores that carried
// the G-01 lead are found on the canonical key.
func TestReplayG01Convergences(t *testing.T) {
	r := loadReplay(t)
	anchors := r.byKey(t)
	a, ok := anchors["l1/rollup/Rollup.sol"]
	if !ok {
		t.Fatalf("no anchor on l1/rollup/Rollup.sol: %+v", anchors)
	}
	if len(a.Stores) < 2 {
		t.Fatalf("anchor named by %d stores: %+v", len(a.Stores), a)
	}
	if !slices.Equal(a.Stores, []string{StoreFindings, StorePlan, StoreSurface}) {
		t.Fatalf("stores = %v", a.Stores)
	}
	if !slices.Contains(a.Rows, "34589e8588") {
		t.Fatalf("the undispositioned tier-0 row is not a member: %+v", a)
	}
	if !slices.Contains(a.Priorities, "LC-008") || !slices.Contains(a.Priorities, "Q-008") {
		t.Fatalf("open priorities are not members: %+v", a)
	}
	if !slices.Contains(a.Findings, "F-000000000001") {
		t.Fatalf("the finding is not a member: %+v", a)
	}
	fn, ok := anchors["l1/rollup/Rollup.sol#commitBatch"]
	if !ok {
		t.Fatalf("no function-level anchor on commitBatch: %+v", anchors)
	}
	if !slices.Equal(fn.Stores, []string{StoreFindings, StoreSurface}) ||
		!slices.Contains(fn.Rows, "34589e8588") ||
		!slices.Contains(fn.Findings, "F-000000000001") {
		t.Fatalf("function anchor = %+v", fn)
	}
	// The l2 gateway copy shares the gateway row's basename and must not be
	// anchored (nothing cites its full path).
	for _, a := range anchors {
		if a.Path == "l2/gateways/L1ERC20Gateway.sol" {
			t.Fatalf("unnamed collision copy converged: %+v", a)
		}
	}
	// The package-level form agrees with the method.
	if got := Convergences(r.store, r.rows, r.prios, r.findings); len(got) != len(anchors) {
		t.Fatalf("package-level Convergences = %d anchors, method = %d", len(got), len(anchors))
	}
}

// TestReplayG01QueryCommitBatch: the pattern the operator types reaches the
// row (and the finding) and nothing on an unrelated path.
func TestReplayG01QueryCommitBatch(t *testing.T) {
	r := loadReplay(t)
	m := r.store.Query("#commitBatch")
	if len(m.Rows) != 1 || m.Rows[0].RowID != "34589e8588" {
		t.Fatalf("#commitBatch rows = %+v", m.Rows)
	}
	if m.Rows[0].Tier != 0 || m.Rows[0].Dispositioned ||
		m.Rows[0].Disposition != "undispositioned" {
		t.Fatalf("row status = %+v", m.Rows[0])
	}
	if !slices.Contains(m.Findings, "F-000000000001") {
		t.Fatalf("#commitBatch findings = %v", m.Findings)
	}
	for _, row := range m.Rows {
		if row.RowID == "a047e6509f" {
			t.Fatalf("#commitBatch matched the unrelated gateway row: %+v", row)
		}
	}
	for _, p := range []string{"l1/rollup/Rollup.sol#commitBatch",
		"l1/rollup/Rollup.sol#commitBatch:204", "Rollup.sol:204",
		"l1/rollup/Rollup.sol", "rollup/Rollup.sol", "#finalizeBatch"} {
		got := r.store.Query(p)
		if len(got.Rows) != 1 || got.Rows[0].RowID != "34589e8588" {
			t.Errorf("Query(%q).Rows = %+v", p, got.Rows)
		}
	}
	// An unrelated path never answers for commitBatch.
	unrelated := r.store.Query("l1/rollup/L1MessageQueueWithGasPriceOracle.sol#commitBatch")
	if len(unrelated.Rows) != 0 || len(unrelated.Findings) != 0 {
		t.Fatalf("unrelated path matched: %+v", unrelated)
	}
	// The basename query still reaches the ambiguous gateway row (a search is
	// allowed to be ambiguous; a convergence claim is not).
	gw := r.store.Query("L1ERC20Gateway.sol#onDropMessage")
	if len(gw.Rows) != 1 || gw.Rows[0].RowID != "a047e6509f" {
		t.Fatalf("gateway basename query rows = %+v", gw.Rows)
	}
}

func TestReplayG01QueryStoresAndOpenOnly(t *testing.T) {
	r := loadReplay(t)
	m := r.store.Query("Rollup.sol")
	if len(m.Rows) != 1 || m.Rows[0].RowID != "34589e8588" {
		t.Fatalf("rows = %+v", m.Rows)
	}
	if !slices.Contains(m.Priorities, "LC-008") || !slices.Contains(m.Priorities, "Q-008") {
		t.Fatalf("open priorities = %v", m.Priorities)
	}
	if slices.Contains(m.Priorities, "Q-999") {
		t.Fatalf("closed priority matched: %v", m.Priorities)
	}
	if len(m.Findings) != 1 || m.Findings[0] != "F-000000000001" {
		t.Fatalf("findings = %v", m.Findings)
	}
	if none := r.store.Query("NoSuchFile.sol"); len(none.Rows)+len(none.Priorities)+
		len(none.Findings) != 0 {
		t.Fatalf("unknown path matched: %+v", none)
	}
}

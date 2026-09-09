package roles

// Port of tests/test_partition_guards.py's proposer-context half: the
// leakage partition filter on roles._known_non_issues, campaign-local and
// through the shared-store wrapper.

import (
	"path/filepath"
	"testing"

	"websec/internal/learning"
	"websec/internal/sharedmem"
	"websec/internal/state"
	"websec/internal/validation"
)

// t35QueuePartitioned is queue_partitioned: queue a negative row and stamp
// its leakage partition the way the dataset adapters will.
func t35QueuePartitioned(t *testing.T, c *state.Campaign,
	partition string) validation.Value {
	t.Helper()
	cls := "reentrancy"
	row, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind:     "disproved",
		Status:   "DISPROVED",
		Pattern:  "a prior observation partitioned " + partition,
		BugClass: &cls})
	if err != nil {
		t.Fatal(err)
	}
	if partition != "dev" {
		row.O = setKey(row, "partition", validation.VStr(partition)).O
		path := filepath.Join(c.MemoryDir, objStr(row, "memory_id")+".json")
		if err := validation.WriteJson(path, row, "memory"); err != nil {
			t.Fatal(err)
		}
	}
	return row
}

// t35KnownIDs is _known_non_issues(c)["known_non_issues"] memory ids.
func t35KnownIDs(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	block, err := KnownNonIssues(c, nil, 12)
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, r := range objAt(block, "known_non_issues").A {
		out = append(out, objStr(r, "memory_id"))
	}
	return out
}

// Port of tests/test_partition_guards.py::test_held_out_and_training_rows_absent_from_proposer_context.
func TestHeldOutAndTrainingRowsAbsentFromProposerContext(t *testing.T) {
	c := newCamp(t)
	dev := t35QueuePartitioned(t, c, "dev")
	held := t35QueuePartitioned(t, c, "held-out")
	training := t35QueuePartitioned(t, c, "training")
	ids := t35KnownIDs(t, c)
	if !t35Contains(ids, objStr(dev, "memory_id")) {
		t.Errorf("dev row missing from %v", ids)
	}
	for _, row := range []validation.Value{held, training} {
		if t35Contains(ids, objStr(row, "memory_id")) {
			t.Errorf("%s row leaked into the proposer context: %v",
				objStr(row, "partition"), ids)
		}
	}
}

// Port of tests/test_partition_guards.py::test_shared_store_held_out_row_absent_dev_row_present.
func TestSharedStoreHeldOutRowAbsentDevRowPresent(t *testing.T) {
	c := newCamp(t)
	held := t35QueuePartitioned(t, c, "held-out")
	dev := t35QueuePartitioned(t, c, "dev")
	store := sharedmem.StoreDir(c.Root)
	wrap := func(row validation.Value) validation.Value {
		return validation.VObj(
			kv("program_key", validation.VStr("Acme Immunefi|-|ethereum")),
			kv("published_at", validation.VStr("2026-09-04T00:00:00+00:00")),
			kv("row", row))
	}
	if err := sharedmem.WriteStore(store, nil,
		[]validation.Value{wrap(held), wrap(dev)}); err != nil {
		t.Fatal(err)
	}
	ids := t35KnownIDs(t, c)
	if t35Contains(ids, objStr(held, "memory_id")) {
		t.Errorf("held-out row leaked through the shared-store wrapper: %v",
			ids)
	}
	if !t35Contains(ids, objStr(dev, "memory_id")) {
		t.Errorf("dev row missing from the shared-store path: %v", ids)
	}
}

// t35Contains is a membership check.
func t35Contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

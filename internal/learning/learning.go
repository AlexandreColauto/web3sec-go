package learning

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"websec/internal/capabilities"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// MEMORY_STATUSES is MEMORY_STATUSES (learning.py), in order.
var MEMORY_STATUSES = []string{"CONFIRMED", "DISPROVED", "DUPLICATE",
	"OUT_OF_SCOPE", "INTENDED_BEHAVIOR", "UNREACHABLE", "NON-ECONOMIC",
	"TEST-HARNESS-ONLY"}

// MemorySchemaVersion is MEMORY_SCHEMA_VERSION: the memory-row shape version.
const MemorySchemaVersion = 2

// REJECTION_CLASSES is REJECTION_CLASSES, in order.
var REJECTION_CLASSES = []string{"invalid-hypothesis", "not-exploitable",
	"below-threshold"}

// rejectionClassByStatus is _REJECTION_CLASS_BY_STATUS.
var rejectionClassByStatus = map[string]string{
	"DISPROVED":         "invalid-hypothesis",
	"UNREACHABLE":       "not-exploitable",
	"INTENDED_BEHAVIOR": "not-exploitable",
	"TEST-HARNESS-ONLY": "not-exploitable",
	"NON-ECONOMIC":      "below-threshold",
	"OUT_OF_SCOPE":      "below-threshold",
}

// MemoryKinds is the `kind` vocabulary queue_memory accepts, in the order
// the error text's tuple is not shown (Python uses a literal tuple).
var MemoryKinds = []string{"confirmed", "disproved", "detector", "benchmark",
	"reflection", "drift", "regression"}

// propositionTypes is the deciding-proposition `type` enum (schema order).
var propositionTypes = []string{"reachability", "authority", "control",
	"state", "invariant", "economic", "environment", "temporal", "cross_domain"}

// QueueOpts carries queue_memory's keyword arguments (pointers are Python's
// None).
type QueueOpts struct {
	Kind                 string
	Status               string
	Pattern              string
	FindingID            *string
	BugClass             *string
	CWE                  *string
	EvidenceSummary      string
	Negative             *validation.Value
	Detector             *validation.Value
	Regression           *validation.Value
	RejectionClass       *string
	DecidingPropositions []validation.Value
}

// findingCapabilityLabels is _finding_capability_labels: normalized
// `capabilities.<key>` labels of the finding a memory row is derived from —
// [] when there is no finding, or it carries none. Never raises on a
// missing finding: queue_memory has always accepted a finding_id without
// requiring the file to exist.
func findingCapabilityLabels(c *state.Campaign, findingID *string,
	key string) []string {
	if findingID == nil || *findingID == "" {
		return nil
	}
	if _, err := os.Stat(findings.FindingPath(c, *findingID)); err != nil {
		return nil
	}
	finding, err := findings.LoadFinding(c, *findingID)
	if err != nil {
		return nil
	}
	caps := validation.ObjAt(finding, "capabilities")
	if caps.Kind != validation.Obj {
		return nil
	}
	return capabilities.NormalizeLabels(strList(validation.ObjAt(caps, key)))
}

// writeThenLog is the r40 unwind-on-refusal door for the learning package's
// WHOLE-FILE writers (memory rows, stripped rows) — the state package's
// AppendJsonlThenLog discipline applied to a WriteJson artifact instead of an
// append-only row: snapshot every path pre-write, write, log, and on a
// refused log (torn ledger, mirror lag or hole, held lock) restore those
// exact bytes — or remove a file that did not exist yet, never creating an
// empty one. The whole window is held under the campaign process lock (the
// inner Log re-enters it by depth). A FAILED restore means the artifact
// bytes are still AHEAD of the refused event — name both failures so no
// caller can report a clean unwind that never happened.
func writeThenLog(c *state.Campaign, paths []string, write func() error,
	log func() error) error {
	if err := c.LockProcess(); err != nil {
		return err
	}
	defer c.UnlockProcess()
	type snap struct {
		path string
		raw  []byte
		had  bool
	}
	snaps := make([]snap, 0, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		had := err == nil
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		snaps = append(snaps, snap{path: p, raw: raw, had: had})
	}
	restore := func() error {
		var rerr error
		for _, s := range snaps {
			if s.had {
				rerr = os.WriteFile(s.path, s.raw, 0o644)
			} else {
				rerr = os.Remove(s.path)
				if os.IsNotExist(rerr) {
					rerr = nil // a missing file the failed write never created
				}
			}
			if rerr != nil {
				return rerr
			}
		}
		return nil
	}
	fail := func(err error) error {
		if rerr := restore(); rerr != nil {
			return fmt.Errorf("%w (UNWIND ALSO FAILED: %v — %s holds "+
				"post-write bytes with no event; repair by hand before "+
				"continuing)", err, rerr, filepath.Base(paths[0]))
		}
		return err
	}
	if err := write(); err != nil {
		return fail(err)
	}
	if err := log(); err != nil {
		return fail(err)
	}
	return nil
}

// QueueMemory is queue_memory: queue a memory candidate. promotion_status
// starts as 'pending' and NOTHING in this codebase can flip it to promoted —
// only ApproveMemory with an explicit human approver does.
func QueueMemory(c *state.Campaign, o QueueOpts) (validation.Value, error) {
	rejectionClass, err := queueMemCheckOpts(o)
	if err != nil {
		return validation.VNull(), err
	}
	if err := checkPropositions(o.DecidingPropositions); err != nil {
		return validation.VNull(), err
	}
	snap, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		return validation.VNull(), err
	}
	mem := queueMemRow(c, o, snap, rejectionClass)
	if err := validation.Validate(mem, "memory", 1); err != nil {
		return validation.VNull(), err
	}
	mid := validation.ObjStr(mem, "memory_id")
	path := filepath.Join(c.MemoryDir, mid+".json")
	data := validation.VObj(
		kv("kind", validation.VStr(o.Kind)),
		kv("status", validation.VStr(o.Status)),
		kv("rejection_class", strOrNull(rejectionClass)),
		kv("deciding_propositions",
			validation.VInt(int64(len(o.DecidingPropositions)))))
	// r40: a queued row on disk without its memory.queued event is an
	// inbox candidate the ledger never recorded — and the retry after the
	// heal would queue a SECOND row for the one event. Unwind on refusal.
	if err := writeThenLog(c, []string{path}, func() error {
		return validation.WriteJson(path, mem, "")
	}, func() error {
		_, lerr := c.Log("memory.queued", &mid, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return mem, nil
}

// queueMemCheckOpts validates a queued row's status, kind and
// rejection_class, returning the resolved rejection class (derived from the
// status when the option is absent).
func queueMemCheckOpts(o QueueOpts) (*string, error) {
	if !slices.Contains(MEMORY_STATUSES, o.Status) {
		return nil, fmt.Errorf("invalid memory status %s",
			pyReprStr(o.Status))
	}
	if !slices.Contains(MemoryKinds, o.Kind) {
		return nil, fmt.Errorf("invalid memory kind %s",
			pyReprStr(o.Kind))
	}
	var rejectionClass *string
	if o.RejectionClass == nil {
		if rc, ok := rejectionClassByStatus[o.Status]; ok {
			rejectionClass = &rc
		}
	} else {
		if !slices.Contains(REJECTION_CLASSES, *o.RejectionClass) {
			return nil, fmt.Errorf("invalid rejection_class %s",
				pyReprStr(*o.RejectionClass))
		}
		rejectionClass = o.RejectionClass
	}
	return rejectionClass, nil
}

// queueMemRow builds the memory row QueueMemory validates and persists.
func queueMemRow(c *state.Campaign, o QueueOpts, snap *string,
	rejectionClass *string) validation.Value {
	mem := validation.VObj(
		kv("memory_id", validation.VStr("MEM-"+idTail(8))),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("finding_id", strOrNull(o.FindingID)),
		kv("snapshot_id", strOrNull(snap)),
		kv("created_at", validation.VStr(state.NowIso())),
		kv("kind", validation.VStr(o.Kind)),
		kv("status", validation.VStr(o.Status)),
		kv("pattern", validation.VStr(o.Pattern)),
		kv("bug_class", strOrNull(o.BugClass)),
		kv("cwe", strOrNull(o.CWE)),
		kv("evidence_summary", validation.VStr(o.EvidenceSummary)),
		kv("schema_version", validation.VInt(MemorySchemaVersion)),
		kv("rejection_class", strOrNull(rejectionClass)),
		kv("promotion_status", validation.VStr("pending")),
		kv("approved_by", validation.VNull()),
		kv("approved_at", validation.VNull()))
	if len(o.DecidingPropositions) > 0 {
		mem.O = append(mem.O, kv("deciding_propositions",
			validation.VArr(o.DecidingPropositions...)))
	}
	if o.Negative != nil && validation.PyTruthy(*o.Negative) {
		mem.O = append(mem.O, kv("negative_mode", *o.Negative))
	}
	if o.Detector != nil && validation.PyTruthy(*o.Detector) {
		mem.O = append(mem.O, kv("detector", *o.Detector))
	}
	if o.Regression != nil && validation.PyTruthy(*o.Regression) {
		mem.O = append(mem.O, kv("regression", *o.Regression))
	}
	// Capability labels (B3/D2): a row derived from a finding carries that
	// finding's explicit capability lists, normalized exactly as
	// shared_memory.derive_signature normalizes them.
	for _, key := range []string{"granted", "required"} {
		labels := findingCapabilityLabels(c, o.FindingID, key)
		if len(labels) > 0 {
			mem.O = append(mem.O, kv(key, validation.StrArr(labels)))
		}
	}
	return mem
}

// checkPropositions is queue_memory's deciding_propositions validation.
func checkPropositions(props []validation.Value) error {
	if len(props) > 16 {
		return errors.New("deciding_propositions must be a list of <= 16")
	}
	for _, p := range props {
		if p.Kind != validation.Obj {
			return errors.New(
				"each deciding proposition needs a statement of 10-500 chars")
		}
		statement, ok := fieldAt(p, "statement")
		if !ok || statement.Kind != validation.Str ||
			len([]rune(statement.S)) < 10 || len([]rune(statement.S)) > 500 {
			return errors.New(
				"each deciding proposition needs a statement of 10-500 chars")
		}
		if t, ok := fieldAt(p, "type"); ok && t.Kind != validation.Null &&
			!(t.Kind == validation.Str && slices.Contains(propositionTypes, t.S)) {
			return fmt.Errorf("invalid proposition type %s", pyRepr(t))
		}
	}
	return nil
}

// ---- small shared helpers -------------------------------------------------

func strOrNull(s *string) validation.Value {
	if s == nil {
		return validation.VNull()
	}
	return validation.VStr(*s)
}

func strList(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, e := range v.A {
		if e.Kind == validation.Str {
			out = append(out, e.S)
		}
	}
	return out
}

// removeKey is `del d[k]` (no-op when absent).
func removeKey(o []validation.KV, key string) []validation.KV {
	out := o[:0]
	for _, e := range o {
		if e.K != key {
			out = append(out, e)
		}
	}
	return out
}

// idTail is new_id('x', n).split('-')[1].
func idTail(n int) string {
	return strings.SplitN(state.NewID("x", n), "-", 2)[1]
}

// pyReprTuple is a Python tuple literal: ('a', 'b').
func pyReprTuple(items []string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, pyReprStr(it))
	}
	if len(parts) == 1 {
		return "(" + parts[0] + ",)"
	}
	return "(" + joinComma(parts) + ")"
}

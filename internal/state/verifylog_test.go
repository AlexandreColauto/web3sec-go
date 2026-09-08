package state

import (
	"os"
	"strings"
	"testing"

	"websec/internal/validation"
)

// TestVerifyLogClean: a fresh campaign verifies; 5 more appends keep it
// clean with the exact counters.
func TestVerifyLogClean(t *testing.T) {
	root := t.TempDir()
	c, err := Init(root, "Acme", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK || v.Events != 1 || v.Chained != 1 || v.LegacyUnchained != 0 ||
		v.MalformedLines != 0 || len(v.Problems) != 0 {
		t.Errorf("clean: %+v", v)
	}
	for i := 0; i < 5; i++ {
		if _, err := c.Log("t", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	v, err = c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK || v.Events != 6 || v.Chained != 6 || v.LegacyUnchained != 0 {
		t.Errorf("after 5: %+v", v)
	}
}

// rewriteLines replaces the physical log lines (tamper helper).
func rewriteLines(t *testing.T, c *Campaign, lines []string) {
	t.Helper()
	if err := os.WriteFile(c.EventsPath, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readLines(t *testing.T, c *Campaign) []string {
	t.Helper()
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
}

func hasProblem(v LogVerdict, sub string) bool {
	for _, p := range v.Problems {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

// TestVerifyLogReordered: swapping the seq fields of the first two events
// breaks contiguity and the recomputation.
func TestVerifyLogReordered(t *testing.T) {
	root := t.TempDir()
	c, _ := Init(root, "Acme", InitOpts{})
	c.Log("t", nil, nil)
	lines := readLines(t, c)
	e0, _ := validation.ParseOrdered([]byte(lines[0]))
	e1, _ := validation.ParseOrdered([]byte(lines[1]))
	// swap the seq fields in place
	setSeq := func(ev validation.Value, seq int64) validation.Value {
		for i, kv := range ev.O {
			if kv.K == "seq" {
				ev.O[i].V = validation.VInt(seq)
			}
		}
		return ev
	}
	lines[0] = validation.CanonSpaced(setSeq(e0, 1))
	lines[1] = validation.CanonSpaced(setSeq(e1, 0))
	rewriteLines(t, c, lines)
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Fatalf("reordered must fail: %+v", v)
	}
	if !hasProblem(v, "seq=") {
		t.Errorf("want seq problem: %v", v.Problems)
	}
	if !hasProblem(v, "event_hash does not recompute") {
		t.Errorf("want recompute problem: %v", v.Problems)
	}
}

// TestVerifyLogStateTailMismatch: tamper the state mirror.
func TestVerifyLogStateTailMismatch(t *testing.T) {
	root := t.TempDir()
	c, _ := Init(root, "Acme", InitOpts{})
	c.Log("t", nil, nil)
	st, _ := c.State()
	evs := objVal(st, "events")
	evs.A = evs.A[:len(evs.A)-1] // drop the last mirrored event
	st.O = replaceKey(st.O, "events", validation.Value{Kind: validation.Arr, A: evs.A})
	if err := c.save(st); err != nil {
		t.Fatal(err)
	}
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK || !hasProblem(v, "state event tail does not match the log suffix") {
		t.Errorf("tail: %+v", v)
	}
}

// TestVerifyLogEditedOldEvent: edit an old event in place; the state tail
// is fixed to match, so ONLY the chain complains.
func TestVerifyLogEditedOldEvent(t *testing.T) {
	root := t.TempDir()
	c, _ := Init(root, "Acme", InitOpts{})
	for i := 0; i < 3; i++ {
		c.Log("t", nil, nil)
	}
	lines := readLines(t, c)
	// corrupt the data of the 3rd event (index 2)
	e2, _ := validation.ParseOrdered([]byte(lines[2]))
	e2 = setObjStr(e2, "data", validation.VObj(kv("evil", validation.VStr("x"))))
	lines[2] = validation.CanonSpaced(e2)
	rewriteLines(t, c, lines)
	// sync the state tail so the tail check passes
	st, _ := c.State()
	events, _ := c.Events()
	st.O = replaceKey(st.O, "events", eventsValue(events))
	if err := c.save(st); err != nil {
		t.Fatal(err)
	}
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Fatalf("edited event must fail: %+v", v)
	}
	if !hasProblem(v, "event 2: event_hash does not recompute (content edited?)") {
		t.Errorf("problems: %v", v.Problems)
	}
	// the following event's prev_hash still matches the (stale) stored
	// hash, so no chain problem for event 3
	if hasProblem(v, "event 3: prev_hash") {
		t.Errorf("unexpected: %v", v.Problems)
	}
}

// TestVerifyLogForgedInsert: a forged seq-99 event with a valid-looking
// hash still breaks seq and chain.
func TestVerifyLogForgedInsert(t *testing.T) {
	root := t.TempDir()
	c, _ := Init(root, "Acme", InitOpts{})
	lines := readLines(t, c)
	forged := validation.VObj(
		kv("seq", validation.VInt(99)),
		kv("at", validation.VStr("2020-01-01T00:00:00.000000+00:00")),
		kv("type", validation.VStr("forged")),
		kv("ref", validation.VNull()),
		kv("data", validation.VObj()),
		kv("prev_hash", validation.VStr("1111111111111111111111111111111111111111111111111111111111111111")),
	)
	forged = validation.VObj(append(append([]validation.KV{}, forged.O...),
		kv("event_hash", validation.VStr(eventHash(forged))))...)
	rewriteLines(t, c, append(lines, validation.CanonSpaced(forged)))
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Fatalf("forged insert must fail: %+v", v)
	}
	if !hasProblem(v, "seq=99") {
		t.Errorf("want seq problem: %v", v.Problems)
	}
	if !hasProblem(v, "prev_hash breaks the chain") {
		t.Errorf("want chain problem: %v", v.Problems)
	}
}

// TestVerifyLogDeletedEvent: dropping an event and renumbering breaks the
// chain (the surviving events still carry the old prev_hash).
func TestVerifyLogDeletedEvent(t *testing.T) {
	root := t.TempDir()
	c, _ := Init(root, "Acme", InitOpts{})
	for i := 0; i < 4; i++ {
		c.Log("t", nil, nil)
	}
	lines := readLines(t, c)
	// drop index 2, renumber the rest 0..3
	var out []string
	next := int64(0)
	for i, ln := range lines {
		if i == 2 {
			continue
		}
		ev, _ := validation.ParseOrdered([]byte(ln))
		for j, k := range ev.O {
			if k.K == "seq" {
				ev.O[j].V = validation.VInt(next)
			}
		}
		out = append(out, validation.CanonSpaced(ev))
		next++
	}
	rewriteLines(t, c, out)
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Fatalf("deleted event must fail: %+v", v)
	}
	if !hasProblem(v, "prev_hash breaks the chain") {
		t.Errorf("problems: %v", v.Problems)
	}
}

// TestVerifyLogLegacyOnly: a legacy (unchained) log verifies with
// chained==0; the next append anchors at legacy-seq-0.
func TestVerifyLogLegacyOnly(t *testing.T) {
	root := t.TempDir()
	c, _ := Init(root, "Acme", InitOpts{})
	legacy := `{"at": "2020-01-01T00:00:00.000000+00:00", "data": {}, "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000", "ref": null, "seq": 0, "type": "legacy.event"}`
	rewriteLines(t, c, []string{legacy})
	// state tail: make it agree (legacy event)
	ev, _ := validation.ParseOrdered([]byte(legacy))
	st, _ := c.State()
	st.O = replaceKey(st.O, "events", validation.Value{Kind: validation.Arr, A: []validation.Value{ev}})
	c.save(st)
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK || v.Events != 1 || v.Chained != 0 || v.LegacyUnchained != 1 {
		t.Errorf("legacy-only: %+v", v)
	}
	nv, err := c.Log("t", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(nv, "prev_hash"); got != "legacy-seq-0" {
		t.Errorf("anchor: %q", got)
	}
	v, err = c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK || v.Chained != 1 || v.LegacyUnchained != 1 {
		t.Errorf("after append: %+v", v)
	}
}

// TestVerifyLogMalformedLine (Go-native hardening): a torn middle line is
// reported, never raised; chain checks stop past it.
func TestVerifyLogMalformedLine(t *testing.T) {
	root := t.TempDir()
	c, _ := Init(root, "Acme", InitOpts{})
	c.Log("t", nil, nil)
	lines := readLines(t, c)
	mid := lines[1][:10] + "{broken"
	torn := append([]string{lines[0]}, mid)
	torn = append(torn, lines[2:]...)
	rewriteLines(t, c, torn)
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Fatalf("malformed must fail: %+v", v)
	}
	if v.MalformedLines != 1 {
		t.Errorf("malformed_lines: %+v", v)
	}
	if !hasProblem(v, "not valid JSON") {
		t.Errorf("problems: %v", v.Problems)
	}
	if v.Chained != 0 {
		t.Errorf("chain must stop past torn line: %+v", v)
	}
}

// TestVerifyLogNonObjectLine: a valid-JSON scalar line is malformed.
func TestVerifyLogNonObjectLine(t *testing.T) {
	root := t.TempDir()
	c, _ := Init(root, "Acme", InitOpts{})
	lines := readLines(t, c)
	rewriteLines(t, c, append(lines, "42"))
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.MalformedLines != 1 || !hasProblem(v, "not a JSON object") {
		t.Errorf("non-object: %+v", v)
	}
}

// TestVerifyLogProblemCap: only the first 10 problems are reported.
func TestVerifyLogProblemCap(t *testing.T) {
	root := t.TempDir()
	c, _ := Init(root, "Acme", InitOpts{})
	for i := 0; i < 20; i++ {
		c.Log("t", nil, nil)
	}
	// break every event's prev_hash
	lines := readLines(t, c)
	for i, ln := range lines {
		ev, _ := validation.ParseOrdered([]byte(ln))
		ev = setObjStr(ev, "prev_hash", validation.VStr("bad"))
		lines[i] = validation.CanonSpaced(ev)
	}
	rewriteLines(t, c, lines)
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Problems) != 10 {
		t.Errorf("problem cap: %d problems", len(v.Problems))
	}
}

// --- tamper helpers -----------------------------------------------------

// replaceKey swaps the value of key in an ordered object (position kept).
func replaceKey(o []validation.KV, key string, v validation.Value) []validation.KV {
	for i, kv := range o {
		if kv.K == key {
			o[i].V = v
		}
	}
	return o
}

func eventsValue(events []validation.Value) validation.Value {
	a := make([]validation.Value, len(events))
	copy(a, events)
	return validation.Value{Kind: validation.Arr, A: a}
}

// setObjStr replaces one key's value inside an object Value.
func setObjStr(ev validation.Value, key string, v validation.Value) validation.Value {
	for i, kv := range ev.O {
		if kv.K == key {
			ev.O[i].V = v
		}
	}
	return ev
}

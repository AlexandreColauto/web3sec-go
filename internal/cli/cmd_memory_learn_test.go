package cli

// cmd_memory_learn_test.go — D5: `memory --reflect` and `memory --reject`. The
// two holes these close are reachability holes, not formatting ones: nothing
// writable reached learnings.jsonl (learning.ReflectionEntry had no caller
// outside its own test, so the learning proof's "no reflection entry" item was
// unclearable), and a queued candidate could only ever be approved. Both are
// flags on the existing verb, so the verb count is unchanged.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/learning"
	"websec/internal/state"
	"websec/internal/validation"
)

// queueMemoryRow queues a real pending row through the production path.
func queueMemoryRow(t *testing.T, c *state.Campaign, pattern string) string {
	t.Helper()
	mem, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind: "disproved", Status: "DISPROVED", Pattern: pattern})
	if err != nil {
		t.Fatal(err)
	}
	return objStr(mem, "memory_id")
}

// eventTypes lists the campaign's logged event types, in order.
func eventTypes(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(events))
	for _, ev := range events {
		out = append(out, objStr(ev, "type"))
	}
	return out
}

func hasEvent(types []string, want string) bool {
	for _, ty := range types {
		if ty == want {
			return true
		}
	}
	return false
}

// reflectLines returns the non-empty lines of the campaign's learnings.jsonl.
func reflectLines(t *testing.T, root, cid string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "campaigns", cid, "learnings.jsonl"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	out := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

func memoryRowPath(root, cid, mem string) string {
	return filepath.Join(root, "campaigns", cid, "memory", mem+".json")
}

func TestMemoryReflectWritesLearningsJsonl(t *testing.T) {
	root, cid, c := noopCamp(t)
	sentence := "the Anvil fork needed an explicit block number"
	code, out, errS := run(t, "--root", root, "memory", cid, "--reflect", sentence)
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	if !strings.Contains(out, "reflection recorded (round 1)") {
		t.Errorf("output does not name the recorded reflection:\n%s", out)
	}
	lines := reflectLines(t, root, cid)
	if len(lines) != 1 {
		t.Fatalf("learnings.jsonl has %d lines, want 1:\n%s", len(lines),
			strings.Join(lines, "\n"))
	}
	entry, err := validation.ParseOrdered([]byte(lines[0]))
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(entry, "campaign_id"); got != cid {
		t.Errorf("entry campaign_id = %q want %q", got, cid)
	}
	if !strings.Contains(lines[0], sentence) {
		t.Errorf("sentence missing from the entry:\n%s", lines[0])
	}
	if !hasEvent(eventTypes(t, c), "reflection.recorded") {
		t.Errorf("reflection.recorded not logged")
	}
	// A second reflection with an explicit round appends (never overwrites).
	code, out, errS = run(t, "--root", root, "memory", cid, "--reflect",
		"a second observation", "--round", "3")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	if !strings.Contains(out, "round 3") {
		t.Errorf("output does not report the round:\n%s", out)
	}
	if lines = reflectLines(t, root, cid); len(lines) != 2 {
		t.Fatalf("learnings.jsonl has %d lines, want 2", len(lines))
	}
}

func TestMemoryReflectArgparse(t *testing.T) {
	root, cid, _ := noopCamp(t)
	cases := []struct {
		name string
		args []string
	}{
		{"round without reflect", []string{"--round", "2"}},
		{"non-integer round", []string{"--reflect", "x", "--round", "abc"}},
		{"reflect with approve", []string{"--reflect", "x", "--approve", "MEM-1"}},
		{"reflect with reject", []string{"--reflect", "x", "--reject", "MEM-1"}},
		{"approve with reject", []string{"--approve", "MEM-1", "--reject", "MEM-2"}},
	}
	for _, tc := range cases {
		args := append([]string{"--root", root, "memory", cid}, tc.args...)
		code, out, errS := run(t, args...)
		if code != 2 {
			t.Errorf("%s: exit %d want 2 (out=%s err=%s)", tc.name, code, out, errS)
			continue
		}
		if !strings.Contains(out+errS, "usage: webv2 memory") {
			t.Errorf("%s: usage line missing from %q / %q", tc.name, out, errS)
		}
	}
}

func TestMemoryRejectRecordsReasonAndClass(t *testing.T) {
	root, cid, c := noopCamp(t)
	mem := queueMemoryRow(t, c, "the oracle was assumed to be spot-priced")
	code, out, errS := run(t, "--root", root, "memory", cid, "--reject", mem,
		"--reason", "the oracle read is real but not reachable")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	if !strings.Contains(out, "rejected "+mem) {
		t.Errorf("output does not report the rejection:\n%s", out)
	}
	if !strings.Contains(out, "reason logged:") {
		t.Errorf("output does not echo the reason:\n%s", out)
	}
	row, err := validation.ReadJson(memoryRowPath(root, cid, mem))
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(row, "promotion_status"); got != "rejected" {
		t.Errorf("promotion_status = %q want rejected", got)
	}
	// The reason is NOT in the row (the memory schema is
	// additionalProperties:false and has no reason field) — it is in the event
	// log, where an audit trail belongs.
	if strings.Contains(validation.DumpsOrdered(row, false), "not reachable") {
		t.Errorf("the reason leaked into the schema-constrained row")
	}
	if !hasEvent(eventTypes(t, c), "memory.rejected") {
		t.Errorf("memory.rejected not logged")
	}
	// The class is optional; when given it must land in the row.
	code, out, errS = run(t, "--root", root, "memory", cid, "--reject", mem,
		"--reason", "wrong about the mechanism",
		"--rejection-class", "invalid-hypothesis")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	row, err = validation.ReadJson(memoryRowPath(root, cid, mem))
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(row, "rejection_class"); got != "invalid-hypothesis" {
		t.Errorf("rejection_class = %q want invalid-hypothesis", got)
	}
}

func TestMemoryRejectRefusesUnknownAndIncomplete(t *testing.T) {
	root, cid, c := noopCamp(t)
	// Unknown row: a real error, not a silent success.
	code, out, errS := run(t, "--root", root, "memory", cid, "--reject",
		"MEM-nope", "--reason", "why not")
	if code == 0 {
		t.Fatalf("rejecting an unknown row succeeded: %s%s", out, errS)
	}
	// Missing reason: argparse exit 2, before any write.
	code, out, errS = run(t, "--root", root, "memory", cid, "--reject", "MEM-nope")
	if code != 2 {
		t.Errorf("reject without --reason: exit %d want 2 (out=%s err=%s)",
			code, out, errS)
	}
	if !strings.Contains(out+errS, "--reason") {
		t.Errorf("the error does not name the missing flag: %q / %q", out, errS)
	}
	// --reason without --reject.
	code, out, errS = run(t, "--root", root, "memory", cid, "--reason", "orphan")
	if code != 2 {
		t.Errorf("--reason without --reject: exit %d want 2 (out=%s err=%s)",
			code, out, errS)
	}
	// An invalid class is refused by the schema, not written.
	mem := queueMemoryRow(t, c, "a pattern that stays pending")
	code, out, errS = run(t, "--root", root, "memory", cid, "--reject", mem,
		"--reason", "r", "--rejection-class", "not-a-class")
	if code == 0 {
		t.Errorf("an invalid rejection class was accepted: %s%s", out, errS)
	}
	row, err := validation.ReadJson(memoryRowPath(root, cid, mem))
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(row, "promotion_status"); got != "pending" {
		t.Errorf("a refused rejection still changed the row: %q", got)
	}
}

// TestMemoryRejectRefusesAnApprovedRow: rejecting is not revocation; silently
// overwriting an approval would erase the record of who approved what.
func TestMemoryRejectRefusesAnApprovedRow(t *testing.T) {
	root, cid, c := noopCamp(t)
	mem := queueMemoryRow(t, c, "a pattern a human then approves")
	if code, out, errS := run(t, "--root", root, "memory", cid, "--approve",
		mem, "--by", "alice"); code != 0 {
		t.Fatalf("approve exit %d: %s%s", code, out, errS)
	}
	code, out, errS := run(t, "--root", root, "memory", cid, "--reject", mem,
		"--reason", "changed my mind")
	if code == 0 {
		t.Fatalf("rejecting an approved row succeeded: %s%s", out, errS)
	}
	if !strings.Contains(out+errS, "revoke") {
		t.Errorf("the refusal does not name the correct action: %q / %q", out, errS)
	}
	row, err := validation.ReadJson(memoryRowPath(root, cid, mem))
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(row, "promotion_status"); got != "human-approved" {
		t.Errorf("promotion_status = %q want human-approved (unchanged)", got)
	}
}

// TestMemoryListingShowsRejected: the listing is the inbox view, so the new
// state must be visible there.
func TestMemoryListingShowsRejected(t *testing.T) {
	root, cid, c := noopCamp(t)
	mem := queueMemoryRow(t, c, "a pattern that gets rejected")
	code, out, errS := run(t, "--root", root, "memory", cid)
	if code != 0 || !strings.Contains(out, "promotion=pending") {
		t.Fatalf("listing exit %d: %s%s", code, out, errS)
	}
	if code, out, errS := run(t, "--root", root, "memory", cid, "--reject",
		mem, "--reason", "mechanism wrong"); code != 0 {
		t.Fatalf("reject exit %d: %s%s", code, out, errS)
	}
	code, out, errS = run(t, "--root", root, "memory", cid)
	if code != 0 {
		t.Fatalf("listing exit %d: %s%s", code, out, errS)
	}
	if !strings.Contains(out, "promotion=rejected") {
		t.Errorf("listing does not show the rejection:\n%s", out)
	}
}

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
	"sort"
	"strings"
	"testing"

	"regexp"
	"websec/internal/completion"
	"websec/internal/findings"
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
	return validation.ObjStr(mem, "memory_id")
}

// queueMemoryStatusRow queues a pending row carrying an explicit finding
// status — the field the --live-only listing filter reads.
func queueMemoryStatusRow(t *testing.T, c *state.Campaign, status,
	pattern string) string {
	t.Helper()
	mem, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind: "disproved", Status: status, Pattern: pattern})
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(mem, "memory_id")
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
		out = append(out, validation.ObjStr(ev, "type"))
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
	if got := validation.ObjStr(entry, "campaign_id"); got != cid {
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
	if got := validation.ObjStr(row, "promotion_status"); got != "rejected" {
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
	if got := validation.ObjStr(row, "rejection_class"); got != "invalid-hypothesis" {
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
	if got := validation.ObjStr(row, "promotion_status"); got != "pending" {
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
	if got := validation.ObjStr(row, "promotion_status"); got != "human-approved" {
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

// memoryListingRows asserts which memory rows a listing printed: every id in
// want appears, every id in absent does not.
func memoryListingRows(t *testing.T, out string, want, absent []string) {
	t.Helper()
	for _, id := range want {
		if !strings.Contains(out, id) {
			t.Errorf("listing must keep %s:\n%s", id, out)
		}
	}
	for _, id := range absent {
		if strings.Contains(out, id) {
			t.Errorf("listing must hide %s:\n%s", id, out)
		}
	}
}

// TestMemoryListLiveOnlyHidesClutterRows is §7.5's second half: the listing is
// the operator's inbox, and a row whose finding status is ingest clutter
// (DUPLICATE/SUPERSEDED/INFORMATIONAL) is bookkeeping, not a decision. The
// filter is opt-in and reports how many rows it dropped; OUT_OF_SCOPE stays
// visible because scope is a judgment the operator re-checks.
func TestMemoryListLiveOnlyHidesClutterRows(t *testing.T) {
	root, cid, c := noopCamp(t)
	live := queueMemoryRow(t, c, "a live disproved pattern")
	dup := queueMemoryStatusRow(t, c, "DUPLICATE", "twin of an ingested finding")
	scope := queueMemoryStatusRow(t, c, "OUT_OF_SCOPE", "outside program scope")

	code, out, errS := run(t, "--root", root, "memory", cid)
	if code != 0 {
		t.Fatalf("listing exit %d: %s%s", code, out, errS)
	}
	memoryListingRows(t, out, []string{live, dup, scope}, nil)
	if strings.Contains(out, "live-only:") {
		t.Errorf("default listing must not print the filter footer:\n%s", out)
	}

	code, out, errS = run(t, "--root", root, "memory", cid, "--list",
		"--live-only")
	if code != 0 {
		t.Fatalf("--list --live-only exit %d: %s%s", code, out, errS)
	}
	memoryListingRows(t, out, []string{live, scope}, []string{dup})
	if !strings.Contains(out, "live-only: 1 rows hidden\n") {
		t.Errorf("--live-only must report the hidden row count:\n%s", out)
	}
}

// memoryViewFlagRefused asserts an action flag refuses a listing-view flag:
// the operator owes an error, not a silently ignored option.
func memoryViewFlagRefused(t *testing.T, root, cid, live, flag string) {
	t.Helper()
	code, _, errS := run(t, "--root", root, "memory", cid, "--approve", live,
		flag)
	if code != 2 || !strings.Contains(errS, flag) {
		t.Errorf("--approve %s must be refused: exit %d, err %q", flag, code,
			errS)
	}
}

// TestMemoryListViewFlagsAreArgparseChecked pins the two new view flags'
// grammar: `--live-only` alone names the same listing as `--list --live-only`,
// and neither may ride along with an action that writes.
func TestMemoryListViewFlagsAreArgparseChecked(t *testing.T) {
	root, cid, c := noopCamp(t)
	live := queueMemoryRow(t, c, "a live disproved pattern")

	code, listed, errS := run(t, "--root", root, "memory", cid, "--list",
		"--live-only")
	if code != 0 {
		t.Fatalf("--list --live-only exit %d: %s%s", code, listed, errS)
	}
	code, alone, errS := run(t, "--root", root, "memory", cid, "--live-only")
	if code != 0 {
		t.Fatalf("--live-only exit %d: %s%s", code, alone, errS)
	}
	if alone != listed {
		t.Errorf("--live-only and --list --live-only diverge:\n--- %q\n--- %q",
			alone, listed)
	}
	memoryViewFlagRefused(t, root, cid, live, "--live-only")
	memoryViewFlagRefused(t, root, cid, live, "--list")
}

// ---- D4: `memory --queue-finding` ------------------------------------------

// memoryRows is the campaign's queued memory row ids, sorted.
func memoryRows(t *testing.T, root, cid string) []string {
	t.Helper()
	matches, err := filepath.Glob(
		filepath.Join(root, "campaigns", cid, "memory", "MEM-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, strings.TrimSuffix(filepath.Base(m), ".json"))
	}
	sort.Strings(out)
	return out
}

// learningMissing is the learning proof's missing-item list.
func learningMissing(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	pr, err := completion.ProofStatus(c, "learning")
	if err != nil {
		t.Fatal(err)
	}
	return strListCLI(validation.ObjAt(pr, "missing"))
}

// learningDemands is whether the learning proof still asks for a row for fid.
func learningDemands(missing []string, fid string) bool {
	for _, m := range missing {
		if strings.HasPrefix(m, fid+": ") {
			return true
		}
	}
	return false
}

// TestMemoryQueueFindingSatisfiesLearningProof is the D4 reproduction: a
// CONFIRMED finding that never went through a ladder rung has no memory row,
// so the learning completion proof can never close; the new flag queues one.
func TestMemoryQueueFindingSatisfiesLearningProof(t *testing.T) {
	root, cid, c := noopCamp(t)
	withPolicy(t, c, root)
	title := "the stale oracle allows a zero-collateral borrow"
	fid := noopHypo(t, c, title, "")
	noopConfirm(t, c, fid)
	if !learningDemands(learningMissing(t, c), fid) {
		t.Fatalf("the learning proof does not demand a row for %s", fid)
	}
	code, out, errS := run(t, "--root", root, "memory", cid,
		"--queue-finding", fid)
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	rows := memoryRows(t, root, cid)
	if len(rows) != 1 {
		t.Fatalf("memory dir holds %d rows, want 1: %v", len(rows), rows)
	}
	mem := rows[0]
	if !strings.Contains(out, mem+" queued for "+fid+" (CONFIRMED)") {
		t.Errorf("output does not name the queued row:\n%s", out)
	}
	if !strings.Contains(out, "approve with: webv2 memory "+cid+
		" --approve "+mem+" --by NAME") {
		t.Errorf("output does not carry the approval command:\n%s", out)
	}
	row, err := validation.ReadJson(memoryRowPath(root, cid, mem))
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(row, "finding_id"); got != fid {
		t.Errorf("finding_id = %q want %q", got, fid)
	}
	if got := validation.ObjStr(row, "status"); got != "CONFIRMED" {
		t.Errorf("status = %q want CONFIRMED", got)
	}
	if got := validation.ObjStr(row, "pattern"); got != title {
		t.Errorf("pattern = %q want the finding title %q", got, title)
	}
	if got := validation.ObjStr(row, "promotion_status"); got != "pending" {
		t.Errorf("promotion_status = %q want pending (queued, never approved)",
			got)
	}
	if !hasEvent(eventTypes(t, c), "memory.queued") {
		t.Errorf("memory.queued not logged")
	}
	if after := learningMissing(t, c); learningDemands(after, fid) {
		t.Errorf("the learning proof still demands a row for %s: %v", fid, after)
	}
}

// TestMemoryQueueFindingRejectsNonMemoryStatus: the row's status vocabulary is
// learning.MEMORY_STATUSES; a finding outside it errors, names the allowed
// values, and writes nothing.
func TestMemoryQueueFindingRejectsNonMemoryStatus(t *testing.T) {
	root, cid, c := noopCamp(t)
	fid := noopHypo(t, c, "a hypothesis that never reached a terminal status", "")
	before := memoryRows(t, root, cid)
	code, out, errS := run(t, "--root", root, "memory", cid,
		"--queue-finding", fid)
	if code == 0 {
		t.Fatalf("queueing a HYPOTHESIS finding succeeded: %s%s", out, errS)
	}
	if !strings.Contains(out+errS, fid) {
		t.Errorf("the error does not name the finding: %q / %q", out, errS)
	}
	if !strings.Contains(out+errS, "CONFIRMED") ||
		!strings.Contains(out+errS, "TEST-HARNESS-ONLY") {
		t.Errorf("the error does not name the allowed statuses: %q / %q",
			out, errS)
	}
	if after := memoryRows(t, root, cid); len(after) != len(before) {
		t.Errorf("a refused queue changed the memory dir: %v -> %v",
			before, after)
	}
}

// TestMemoryQueueFindingKindDerivation: --kind is explicit when given, derived
// for CONFIRMED/DISPROVED when not, and an error naming learning.MemoryKinds
// for any other memory status.
func TestMemoryQueueFindingKindDerivation(t *testing.T) {
	root, cid, c := noopCamp(t)
	// DISPROVED derives `disproved` with no --kind.
	fid := noopHypo(t, c, "the oracle was assumed to be spot-priced", "DISPROVED")
	code, out, errS := run(t, "--root", root, "memory", cid,
		"--queue-finding", fid, "--pattern", "oracle assumed spot-priced")
	if code != 0 {
		t.Fatalf("exit %d: %s%s", code, out, errS)
	}
	rows := memoryRows(t, root, cid)
	if len(rows) != 1 {
		t.Fatalf("memory dir holds %d rows, want 1: %v", len(rows), rows)
	}
	row, err := validation.ReadJson(memoryRowPath(root, cid, rows[0]))
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(row, "kind"); got != "disproved" {
		t.Errorf("kind = %q want disproved (derived from DISPROVED)", got)
	}
	if got := validation.ObjStr(row, "status"); got != "DISPROVED" {
		t.Errorf("status = %q want DISPROVED", got)
	}
	if got := validation.ObjStr(row, "pattern"); got != "oracle assumed spot-priced" {
		t.Errorf("pattern = %q want the explicit --pattern", got)
	}
	// An explicit --kind wins over the status default.
	code, out, errS = run(t, "--root", root, "memory", cid,
		"--queue-finding", fid, "--kind", "confirmed")
	if code != 0 {
		t.Fatalf("explicit --kind exit %d: %s%s", code, out, errS)
	}
	rows = memoryRows(t, root, cid)
	if len(rows) != 2 {
		t.Fatalf("queueing twice must queue two rows, got %v", rows)
	}
	second := strings.Fields(out)[0]
	secondRow, err := validation.ReadJson(memoryRowPath(root, cid, second))
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(secondRow, "kind"); got != "confirmed" {
		t.Errorf("explicit --kind ignored: kind = %q", got)
	}
	// DUPLICATE is a memory status but has no default kind.
	dup := noopHypo(t, c, "a sibling already covers this", "DUPLICATE")
	code, out, errS = run(t, "--root", root, "memory", cid,
		"--queue-finding", dup)
	if code == 0 {
		t.Fatalf("queueing DUPLICATE without --kind succeeded: %s%s", out, errS)
	}
	if !strings.Contains(out+errS, "'confirmed'") ||
		!strings.Contains(out+errS, "'detector'") {
		t.Errorf("the error does not name learning.MemoryKinds: %q / %q",
			out, errS)
	}
	if len(memoryRows(t, root, cid)) != 2 {
		t.Errorf("a refused queue changed the memory dir")
	}
}

// TestMemoryQueueFindingArgparse: the new flags belong to this verb only, and
// the existing actions stay mutually exclusive with them.
func TestMemoryQueueFindingArgparse(t *testing.T) {
	root, cid, _ := noopCamp(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"kind without queue-finding", []string{"--kind", "confirmed"},
			"argument --kind: only meaningful with --queue-finding"},
		{"pattern without queue-finding", []string{"--pattern", "p"},
			"argument --pattern: only meaningful with --queue-finding"},
		{"queue-finding with approve",
			[]string{"--queue-finding", "F-1", "--approve", "MEM-1"},
			"argument --queue-finding: not allowed with"},
		{"queue-finding with reflect",
			[]string{"--queue-finding", "F-1", "--reflect", "x"},
			"argument --queue-finding: not allowed with"},
		{"queue-finding with reject",
			[]string{"--queue-finding", "F-1", "--reject", "MEM-1"},
			"argument --queue-finding: not allowed with"},
	}
	for _, tc := range cases {
		args := append([]string{"--root", root, "memory", cid}, tc.args...)
		code, out, errS := run(t, args...)
		if code != 2 {
			t.Errorf("%s: exit %d want 2 (out=%s err=%s)", tc.name, code, out, errS)
			continue
		}
		if !strings.Contains(out+errS, tc.want) {
			t.Errorf("%s: error %q does not contain %q", tc.name, out+errS, tc.want)
		}
		if !strings.Contains(out+errS, "usage: webv2 memory") {
			t.Errorf("%s: usage line missing from %q / %q", tc.name, out, errS)
		}
	}
}

// TestMemoryApproveWarnsOnStaleClass pins r7's queue-drift observation:
// amending the source finding's class after queueing must make the
// approval NOTICE the label gap (the judgment stands, the label is
// reviewed) instead of promoting a stale taxonomy silently.
func TestMemoryApproveWarnsOnStaleClass(t *testing.T) {
	c, root, fid := t23Campaign(t, "memory-stale")
	cid := c.CampaignID
	if code, _, errS := run(t, "--root", root, "move", cid, fid,
		"DISPROVED", "--adjacent", "the TWAP staleness window was never "+
			"checked", "--reason", "repro disproves the rounding path as "+
			"filed"); code != 0 {
		t.Fatalf("disprove: %q", errS)
	}
	if code, out, errS := run(t, "--root", root, "memory", cid,
		"--queue-finding", fid, "--kind", "disproved", "--pattern",
		"logic-error rounding drains value at conversion"); code != 0 {
		t.Fatalf("queue: exit %d %q %q", code, out, errS)
	}
	// The source finding re-files itself under another class.
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	rc := validation.ObjAt(f, "root_cause")
	rc.O = validation.SetOrAppend(rc.O, "class",
		validation.VStr("access-control"))
	f.O = validation.SetOrAppend(f.O, "root_cause", rc)
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	// Find the queued id from the plain listing line "MEM-…".
	code, out, errS := run(t, "--root", root, "memory", cid)
	if code != 0 {
		t.Fatalf("list: exit %d %q", code, errS)
	}
	mid := regexp.MustCompile(`MEM-[0-9a-f]+`).FindString(out)
	if mid == "" {
		t.Fatalf("no queued row in listing: %q", out)
	}
	code, out, errS = run(t, "--root", root, "memory", cid,
		"--approve", mid, "--by", "operator")
	if code != 0 {
		t.Fatalf("approve stands: exit %d out %q err %q", code, out, errS)
	}
	if !strings.Contains(errS, "source finding is now classified") ||
		!strings.Contains(errS, "access-control") {
		t.Fatalf("stale label must be warned with the new class: %q",
			errS)
	}
}

// TestMemoryApproveWarnsAcrossSupersede pins r8 issue 4: when the source
// finding is SUPERSEDED by a differently-classed successor, the approval
// must name the drift too — the frozen row class is not the taxonomy in
// force anymore.
func TestMemoryApproveWarnsAcrossSupersede(t *testing.T) {
	// The only window where the class can move AFTER the row exists:
	// queue against a CONFIRMED finding (queueable, still live for
	// supersession), then hand the finding to a differently-classed
	// successor. Supersede freezes the old row's class — StaleBugClass
	// must follow the chain or the stale label promotes in silence
	// (r8-4).
	c, root := t15Campaign(t, "memory-supersede")
	cid := c.CampaignID
	t15GlobalRow(t, "MEM-global01", "logic-error")
	f := cliPassingLogicError(t, c)
	fid := validation.ObjStr(f, "finding_id")
	if code, _, errS := run(t, "--root", root, "move", cid, fid,
		"POSSIBLE", "--reason", "triage survived the critic",
		"--actor", "golden"); code != 0 {
		t.Fatalf("POSSIBLE: %q", errS)
	}
	if code, _, errS := run(t, "--root", root, "move", cid, fid,
		"CONFIRMED", "--reason", "the PoC reproduces on the pinned fork",
		"--actor", "golden"); code != 0 {
		t.Fatalf("CONFIRMED: %q", errS)
	}
	if code, out, errS := run(t, "--root", root, "memory", cid,
		"--queue-finding", fid, "--kind", "confirmed", "--pattern",
		"logic-error rounding drains value at conversion"); code != 0 {
		t.Fatalf("queue: %q %q", out, errS)
	}
	newFid := t23Ingest(t, root, cid, "Same drain, right framing",
		"access-control", []string{"withdraw_without_auth"}, nil)
	if code, _, errS := run(t, "--root", root, "supersede", cid, newFid,
		"--of", fid); code != 0 {
		t.Fatalf("supersede: %q", errS)
	}
	_, out, _ := run(t, "--root", root, "memory", cid)
	mid := ""
	for _, tok := range strings.Fields(out) {
		if strings.HasPrefix(tok, "MEM-") {
			mid = strings.TrimSuffix(tok, "]")
			break
		}
	}
	if mid == "" {
		t.Fatalf("no queued row: %q", out)
	}
	code, _, errS := run(t, "--root", root, "memory", cid,
		"--approve", mid, "--by", "operator")
	if code != 0 {
		t.Fatalf("approve stands: exit %d %q", code, errS)
	}
	if !strings.Contains(errS, "access-control") {
		t.Fatalf("the successor's class must surface in the warn: %q",
			errS)
	}
}

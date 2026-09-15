package state

import (
	"os"
	"strings"
	"testing"

	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// r34 F2 — THE GENESIS HEAL KEYS ON THE LEDGER HOLDING NO RECORDS, NOT ON
// events.jsonl BEING ABSENT.
//
// Before this round log() healed only when os.Stat(c.EventsPath) said
// IsNotExist. A ledger cut to ZERO BYTES — `: > events.jsonl`, a bad
// restore, a crash that lost the file's contents but not its inode — is
// the SAME loss spelled differently, and it took the opposite branch:
// three lines (one per surviving file) saw a readable empty log, called
// it seq 0, appended one event, and reported SUCCESS. The projection kept
// the three dead events plus the new one, `verify` exited 1 forever with
// "state event tail is LONGER than the log (4 projected vs 1 logged) —
// events are GONE from the tail", the first event carried no
// ledger_rewound at all, and `webv2 doctor` then laundered the loss with
// no record of it. Truncation-to-empty is the ordinary shell shape; only
// the REMOVE shape had a pin.
//
// The law the code now honours: a ledger with NO RECORDS is genesis
// exactly like a missing one — same heal, same mirror rewind, same
// hashed ledger_rewound{dropped_tail:N} disclosure in the new chain's
// first event, and no "success" line over a loss nobody recorded.
// ---------------------------------------------------------------------------

// r34Seed3 builds a campaign with EXACTLY the 3-event history the finding
// describes (campaign.created + two notes) and asserts the projection
// mirrors all three, so a later heal has 3 dead events to disclose.
func r34Seed3(t *testing.T, id string) *Campaign {
	t.Helper()
	c, err := Init(t.TempDir(), "F2 genesis program", InitOpts{CampaignID: id})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		d := validation.VObj(kv("text", validation.VStr("history")))
		if _, err := c.Log("note.added", nil, &d); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(r34Mirror(t, c)); n != 3 {
		t.Fatalf("fixture must mirror a 3-event history, got %d", n)
	}
	return c
}

func r34Mirror(t *testing.T, c *Campaign) []validation.Value {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	return objAt(st, "events").A
}

func r34Bytes(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// r34AssertHealedGenesis is the F2 contract for every genesis shape: the
// write SUCCEEDS, the mirror is rewound to the new chain, the first event
// DISCLOSES the dropped tail (hashed, so it cannot be quietly rewritten
// later), and verify is green afterwards.
func r34AssertHealedGenesis(t *testing.T, c *Campaign, shape string,
	wantDropped int64) {
	t.Helper()
	if _, err := c.Log("note.added", nil, nil); err != nil {
		t.Fatalf("%s: a genesis ledger must heal on the next write, got: %v",
			shape, err)
	}
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK {
		t.Fatalf("%s: verify must be GREEN after the heal, got %v",
			shape, v.Problems)
	}
	if n := len(r34Mirror(t, c)); n != 1 {
		t.Fatalf("%s: the mirror must be rewound to the new chain "+
			"(1 event), got %d", shape, n)
	}
	evts, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(evts) != 1 {
		t.Fatalf("%s: the ledger must hold exactly the new event, got %d",
			shape, len(evts))
	}
	lr := objAt(objAt(evts[0], "data"), "ledger_rewound")
	if lr.Kind != validation.Obj {
		t.Fatalf("%s: the first event must DISCLOSE the rewind, got %s",
			shape, validation.DumpsOrdered(evts[0], false))
	}
	if got := objAt(lr, "dropped_tail"); got.Kind != validation.Int ||
		got.I != wantDropped {
		t.Fatalf("%s: dropped_tail must be %d, got %s", shape, wantDropped,
			validation.DumpsOrdered(evts[0], false))
	}
}

// TestR34CutLedgerIsGenesisNotASilentAppend pins the F2 fix on every
// shape that means "this ledger holds no records at all".
//
// Two of the four shapes are decisions, stated here so the intent is
// reviewable: a ledger holding ONLY A NEWLINE and one holding ONLY
// WHITESPACE are genesis too — zero records survive in them (logLines and
// verify already skip blank lines), so healing them is the same act on
// the same evidence. Refusing them would strand a campaign whose log a
// restore left blank-but-not-empty.
func TestR34CutLedgerIsGenesisNotASilentAppend(t *testing.T) {
	cases := []struct {
		shape string
		id    string
		apply func(t *testing.T, c *Campaign)
	}{
		{"removed", "C-r34rm000001", func(t *testing.T, c *Campaign) {
			if err := os.Remove(c.EventsPath); err != nil {
				t.Fatal(err)
			}
		}},
		{"truncated to zero bytes", "C-r34zero0001",
			func(t *testing.T, c *Campaign) {
				if err := os.WriteFile(c.EventsPath, nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}},
		{"a single newline", "C-r34nl000001",
			func(t *testing.T, c *Campaign) {
				if err := os.WriteFile(c.EventsPath, []byte("\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}},
		{"whitespace only", "C-r34ws000001",
			func(t *testing.T, c *Campaign) {
				if err := os.WriteFile(c.EventsPath, []byte(" \t\n  \n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.shape, func(t *testing.T) {
			c := r34Seed3(t, tc.id)
			tc.apply(t, c)
			r34AssertHealedGenesis(t, c, tc.shape, 3)
		})
	}
}

// TestR34GenesisWithEmptyMirrorDisclosesNothing pins the boundary of the
// disclosure law: ledger_rewound{dropped_tail:N} says how much was LOST,
// so a genesis write over a projection that had nothing to lose must not
// manufacture the key (a `dropped_tail: 0` would be noise an auditor has
// to explain away). The heal still runs — it just has nothing to rewind.
func TestR34GenesisWithEmptyMirrorDisclosesNothing(t *testing.T) {
	c := r34Seed3(t, "C-r34empty001")
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	st.O = validation.SetOrAppend(st.O, "events", validation.VArr())
	if err := c.SaveState(st); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.EventsPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Log("note.added", nil, nil); err != nil {
		t.Fatalf("genesis write over an empty mirror must succeed: %v", err)
	}
	evts, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(evts) != 1 {
		t.Fatalf("ledger must hold the new event only, got %d", len(evts))
	}
	if lr := objAt(objAt(evts[0], "data"), "ledger_rewound"); lr.Kind != validation.Null {
		t.Fatalf("nothing was dropped, so nothing may be disclosed: %s",
			validation.DumpsOrdered(evts[0], false))
	}
	if n := len(r34Mirror(t, c)); n != 1 {
		t.Fatalf("mirror must hold the new event only, got %d", n)
	}
	if v, err := c.VerifyLog(); err != nil || !v.OK {
		t.Fatalf("verify must be green: %v %v", v.Problems, err)
	}
}

// TestR34CutChainRefusalUnwindsTheWrite pins r16's unwind law on the NEW
// refusal shape: the save-then-log verbs (r16: ceiling, stage, artifact,
// phase, halt, complete) restore the exact pre-write bytes when Log
// refuses, so a prefix-cut ledger must not leave a half-landed decision
// behind — the old path did not refuse at all here, so the "success" it
// printed sat on top of a projection change the ledger never recorded.
func TestR34CutChainRefusalUnwindsTheWrite(t *testing.T) {
	c := r34Seed3(t, "C-r34unwind01")
	v := validation.VFloat(42.0)
	if _, err := c.SetCostCeiling(&v, "op"); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(r34Bytes(t, c.EventsPath), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("fixture must hold 4 log lines, got %d", len(lines))
	}
	if err := os.WriteFile(c.EventsPath, []byte(lines[0]+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stBefore := r34Bytes(t, c.StatePath)
	v2 := validation.VFloat(50.0)
	if _, err := c.SetCostCeiling(&v2, "op"); err == nil {
		t.Fatal("the ceiling set must refuse a ledger cut behind the projection")
	}
	if got := r34Bytes(t, c.StatePath); got != stBefore {
		t.Fatal("the refused set must leave the projection at its exact " +
			"pre-write bytes")
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	ceil := objAt(objAt(st, "budget"), "max_total_cost_usd")
	if ceil.Kind != validation.Flt || ceil.F != 42.0 {
		t.Fatalf("refused set left the ceiling half-landed at %v — the "+
			"unwind must restore 42.0", ceil)
	}
}

// TestR34BlankLedgerWithoutNewlineRefusesWithoutEmptyingTheMirror pins the
// ORDERING half of the F2 heal: the rewind lands WITH the event, never in
// a save of its own before it. A ledger holding only whitespace and no
// trailing newline is genesis by content, but the JSONL framing guard
// (validation/atomicio.go) refuses to append behind it — it cannot tell a
// blank ledger from a torn write. If the rewind were written first, that
// refusal would leave the projection EMPTIED: the dead tail gone, no
// event, no ledger_rewound anywhere, and `verify` GREEN over a campaign
// that had silently forgotten three events (it skips an empty tail). A
// heal that does not land must change nothing.
func TestR34BlankLedgerWithoutNewlineRefusesWithoutEmptyingTheMirror(t *testing.T) {
	c := r34Seed3(t, "C-r34blank001")
	if err := os.WriteFile(c.EventsPath, []byte("   "), 0o644); err != nil {
		t.Fatal(err)
	}
	logBefore := r34Bytes(t, c.EventsPath)
	stBefore := r34Bytes(t, c.StatePath)
	_, err := c.Log("note.added", nil, nil)
	if err == nil {
		t.Fatal("the framing guard must refuse to append behind an " +
			"unterminated blank ledger")
	}
	if !strings.Contains(err.Error(), "does not end in a newline") {
		t.Fatalf("the refusal must be the framing guard's own: %v", err)
	}
	if got := r34Bytes(t, c.EventsPath); got != logBefore {
		t.Fatal("the refused write must leave the ledger byte-identical")
	}
	if got := r34Bytes(t, c.StatePath); got != stBefore {
		t.Fatal("the refused write emptied the projection: the mirror is " +
			"the only record of the dead tail, so a heal that did not " +
			"land must leave it exactly as it was")
	}
	if n := len(r34Mirror(t, c)); n != 3 {
		t.Fatalf("the projection must still mirror 3 events, got %d", n)
	}
}

// TestR34PrefixCutRefusesAndNamesTheLoss is the F2 decision for the
// neighbouring shape: the ledger was cut to a PREFIX OF ITS OWN BYTES at
// a record boundary (`head -n 1`, a partial restore). Every surviving line
// is a complete event, so the chain still verifies — which is exactly why
// this shape cannot be healed by appending. The lost events are gone from
// the ledger, and the PROJECTION IS THE ONLY SURVIVING COPY of them:
// rewinding the mirror here would destroy the last record that they ever
// existed, and appending onto the cut chain (the pre-fix behaviour) wrote
// a success line and stranded verify red forever with no ledger_rewound
// anywhere. So it REFUSES, names the counts it found, and routes the
// operator to the sanctioned repair (the RUNBOOK's "Torn log recovery"
// step 4 / `webv2 doctor`, which re-derives the projection from the log
// and DISCLOSES what it drops) — never a success line over a silent loss.
func TestR34PrefixCutRefusesAndNamesTheLoss(t *testing.T) {
	c := r34Seed3(t, "C-r34pfx00001")
	raw := r34Bytes(t, c.EventsPath)
	lines := strings.Split(strings.TrimRight(raw, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("fixture must hold 3 log lines, got %d", len(lines))
	}
	if err := os.WriteFile(c.EventsPath, []byte(lines[0]+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Fatalf("fixture must be the projection-longer-than-ledger shape")
	}
	logBefore := r34Bytes(t, c.EventsPath)
	stBefore := r34Bytes(t, c.StatePath)
	_, lerr := c.Log("note.added", nil, nil)
	if lerr == nil {
		t.Fatal("appending onto a ledger cut back behind the projection " +
			"must REFUSE: the mirror is the only surviving copy of the " +
			"lost events")
	}
	msg := lerr.Error()
	if !strings.Contains(msg, "holds 1 event(s)") ||
		!strings.Contains(msg, "mirrors 3") {
		t.Fatalf("the refusal must name the counts it found: %v", lerr)
	}
	if !strings.Contains(msg, "doctor") {
		t.Fatalf("the refusal must name the sanctioned repair: %v", lerr)
	}
	if got := r34Bytes(t, c.EventsPath); got != logBefore {
		t.Fatal("the refused write must leave the cut ledger byte-identical")
	}
	if got := r34Bytes(t, c.StatePath); got != stBefore {
		t.Fatal("the refused write must leave the projection byte-identical " +
			"(it is the evidence of the loss)")
	}
}

// TestR34TornTailStillRefuses pins that re-keying the heal on "no records"
// did NOT start healing a ledger whose last record is torn: a torn tail is
// NOT genesis. The parse error stays a refusal, attributed to the line
// (r15's law), the ledger and the projection stay byte-identical, and the
// RUNBOOK's hand-recovery ("cut back to the last complete record") remains
// the only path.
func TestR34TornTailStillRefuses(t *testing.T) {
	cases := []struct {
		shape string
		id    string
		build func(t *testing.T, c *Campaign) string
		want  string
	}{
		{"torn record after a complete one", "C-r34torn0001",
			func(t *testing.T, c *Campaign) string {
				lines := strings.Split(
					strings.TrimRight(r34Bytes(t, c.EventsPath), "\n"), "\n")
				// a crash mid-append: the record stops inside its line
				return lines[0] + "\n" + lines[1][:20]
			}, "line 2"},
		{"a lone torn record", "C-r34torn0002",
			func(t *testing.T, c *Campaign) string {
				return `{"seq": 0, "at": "2026-01-01T00:00:00.000000+00:00"`
			}, "line 1"},
	}
	for _, tc := range cases {
		t.Run(tc.shape, func(t *testing.T) {
			c := r34Seed3(t, tc.id)
			torn := tc.build(t, c)
			if err := os.WriteFile(c.EventsPath, []byte(torn), 0o644); err != nil {
				t.Fatal(err)
			}
			stBefore := r34Bytes(t, c.StatePath)
			_, err := c.Log("note.added", nil, nil)
			if err == nil {
				t.Fatal("a torn tail must be REFUSED, never healed: its " +
					"last record is not a complete event")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the refusal must attribute the torn line "+
					"(%s): %v", tc.want, err)
			}
			if got := r34Bytes(t, c.EventsPath); got != torn {
				t.Fatal("the refused write must leave the torn ledger " +
					"byte-identical")
			}
			if got := r34Bytes(t, c.StatePath); got != stBefore {
				t.Fatal("the refused write must leave the projection " +
					"byte-identical")
			}
		})
	}
}

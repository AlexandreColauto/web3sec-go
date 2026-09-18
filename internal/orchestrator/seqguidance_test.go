// Port of the queue/roles half of tests/test_sequence_guidance.py: the
// reproduction queue flags a multi-step finding with a counts-only note
// (proposer-controlled actor strings never reach the note), and malformed
// on-disk sequence entries degrade instead of crashing the consumer.
//
// The role-bundle half of that file (build_proposer_context /
// build_critic_context) has no Go twin in this wave — internal/roles is not
// ported — so it is not transcribed here.
package orchestrator

import (
	"os"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/sequencepoc"
	"websec/internal/state"
	"websec/internal/validation"
)

// seqWire installs the sequence_poc predicate the queue reads (cmd/webv2/
// main.go wires the same function at boot).
func seqWire(t *testing.T) {
	t.Helper()
	prev := seqAPI
	SetSequencePOC(SequencePOCAPI{IsSequenceRequired: sequencepoc.IsSequenceRequired})
	t.Cleanup(func() { seqAPI = prev })
}

// seqQueueCampaign is Campaign.init in the fixture.
func seqQueueCampaign(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "test-program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// seqFindingIn is _mk: a live finding via the real ingest path, with the
// requested exploit_sequence.
func seqFindingIn(t *testing.T, c *state.Campaign, seq validation.Value) string {
	t.Helper()
	payload := validation.VObj(
		kvOf("title", validation.VStr("multi-tx sequence bug")),
		kvOf("root_cause", validation.VObj(
			kvOf("class", validation.VStr("access-control")),
			kvOf("description", validation.VStr("missing check across two calls")))),
		kvOf("affected", validation.VArr(validation.VObj(
			kvOf("path", validation.VStr("src/V.sol")),
			kvOf("contract", validation.VStr("V")),
			kvOf("function", validation.VStr("claim"))))),
		kvOf("attacker", validation.VObj(
			kvOf("profile", validation.VStr("arbitrary EOA")),
			kvOf("capabilities", validation.VArr()))))
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := strAt(f, "finding_id")
	f, err = findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	f.O = validation.SetOrAppend(f.O, "status", validation.VStr("POSSIBLE"))
	if seq.Kind == validation.Arr {
		f.O = validation.SetOrAppend(f.O, "exploit_sequence", seq)
	}
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	return fid
}

// seqQueue is reproduction_queue keyed by finding_id.
func seqQueue(t *testing.T, o *Orchestrator) map[string]validation.Value {
	t.Helper()
	q, err := o.ReproductionQueue()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]validation.Value{}
	for _, e := range q.A {
		out[strAt(e, "finding_id")] = e
	}
	return out
}

func TestQueueFlagsSequenceRequired(t *testing.T) {
	seqWire(t)
	c := seqQueueCampaign(t)
	fidSeq := seqFindingIn(t, c, validation.VArr(
		validation.VObj(kvOf("step", validation.VInt(1)),
			kvOf("actor", validation.VStr("alice")),
			kvOf("action", validation.VStr("deposit"))),
		validation.VObj(kvOf("step", validation.VInt(2)),
			kvOf("actor", validation.VStr("bob")),
			kvOf("action", validation.VStr("drain")))))
	fidSolo := seqFindingIn(t, c, validation.VNull())
	q := seqQueue(t, New(c))
	seqRow, ok := q[fidSeq]
	if !ok {
		t.Fatalf("sequence finding missing from queue: %v", q)
	}
	if v := validation.ObjAt(seqRow, "sequence_required"); v.Kind != validation.Bool || !v.B {
		t.Errorf("sequence_required = %v, want true", v)
	}
	note := strAt(seqRow, "note")
	if !strings.Contains(note, "webv2 sequence run") {
		t.Errorf("note = %q", note)
	}
	// note is counts + static text: proposer-controlled actor values absent
	if strings.Contains(note, "alice") || strings.Contains(note, "bob") {
		t.Errorf("note leaks actor values: %q", note)
	}
	soloRow := q[fidSolo]
	if v := validation.ObjAt(soloRow, "sequence_required"); v.Kind != validation.Bool || v.B {
		t.Errorf("solo sequence_required = %v, want false", v)
	}
	if validation.ObjAt(soloRow, "note").Kind != validation.Null {
		t.Errorf("solo note = %v, want absent", validation.ObjAt(soloRow, "note"))
	}
	// pre-existing keys untouched (ordering contract preserved)
	for _, k := range []string{"finding_id", "next_tier", "attempts", "prior"} {
		found := false
		for _, kv := range seqRow.O {
			if kv.K == k {
				found = true
			}
		}
		if !found {
			t.Errorf("queue row lost key %q", k)
		}
	}
}

func TestMalformedSequenceEntriesDoNotCrashQueue(t *testing.T) {
	// I1 pin: the queue runs the same actor projection as the verifier over
	// unvalidated on-disk data; non-dict entries are skipped, never
	// dereferenced.
	seqWire(t)
	c := seqQueueCampaign(t)
	fid := seqFindingIn(t, c, validation.VNull())
	plant := func(mutate func(validation.Value) validation.Value) {
		t.Helper()
		p := findings.FindingPath(c, fid)
		f, err := validation.ReadJson(p)
		if err != nil {
			t.Fatal(err)
		}
		f = mutate(f)
		if err := os.WriteFile(p, []byte(validation.DumpIndented(f)),
			0o644); err != nil {
			t.Fatal(err)
		}
	}
	plant(func(f validation.Value) validation.Value {
		f.O = validation.SetOrAppend(f.O, "exploit_sequence", validation.VArr(
			validation.VStr("not-a-dict"),
			validation.VObj(kvOf("step", validation.VInt(1)),
				kvOf("actor", validation.VStr("alice"))),
			validation.VInt(42),
			validation.VNull(),
			validation.VObj(kvOf("step", validation.VInt(2)),
				kvOf("actor", validation.VStr("bob")))))
		return f
	})
	q := seqQueue(t, New(c))
	row := q[fid]
	if v := validation.ObjAt(row, "sequence_required"); v.Kind != validation.Bool || !v.B {
		t.Fatalf("sequence_required = %v, want true", v)
	}
	if !strings.Contains(strAt(row, "note"), "webv2 sequence run") {
		t.Errorf("note = %q", strAt(row, "note"))
	}
	if !strings.Contains(strAt(row, "note"), "5 steps / 2 actor(s)") {
		t.Errorf("note counts = %q", strAt(row, "note"))
	}
	// attempts=None (same unvalidated family) degrades to 0, never raises
	plant(func(f validation.Value) validation.Value {
		f.O = validation.SetOrAppend(f.O, "verification", validation.VObj(
			kvOf("reproduction", validation.VObj(
				kvOf("attempts", validation.VNull()),
				kvOf("tier_reached", validation.VStr("none"))))))
		return f
	})
	q2 := seqQueue(t, New(c))
	if v := validation.ObjAt(q2[fid], "attempts"); v.Kind != validation.Int || v.I != 0 {
		t.Errorf("attempts = %v, want 0", v)
	}
}

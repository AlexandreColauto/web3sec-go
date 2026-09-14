package sections

// Task 18 (G8) render pins: invariant_verification gains the
// presence-gated harness_runs key — one exact line per invariant carrying
// verification.harness — and campaigns without the field serialize with
// the historical key set only (golden bytes untouched).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// harnessLinks seeds two invariants and optionally lands a
// verification.harness object on each.
func harnessLinks(t *testing.T, c *state.Campaign,
	fields map[string]validation.Value) {
	t.Helper()
	model := validation.VObj(
		KV("invariants", validation.VArr(
			validation.VObj(
				KV("id", validation.VStr("INV-3")),
				KV("statement",
					validation.VStr("total assets must cover all shares")),
			),
			validation.VObj(
				KV("id", validation.VStr("INV-4")),
				KV("statement",
					validation.VStr("withdrawals must never exceed deposits")),
			),
		)),
	)
	if _, err := invariants.SeedFromModel(c, model); err != nil {
		t.Fatal(err)
	}
	if len(fields) == 0 {
		return
	}
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := objAt(links, "invariants")
	for iid, h := range fields {
		e := objAt(reg, iid)
		e.O = validation.SetOrAppend(e.O, "verification",
			validation.VObj(KV("harness", h)))
		reg.O = validation.SetOrAppend(reg.O, iid, e)
	}
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
	// r21 F7: the cross-check made event-less slots ILLEGAL state — the
	// fixture must write what a mapper writes: rung + harness_run
	// together. Tests that want an unbacked slot delete the events
	// afterwards.
	for iid, h := range fields {
		backEvent(t, c, iid, h)
	}
}

// backEvent lands the harness_run event a mapper would have written for
// this slot — required state since the r21 F7 cross-check (an event-less
// slot is ILLEGAL, not merely unshown).
func backEvent(t *testing.T, c *state.Campaign, iid string,
	h validation.Value) {
	t.Helper()
	if objStr(h, "exec") == "" {
		return // malformed: no line, no event (skip arm's world)
	}
	data := validation.VObj(
		KV("rung", validation.VStr(objStr(h, "rung"))),
		KV("exec", validation.VStr(objStr(h, "exec"))),
		KV("invariant", validation.VStr(iid)),
		KV("summary", validation.VStr(objStr(h, "summary"))),
		KV("bounded_k", objAt(h, "bounded_k")),
		// Mirror the mapper r23 F1: proof subtree rides as a digest.
		KV("proof_sha256", validation.VStr(
			hexText(sha256.Sum256([]byte(validation.CanonCompact(
				objAt(h, "proof"))))))),
	)
	ref := iid
	if _, err := c.Log("harness_run", &ref, &data); err != nil {
		t.Fatal(err)
	}
	// r24: blessing rungs get their EVIDENCE too — the audit re-derives
	// minicertora claims from the exec ledger, so a fixture that
	// displays PROVEN-BOUNDED must own a stdout that re-maps to it.
	if objStr(h, "kind") == "minicertora" &&
		strings.HasPrefix(objStr(h, "exec"), "EXEC-") &&
		(objStr(h, "rung") == "proved-bounded" ||
			objStr(h, "rung") == "counterexample") {
		mintExecEvidence(t, c, iid, h)
	}
	if (objStr(h, "kind") == "halmos" ||
		objStr(h, "kind") == "forge-fuzz") &&
		(objStr(h, "rung") == "proved-bounded" ||
			objStr(h, "rung") == "counterexample") {
		mintMapRunEvidence(t, c, iid, h)
	}
}

// mintExecEvidence writes the exec dir whose bytes MapMinicertora
// re-derives into exactly this slot's claim.
func mintExecEvidence(t *testing.T, c *state.Campaign, iid string,
	h validation.Value) {
	t.Helper()
	rule := harness.MspecRuleName(iid)
	exec := objStr(h, "exec")
	dir := filepath.Join(c.ExecsDir, exec)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var line string
	exit := 0
	if objStr(h, "rung") == "proved-bounded" {
		exit = 0
		line = fmt.Sprintf(
			`{"rule": %s, "verdict": "PROVEN", `+
				`"bounds": {"loop_bound": %s, "trace_length": 0, `+
				`"steps": 0}, "reason": null, "assumptions": [], `+
				`"warnings": [], "ghosts": [], "invariant": null, `+
				`"calls": []}`,
			validation.CanonCompact(validation.VStr(rule)),
			validation.CanonCompact(objAt(h, "bounded_k")))
		// bounded_k null? the fixture only uses ints here.
		if objAt(h, "bounded_k").Kind != validation.Int {
			line = fmt.Sprintf(
				`{"rule": %s, "verdict": "PROVEN", "reason": null, `+
					`"assumptions": [], "warnings": [], "ghosts": [], `+
					`"invariant": null, "calls": []}`,
				validation.CanonCompact(validation.VStr(rule)))
		}
	} else {
		exit = 1
		line = fmt.Sprintf(`{"rule": %s, "verdict": "VIOLATED", `+
			`"reason": null, "assumptions": [], "warnings": [], `+
			`"ghosts": [], "invariant": null, "calls": []}`,
			validation.CanonCompact(validation.VStr(rule)))
	}
	// Append, never overwrite: several invariants' rows share a witness
	// dir in fixtures exactly as one scaffold run attributes many rules
	// — mcAttributed scans JSONL lines for THIS rule.
	f, err := os.OpenFile(filepath.Join(dir, "stdout.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	// exit_status: PROVEN rows need 0, VIOLATED rows 1 — one record per
	// dir; a mixed fixture dir would contradict itself, so bump to the
	// worst verdict present is NOT possible here (per-row exit is a
	// single-run truth). Fixtures keep one run per rung kind by id.
	rec := validation.VObj(
		KV("exec_id", validation.VStr(exec)),
		KV("exit_status", validation.VInt(int64(exit))),
	)
	if err := validation.WriteJson(filepath.Join(dir,
		"exec_record.json"), rec, ""); err != nil {
		t.Fatal(err)
	}
}

// TestInvariantVerificationUnbackedSlotBurns pins r21 F7 in the
// section's own seat: a slot whose LAST event disagrees (or is absent)
// is a problem, not a display line beyond reproach.
func TestInvariantVerificationUnbackedSlotBurns(t *testing.T) {
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	harnessLinks(t, c, map[string]validation.Value{
		"INV-3": harnessObj("halmos", "proved-bounded", "EXEC-7",
			validation.VInt(100), "proved bounded (k=100)"),
	})
	// (a) drift: strengthen the slot after the event landed.
	links, _ := invariants.LoadLinks(c)
	e := objAt(objAt(links, "invariants"), "INV-3")
	h := objAt(objAt(e, "verification"), "harness")
	h.O = validation.SetOrAppend(h.O, "summary",
		validation.VStr("proved bounded (k=999999)"))
	e.O = validation.SetOrAppend(e.O, "verification",
		validation.VObj(KV("harness", h)))
	reg := objAt(links, "invariants")
	reg.O = validation.SetOrAppend(reg.O, "INV-3", e)
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	if objAt(v, "ok").B {
		t.Fatalf("drifted slot must burn: %s", validation.CanonCompact(v))
	}
}

func harnessObj(kind, rung, exec string, bk validation.Value,
	summary string) validation.Value {
	return validation.VObj(
		KV("kind", validation.VStr(kind)),
		KV("rung", validation.VStr(rung)),
		KV("exec", validation.VStr(exec)),
		KV("bounded_k", bk),
		KV("summary", validation.VStr(summary)),
	)
}

// TestInvariantVerificationWithoutHarnessIsHistorical pins the golden
// contract: no verification.harness anywhere means no harness_runs key at
// all (not an empty one).
func TestInvariantVerificationWithoutHarnessIsHistorical(t *testing.T) {
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	harnessLinks(t, c, nil)
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	if v.Kind != validation.Obj {
		t.Fatalf("section kind = %v, want Obj", v.Kind)
	}
	var keys []string
	for _, kv := range v.O {
		keys = append(keys, kv.K)
	}
	want := []string{"checked", "problems", "ok"}
	if len(keys) != len(want) {
		t.Fatalf("section keys = %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("section keys = %v, want %v", keys, want)
		}
	}
}

// TestInvariantVerificationHarnessLines pins the exact per-rung lines:
// proved-bounded uppercases with k, the other rungs stay lowercase.
func TestInvariantVerificationHarnessLines(t *testing.T) {
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	harnessLinks(t, c, map[string]validation.Value{
		"INV-3": harnessObj("halmos", "proved-bounded", "EXEC-7",
			validation.VInt(100), "proved bounded (k=100)"),
		"INV-4": harnessObj("forge-fuzz", "counterexample", "EXEC-9",
			validation.VNull(), "counterexample: fuzz test seed: 5"),
	})
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	runs := objAt(v, "harness_runs")
	if runs.Kind != validation.Arr || len(runs.A) != 2 {
		t.Fatalf("harness_runs = %s, want 2 lines",
			validation.CanonCompact(runs))
	}
	if got := runs.A[0].S; got !=
		"INV-3: PROVEN-BOUNDED (halmos, k=100, EXEC-7)" {
		t.Fatalf("line 0 = %q", got)
	}
	if got := runs.A[1].S; got !=
		"INV-4: counterexample (forge-fuzz, EXEC-9)" {
		t.Fatalf("line 1 = %q", got)
	}
	// The rung lines never disturb the verdict halves.
	if !objAt(v, "ok").B {
		t.Fatalf("ok must stay true: %s", validation.CanonCompact(v))
	}
}

// TestInvariantVerificationHarnessSkipsMalformed pins the fail-soft read:
// an entry whose harness object lacks exec contributes no line (and no
// problem — the field is informational, not a verdict input).
func TestInvariantVerificationHarnessSkipsMalformed(t *testing.T) {
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	bad := validation.VObj(
		KV("kind", validation.VStr("halmos")),
		KV("rung", validation.VStr("inconclusive")),
		KV("bounded_k", validation.VNull()),
		KV("summary", validation.VStr("x")),
	)
	harnessLinks(t, c, map[string]validation.Value{"INV-3": bad})
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	if h := objAt(v, "harness_runs"); h.Kind != validation.Null {
		t.Fatalf("malformed harness must contribute no key, got %s",
			validation.CanonCompact(h))
	}
}

// harnessProofObj is harnessObj plus the proof sidecar (attributed
// minicertora lines carry one; every other kind omits the key).
func harnessProofObj(kind, rung, exec string, bk validation.Value,
	summary string, proof validation.Value) validation.Value {
	return validation.VObj(
		KV("kind", validation.VStr(kind)),
		KV("rung", validation.VStr(rung)),
		KV("exec", validation.VStr(exec)),
		KV("bounded_k", bk),
		KV("summary", validation.VStr(summary)),
		KV("proof", proof),
	)
}

// proofBounds is proof.bounds with the given loop_bound.
func proofBounds(loopBound validation.Value) validation.Value {
	return validation.VObj(KV("bounds", validation.VObj(
		KV("loop_bound", loopBound))))
}

// harnessEntry is the invariant-entry shape harnessRunLine reads.
func harnessEntry(h validation.Value) validation.Value {
	return validation.VObj(
		KV("verification", validation.VObj(KV("harness", h))))
}

// TestHarnessRunLineDispositions pins the line shapes: only a minicertora
// inconclusive RUN (a summary that actually disposes) gains the
// " | next: <advice> (<class>)" suffix; every other kind, rung, and
// plumbing floor stays byte-identical to the historical line.
func TestHarnessRunLineDispositions(t *testing.T) {
	const floor = "INV-1: inconclusive (minicertora, EXEC-9)"
	tests := []struct {
		name string
		h    validation.Value
		want string
	}{{
		"halmos inconclusive unchanged",
		harnessObj("halmos", "inconclusive", "EXEC-3", validation.VNull(),
			"inconclusive (exit output unmapped)"),
		"INV-1: inconclusive (halmos, EXEC-3)",
	}, {
		"forge-fuzz inconclusive unchanged",
		harnessObj("forge-fuzz", "inconclusive", "EXEC-3", validation.VNull(),
			"inconclusive (exit output unmapped)"),
		"INV-1: inconclusive (forge-fuzz, EXEC-3)",
	}, {
		"minicertora counterexample unchanged",
		harnessObj("minicertora", "counterexample", "EXEC-9",
			validation.VNull(), "counterexample: total >= before"),
		"INV-1: counterexample (minicertora, EXEC-9)",
	}, {
		"minicertora inconclusive names its next action",
		harnessObj("minicertora", "inconclusive", "EXEC-9", validation.VNull(),
			"inconclusive (loop-bound-may-be-exceeded: x)"),
		floor + " | next: re-run the same scaffold at --loop-bound 8, " +
			"then 16, ceiling 32 (" + harness.EscalateBound + ")",
	}, {
		"minicertora unmapped reason names the generic action",
		harnessObj("minicertora", "inconclusive", "EXEC-9", validation.VNull(),
			"inconclusive (quark-tunneling: x)"),
		floor + " | next: review the spec and the tool version; the " +
			"refusal names no known disposition (unmapped)",
	}, {
		"minicertora plumbing floor has no suffix",
		harnessObj("minicertora", "inconclusive", "EXEC-9", validation.VNull(),
			"inconclusive (exit output unmapped)"),
		floor,
	}, {
		"minicertora contradiction floor has no suffix",
		harnessObj("minicertora", "inconclusive", "EXEC-9", validation.VNull(),
			"inconclusive (report-contradiction: exit 0 with verdict PROVEN)"),
		floor,
	}, {
		"minicertora abort floor has no suffix",
		harnessObj("minicertora", "inconclusive", "EXEC-9", validation.VNull(),
			"aborted: tool-error: spec file unreadable"),
		floor,
	}, {
		// The CLI stores the summary with the binding decoration appended
		// (harnessMapBound: " (unbound: harness file hash not recorded)").
		// End-to-end the audit line must classify the base refusal, so a
		// decorated MAPPED reason still names its real next action.
		"minicertora decorated bound reason names its real action",
		harnessObj("minicertora", "inconclusive", "EXEC-9", validation.VNull(),
			"inconclusive (loop-bound-may-be-exceeded: x) "+
				"(unbound: harness file hash not recorded)"),
		floor + " | next: re-run the same scaffold at --loop-bound 8, " +
			"then 16, ceiling 32 (" + harness.EscalateBound + ")",
	}, {
		// …and a decorated plumbing floor renders NO advice: the
		// decoration is transport metadata, not a disposition (before the
		// strip, its own ": " made the floor look like an unknown reason
		// and rendered a bogus "| next: … (unmapped)" tail).
		"minicertora decorated floor has no suffix",
		harnessObj("minicertora", "inconclusive", "EXEC-9", validation.VNull(),
			"inconclusive (exit output unmapped) "+
				"(unbound: harness file hash not recorded)"),
		floor,
	}, {
		// The named runtime floor: a killed/timed-out minicertora run
		// never produced a verdict, so the line names the one next
		// action that can help — a larger wall-clock — instead of
		// rendering a bare inconclusive. Both stored shapes are pinned
		// byte-exact.
		"minicertora timed-out run names the runtime escalation",
		harnessObj("minicertora", "inconclusive", "EXEC-9", validation.VNull(),
			"inconclusive (no clean completion; loop bound was 4)"),
		floor + " | next: the run never completed — re-run with a larger " +
			"--timeout-ms or a longer exec wall-clock; a killed or " +
			"timed-out run maps no verdict (" + harness.EscalateRuntime + ")",
	}, {
		"minicertora timed-out run without a bound names the runtime escalation",
		harnessObj("minicertora", "inconclusive", "EXEC-9", validation.VNull(),
			"inconclusive (no clean completion)"),
		floor + " | next: the run never completed — re-run with a larger " +
			"--timeout-ms or a longer exec wall-clock; a killed or " +
			"timed-out run maps no verdict (" + harness.EscalateRuntime + ")",
	}, {
		// halmos summaries are "timeout after Ns", never the
		// inconclusive wrapper — the kind guard rejects them, so the
		// line stays plain.
		"halmos timeout summary stays plain",
		harnessObj("halmos", "inconclusive", "EXEC-3", validation.VNull(),
			"timeout after 30s"),
		"INV-1: inconclusive (halmos, EXEC-3)",
	}, {
		// Kind guard: the disposition branch is minicertora-only, so a
		// non-minicertora run whose summary WOULD dispose stays plain.
		"halmos disposing summary stays plain",
		harnessObj("halmos", "inconclusive", "EXEC-3", validation.VNull(),
			"inconclusive (loop-bound-may-be-exceeded: x)"),
		"INV-1: inconclusive (halmos, EXEC-3)",
	}, {
		"minicertora proved-bounded int k unchanged",
		harnessObj("minicertora", "proved-bounded", "EXEC-7",
			validation.VInt(100), "proved bounded (k=100)"),
		"INV-1: PROVEN-BOUNDED (minicertora, k=100, EXEC-7)",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := harnessRunLine("INV-1", harnessEntry(tc.h))
			if !ok {
				t.Fatalf("harnessRunLine ok=false, want true")
			}
			if got != tc.want {
				t.Fatalf("line = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestHarnessRunLineBoundKFallback pins the display k precedence on the
// audit line: bounded_k first, then proof.bounds.loop_bound (the same
// exact-decimal rule the CLI display uses) when bounded_k is null or
// absent; a non-integer in either place drops k.
func TestHarnessRunLineBoundKFallback(t *testing.T) {
	tests := []struct {
		name string
		h    validation.Value
		want string
	}{{
		"bounded_k wins over the sidecar",
		harnessProofObj("minicertora", "proved-bounded", "EXEC-9",
			validation.VInt(8), "proved bounded (k=8)",
			proofBounds(validation.VInt(4))),
		"INV-1: PROVEN-BOUNDED (minicertora, k=8, EXEC-9)",
	}, {
		"null bounded_k falls back to proof.bounds.loop_bound",
		harnessProofObj("minicertora", "proved-bounded", "EXEC-9",
			validation.VNull(), "proved bounded",
			proofBounds(validation.VInt(4))),
		"INV-1: PROVEN-BOUNDED (minicertora, k=4, EXEC-9)",
	}, {
		"absent bounded_k falls back to proof.bounds.loop_bound",
		validation.VObj(
			KV("kind", validation.VStr("minicertora")),
			KV("rung", validation.VStr("proved-bounded")),
			KV("exec", validation.VStr("EXEC-9")),
			KV("summary", validation.VStr("proved bounded")),
			KV("proof", proofBounds(validation.VInt(4)))),
		"INV-1: PROVEN-BOUNDED (minicertora, k=4, EXEC-9)",
	}, {
		"beyond-int64 sidecar bound renders verbatim",
		harnessProofObj("minicertora", "proved-bounded", "EXEC-9",
			validation.VNull(), "proved bounded",
			proofBounds(validation.VBigInt("99999999999999999999"))),
		"INV-1: PROVEN-BOUNDED (minicertora, k=99999999999999999999, EXEC-9)",
	}, {
		"non-integer sidecar bound drops k",
		harnessProofObj("minicertora", "proved-bounded", "EXEC-9",
			validation.VNull(), "proved bounded",
			proofBounds(validation.VStr("4"))),
		"INV-1: PROVEN-BOUNDED (minicertora, EXEC-9)",
	}, {
		"null sidecar bound drops k",
		harnessProofObj("minicertora", "proved-bounded", "EXEC-9",
			validation.VNull(), "proved bounded",
			proofBounds(validation.VNull())),
		"INV-1: PROVEN-BOUNDED (minicertora, EXEC-9)",
	}, {
		"no proof sidecar drops k",
		harnessObj("minicertora", "proved-bounded", "EXEC-9",
			validation.VNull(), "proved bounded"),
		"INV-1: PROVEN-BOUNDED (minicertora, EXEC-9)",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := harnessRunLine("INV-1", harnessEntry(tc.h))
			if !ok {
				t.Fatalf("harnessRunLine ok=false, want true")
			}
			if got != tc.want {
				t.Fatalf("line = %q, want %q", got, tc.want)
			}
		})
	}
}

// witnessProof is a minicertora proof sidecar carrying the L4 witness: the
// verdict line's calls array (the shape minicertora's `_extract` prints)
// alongside the sidecar's own scalar keys.
func witnessProof(calls ...validation.Value) validation.Value {
	return validation.VObj(
		KV("tool_version", validation.VStr("0.4.2")),
		KV("reason", validation.VStr("assertion-violated")),
		KV("calls", validation.VArr(calls...)),
	)
}

// witnessCall is one call entry of a bridged witness.
func witnessCall(step int, sender string, reverted bool) validation.Value {
	return validation.VObj(
		KV("step", validation.VInt(int64(step))),
		KV("function", validation.VStr("withdraw")),
		KV("target",
			validation.VStr("0x1111111111111111111111111111111111111111")),
		KV("args", validation.VArr(validation.VStr("1000"))),
		KV("env", validation.VObj(
			KV("msg.sender", validation.VStr(sender)),
			KV("msg.value", validation.VStr("0")))),
		KV("reverted", validation.VBool(reverted)),
		KV("reentrant", validation.VBool(false)),
		KV("overrides", validation.VObj()),
	)
}

// TestHarnessRunLineWitnessLabel pins the L4 suffix: a minicertora
// counterexample whose proof sidecar carries a non-empty calls array names
// the bridged call count; every other kind, rung, and witness-less sidecar
// keeps the historical line byte-for-byte.
func TestHarnessRunLineWitnessLabel(t *testing.T) {
	const (
		hexA = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		hexB = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)
	tests := []struct {
		name string
		h    validation.Value
		want string
	}{{
		"minicertora counterexample with a witness labels the bridge",
		harnessProofObj("minicertora", "counterexample", "EXEC-9",
			validation.VNull(), "counterexample: total >= before",
			witnessProof(witnessCall(0, hexA, false),
				witnessCall(1, hexB, true))),
		"INV-1: counterexample (minicertora, EXEC-9) | poc: 2 calls bridged",
	}, {
		"the label is the length alone",
		harnessProofObj("minicertora", "counterexample", "EXEC-9",
			validation.VNull(), "counterexample: total >= before",
			witnessProof(witnessCall(0, hexA, false),
				witnessCall(1, hexB, false),
				witnessCall(2, hexA, true))),
		"INV-1: counterexample (minicertora, EXEC-9) | poc: 3 calls bridged",
	}, {
		"no proof sidecar stays plain",
		harnessObj("minicertora", "counterexample", "EXEC-9",
			validation.VNull(), "counterexample: total >= before"),
		"INV-1: counterexample (minicertora, EXEC-9)",
	}, {
		"sidecar without calls stays plain",
		harnessProofObj("minicertora", "counterexample", "EXEC-9",
			validation.VNull(), "counterexample: total >= before",
			validation.VObj(KV("reason", validation.VStr("assertion-violated")))),
		"INV-1: counterexample (minicertora, EXEC-9)",
	}, {
		"empty calls array stays plain",
		harnessProofObj("minicertora", "counterexample", "EXEC-9",
			validation.VNull(), "counterexample: total >= before",
			witnessProof()),
		"INV-1: counterexample (minicertora, EXEC-9)",
	}, {
		"non-array calls stays plain",
		harnessProofObj("minicertora", "counterexample", "EXEC-9",
			validation.VNull(), "counterexample: total >= before",
			validation.VObj(KV("calls", validation.VObj()))),
		"INV-1: counterexample (minicertora, EXEC-9)",
	}, {
		"halmos counterexample stays plain",
		harnessProofObj("halmos", "counterexample", "EXEC-3",
			validation.VNull(), "counterexample: assert failed",
			witnessProof(witnessCall(0, hexA, true))),
		"INV-1: counterexample (halmos, EXEC-3)",
	}, {
		"minicertora inconclusive stays plain",
		harnessProofObj("minicertora", "inconclusive", "EXEC-9",
			validation.VNull(), "inconclusive (exit output unmapped)",
			witnessProof(witnessCall(0, hexA, true))),
		"INV-1: inconclusive (minicertora, EXEC-9)",
	}, {
		"minicertora proved-bounded stays plain",
		harnessProofObj("minicertora", "proved-bounded", "EXEC-9",
			validation.VInt(4), "proved bounded (k=4)",
			witnessProof(witnessCall(0, hexA, true))),
		"INV-1: PROVEN-BOUNDED (minicertora, k=4, EXEC-9)",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := harnessRunLine("INV-1", harnessEntry(tc.h))
			if !ok {
				t.Fatalf("harnessRunLine ok=false, want true")
			}
			if got != tc.want {
				t.Fatalf("line = %q, want %q", got, tc.want)
			}
		})
	}
}

func hexText(b [32]byte) string { return hex.EncodeToString(b[:]) }

// TestInvariantVerificationRecheckCatchesAForgedPair pins the r24
// read-time law: slot AND event can agree by conspiracy — only
// re-deriving from the exec stdout the event names tells whether the
// bytes ever said k=100. This is the critic's F2 forgery minus the
// hash-forgery plumbing: an internally consistent (slot,event) pair
// whose numbers the EVIDENCE denies.
func TestInvariantVerificationRecheckCatchesAForgedPair(t *testing.T) {
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	h := harnessObj("minicertora", "proved-bounded", "EXEC-77",
		validation.VInt(100), "proved bounded (k=100)")
	harnessLinks(t, c, map[string]validation.Value{"INV-3": h})
	// The real bytes say k=4 (backEvent minted from the slot claim??
	// no: mintExecEvidence renders bounded_k FROM the slot, so forge a
	// mismatch by rewriting stdout to the honest k=4 run):
	stdout := filepath.Join(c.ExecsDir, "EXEC-77", "stdout.log")
	line := `{"rule": "inv_3", "verdict": "PROVEN", "bounds": ` +
		`{"loop_bound": 4, "trace_length": 0, "steps": 0}, ` +
		`"reason": null, "assumptions": [], "warnings": [], ` +
		`"ghosts": [], "invariant": null, "calls": []}` + "\n"
	if err := os.WriteFile(stdout, []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	if objAt(v, "ok").B {
		t.Fatalf("conspiring pair must burn on re-derivation: %s",
			validation.CanonCompact(v)[:400])
	}
	joined := ""
	for _, p := range objAt(v, "problems").A {
		joined += p.S
	}
	if !strings.Contains(joined, "re-derives bounded_k 4; the event pins 100") {
		t.Fatalf("want inflated-bound problem, got %q", joined)
	}
}

// mintMapRunEvidence writes stdout the MapRun family re-derives to
// THIS claim: halmos renders its k from the stdout marker, forge-fuzz
// from the invocation flag in the recorded command.
func mintMapRunEvidence(t *testing.T, c *state.Campaign, iid string,
	h validation.Value) {
	t.Helper()
	exec := objStr(h, "exec")
	k := objAt(h, "bounded_k")
	if k.Kind != validation.Int && objStr(h, "rung") == "proved-bounded" {
		return // no bound claimed: nothing for recheck to reproduce
	}
	if k.Kind != validation.Int {
		k = validation.VInt(4)
	}
	dir := filepath.Join(c.ExecsDir, exec)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var stdout, cmd string
	exitOverride := 0
	switch objStr(h, "kind") {
	case "halmos":
		if objStr(h, "rung") == "counterexample" {
			stdout = "Status: fail\nCounterexample:\n  a = 5\n"
			cmd = "halmos"
			exitOverride = 1
			break
		}
		stdout = "Running halmos...\nCounterexample: none\n" +
			"Status: passed\n[PASS] check_" + iid +
			" (path: k = " + validation.IntText(k) + ")\n"
		cmd = "halmos --loop " + validation.IntText(k)
	case "forge-fuzz":
		stdout = "Suite result: ok.\n1 passed; 0 failed;\n"
		cmd = "forge test --fuzz-runs " + validation.IntText(k)
		if objStr(h, "rung") == "counterexample" {
			stdout = "[FAIL]InvariantTest.testTotal() (fuzz test, " +
				"seed: 5)\n"
			cmd = "forge test --fuzz-runs 10000"
			exitOverride = 1
		}
	default:
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "stdout.log"),
		[]byte(stdout), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := validation.VObj(
		KV("exec_id", validation.VStr(exec)),
		KV("exit_status", validation.VInt(int64(exitOverride))),
		KV("command", validation.VStr(cmd)),
	)
	if err := validation.WriteJson(filepath.Join(dir,
		"exec_record.json"), rec, ""); err != nil {
		t.Fatal(err)
	}
}

// TestInvariantVerificationFabricatedAdviceBurns pins the r25
// preemption: a conspiring (slot,event) pair claiming inconclusive
// with INVENTED advice burns when the exec's own stdout re-derives
// different words — and stays silent when the witness aged out
// (absence of evidence is not evidence of a lie).
func TestInvariantVerificationFabricatedAdviceBurns(t *testing.T) {
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// The BOUND pair claims the escalate-flag class; the bytes carry a
	// loop-bound reason (escalate-bound). Same rung, different advice —
	// exactly what steers the disposition tally.
	bad := harnessObj("minicertora", "inconclusive", "EXEC-55",
		validation.VNull(),
		"inconclusive (path-limit-reached: 256)")
	harnessLinks(t, c, map[string]validation.Value{"INV-3": bad})
	// mintExecEvidence never ran (rung not blessing): write the honest
	// INCONCLUSIVE output the pair contradicts — a rule-attributed
	// UNKNOWN line.
	dir := filepath.Join(c.ExecsDir, "EXEC-55")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	line := `{"rule": "inv_3", "verdict": "UNKNOWN", "reason": ` +
		`"loop-bound-may-be-exceeded", "details": "bound 4 < 8", ` +
		`"assumptions": [], "warnings": [], ` +
		`"ghosts": [], "invariant": null, "calls": []}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "stdout.log"),
		[]byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(filepath.Join(dir,
		"exec_record.json"), validation.VObj(
		KV("exec_id", validation.VStr("EXEC-55")),
		KV("exit_status", validation.VInt(2))), ""); err != nil {
		t.Fatal(err)
	}
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	if objAt(v, "ok").B {
		t.Fatalf("fabricated advice must burn: %s",
			validation.CanonCompact(v))
	}
	joined := ""
	for _, pr := range objAt(v, "problems").A {
		joined += pr.S
	}
	if !strings.Contains(joined, "the bound pair claims") {
		t.Fatalf("must burn on the ADVICE axis, not elsewhere: %q",
			joined)
	}
	// Aged-out witness: same forged pair, evidence gone — the rail
	// falls silent (inconclusive is not a blessing; noise there would
	// only punish honest age).
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	v2, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, pr := range objAt(v2, "problems").A {
		if strings.Contains(pr.S, "the bound pair claims") {
			t.Fatalf("missing witness must skip, not burn: %q", pr.S)
		}
	}
	// And the DECORATED honest shape must never burn: the mapper
	// appends " (unbound: …)" / renders its own timeout wording, and
	// Disposition treats those as transport, not as a different class.
	_ = v2
}

// TestInvariantVerificationDecoratedInconclusiveStaysQuiet pins the
// class rule's other direction (the r25 first cut compared summary
// BYTES and would have burned honest binds): the mapper legitimately
// appends " (unbound: …)" and renders its own timeout wording, and
// Disposition() treats those as transport. Same class = no lie.
func TestInvariantVerificationDecoratedInconclusiveStaysQuiet(t *testing.T) {
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	h := harnessObj("minicertora", "inconclusive", "EXEC-56",
		validation.VNull(),
		"inconclusive (path-limit-reached: 256) "+
			"(unbound: harness file hash not recorded)")
	harnessLinks(t, c, map[string]validation.Value{"INV-3": h})
	dir := filepath.Join(c.ExecsDir, "EXEC-56")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	line := `{"rule": "inv_3", "verdict": "UNKNOWN", "reason": ` +
		`"path-limit-reached", "details": "cap 256", ` +
		`"assumptions": [], "warnings": [], ` +
		`"ghosts": [], "invariant": null, "calls": []}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "stdout.log"),
		[]byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(filepath.Join(dir,
		"exec_record.json"), validation.VObj(
		KV("exec_id", validation.VStr("EXEC-56")),
		KV("exit_status", validation.VInt(2))), ""); err != nil {
		t.Fatal(err)
	}
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	if !objAt(v, "ok").B {
		t.Fatalf("a decorated honest bind must not burn: %s",
			validation.CanonCompact(v))
	}
	// Second honest shape: a TIMED-OUT run. The mapper gives it its own
	// "no clean completion" wording (MapRun would lie about seconds) —
	// the runtime floor, which is exactly the class the pair claims.
	c2, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	h2 := harnessObj("minicertora", "inconclusive", "EXEC-57",
		validation.VNull(),
		"inconclusive (no clean completion; loop bound was 4)")
	harnessLinks(t, c2, map[string]validation.Value{"INV-3": h2})
	dir2 := filepath.Join(c2.ExecsDir, "EXEC-57")
	if err := os.MkdirAll(dir2, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir2, "stdout.log"),
		[]byte("partial garbage that never completed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validation.WriteJson(filepath.Join(dir2,
		"exec_record.json"), validation.VObj(
		KV("exec_id", validation.VStr("EXEC-57")),
		KV("exit_status", validation.VInt(-1))), ""); err != nil {
		t.Fatal(err)
	}
	v2, err := InvariantVerification(c2)
	if err != nil {
		t.Fatal(err)
	}
	if !objAt(v2, "ok").B {
		t.Fatalf("a timed-out honest bind must not burn: %s",
			validation.CanonCompact(v2))
	}
}

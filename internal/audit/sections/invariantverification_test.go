package sections

// Task 18 (G8) render pins: invariant_verification gains the
// presence-gated harness_runs key — one exact line per invariant carrying
// verification.harness — and campaigns without the field serialize with
// the historical key set only (golden bytes untouched).

import (
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

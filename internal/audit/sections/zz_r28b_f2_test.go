package sections

// zz_r28b_f2_test.go — r28b F2/F3 regressions in section 11's own seat.
//
// F2: the blessed arm read the exec record's exit_status with `es := 0` and
// no guard, so a chain-valid forged (slot, event) pair — every layer claiming
// proved-bounded k=4 — over a record whose exit_status was ABSENT or null
// re-derived proved-bounded from the PROVEN stdout and audited GREEN. The
// bind maps the same record as inconclusive ("exit output unmapped", -2), so
// the two halves of "bind == audit" disagreed on the one field neither side
// pins in the event. Absence is inconclusive, never a blessing.
//
// F3: the re-derivation now goes through harness.DecideBound — the bind's own
// entry point — so the recorded-hash arm and the Validate re-render run here
// too; the fixtures below also pin the constraint-(3) boundary: a rung whose
// record carries hash evidence burns when the scaffold bytes cannot be
// obtained, while the unbound arm (no hash evidence at all) keeps the honest
// behaviour it has today.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// r28bWriteRecord rewrites one exec record to the EXACT shape under test:
// the key set is the argument, so "exit_status absent" and "exit_status null"
// are different fixtures, not different defaults.
func r28bWriteRecord(t *testing.T, c *state.Campaign, exec string,
	rec validation.Value) {
	t.Helper()
	p := filepath.Join(c.ExecsDir, exec, "exec_record.json")
	if err := validation.WriteJson(p, rec, ""); err != nil {
		t.Fatal(err)
	}
}

// r28bForgedPair is the chain-valid forgery the F2 repro used: the fixture
// mints honest k=4 PROVEN evidence for EXEC-70 and its harness_run event,
// and the caller then rewrites the record's exit_status to the shape under
// test. Slot, event and event-side bounded_k all agree; only the record's
// exit field moved.
func r28bForgedPair(t *testing.T, exec string) (*state.Campaign,
	validation.Value) {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	h := harnessObj("minicertora", "proved-bounded", exec,
		validation.VInt(4), "proved bounded (k=4)")
	harnessLinks(t, c, map[string]validation.Value{"INV-3": h})
	return c, h
}

// r28bHead truncates a canonical dump for a failure message; the section's
// JSON is short when it is entirely green, so slicing must be guarded.
func r28bHead(s string) string {
	if len(s) <= 400 {
		return s
	}
	return s[:400]
}

// r28bProblems joins the section's problem strings.
func r28bProblems(v validation.Value) string {
	joined := ""
	for _, p := range objAt(v, "problems").A {
		joined += p.S
	}
	return joined
}

// TestZZR28BAbsentExitStatusIsNotABlessing is the F2 repro (absent shape):
// the forged pair must burn, and the burn must name the state observed (the
// mapper's own "exit output unmapped", not a generic drift).
func TestZZR28BAbsentExitStatusIsNotABlessing(t *testing.T) {
	for _, tc := range []struct {
		name string
		rec  validation.Value
	}{
		{"absent", validation.VObj(
			KV("exec_id", validation.VStr("EXEC-70")))},
		{"null", validation.VObj(
			KV("exec_id", validation.VStr("EXEC-70")),
			KV("exit_status", validation.VNull()))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := r28bForgedPair(t, "EXEC-70")
			// The record the pair rides: schema-valid, no usable exit
			// status. (mintExecEvidence wrote exit 0 + a PROVEN k=4 line.)
			r28bWriteRecord(t, c, "EXEC-70", tc.rec)
			v, err := InvariantVerification(c)
			if err != nil {
				t.Fatal(err)
			}
			if objAt(v, "ok").B {
				t.Fatalf("an exit_status %s must not bless: %s", tc.name,
					r28bHead(validation.CanonCompact(v)))
			}
			joined := r28bProblems(v)
			if !strings.Contains(joined, "re-derives rung 'inconclusive'") {
				t.Fatalf("want the re-derivation burn, got %q", joined)
			}
			if !strings.Contains(joined, "exit output unmapped") {
				t.Fatalf("the burn must name the observed state "+
					"(exit output unmapped), got %q", joined)
			}
			// A burned blessing is qualified on the line a consumer reads.
			runs := objAt(v, "harness_runs")
			if runs.Kind != validation.Arr || len(runs.A) != 1 {
				t.Fatalf("harness_runs = %s",
					validation.CanonCompact(runs))
			}
			if !strings.HasSuffix(runs.A[0].S, " (UNBACKED)") {
				t.Fatalf("the burned line must be qualified: %q",
					runs.A[0].S)
			}
		})
	}
}

// TestZZR28BPresentExitStatusStillBlesses is the control the F2 burn must
// never touch: the SAME forged pair with a reported exit 0 re-derives
// proved-bounded and stays green — the burn above is about the absent field,
// not about the fixture.
func TestZZR28BPresentExitStatusStillBlesses(t *testing.T) {
	c, _ := r28bForgedPair(t, "EXEC-71")
	r28bWriteRecord(t, c, "EXEC-71", validation.VObj(
		KV("exec_id", validation.VStr("EXEC-71")),
		KV("exit_status", validation.VInt(0))))
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	if !objAt(v, "ok").B {
		t.Fatalf("an honest exit 0 run must stay green: %s",
			r28bHead(validation.CanonCompact(v)))
	}
}

// TestZZR28BMissingScaffoldBoundRungBurns pins constraint (3)'s first half:
// a blessing whose record CARRIES hash evidence cannot be re-derived without
// the scaffold bytes the hash was compared against, so section 11 refuses
// (naming what is missing) instead of blessing on a guess. The fixture world
// has no scaffold artifact at all, which is exactly "the artifact is gone".
func TestZZR28BMissingScaffoldBoundRungBurns(t *testing.T) {
	c, _ := r28bForgedPair(t, "EXEC-72")
	r28bWriteRecord(t, c, "EXEC-72", validation.VObj(
		KV("exec_id", validation.VStr("EXEC-72")),
		KV("exit_status", validation.VInt(0)),
		KV("input_hashes", validation.VObj(
			KV("artifacts/harness/INV-3/INV.mspec",
				validation.VStr(strings.Repeat("a", 64)))))))
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	if objAt(v, "ok").B {
		t.Fatalf("hash evidence with no scaffold bytes must not bless: %s",
			r28bHead(validation.CanonCompact(v)))
	}
	joined := r28bProblems(v)
	if !strings.Contains(joined, "cannot be re-derived") ||
		!strings.Contains(joined, "not backed") {
		t.Fatalf("the burn must name what is missing, got %q", joined)
	}
	if !strings.Contains(joined, "HARNESS-INV-3-minicertora") {
		t.Fatalf("the burn must name the scaffold the bind hashed, got %q",
			joined)
	}
}

// TestZZR28BMissingScaffoldUnboundStaysHonest pins constraint (3)'s second
// half: with NO hash evidence the unbound arm needs no scaffold bytes for its
// mapping (its hash comparison is vacuous), so the same missing-artifact
// world keeps the honest behaviour the bind has today — no burn, and the
// display line unchanged. TestZZR28BPresentExitStatusStillBlesses is the
// same shape with a reported exit.
func TestZZR28BMissingScaffoldUnboundStaysHonest(t *testing.T) {
	c, _ := r28bForgedPair(t, "EXEC-73")
	// No input_hashes key at all: mintExecEvidence's record plus exit 0.
	r28bWriteRecord(t, c, "EXEC-73", validation.VObj(
		KV("exec_id", validation.VStr("EXEC-73")),
		KV("exit_status", validation.VInt(0))))
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	if !objAt(v, "ok").B {
		t.Fatalf("the unbound arm must stay honest: %s",
			r28bHead(validation.CanonCompact(v)))
	}
	runs := objAt(v, "harness_runs")
	if runs.Kind != validation.Arr || len(runs.A) != 1 ||
		runs.A[0].S != "INV-3: PROVEN-BOUNDED (minicertora, k=4, EXEC-73)" {
		t.Fatalf("harness_runs = %s", validation.CanonCompact(runs))
	}
}

// TestZZR28BScaffoldArtifactPresentReDerives pins that the new scaffold read
// does not disturb the settled shape: an unbound blessing over a campaign
// whose scaffold artifact exists on disk (registered through the artifacts
// API) still audits green with its historical line.
func TestZZR28BScaffoldArtifactPresentReDerives(t *testing.T) {
	c, _ := r28bForgedPair(t, "EXEC-74")
	r28bWriteRecord(t, c, "EXEC-74", validation.VObj(
		KV("exec_id", validation.VStr("EXEC-74")),
		KV("exit_status", validation.VInt(0))))
	// Prove the read arm itself: the section must be able to obtain bytes
	// for the INV-3 minicertora scaffold once one is registered.
	if _, why := harnessScaffoldArtifactBytes(c, mustEvents(t, c), "INV-3",
		"minicertora"); why == "" {
		t.Fatalf("fixture has no scaffold artifact, but the reader "+
			"reported one: %s", why)
	}
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	if !objAt(v, "ok").B {
		t.Fatalf("an unbound blessing must stay green: %s",
			r28bHead(validation.CanonCompact(v)))
	}
}

// mustEvents reads the campaign ledger for the readers under test.
func mustEvents(t *testing.T, c *state.Campaign) []validation.Value {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	return events
}

// TestZZR28BScaffoldReaderNamesWhatIsMissing pins the reader's own contract:
// an absent scaffold event and an unregistered artifact each produce a why
// string that names the missing thing (the burn's evidence).
func TestZZR28BScaffoldReaderNamesWhatIsMissing(t *testing.T) {
	c, _ := r28bForgedPair(t, "EXEC-75")
	events := mustEvents(t, c)
	if _, why := harnessScaffoldArtifactBytes(c, events, "INV-3",
		"minicertora"); !strings.Contains(why,
		"no harness_scaffold event names HARNESS-INV-3-minicertora") {
		t.Fatalf("no-event why = %q", why)
	}
	if _, why := harnessScaffoldArtifactBytes(c, events, "INV-4",
		"halmos"); why == "" {
		t.Fatal("a missing scaffold must report a why")
	}
}

// TestZZR28BNoScaffoldFileIsNotAGreenLight is the file-level half of the
// reader: a registered row whose file was deleted must report a why (so the
// bound arm burns) rather than hand back empty bytes that silently skip the
// hash comparison.
func TestZZR28BNoScaffoldFileIsNotAGreenLight(t *testing.T) {
	c, _ := r28bForgedPair(t, "EXEC-76")
	// Register a scaffold artifact row, then delete its file: the shape
	// "the scaffold artifact is gone" constraint (3) names.
	raw := []byte("// web3sec G8 harness scaffold — MiniCertora bounded verifier.\n")
	p := filepath.Join(c.ArtifactsDir, "harness", "INV-3", "INV.mspec")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := c.RegisterArtifact("harness", p, "test scaffold", nil)
	if err != nil {
		t.Fatal(err)
	}
	ref := id
	data := validation.VObj(
		KV("artifact_id", validation.VStr("HARNESS-INV-3-minicertora")),
		KV("invariant", validation.VStr("INV-3")),
		KV("kind", validation.VStr("minicertora")),
	)
	if _, err := c.Log("harness_scaffold", &ref, &data); err != nil {
		t.Fatal(err)
	}
	if _, why := harnessScaffoldArtifactBytes(c, mustEvents(t, c), "INV-3",
		"minicertora"); why != "" {
		t.Fatalf("a present file must read clean, got %q", why)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	// The row is still registered, the bytes are gone: the reader says so.
	if _, why := harnessScaffoldArtifactBytes(c, mustEvents(t, c), "INV-3",
		"minicertora"); why == "" {
		t.Fatal("a deleted scaffold file must report a why")
	}
}

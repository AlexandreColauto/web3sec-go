package sections

// zz_r29b_f1f3_test.go — r29b F1/F3 in section 11's own seat.
//
// F1: a chain-valid forgery that rewrites the KIND in the slot AND in the
// last harness_run event (with everything else copied from an honest bind)
// used to audit GREEN: harnessRunLine renders a line for any non-empty kind,
// harnessRungBacked compares kind as an exact string (so editing both sides
// satisfies it), and recheckExecEvidence returned early unless the kind was
// exactly "minicertora" — its comment claimed unknown kinds render no line,
// which is false. Now the kind is resolved first: a kind no mapper implements
// ("mythril"), or a spelling the bind never writes ("MINICERTORA"), burns and
// names the kind; the honest kind is unaffected.
//
// F3: the "scaffold bytes unobtainable" arm asked `len(hashes) > 0`, which is
// true for EVERY real record (the sandbox's own artifact_hashes holds the
// stdout/stderr digests), so pruning a normal campaign's scaffold row made it
// claim hash evidence the record never carried. It now asks the bind's own
// predicate — does a recorded key name a scaffold FILE — and names the state
// it actually observed. The mirror half: with no harness-file hash the bind
// still Validates the scaffold file it reads from disk, so the audit reads
// that same file the same way and burns a drifted claim instead of blessing
// it; when even that read is unobtainable the arm stays silent (absence is
// inconclusive).

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// zzR29bBackEventWithKind lands the harness_run event the repro's forgery
// needs: the same payload backEvent writes, plus the KIND (which the mapper
// has carried since r21). The last event for the invariant then AGREES with
// the forged slot on every field, so the only thing wrong with the pair is
// the kind string itself.
func zzR29bBackEventWithKind(t *testing.T, c *state.Campaign, iid string,
	h validation.Value, kind string) {
	t.Helper()
	data := validation.VObj(
		KV("kind", validation.VStr(kind)),
		KV("rung", validation.VStr(objStr(h, "rung"))),
		KV("exec", validation.VStr(objStr(h, "exec"))),
		KV("invariant", validation.VStr(iid)),
		KV("summary", validation.VStr(objStr(h, "summary"))),
		KV("bounded_k", objAt(h, "bounded_k")),
		KV("proof_sha256", validation.VStr(
			hexText(sha256.Sum256([]byte(validation.CanonCompact(
				objAt(h, "proof"))))))),
	)
	ref := iid
	if _, err := c.Log("harness_run", &ref, &data); err != nil {
		t.Fatal(err)
	}
}

// zzR29bSetStatement rewrites one invariant's statement in the links store —
// the "the claim drifted after the run" shape.
func zzR29bSetStatement(t *testing.T, c *state.Campaign, iid,
	stmt string) {
	t.Helper()
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := objAt(links, "invariants")
	e := objAt(reg, iid)
	if e.Kind != validation.Obj {
		t.Fatalf("no %s entry", iid)
	}
	e.O = validation.SetOrAppend(e.O, "statement", validation.VStr(stmt))
	reg.O = validation.SetOrAppend(reg.O, iid, e)
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
}

// zzR29bRegisterScaffold writes, registers and logs a REAL scaffold for one
// invariant (the bytes harness.Scaffold renders from the CURRENT claim), so
// the fixture owns the artifact row + harness_scaffold event the bind's own
// reader follows. It returns the file path and the registry row id.
func zzR29bRegisterScaffold(t *testing.T, c *state.Campaign,
	iid string) (string, string) {
	t.Helper()
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	entry := objAt(objAt(links, "invariants"), iid)
	if entry.Kind != validation.Obj {
		t.Fatalf("no %s entry", iid)
	}
	body, err := harness.Scaffold(harness.MiniCertora,
		harness.InvValue(iid, entry))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(c.ArtifactsDir, "harness", iid, "INV.mspec")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := c.RegisterArtifact("harness", p, "test scaffold", nil)
	if err != nil {
		t.Fatal(err)
	}
	ref := id
	data := validation.VObj(
		KV("artifact_id", validation.VStr("HARNESS-"+iid+"-minicertora")),
		KV("invariant", validation.VStr(iid)),
		KV("kind", validation.VStr("minicertora")),
	)
	if _, err := c.Log("harness_scaffold", &ref, &data); err != nil {
		t.Fatal(err)
	}
	return p, id
}

// TestZZR29BForgedKindBurnsInSectionEleven is F1's repro at the section: a
// conspiring (slot, event) pair whose kind no mapper implements must burn and
// name the kind — and the same fixture with the honest kind stays green, so
// the burn is about the kind and not about the fixture.
func TestZZR29BForgedKindBurnsInSectionEleven(t *testing.T) {
	cases := []struct {
		kind     string
		wantText string
	}{
		{"mythril", "names no mapper this audit can re-derive"},
		{"MYTHRIL", "names no mapper this audit can re-derive"},
		{"MINICERTORA", "is not the canonical spelling"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			c, err := state.Init(t.TempDir(), "Acme Program",
				state.InitOpts{})
			if err != nil {
				t.Fatal(err)
			}
			h := harnessObj(tc.kind, "proved-bounded", "EXEC-70",
				validation.VInt(999999), "proved bounded (k=999999)")
			harnessLinks(t, c, map[string]validation.Value{"INV-3": h})
			zzR29bBackEventWithKind(t, c, "INV-3", h, tc.kind)

			v, err := InvariantVerification(c)
			if err != nil {
				t.Fatal(err)
			}
			if objAt(v, "ok").B {
				t.Fatalf("a forged kind must not bless: %s",
					r28bHead(validation.CanonCompact(v)))
			}
			joined := r28bProblems(v)
			if !strings.Contains(joined, tc.wantText) {
				t.Fatalf("the burn must name the kind as the reason "+
					"(%q), got %q", tc.wantText, joined)
			}
			if !strings.Contains(joined, tc.kind) {
				t.Fatalf("the burn must name the kind %q, got %q",
					tc.kind, joined)
			}
			runs := objAt(v, "harness_runs")
			if runs.Kind != validation.Arr || len(runs.A) != 1 ||
				!strings.Contains(runs.A[0].S, tc.kind) ||
				!strings.HasSuffix(runs.A[0].S, " (UNBACKED)") {
				t.Fatalf("the burned line must be qualified: %s",
					validation.CanonCompact(runs))
			}
		})
	}
	t.Run("honest kind unaffected", func(t *testing.T) {
		c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{})
		if err != nil {
			t.Fatal(err)
		}
		h := harnessObj("minicertora", "proved-bounded", "EXEC-71",
			validation.VInt(4), "proved bounded (k=4)")
		harnessLinks(t, c, map[string]validation.Value{"INV-3": h})
		v, err := InvariantVerification(c)
		if err != nil {
			t.Fatal(err)
		}
		if !objAt(v, "ok").B {
			t.Fatalf("an honest kind must stay green: %s",
				r28bHead(validation.CanonCompact(v)))
		}
		runs := objAt(v, "harness_runs")
		if runs.Kind != validation.Arr || len(runs.A) != 1 ||
			runs.A[0].S != "INV-3: PROVEN-BOUNDED (minicertora, k=4, EXEC-71)" {
			t.Fatalf("harness_runs = %s", validation.CanonCompact(runs))
		}
	})
}

// TestZZR29BPrunedScaffoldRowNamesTheRealState is F3(a)(b): a normal
// campaign whose scaffold row is pruned, over a record that really does carry
// the scaffold FILE hash. The burn must name the harness-file key it found
// and the artifact that is gone — not claim generic "recorded harness file
// hash(es)" that were "bound to" bytes the record never mentioned (the old
// arm's text, which `len(hashes) > 0` made true for every real record).
func TestZZR29BPrunedScaffoldRowNamesTheRealState(t *testing.T) {
	c, _ := r28bForgedPair(t, "EXEC-80")
	p, refID := zzR29bRegisterScaffold(t, c, "INV-3")
	sha, err := validation.Sha256File(p)
	if err != nil {
		t.Fatal(err)
	}
	// The sandbox's own record shape: input_hashes carries the scaffold file
	// the run took in, artifact_hashes the captures it produced.
	r28bWriteRecord(t, c, "EXEC-80", validation.VObj(
		KV("exec_id", validation.VStr("EXEC-80")),
		KV("exit_status", validation.VInt(0)),
		KV("input_hashes", validation.VObj(
			KV("artifacts/harness/INV-3/INV.mspec", validation.VStr(sha)))),
		KV("artifact_hashes", validation.VObj(
			KV("stdout.log", validation.VStr(strings.Repeat("a", 64))),
			KV("stderr.log", validation.VStr(strings.Repeat("b", 64)))))))
	if _, err := c.PruneArtifact(refID, "operator retired the scaffold"); err != nil {
		t.Fatal(err)
	}
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	if objAt(v, "ok").B {
		t.Fatalf("a hash-carrying rung with no scaffold row must not "+
			"bless: %s", r28bHead(validation.CanonCompact(v)))
	}
	joined := r28bProblems(v)
	if !strings.Contains(joined, "records a harness-file hash") {
		t.Fatalf("the burn must ask the harness-FILE question, got %q",
			joined)
	}
	if !strings.Contains(joined, "artifacts/harness/INV-3/INV.mspec") {
		t.Fatalf("the burn must quote the key it found, got %q", joined)
	}
	if !strings.Contains(joined, "not registered any more") {
		t.Fatalf("the burn must name the pruned row as what is missing, "+
			"got %q", joined)
	}
	if !strings.Contains(joined, "not backed") {
		t.Fatalf("the burn must refuse backing, got %q", joined)
	}
	if strings.Contains(joined, "carries recorded harness file hash(es)") {
		t.Fatalf("the old misnaming survived: %q", joined)
	}
}

// TestZZR29BStdoutDigestsAreNotHarnessFileEvidence is F3(a)'s width: the
// record shape the sandbox really writes carries artifact_hashes stdout.log /
// stderr.log, so `len(hashes) > 0` was true for every real record and this
// arm told the operator about hash evidence that does not exist. With no
// scaffold row this is the UNBOUND arm: the mapping still reproduces and the
// section stays green — and when even the bind's own read of the scaffold
// file is unobtainable the arm stays SILENT (absence is inconclusive, never a
// blessing and never a burn: a bind could not have produced the rung in that
// world either).
func TestZZR29BStdoutDigestsAreNotHarnessFileEvidence(t *testing.T) {
	c, _ := r28bForgedPair(t, "EXEC-81")
	r28bWriteRecord(t, c, "EXEC-81", validation.VObj(
		KV("exec_id", validation.VStr("EXEC-81")),
		KV("exit_status", validation.VInt(0)),
		KV("artifact_hashes", validation.VObj(
			KV("stdout.log", validation.VStr(strings.Repeat("a", 64))),
			KV("stderr.log", validation.VStr(strings.Repeat("b", 64)))))))
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	joined := r28bProblems(v)
	if strings.Contains(joined, "cannot be re-derived") {
		t.Fatalf("a record whose only hashes are its own capture digests "+
			"carries no harness-file hash, got %q", joined)
	}
	if !objAt(v, "ok").B {
		t.Fatalf("the unbound arm must still reproduce the mapping: %s",
			r28bHead(validation.CanonCompact(v)))
	}
}

// TestZZR29BHashlessDriftedClaimBurns is F3(c)'s mirror half: a record with
// NO harness-file hash at all (the only shape the carve-out is reachable in)
// plus a drift the bind would refuse. The bind reads the scaffold file from
// disk raw and Validates it against the CURRENT claim, so the audit must read
// that same file the same way — and burn the drifted claim — even when the
// pinned reader refuses the file (its bytes no longer hash to the registered
// sha, a check the bind never makes).
func TestZZR29BHashlessDriftedClaimBurns(t *testing.T) {
	c, _ := r28bForgedPair(t, "EXEC-82")
	p, _ := zzR29bRegisterScaffold(t, c, "INV-3")
	// Baseline: the pinned reader obtains the bytes from the claims that
	// rendered them, and the section is green.
	if _, why := harnessScaffoldArtifactBytes(c, mustEvents(t, c), "INV-3",
		"minicertora"); why != "" {
		t.Fatalf("fixture must start with obtainable scaffold bytes: %q",
			why)
	}
	v, err := InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	if !objAt(v, "ok").B {
		t.Fatalf("baseline must be green: %s",
			r28bHead(validation.CanonCompact(v)))
	}
	// (1) the claim drifts in the ledger...
	zzR29bSetStatement(t, c, "INV-3",
		"total assets must cover all shares, always")
	// (2) ...and the scaffold FILE moves inside its free BODY window, so the
	// row's pinned sha no longer matches what is on disk. The BIND never
	// checks that sha; the audit's pinned reader does — this is the carve-out
	// the old code answered with "no re-derivation needed" and a blessing.
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(raw), harness.EndMarker,
		"// r29b extra body line\n"+harness.EndMarker, 1)
	if edited == string(raw) {
		t.Fatal("fixture: the scaffold has no body window to edit")
	}
	if err := os.WriteFile(p, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, why := harnessScaffoldArtifactBytes(c, mustEvents(t, c), "INV-3",
		"minicertora"); why == "" {
		t.Fatal("the pinned reader must refuse the edited file (that is " +
			"the carve-out this test drives)")
	}
	if _, why := harnessScaffoldBindBytes(c, mustEvents(t, c), "INV-3",
		"minicertora"); why != "" {
		t.Fatalf("the bind's own read must still obtain those bytes: %q",
			why)
	}
	v, err = InvariantVerification(c)
	if err != nil {
		t.Fatal(err)
	}
	if objAt(v, "ok").B {
		t.Fatalf("a hash-less drifted claim must burn, not bless: %s",
			r28bHead(validation.CanonCompact(v)))
	}
	joined := r28bProblems(v)
	if !strings.Contains(joined, "re-derives rung 'inconclusive'") ||
		!strings.Contains(joined, "scaffold-degraded") ||
		!strings.Contains(joined, "natspec invariant line changed") {
		t.Fatalf("the burn must carry the bind's own refusal reason, "+
			"got %q", joined)
	}
}

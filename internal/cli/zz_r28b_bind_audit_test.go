package cli

// zz_r28b_bind_audit_test.go — r28b F3 end to end: the bind and section 11
// must re-derive the SAME decision through the SAME code path
// (harness.DecideBound), with the same arguments.
//
// Before the fix section 11 called the kind mappers directly, so only the
// LAST step of the bind's decision was reproduced. Both repros below bound
// cleanly and then moved state the hash arm alone can see:
//
//   (A) the invariant CLAIM drifted after the run — the bind's Validate
//       re-render refuses "scaffold-degraded: natspec invariant line
//       changed" while the old audit kept blessing the stored rung;
//   (B) the exec record's recorded hash was replaced by a FOREIGN sha —
//       the bind refuses "scaffold-bound violation: …" while the old audit
//       kept blessing it;
//
// and the honest control (C): a run with NO hash info still maps normally
// with the unbound suffix and audits green.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// The pinned summary strings (constraint 1/d): the bind's existing bytes,
// asserted exactly. They live here as literals so a wording regression in
// the moved decision code cannot pass unnoticed.
const (
	zzR28bDegraded  = "scaffold-degraded: natspec invariant line changed"
	zzR28bViolation = "scaffold-bound violation: harness file hash " +
		"differs from stored scaffold"
	zzR28bUnboundSuffix = " (unbound: harness file hash not recorded)"
	zzR28bStatement     = "total always covers sum(payouts)"
	zzR28bDrifted       = "total always covers sum(payouts), always"
)

// zzR28bCamp seeds INV-1 and scaffolds it as minicertora through the real
// production flow, so the harness_scaffold event and artifact row exist
// exactly as the bind and the audit read them.
func zzR28bCamp(t *testing.T, program string) (*state.Campaign, string) {
	t.Helper()
	c, root := t15Campaign(t, program)
	t15SeedInvariant(t, c, "INV-1", zzR28bStatement)
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold", "minicertora", "--invariant", "INV-1")
	if code != 0 {
		t.Fatalf("scaffold exit %d: out=%q err=%q", code, out, errS)
	}
	return c, root
}

// zzR28bScaffoldSHA is the stored INV.mspec content hash a bound run echoes.
func zzR28bScaffoldSHA(t *testing.T, c *state.Campaign) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(c.ArtifactsDir, "harness",
		"INV-1", "INV.mspec"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// zzR28bDrift edits the invariant claim the scaffold was rendered from —
// the "bind first, edit the claim later" shape of repro (A).
func zzR28bDrift(t *testing.T, c *state.Campaign, stmt string) {
	t.Helper()
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := validation.ObjAt(links, "invariants")
	entry := validation.ObjAt(reg, "INV-1")
	if entry.Kind != validation.Obj {
		t.Fatal("no INV-1 entry")
	}
	entry.O = validation.SetOrAppend(entry.O, "statement",
		validation.VStr(stmt))
	reg.O = validation.SetOrAppend(reg.O, "INV-1", entry)
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	if _, err := invariants.SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
}

// zzR28bBind runs the bind and returns its exact stdout.
func zzR28bBind(t *testing.T, root, cid, exec string) string {
	t.Helper()
	code, out, errS := run(t, "--root", root, "verify", cid,
		"--harness-result", "INV-1", "--exec", exec)
	if code != 0 {
		t.Fatalf("bind exit %d: out=%q err=%q", code, out, errS)
	}
	return out
}

// zzR28bHarness is verification.harness for INV-1, read back from the links
// FILE (the state the audit reads, not an in-memory handle).
func zzR28bHarness(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	links, err := invariants.LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjAt(validation.ObjAt(validation.ObjAt(validation.ObjAt(links, "invariants"), "INV-1"),
		"verification"), "harness")
}

// zzR28bAudit runs `audit --json` and returns the exit code, whether
// section 11 is ok, its joined problems and its harness_runs array.
func zzR28bAudit(t *testing.T, root, cid string) (int, bool, string,
	validation.Value) {
	t.Helper()
	code, out, errS := run(t, "--root", root, "audit", cid, "--json")
	if out == "" {
		t.Fatalf("audit printed no report (exit %d, stderr %q)", code, errS)
	}
	rep, err := validation.ParseOrdered([]byte(out))
	if err != nil {
		t.Fatalf("audit --json did not parse: %v\n%s", err, out)
	}
	sect := validation.ObjAt(validation.ObjAt(rep, "sections"), "invariant_verification")
	ok := validation.ObjAt(sect, "ok")
	joined := ""
	for _, p := range validation.ObjAt(sect, "problems").A {
		joined += p.S
	}
	return code, ok.Kind == validation.Bool && ok.B, joined,
		validation.ObjAt(sect, "harness_runs")
}

// TestZZR28BClaimDriftBurnsOnBothSides is repro (A): the bind lands
// proved-bounded k=4, the claim then drifts, and the audit must burn with
// the very reason the bind would refuse over the identical record + claim.
func TestZZR28BClaimDriftBurnsOnBothSides(t *testing.T) {
	c, root := zzR28bCamp(t, "r28b-claim-drift")
	const execID = "EXEC-1"
	mcHarnessExec(t, c, execID, mcProvenLine,
		"minicertora --rule inv_1 --loop-bound 4",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": zzR28bScaffoldSHA(t, c)},
		0)

	// The pinned bind bytes (constraint 1/d).
	if want := "INV-1: proved-bounded (minicertora, k=4, " + execID +
		")\n"; zzR28bBind(t, root, c.CampaignID, execID) != want {
		t.Fatalf("bind stdout = %q, want %q",
			zzR28bBind(t, root, c.CampaignID, execID), want)
	}
	h := zzR28bHarness(t, c)
	if got := validation.ObjStr(h, "summary"); got != "proved bounded (k=4)" {
		t.Fatalf("bound summary = %q", got)
	}
	// Baseline: the campaign is green while the claim still matches.
	if code, ok, joined, _ := zzR28bAudit(t, root, c.CampaignID); code != 0 ||
		!ok {
		t.Fatalf("pre-drift audit must be green: exit %d ok=%v %q",
			code, ok, joined)
	}

	// The claim drifts. NOTHING else moves: the exec record, the stored
	// rung and the harness_run event are untouched.
	zzR28bDrift(t, c, zzR28bDrifted)
	code, ok, joined, runs := zzR28bAudit(t, root, c.CampaignID)
	if code == 0 || ok {
		t.Fatalf("the audit must burn a blessing whose claim drifted: "+
			"exit %d ok=%v runs=%s", code, ok,
			validation.CanonCompact(runs))
	}
	if !strings.Contains(joined, "re-derives rung 'inconclusive'") {
		t.Fatalf("want the re-derivation burn, got %q", joined)
	}
	if !strings.Contains(joined, zzR28bDegraded) {
		t.Fatalf("the burn must name the reason the bind refuses "+
			"(%q), got %q", zzR28bDegraded, joined)
	}
	if runs.Kind != validation.Arr || len(runs.A) != 1 ||
		!strings.HasSuffix(runs.A[0].S, " (UNBACKED)") {
		t.Fatalf("the burned line must be qualified: %s",
			validation.CanonCompact(runs))
	}

	// Equivalence: the bind over the identical record + claim refuses, and
	// its refusal text is exactly the reason the audit's burn carried.
	if out := zzR28bBind(t, root, c.CampaignID, execID); out !=
		"INV-1: inconclusive (minicertora, "+execID+")\n" {
		t.Fatalf("re-bind stdout = %q", out)
	}
	h = zzR28bHarness(t, c)
	if got := validation.ObjStr(h, "summary"); got != zzR28bDegraded {
		t.Fatalf("re-bind summary = %q, want %q", got, zzR28bDegraded)
	}
	if bk := validation.ObjAt(h, "bounded_k"); bk.Kind != validation.Null {
		t.Fatalf("a degraded refusal carries no bound: %s",
			validation.CanonCompact(h))
	}
}

// TestZZR28BForeignHashBurnsOnBothSides is repro (B): a clean bind, then the
// exec record's recorded hash is replaced by a foreign sha. The bind refuses
// the hash arm; the audit must too, naming the same violation.
func TestZZR28BForeignHashBurnsOnBothSides(t *testing.T) {
	c, root := zzR28bCamp(t, "r28b-foreign-hash")
	const execID = "EXEC-2"
	const cmd = "minicertora --rule inv_1 --loop-bound 4"
	mcHarnessExec(t, c, execID, mcProvenLine, cmd,
		map[string]string{"artifacts/harness/INV-1/INV.mspec": zzR28bScaffoldSHA(t, c)},
		0)
	if out := zzR28bBind(t, root, c.CampaignID, execID); out !=
		"INV-1: proved-bounded (minicertora, k=4, "+execID+")\n" {
		t.Fatalf("bind stdout = %q", out)
	}
	// The record's hash entry is swapped for a foreign sha (stdout, claim
	// and stored rung untouched).
	foreign := strings.Repeat("0", 64)
	mcHarnessExec(t, c, execID, mcProvenLine, cmd,
		map[string]string{"artifacts/harness/INV-1/INV.mspec": foreign},
		0)

	code, ok, joined, runs := zzR28bAudit(t, root, c.CampaignID)
	if code == 0 || ok {
		t.Fatalf("the audit must burn a blessing whose recorded hash is "+
			"foreign: exit %d ok=%v runs=%s", code, ok,
			validation.CanonCompact(runs))
	}
	if !strings.Contains(joined, "re-derives rung 'inconclusive'") ||
		!strings.Contains(joined, zzR28bViolation) {
		t.Fatalf("want the hash-arm burn naming %q, got %q",
			zzR28bViolation, joined)
	}
	// Equivalence with the bind over the identical record + claim.
	if out := zzR28bBind(t, root, c.CampaignID, execID); out !=
		"INV-1: inconclusive (minicertora, "+execID+")\n" {
		t.Fatalf("re-bind stdout = %q", out)
	}
	if got := validation.ObjStr(zzR28bHarness(t, c), "summary"); got != zzR28bViolation {
		t.Fatalf("re-bind summary = %q, want %q", got, zzR28bViolation)
	}
}

// TestZZR28BHonestUnboundAuditsGreen is control (C): no hash info at all is
// the bind's honest-limitation arm — it still maps, keeps its suffix byte for
// byte, and must NOT burn (constraint 2/3).
func TestZZR28BHonestUnboundAuditsGreen(t *testing.T) {
	c, root := zzR28bCamp(t, "r28b-honest-unbound")
	const execID = "EXEC-3"
	mcHarnessExec(t, c, execID, mcProvenLine,
		"minicertora --rule inv_1 --loop-bound 4", nil, 0)
	if out := zzR28bBind(t, root, c.CampaignID, execID); out !=
		"INV-1: proved-bounded (minicertora, k=4, "+execID+")\n" {
		t.Fatalf("bind stdout = %q", out)
	}
	h := zzR28bHarness(t, c)
	wantSummary := "proved bounded (k=4)" + zzR28bUnboundSuffix
	if got := validation.ObjStr(h, "summary"); got != wantSummary {
		t.Fatalf("unbound summary = %q, want %q", got, wantSummary)
	}
	if bk := validation.ObjAt(h, "bounded_k"); bk.Kind != validation.Int || bk.I != 4 {
		t.Fatalf("bounded_k = %s, want 4", validation.CanonCompact(bk))
	}
	code, ok, joined, runs := zzR28bAudit(t, root, c.CampaignID)
	if code != 0 || !ok {
		t.Fatalf("an honest unbound bind must audit green: exit %d ok=%v "+
			"problems=%q", code, ok, joined)
	}
	want := "INV-1: PROVEN-BOUNDED (minicertora, k=4, " + execID + ")"
	if runs.Kind != validation.Arr || len(runs.A) != 1 ||
		runs.A[0].S != want {
		t.Fatalf("harness_runs = %s, want [%q]",
			validation.CanonCompact(runs), want)
	}
}

// TestZZR28BMissingScaffoldBoundArmBurns is constraint (3) end to end: the
// scaffold artifact's FILE disappears after the bind. The record still
// carries the hash the bind compared, so the decision cannot be re-derived —
// the audit refuses and names what is missing instead of blessing.
func TestZZR28BMissingScaffoldBoundArmBurns(t *testing.T) {
	c, root := zzR28bCamp(t, "r28b-scaffold-gone")
	const execID = "EXEC-4"
	mcHarnessExec(t, c, execID, mcProvenLine,
		"minicertora --rule inv_1 --loop-bound 4",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": zzR28bScaffoldSHA(t, c)},
		0)
	if out := zzR28bBind(t, root, c.CampaignID, execID); out !=
		"INV-1: proved-bounded (minicertora, k=4, "+execID+")\n" {
		t.Fatalf("bind stdout = %q", out)
	}
	if err := os.Remove(filepath.Join(c.ArtifactsDir, "harness", "INV-1",
		"INV.mspec")); err != nil {
		t.Fatal(err)
	}
	code, ok, joined, _ := zzR28bAudit(t, root, c.CampaignID)
	if code == 0 || ok {
		t.Fatalf("a bound rung with no scaffold bytes must not bless: "+
			"exit %d ok=%v %q", code, ok, joined)
	}
	if !strings.Contains(joined, "cannot be re-derived") ||
		!strings.Contains(joined, "not backed") {
		t.Fatalf("the burn must name what is missing, got %q", joined)
	}
}

// TestZZR28BPinnedBindSummaries is the byte-identical pin (constraint 1/d):
// each arm's summary is asserted as an EXACT string, so the move into
// package harness cannot drift a single byte of the bind's vocabulary.
func TestZZR28BPinnedBindSummaries(t *testing.T) {
	c, root := zzR28bCamp(t, "r28b-pinned-bytes")
	const execID = "EXEC-5"
	mcHarnessExec(t, c, execID, mcProvenLine,
		"minicertora --rule inv_1 --loop-bound 4",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": zzR28bScaffoldSHA(t, c)},
		0)
	if out := zzR28bBind(t, root, c.CampaignID, execID); out !=
		"INV-1: proved-bounded (minicertora, k=4, "+execID+")\n" {
		t.Fatalf("proved-bounded stdout = %q", out)
	}
	if got := validation.ObjStr(zzR28bHarness(t, c), "summary"); got !=
		"proved bounded (k=4)" {
		t.Fatalf("proved-bounded summary = %q", got)
	}
	// The degraded arm: the exact wording the CLI tests already pin.
	zzR28bDrift(t, c, zzR28bDrifted)
	if out := zzR28bBind(t, root, c.CampaignID, execID); out !=
		"INV-1: inconclusive (minicertora, "+execID+")\n" {
		t.Fatalf("degraded stdout = %q", out)
	}
	if got := validation.ObjStr(zzR28bHarness(t, c), "summary"); got != zzR28bDegraded {
		t.Fatalf("degraded summary = %q, want %q", got, zzR28bDegraded)
	}
	// The violation arm: a harness-named hash entry with a foreign sha.
	c2, root2 := zzR28bCamp(t, "r28b-pinned-bytes-hash")
	mcHarnessExec(t, c2, execID, mcProvenLine,
		"minicertora --rule inv_1 --loop-bound 4",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": strings.Repeat("0", 64)},
		0)
	if out := zzR28bBind(t, root2, c2.CampaignID, execID); out !=
		"INV-1: inconclusive (minicertora, "+execID+")\n" {
		t.Fatalf("violation stdout = %q", out)
	}
	if got := validation.ObjStr(zzR28bHarness(t, c2), "summary"); got != zzR28bViolation {
		t.Fatalf("violation summary = %q, want %q", got, zzR28bViolation)
	}
	// The unbound arm's suffix, verbatim.
	c3, root3 := zzR28bCamp(t, "r28b-pinned-bytes-unbound")
	mcHarnessExec(t, c3, execID, mcProvenLine,
		"minicertora --rule inv_1 --loop-bound 4", nil, 0)
	if out := zzR28bBind(t, root3, c3.CampaignID, execID); out !=
		"INV-1: proved-bounded (minicertora, k=4, "+execID+")\n" {
		t.Fatalf("unbound stdout = %q", out)
	}
	if got := validation.ObjStr(zzR28bHarness(t, c3), "summary"); got !=
		"proved bounded (k=4)"+zzR28bUnboundSuffix {
		t.Fatalf("unbound summary = %q", got)
	}
}

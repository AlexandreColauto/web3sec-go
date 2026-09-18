package cli

// zz_r35_test.go — r35 F1, end to end.
//
// THE AUDITOR'S REPRO: a green scaffold-rung campaign plus a legacy duplicate
// row at the scaffold's own path, then
//
//	webv2 artifact-register <C> <path> --kind harness
//
// Before this round the re-registration pruned the duplicate UNCONDITIONALLY,
// and the row it retired was the one the campaign's `harness_scaffold` event
// names as its `ref` — the scaffold every re-derivation of that rung re-reads
// (audit/sections/invariantverification.go:544, cli/cmd_verify_harness.go:627).
// The log is append-only and the id is uuid-random, so the loss was permanent:
// section 11 reported the rung UNBACKED forever and re-binding refused ("the
// scaffold artifact … is not registered").
//
// Now the ghost decision is CITE-CHECKED (state.ArtifactCitedByLiveBinds, the
// ONE predicate), the cited row survives, the audit stays GREEN — and an
// UNCITED same-path ghost is still pruned, because the RUNBOOK's one-row-per-
// path law is about the shape that law was written for.
//
// The verb's stdout contract is untouched: the first line is still
// "<ID>: kind=K path=P" (the RUNBOOK's verb list documents the verb, and the
// r34 tests pin the shape). The kept-row disclosure rides STDERR, the
// documented convention for warnings.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// r35ScaffoldRef is the registry row the latest harness_scaffold event names
// as its ref — the id the audit re-derives the rung's scaffold from.
func r35ScaffoldRef(t *testing.T, c *state.Campaign) string {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	ref := ""
	for _, ev := range events {
		if validation.ObjStr(ev, "type") != "harness_scaffold" {
			continue
		}
		if validation.ObjStr(validation.ObjAt(ev, "data"), "artifact_id") !=
			"HARNESS-INV-1-minicertora" {
			continue
		}
		ref = validation.ObjStr(ev, "ref")
	}
	if ref == "" {
		t.Fatal("the fixture has no harness_scaffold event naming the row")
	}
	return ref
}

// r35Backdate pins a row's registered_at so the "latest row" choice cannot
// depend on the clock (WEBV2_NOW pins it in some suites, and ties keep the
// FIRST row).
func r35Backdate(t *testing.T, c *state.Campaign, id, stamp string) {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	arts := validation.ObjAt(st, "artifacts")
	found := false
	for i, a := range arts.A {
		if validation.ObjStr(a, "artifact_id") != id {
			continue
		}
		a.O = validation.SetOrAppend(a.O, "registered_at",
			validation.VStr(stamp))
		arts.A[i] = a
		found = true
	}
	if !found {
		t.Fatalf("no registry row %s to backdate", id)
	}
	st.O = validation.SetOrAppend(st.O, "artifacts", arts)
	if err := c.SaveState(st); err != nil {
		t.Fatal(err)
	}
}

// r35RowIDs is the registry's current row ids, in order.
func r35RowIDs(t *testing.T, c *state.Campaign) []string {
	t.Helper()
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, a := range validation.ObjAt(st, "artifacts").A {
		ids = append(ids, validation.ObjStr(a, "artifact_id"))
	}
	return ids
}

// TestR35ArtifactRegisterKeepsTheCitedScaffoldRow is the repro: the CITED row
// survives, the audit stays GREEN, and the operator is told what happened.
func TestR35ArtifactRegisterKeepsTheCitedScaffoldRow(t *testing.T) {
	c, root := mcCamp(t, "r35-kept-ghost")
	// The green rung: the recorded INV.mspec sha binds the minicertora run.
	mcHarnessExec(t, c, "EXEC-1", mcProvenLine,
		"minicertora --rule inv_1 --loop-bound 4",
		map[string]string{"artifacts/harness/INV-1/INV.mspec": mcScaffoldSHA(t, c)},
		0)
	if code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--harness-result", "INV-1", "--exec", "EXEC-1"); code != 0 {
		t.Fatalf("bind exit %d out=%q err=%q", code, out, errS)
	}
	code, sec := t27AuditSection(t, root, c.CampaignID)
	if code != 0 || !validation.ObjAt(sec, "ok").B {
		t.Fatalf("the fixture must start green: exit %d section %s", code,
			validation.CanonCompact(sec))
	}
	scaffold := r35ScaffoldRef(t, c)
	path := filepath.Join(c.Dir, "artifacts", "harness", "INV-1", "INV.mspec")
	// The legacy duplicate at the same path (the append primitive's shape),
	// NEWER than the scaffold row so it is the row the refresh keeps live.
	snap, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		t.Fatal(err)
	}
	dup, err := c.RegisterArtifact("other", path, "", snap)
	if err != nil {
		t.Fatal(err)
	}
	if dup == scaffold {
		t.Fatal("the fixture must hold TWO rows at the path")
	}
	r35Backdate(t, c, scaffold, "2020-01-01T00:00:00.000000+00:00")

	code, out, errS := run(t, "--root", root, "artifact-register",
		c.CampaignID, path, "--kind", "harness")
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	// (1) The documented stdout contract: the FIRST line is byte-identical.
	first := strings.SplitN(out, "\n", 2)[0]
	if want := dup + ": kind=harness path=" + path; first != want {
		t.Fatalf("stdout first line\n%q\nwant\n%q", first, want)
	}
	// (2) The disclosure names the kept id, its kind and the citation that
	// holds it — and says plainly that the path now holds two rows.
	for _, want := range []string{"WARNING", scaffold, "kind=harness",
		"harness_scaffold event", "HARNESS-INV-1-minicertora", "INV-1",
		"now holds 2 registry rows"} {
		if !strings.Contains(errS, want) {
			t.Fatalf("stderr must name %q:\n%s", want, errS)
		}
	}
	if !strings.Contains(errS, dup) {
		t.Fatalf("the disclosure must name the refreshed row too:\n%s", errS)
	}
	// (3) Both rows stand — the cited one was NOT retired.
	ids := r35RowIDs(t, c)
	if len(ids) != 2 || ids[0]+ids[1] != scaffold+dup {
		t.Fatalf("rows = %v, want the cited scaffold %s + the refreshed %s",
			ids, scaffold, dup)
	}
	// (4) The audit stays GREEN, and the rung prints unqualified: the kept
	// row is exactly the evidence section 11 re-derives it from.
	code, sec = t27AuditSection(t, root, c.CampaignID)
	if code != 0 || !validation.ObjAt(sec, "ok").B {
		t.Fatalf("the audit must stay green: exit %d section %s", code,
			validation.CanonCompact(sec))
	}
	runs := validation.ObjAt(sec, "harness_runs")
	if len(runs.A) != 1 {
		t.Fatalf("harness_runs = %s", validation.CanonCompact(runs))
	}
	// The display renders the rung in the audit's own vocabulary
	// (PROVEN-BOUNDED), which is what the campaign's other pins assert.
	if !strings.Contains(runs.A[0].S, "INV-1: PROVEN-BOUNDED") ||
		strings.Contains(runs.A[0].S, "UNBACKED") {
		t.Fatalf("the rung must stay backed: %q", runs.A[0].S)
	}
}

// TestR35ArtifactRegisterStillPrunesAnUncitedGhost is the other polarity of
// the same verb: a same-path ghost NOTHING cites is still retired, so the
// RUNBOOK's one-row-per-path law holds for the shape it was written for — and
// the warning channel stays silent (nothing was kept).
func TestR35ArtifactRegisterStillPrunesAnUncitedGhost(t *testing.T) {
	c, root := t15Campaign(t, "r35-uncited-ghost")
	path := filepath.Join(c.Root, "report.md")
	if err := os.WriteFile(path, []byte("r1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		t.Fatal(err)
	}
	ghost, err := c.RegisterArtifact("other", path, "", snap)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "artifact-register",
		c.CampaignID, path, "--kind", "report")
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	if errS != "" {
		t.Fatalf("an uncited ghost must prune with no warning: %q", errS)
	}
	first := strings.SplitN(out, "\n", 2)[0]
	if want := ghost + ": kind=report path=" + path; first != want {
		t.Fatalf("stdout first line\n%q\nwant\n%q", first, want)
	}
	if ids := r35RowIDs(t, c); len(ids) != 1 || ids[0] != ghost {
		t.Fatalf("rows = %v, want one row per path (%s)", ids, ghost)
	}
}

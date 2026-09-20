package cli

// cmd_amend_test.go: G14a amend/supersede CLI tests — the run() suite style
// (cmd_ingest_test.go:26): exit codes, stdout/stderr text, and the stored
// record behind each success line.

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

func amendEv(id, level, typ, desc string) validation.Value {
	return validation.VObj(
		kvT("evidence_id", validation.VStr(id)),
		kvT("level", validation.VStr(level)),
		kvT("type", validation.VStr(typ)),
		kvT("description", validation.VStr(desc)),
	)
}

// supersedeIngest ingests the ladder payload WITHOUT its invariant block
// (so test evidence can rise without triaging the invariant guardrail)
// and returns the minted finding id.
func supersedeIngest(t *testing.T, c *state.Campaign) string {
	t.Helper()
	raw := `{"title":"reentrancy drain hypothesis",` +
		`"root_cause":{"class":"reentrancy","description":"withdraw re-enters ` +
		`the vault before the balance updates"},"affected":[{"path":` +
		`"src/Vault.sol","contract":"Vault","function":"withdraw"}],` +
		`"attacker":{"profile":"EOA","capabilities":[]}}`
	payload, err := validation.ParseOrdered([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(f, "finding_id")
}

func TestAmendHappyPath(t *testing.T) {
	c, root := t15Campaign(t, "amend-happy")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	code, out, errS := run(t, "--root", root, "amend", c.CampaignID, fid,
		"--title", "reentrancy drain hypothesis, restated after review",
		"--note", "retitled after reading the vault code")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
	want := "amended " + fid + ": claim_version 1 (title)\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(f, "status"); got != "HYPOTHESIS" {
		t.Fatalf("status = %q, want HYPOTHESIS (amend never moves status)", got)
	}
	if v := validation.ObjAt(f, "claim_version"); v.Kind != validation.Int || v.I != 1 {
		t.Fatalf("claim_version = %v, want 1", v)
	}
	hist := validation.ObjAt(f, "history").A
	last := hist[len(hist)-1]
	wantReason := "amend: title — retitled after reading the vault code"
	if validation.ObjStr(last, "reason") != wantReason {
		t.Fatalf("history reason = %q, want %q", validation.ObjStr(last, "reason"),
			wantReason)
	}
	// Actor flag default is "model".
	if validation.ObjStr(last, "actor") != "model" {
		t.Fatalf("history actor = %q, want model", validation.ObjStr(last, "actor"))
	}
	if types := eventTypes(t, c); !containsStrCLI(types, "finding.amended") {
		t.Fatalf("finding.amended missing from %v", types)
	}
}

func TestAmendClaimAndClass(t *testing.T) {
	c, root := t15Campaign(t, "amend-claim-class")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	code, out, errS := run(t, "--root", root, "amend", c.CampaignID, fid,
		"--class", "logic-error",
		"--claim", "the vault balance update happens after the external call",
		"--actor", "reviewer")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "amended " + fid + ": claim_version 1 (class, claim)\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
	f, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if cls := validation.ObjStr(validation.ObjAt(f, "root_cause"), "class"); cls != "logic-error" {
		t.Fatalf("root_cause.class = %q", cls)
	}
}

func TestAmendNoFlagIsExit2(t *testing.T) {
	c, root := t15Campaign(t, "amend-no-flag")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	code, out, errS := run(t, "--root", root, "amend", c.CampaignID, fid)
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.HasPrefix(errS, amendUsage) {
		t.Fatalf("stderr missing usage: %q", errS)
	}
	if !strings.Contains(errS, "at least one of --title, --class, "+
		"--claim, --note is required") {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestAmendUnknownClassIsExit2(t *testing.T) {
	c, root := t15Campaign(t, "amend-bad-class")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	code, out, errS := run(t, "--root", root, "amend", c.CampaignID, fid,
		"--class", "vibes-based")
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	want := "amend failed: unknown bug class 'vibes-based' " +
		"(not in taxonomy.known_classes)\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestSupersedeHappyPath(t *testing.T) {
	c, root := t15Campaign(t, "supersede-happy")
	// Ingested WITHOUT the invariant block: the ladder payload's
	// unverified INV-1 would make any evidence rise refuse, and the rise
	// guardrail is not what this verb test is about.
	oldID := supersedeIngest(t, c)
	if _, err := findings.AddEvidence(c, oldID, amendEv("EV-aaa",
		"E1", "reasoning", "the deposit path has no share-price guard")); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.AddEvidence(c, oldID, amendEv("EV-aab",
		"E2", "reachability", "empty-vault first deposit is reachable")); err != nil {
		t.Fatal(err)
	}
	before, err := findings.LoadFinding(c, oldID)
	if err != nil {
		t.Fatal(err)
	}
	beforeEv := validation.CanonSpaced(validation.ObjAt(before, "evidence"))
	newID := supersedeIngest(t, c)
	code, out, errS := run(t, "--root", root, "supersede", c.CampaignID,
		newID, "--of", oldID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
	want := "superseded " + oldID + " by " + newID +
		" (2 evidence items re-parented)\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	old, err := findings.LoadFinding(c, oldID)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(old, "status"); got != "SUPERSEDED" {
		t.Fatalf("old status = %q, want SUPERSEDED", got)
	}
	if after := validation.CanonSpaced(validation.ObjAt(old, "evidence")); after != beforeEv {
		t.Fatalf("old evidence mutated:\nbefore %s\nafter  %s", beforeEv, after)
	}
	cur, err := findings.LoadFinding(c, newID)
	if err != nil {
		t.Fatal(err)
	}
	ev := validation.ObjAt(cur, "evidence")
	if len(ev.A) != 2 {
		t.Fatalf("new evidence has %d items, want 2", len(ev.A))
	}
	for _, it := range ev.A {
		if validation.ObjStr(it, "re_parented_from") != oldID {
			t.Errorf("item %s missing re_parented_from",
				validation.ObjStr(it, "evidence_id"))
		}
	}
	if sup := validation.ObjStr(validation.ObjAt(cur, "dedup_meta"), "supersedes"); sup != oldID {
		t.Fatalf("dedup_meta.supersedes = %q, want %q", sup, oldID)
	}
	if types := eventTypes(t, c); !containsStrCLI(types, "finding.superseded") {
		t.Fatalf("finding.superseded missing from %v", types)
	}
}

func TestSupersedeTerminalOldRefused(t *testing.T) {
	c, root := t15Campaign(t, "supersede-terminal")
	oldID := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	if code, _, errS := run(t, "--root", root, "move", c.CampaignID, oldID,
		"DISPROVED", "--reason", "not a bug"); code != 0 {
		t.Fatalf("move exit %d: %q", code, errS)
	}
	newID := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	code, out, errS := run(t, "--root", root, "supersede", c.CampaignID,
		newID, "--of", oldID)
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	want := "supersede failed: cannot supersede terminal finding " + oldID +
		" (DISPROVED)\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestSupersedeSelfRefused(t *testing.T) {
	c, root := t15Campaign(t, "supersede-self")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	code, _, errS := run(t, "--root", root, "supersede", c.CampaignID,
		fid, "--of", fid)
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	want := "supersede failed: cannot supersede a finding with itself (" +
		fid + ")\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestSupersedeMissingOfIsExit2(t *testing.T) {
	c, root := t15Campaign(t, "supersede-no-of")
	fid := moveIngest(t, root, c.CampaignID, moveLadderPayload)
	code, out, errS := run(t, "--root", root, "supersede", c.CampaignID, fid)
	if code != 2 {
		t.Fatalf("exit %d, want 2: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.HasPrefix(errS, supersedeUsage) {
		t.Fatalf("stderr missing usage: %q", errS)
	}
	if !strings.Contains(errS, "the following arguments are required: --of") {
		t.Fatalf("stderr = %q", errS)
	}
}

// TestSupersedeWarnsWhenGrantsDie pins r13 issue 4: since the r12
// terminal law, a SUPERSEDED granter stops granting and stops seeding
// chain proposals — correct, but it was SILENT proposal loss. The
// successor inherits evidence, not capabilities; supersede now says so
// on stderr, naming exactly the labels that died.
func TestSupersedeWarnsWhenGrantsDie(t *testing.T) {
	c, root := t15Campaign(t, "supersede-grants")
	oldID := supersedeIngest(t, c)
	f, err := findings.LoadFinding(c, oldID)
	if err != nil {
		t.Fatal(err)
	}
	f.O = validation.SetOrAppend(f.O, "capabilities", validation.VObj(
		validation.KV{K: "granted", V: validation.VArr(
			validation.VStr("withdraw_arbitrary"))},
		validation.KV{K: "required", V: validation.VArr()}))
	if err := findings.SaveFinding(c, &f); err != nil {
		t.Fatal(err)
	}
	newID := supersedeIngest(t, c)
	code, out, errS := run(t, "--root", root, "supersede", c.CampaignID,
		newID, "--of", oldID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.Contains(errS, "withdraw_arbitrary") ||
		!strings.Contains(errS, "no longer grant") {
		t.Fatalf("stderr must name the dead grant: %q (out %q)", errS, out)
	}
	// r14: the MOVE door into the same terminal must warn identically —
	// one law, every door.
	c3, root3 := t15Campaign(t, "move-grants")
	g := supersedeIngest(t, c3)
	gf, err := findings.LoadFinding(c3, g)
	if err != nil {
		t.Fatal(err)
	}
	gf.O = validation.SetOrAppend(gf.O, "capabilities", validation.VObj(
		validation.KV{K: "granted", V: validation.VArr(
			validation.VStr("flash_loan"))},
		validation.KV{K: "required", V: validation.VArr()}))
	if err := findings.SaveFinding(c3, &gf); err != nil {
		t.Fatal(err)
	}
	code, _, errS3 := run(t, "--root", root3, "move", c3.CampaignID,
		g, "SUPERSEDED", "--reason", "retire via the move door",
		"--actor", "op")
	if code != 0 || !strings.Contains(errS3, "flash_loan") {
		t.Fatalf("move into terminal must warn about the dead grant: "+
			"exit %d stderr %q", code, errS3)
	}
	// Successor WITHOUT the grant warns; a campaign where nothing dies
	// stays quiet (supersedeIngest rows carry no grants at all).
	c2, root2 := t15Campaign(t, "supersede-nogrant")
	a := supersedeIngest(t, c2)
	b := supersedeIngest(t, c2)
	code, _, errS2 := run(t, "--root", root2, "supersede", c2.CampaignID,
		b, "--of", a)
	if code != 0 || errS2 != "" {
		t.Fatalf("grantless supersede must stay silent: exit %d %q",
			code, errS2)
	}
}

// R3-9a: bumping claim_version stale-grades the recorded critic verdict
// (the boundary refuses a verdict pinned to an older claim) — amend must
// announce that, the way it announces a moved CONFIRMED floor.
func TestAmendAnnouncesRestaledVerdict(t *testing.T) {
	c, root := t15Campaign(t, "amendstale")
	fid := validation.ObjStr(t15Finding(t, c, "an inflation claim",
		"logic-error"), "finding_id")
	if code, _, errS := run(t, "--root", root, "verdict", c.CampaignID,
		fid, "--verdict", "confirmed", "--reason",
		"no compensating control"); code != 0 {
		t.Fatalf("verdict fixture: exit %d %q", code, errS)
	}
	f0, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	oldTxt := "0"
	if v := validation.ObjAt(f0, "claim_version"); v.Kind == validation.Int {
		oldTxt = validation.IntText(v)
	}
	note := "note: the critic verdict pinned claim version " + oldTxt +
		" — re-run webv2 verdict to re-attest\n"

	// (1) a real claim edit: announced exactly once
	if code, _, errS := run(t, "--root", root, "amend", c.CampaignID, fid,
		"--title", "the corrected inflation claim", "--actor", "op"); code !=
		0 || strings.Count(errS, note) != 1 {
		t.Fatalf("title amend: exit %d stderr %q", code, errS)
	}

	// (2) a same-bytes note-only amend too: every successful amend bumps
	// claim_version (findings.Amend's pinned law), so it re-stales and is
	// announced — pinning the OBSERVED behavior, not a hoped-for one.
	if code, _, errS := run(t, "--root", root, "amend", c.CampaignID, fid,
		"--note", "clarified wording", "--actor", "op"); code != 0 ||
		strings.Count(errS, note[:40]) != 1 {
		t.Fatalf("note-only amend: exit %d stderr %q", code, errS)
	}

	// (3) a finding that never carried a verdict stays silent.
	fid2 := validation.ObjStr(t15Finding(t, c, "a second inflation claim",
		"logic-error"), "finding_id")
	code, _, errS := run(t, "--root", root, "amend", c.CampaignID, fid2,
		"--title", "the renamed second claim", "--actor", "op")
	if code != 0 {
		t.Fatalf("exit %d %q", code, errS)
	}
	if strings.Contains(errS, "critic verdict") {
		t.Fatalf("no verdict on the row: the note must not fire: %q", errS)
	}
}

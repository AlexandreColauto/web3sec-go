package state

// zz_r35_test.go — r35 F1: THE CITE PREDICATE.
//
// The auditor's repro: a green scaffold-rung campaign plus a legacy duplicate
// row at the scaffold's path, then `artifact-register <C> <path> --kind
// harness`. The r34 code pruned the duplicate UNCONDITIONALLY, and the row it
// retired was the one the campaign's `harness_scaffold` event names as its
// `ref` — the scaffold every re-derivation of that rung re-reads
// (audit/sections/invariantverification.go:544, cli/cmd_verify_harness.go:627).
// The log is append-only and the id is uuid-random, so the loss was
// permanent: section 11 reported the rung UNBACKED forever, and re-binding
// refused ("the scaffold artifact … is not registered").
//
// ArtifactCitedByLiveBinds is the ONE predicate that decides this, and it
// answers BOTH shapes of citation: by CONTENT (the row's sha256 as a bind
// pinned it) and by IDENTITY (the row's id where an event or a registry field
// names it — the shape byte equality cannot see). These tests pin every arm,
// the ghost decision that consumes it, and the law that a cite check which
// cannot READ its sources is not a clearance to destroy.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// r35Register writes a file into the campaign root and registers it, returning
// the row id and the absolute path (the append primitive, as the legacy
// duplicate rows were minted).
func r35Register(t *testing.T, c *Campaign, name, body string) (string, string) {
	t.Helper()
	p := filepath.Join(c.Root, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := c.RegisterArtifact("other", p, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return id, p
}

// r35Log lands one event (the fixtures write the shapes the verbs write).
func r35Log(t *testing.T, c *Campaign, typ, ref string,
	data validation.Value) {
	t.Helper()
	if _, err := c.Log(typ, &ref, &data); err != nil {
		t.Fatal(err)
	}
}

// r35Cite asks THE predicate and fails the test if it cannot answer.
func r35Cite(t *testing.T, c *Campaign, id string) (bool, string) {
	t.Helper()
	cited, why, err := ArtifactCitedByLiveBinds(c, id)
	if err != nil {
		t.Fatalf("cite check for %s: %v", id, err)
	}
	return cited, why
}

// r35Sha is the row's pinned sha256.
func r35Sha(t *testing.T, c *Campaign, id string) string {
	t.Helper()
	return objStr(mustArtifact(t, c, id), "sha256")
}

// r35ExecRecord writes one exec record whose input_hashes pin name -> sha.
func r35ExecRecord(t *testing.T, c *Campaign, execID string,
	inputs map[string]string) {
	t.Helper()
	dir := filepath.Join(c.ExecsDir, execID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	kvs := make([]validation.KV, 0, len(inputs))
	for k, v := range inputs {
		kvs = append(kvs, kv(k, validation.VStr(v)))
	}
	rec := validation.VObj(
		kv("exec_id", validation.VStr(execID)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("profile", validation.VStr("minicertora")),
		kv("input_hashes", validation.VObj(kvs...)),
	)
	// "" = no schema check: the fixture writes only the keys the citation
	// arms read (the sandbox's own writer validates its full shape).
	if err := validation.WriteJson(filepath.Join(dir, "exec_record.json"),
		rec, ""); err != nil {
		t.Fatal(err)
	}
}

// TestR35CitePredicateShaArms pins the CONTENT half — the two arms r25/r28
// shipped (they now live in state, and the cli's helpers delegate here).
func TestR35CitePredicateShaArms(t *testing.T) {
	// (a) the report arm: the event's own report_sha256 is the row's sha.
	c, err := Init(t.TempDir(), "r35 sha report", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	row, _ := r35Register(t, c, "report.json", "report bytes\n")
	sha := r35Sha(t, c, row)
	r35Log(t, c, "harness_run", "INV-1", validation.VObj(
		kv("invariant", validation.VStr("INV-1")),
		kv("exec", validation.VStr("REPORT-"+sha[:12])),
		kv("report_sha256", validation.VStr(sha)),
	))
	cited, why := r35Cite(t, c, row)
	if !cited {
		t.Fatalf("the report pin must cite the row: %q", why)
	}
	for _, want := range []string{"harness_run event", "INV-1", "report bytes"} {
		if !strings.Contains(why, want) {
			t.Fatalf("why must name %q: %q", want, why)
		}
	}

	// (b) the EXEC arm: the event names an exec whose record pins the row's
	// sha256 as the bytes the run took in (N1 — the scaffold rung).
	c2, err := Init(t.TempDir(), "r35 sha exec", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	row2, _ := r35Register(t, c2, "INV.mspec", "invariant total\n")
	sha2 := r35Sha(t, c2, row2)
	r35ExecRecord(t, c2, "EXEC-0000000001", map[string]string{"INV.mspec": sha2})
	r35Log(t, c2, "harness_run", "INV-2", validation.VObj(
		kv("invariant", validation.VStr("INV-2")),
		kv("kind", validation.VStr("minicertora")),
		kv("exec", validation.VStr("EXEC-0000000001")),
	))
	cited, why = r35Cite(t, c2, row2)
	if !cited {
		t.Fatalf("the exec pin must cite the row: %q", why)
	}
	for _, want := range []string{"EXEC-0000000001", "INV-2", "took in"} {
		if !strings.Contains(why, want) {
			t.Fatalf("why must name %q: %q", want, why)
		}
	}
	// An exec record alone is not a citation: no live event names it.
	c3, err := Init(t.TempDir(), "r35 sha unbound", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	row3, _ := r35Register(t, c3, "INV.mspec", "invariant total\n")
	r35ExecRecord(t, c3, "EXEC-0000000002",
		map[string]string{"INV.mspec": r35Sha(t, c3, row3)})
	if cited, why := r35Cite(t, c3, row3); cited {
		t.Fatalf("an unbound pin must not cite the row: %q", why)
	}
}

// TestR35CitePredicateScaffoldRefNeedsALiveBind pins the id arm the auditor
// proved missing AND its boundary: a `harness_scaffold` event's `ref` is a
// live citation only while a harness_run bind re-reads that scaffold — the
// readers (harnessScaffoldArtifactBytes / cli.harnessScaffoldBytes) resolve
// HARNESS-<invariant>-<kind> off the latest harness_scaffold event, and the
// audit asks for those bytes only under harnessRunLine's `ok` arm, i.e. for an
// invariant that carries a landed bind.
//
// The boundary is not decoration: cmd_artifact_prune_test.go's
// TestR28ExecCitationNeedsALiveEvent builds exactly this shape
// (`verify --scaffold minicertora` with no bind) and pins that its row is
// retirable with EMPTY stderr, so the operator verb's warning must keep
// agreeing with the bind: no bind, no live citation.
func TestR35CitePredicateScaffoldRefNeedsALiveBind(t *testing.T) {
	c, err := Init(t.TempDir(), "r35 scaffold", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	row, p := r35Register(t, c, "INV.mspec", "invariant total\n")
	sha := r35Sha(t, c, row)
	r35Log(t, c, "harness_scaffold", row, validation.VObj(
		kv("artifact_id", validation.VStr("HARNESS-INV-1-minicertora")),
		kv("invariant", validation.VStr("INV-1")),
		kv("kind", validation.VStr("minicertora")),
		kv("path", validation.VStr(p)),
		kv("sha256", validation.VStr(sha)),
	))
	// (a) the scaffold event alone is not a citation: nothing re-reads it.
	if cited, why := r35Cite(t, c, row); cited {
		t.Fatalf("a scaffold no bind re-reads must not cite the row: %q", why)
	}
	// (b) a bind of a DIFFERENT kind re-reads a different scaffold: still not
	// a citation of THIS row.
	r35Log(t, c, "harness_run", "INV-1", validation.VObj(
		kv("invariant", validation.VStr("INV-1")),
		kv("kind", validation.VStr("halmos")),
		kv("exec", validation.VStr("EXEC-0000000003")),
	))
	if cited, why := r35Cite(t, c, row); cited {
		t.Fatalf("a bind of another kind must not cite this scaffold: %q", why)
	}
	// (c) the minicertora bind lands: NOW the row is the evidence the audit
	// re-derives that rung from, and the why names exactly which citation.
	r35Log(t, c, "harness_run", "INV-1", validation.VObj(
		kv("invariant", validation.VStr("INV-1")),
		kv("kind", validation.VStr("minicertora")),
		kv("exec", validation.VStr("EXEC-0000000004")),
	))
	cited, why := r35Cite(t, c, row)
	if !cited {
		t.Fatalf("the live bind re-reads the scaffold the event refs: %q", why)
	}
	for _, want := range []string{"harness_scaffold event",
		"HARNESS-INV-1-minicertora", "minicertora"} {
		if !strings.Contains(why, want) {
			t.Fatalf("why must name %q: %q", want, why)
		}
	}
}

// r35WriteLinks writes the invariants registry (the file
// invariants.SaveLinks writes: artifacts/invariant_links.json).
func r35WriteLinks(t *testing.T, c *Campaign, reg validation.Value) {
	t.Helper()
	if err := validation.WriteJson(filepath.Join(c.ArtifactsDir,
		"invariant_links.json"), validation.VObj(
		kv("invariants", reg)), ""); err != nil {
		t.Fatal(err)
	}
}

// TestR35CitePredicateRegistryArms pins the IDENTITY arms read off the
// invariants registry: verified_by (invariants.VerifyInvariantStatement +
// guard.IsVerified resolve it with c.Artifact), tests[] (LinkTest) and
// contradiction (the CONTRADICTED anchor guard.IsVerified resolves when it is
// a registered artifact id).
func TestR35CitePredicateRegistryArms(t *testing.T) {
	c, err := Init(t.TempDir(), "r35 registry", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	verified, _ := r35Register(t, c, "code-check.md", "code check\n")
	tests, _ := r35Register(t, c, "held.t.sol", "test\n")
	contra, _ := r35Register(t, c, "counterexample.md", "the attack works\n")
	r35WriteLinks(t, c, validation.VObj(
		kv("INV-7", validation.VObj(
			kv("status", validation.VStr("CHECKED_AGAINST_CODE")),
			kv("verified_by", validation.VStr(verified)))),
		kv("INV-8", validation.VObj(
			kv("test_status", validation.VStr("held")),
			kv("tests", validation.VArr(validation.VStr(tests))))),
		kv("INV-9", validation.VObj(
			kv("status", validation.VStr("CONTRADICTED")),
			kv("contradiction", validation.VStr(contra)))),
	))
	for _, tc := range []struct{ id, want, want2 string }{
		{verified, "INV-7", "verified_by"},
		{tests, "INV-8", "test artifacts"},
		{contra, "INV-9", "contradiction anchor"},
	} {
		cited, why := r35Cite(t, c, tc.id)
		if !cited {
			t.Fatalf("%s must be cited by the registry: %q", tc.id, why)
		}
		for _, want := range []string{tc.want, tc.want2} {
			if !strings.Contains(why, want) {
				t.Fatalf("why for %s must name %q: %q", tc.id, want, why)
			}
		}
	}
}

// TestR35CitePredicateEventIDArms pins the four IDENTITY arms that live on the
// append-only ledger: invariant.verified (guard.IsVerified requires the event
// AND the link, so the event alone still names the row), invariant.linked_test
// and invariant.contradicted (the payloads guards and the audit resolve with
// c.Artifact), and finding.impact_quantified (risk.MintImpactEvidence's E7
// citation — "E7 MUST cite a registered artifact", RUNBOOK hard rules).
func TestR35CitePredicateEventIDArms(t *testing.T) {
	c, err := Init(t.TempDir(), "r35 events", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	verified, _ := r35Register(t, c, "one.md", "1\n")
	linked, _ := r35Register(t, c, "two.md", "2\n")
	contra, _ := r35Register(t, c, "three.md", "3\n")
	quant, _ := r35Register(t, c, "impact.md", "4\n")
	r35Log(t, c, "invariant.verified", "INV-2", validation.VObj(
		kv("artifact", validation.VStr(verified))))
	r35Log(t, c, "invariant.linked_test", "INV-3", validation.VObj(
		kv("artifact", validation.VStr(linked))))
	r35Log(t, c, "invariant.contradicted", "INV-4", validation.VObj(
		kv("evidence", validation.VStr(contra))))
	r35Log(t, c, "finding.impact_quantified", "F-0123456789ab",
		validation.VObj(
			kv("artifact_id", validation.VStr(quant)),
			kv("from_level", validation.VStr("E6"))))
	for _, tc := range []struct{ id, want, want2 string }{
		{verified, "invariant.verified", "INV-2"},
		{linked, "invariant.linked_test", "INV-3"},
		{contra, "invariant.contradicted", "INV-4"},
		{quant, "finding.impact_quantified", "F-0123456789ab"},
	} {
		cited, why := r35Cite(t, c, tc.id)
		if !cited {
			t.Fatalf("%s must be cited by its event: %q", tc.id, why)
		}
		for _, want := range []string{tc.want, tc.want2} {
			if !strings.Contains(why, want) {
				t.Fatalf("why for %s must name %q: %q", tc.id, want, why)
			}
		}
	}
	// The row's OWN events are not citations: artifact.registered (the ref is
	// the id the registration mints) and artifact.refreshed. Reading those
	// would make every row unprunable.
	own, _ := r35Register(t, c, "own.md", "own\n")
	if cited, why := r35Cite(t, c, own); cited {
		t.Fatalf("a row's own registration/refresh events must not cite it: %q",
			why)
	}
}

// TestR35CitePredicateFindingArms pins the findings store's two id fields:
// evidence[].artifact_id (the E7 citation risk.MintImpactEvidence writes after
// c.Artifact(artifactID), and the field findings.assumptions'
// resolveEvidenceRef resolves through campaign.Artifact) and
// verification.reproduction.attempts[].artifact_id (record_attempt's
// --artifact linkage).
func TestR35CitePredicateFindingArms(t *testing.T) {
	c, err := Init(t.TempDir(), "r35 findings", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	quant, _ := r35Register(t, c, "impact.md", "impact\n")
	att, _ := r35Register(t, c, "attempt-copy.md", "attempt\n")
	f := validation.VObj(
		kv("finding_id", validation.VStr("F-0123456789ab")),
		kv("evidence", validation.VArr(validation.VObj(
			kv("evidence_id", validation.VStr("EV-000001")),
			kv("level", validation.VStr("E7")),
			kv("artifact_id", validation.VStr(quant))))),
		kv("verification", validation.VObj(kv("reproduction",
			validation.VObj(kv("attempts", validation.VArr(
				validation.VObj(
					kv("attempt_id", validation.VStr("ATT-abcdef")),
					kv("artifact_id", validation.VStr(att))))))))),
	)
	if err := validation.WriteJson(filepath.Join(c.FindingsDir,
		"F-0123456789ab.json"), f, ""); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ id, want, want2 string }{
		{quant, "EV-000001", "artifact_id"},
		{att, "ATT-abcdef", "artifact_id"},
	} {
		cited, why := r35Cite(t, c, tc.id)
		if !cited {
			t.Fatalf("%s must be cited by the finding: %q", tc.id, why)
		}
		for _, want := range []string{"F-0123456789ab", tc.want, tc.want2} {
			if !strings.Contains(why, want) {
				t.Fatalf("why for %s must name %q: %q", tc.id, want, why)
			}
		}
	}
}

// TestR35CitePredicateUncitedRow is the other polarity: a row NOTHING names is
// uncited, with no `why` — the ghost-prune must still prune it (one row per
// path for the shape the RUNBOOK's law was written for).
func TestR35CitePredicateUncitedRow(t *testing.T) {
	c, err := Init(t.TempDir(), "r35 uncited", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	row, _ := r35Register(t, c, "orphan.md", "nobody cites me\n")
	cited, why := r35Cite(t, c, row)
	if cited {
		t.Fatalf("an uncited row must not be cited: %q", why)
	}
	if why != "" {
		t.Fatalf("an uncited row has no citation to name: %q", why)
	}
	// An id no row carries is uncited too (the row is already gone).
	if cited, why, err := ArtifactCitedByLiveBinds(c, "OTH-nope1234"); err != nil ||
		cited || why != "" {
		t.Fatalf("unknown id: cited=%v why=%q err=%v", cited, why, err)
	}
}

// r35RegisterAt registers one file at an explicit path (the same-path
// duplicate rows are the whole point of the ghost decision).
func r35RegisterAt(t *testing.T, c *Campaign, p, body string,
	kind string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := c.RegisterArtifact(kind, p, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// r35Rows is the registry's current rows.
func r35Rows(t *testing.T, c *Campaign) []validation.Value {
	t.Helper()
	return objAt(mustState(t, c), "artifacts").A
}

// TestR35KeptGhostSurvivesAndUncitedGhostStillPrunes is the auditor's repro at
// the state layer: three rows at ONE path — the cited scaffold row, an uncited
// legacy duplicate, and the newest row a re-registration refreshes. The
// re-registration must KEEP the cited scaffold (it is the evidence section 11
// re-derives the rung from, by id) and still PRUNE the uncited duplicate (one
// row per path for the shape the RUNBOOK's law was written for).
func TestR35KeptGhostSurvivesAndUncitedGhostStillPrunes(t *testing.T) {
	c, err := Init(t.TempDir(), "r35 kept ghost", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(c.ArtifactsDir, "harness", "INV-1", "INV.mspec")
	body := "invariant total always covers sum(payouts)\n"
	// The scaffold row, registered the way verify --scaffold registers it, and
	// the harness_scaffold event that names it as its ref.
	scaffold := r35RegisterAt(t, c, p, body, "harness")
	sha := r35Sha(t, c, scaffold)
	r35Log(t, c, "harness_scaffold", scaffold, validation.VObj(
		kv("artifact_id", validation.VStr("HARNESS-INV-1-minicertora")),
		kv("invariant", validation.VStr("INV-1")),
		kv("kind", validation.VStr("minicertora")),
		kv("path", validation.VStr(p)),
		kv("sha256", validation.VStr(sha)),
	))
	// The live bind that re-reads that scaffold (the green rung).
	r35Log(t, c, "harness_run", "INV-1", validation.VObj(
		kv("invariant", validation.VStr("INV-1")),
		kv("kind", validation.VStr("minicertora")),
		kv("rung", validation.VStr("proved-bounded")),
		kv("exec", validation.VStr("EXEC-0000000009")),
	))
	// The legacy duplicate (nothing cites it) and the newest row.
	dup := r35RegisterAt(t, c, p, body, "other")
	newest := r35RegisterAt(t, c, p, body, "harness")
	// Deterministic ordering: the newest row must be the latest, whatever the
	// clock says (WEBV2_NOW pins it in some suites, and max ties keep the
	// FIRST row).
	backdateArtifact(t, c, scaffold, "2020-01-01T00:00:00.000000+00:00")
	backdateArtifact(t, c, dup, "2021-01-01T00:00:00.000000+00:00")

	id, kept, err := c.RegisterOrRefreshKeptGhosts("harness", p, "", nil,
		"re-registered (content may have changed)")
	if err != nil {
		t.Fatal(err)
	}
	if id != newest {
		t.Fatalf("refreshed row: %q want the newest (%q)", id, newest)
	}
	if len(kept) != 1 || kept[0].ArtifactID != scaffold {
		t.Fatalf("kept rows: %+v want exactly the cited scaffold %s", kept,
			scaffold)
	}
	if kept[0].Kind != "harness" {
		t.Fatalf("kept kind: %q", kept[0].Kind)
	}
	for _, want := range []string{"harness_scaffold event",
		"HARNESS-INV-1-minicertora", "INV-1"} {
		if !strings.Contains(kept[0].Citation, want) {
			t.Fatalf("the report must name %q: %q", want, kept[0].Citation)
		}
	}
	rows := r35Rows(t, c)
	live := map[string]bool{}
	for _, r := range rows {
		live[objStr(r, "artifact_id")] = true
	}
	if len(rows) != 2 || !live[scaffold] || !live[newest] {
		t.Fatalf("rows after the re-registration: %v (want the cited scaffold "+
			"%s + the refreshed %s)",
			validation.CanonCompact(validation.VArr(rows...)), scaffold, newest)
	}
	if live[dup] {
		t.Fatalf("the UNCITED duplicate %s must still be pruned", dup)
	}
	// The retired duplicate is recoverable from the log (kind + path + why).
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	pruned := false
	for _, ev := range events {
		if objStr(ev, "type") == "artifact.pruned" &&
			objStr(ev, "ref") == dup {
			pruned = true
			if got := objStr(objAt(ev, "data"), "reason"); got !=
				"superseded: same path re-registered as kind harness" {
				t.Fatalf("prune reason: %q", got)
			}
		}
	}
	if !pruned {
		t.Fatalf("no artifact.pruned event names the uncited duplicate %s", dup)
	}
}

// TestR35UnreadableCitationSourceIsNotAClearance pins the law that a check
// which cannot READ its sources is not a clearance to destroy: the predicate
// returns the error (never a silent false), and the ghost decision KEEPS the
// row and reports the unreadable source instead of pruning on an unknown.
func TestR35UnreadableCitationSourceIsNotAClearance(t *testing.T) {
	// (a) the event log cannot be read: the predicate refuses to answer.
	c, err := Init(t.TempDir(), "r35 unreadable log", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	row, _ := r35Register(t, c, "orphan.md", "nobody cites me\n")
	if err := os.Remove(c.EventsPath); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(c.EventsPath, 0o755); err != nil {
		t.Fatal(err)
	}
	cited, why, cerr := ArtifactCitedByLiveBinds(c, row)
	if cerr == nil {
		t.Fatalf("an unreadable event log must not read as uncited "+
			"(cited=%v why=%q)", cited, why)
	}
	if !strings.Contains(cerr.Error(), "is a directory") {
		t.Fatalf("the error must name the unreadable source: %v", cerr)
	}

	// (b) the invariants registry cannot be read: the ghost-prune keeps the
	// row and says why it survived.
	c2, err := Init(t.TempDir(), "r35 unreadable links", InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(c2.Root, "report.md")
	ghost := r35RegisterAt(t, c2, p, "r1\n", "other")
	newest := r35RegisterAt(t, c2, p, "r1\n", "report")
	if err := os.MkdirAll(filepath.Join(c2.ArtifactsDir,
		"invariant_links.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	id, kept, err := c2.RegisterOrRefreshKeptGhosts("report", p, "", nil,
		"re-registered (content may have changed)")
	if err != nil {
		t.Fatalf("a cite check that cannot read must not fail the refresh: %v",
			err)
	}
	if id != newest {
		t.Fatalf("refreshed row: %q want %q", id, newest)
	}
	if len(kept) != 1 || kept[0].ArtifactID != ghost {
		t.Fatalf("kept rows: %+v want the row whose citations could not be "+
			"read (%s)", kept, ghost)
	}
	if !strings.Contains(kept[0].Citation, "could not read") ||
		!strings.Contains(kept[0].Citation, "invariant_links.json") {
		t.Fatalf("the report must name the unreadable source: %q",
			kept[0].Citation)
	}
	live := map[string]bool{}
	for _, r := range r35Rows(t, c2) {
		live[objStr(r, "artifact_id")] = true
	}
	if !live[ghost] {
		t.Fatalf("the row must survive an unreadable cite check: %v", live)
	}
}

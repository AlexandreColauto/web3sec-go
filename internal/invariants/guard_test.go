// guard_test.go: the F1(b)/F1(c) guardrail — the invariant guard as wired
// into findings ingest/add_evidence, plus the CONFIRMED-gate checks. Ported
// from tests/test_invariants_structured.py.
package invariants

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// findingsDefaultNormalizeInvID mirrors the placeholder findings ships with
// so cleanup restores exactly the pre-test seam value.
var findingsDefaultNormalizeInvID = func() func(string) string {
	re := regexp.MustCompile(`^INV-([0-9]+)$`)
	return func(iid string) string {
		m := re.FindStringSubmatch(iid)
		if m == nil {
			return iid
		}
		n, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return iid
		}
		return "INV-" + strconv.FormatInt(n, 10)
	}
}()

// docMap adapts DocumentedInvariants to findings' seam shape.
func docMap(c *state.Campaign) (map[string]validation.Value, error) {
	doc, err := DocumentedInvariants(c, nil)
	if err != nil {
		return nil, err
	}
	out := make(map[string]validation.Value, len(doc.O))
	for _, e := range doc.O {
		out[e.K] = e.V
	}
	return out, nil
}

// intentMap adapts IntentClaims to findings' seam shape.
func intentMap(c *state.Campaign) (map[string]validation.Value, error) {
	claims, err := IntentClaims(c, nil)
	if err != nil {
		return nil, err
	}
	out := make(map[string]validation.Value, len(claims.O))
	for _, e := range claims.O {
		out[e.K] = e.V
	}
	return out, nil
}

// wireFindings wires every seam findings consumes from this package (the
// orchestrator does the same in production) and restores them afterwards.
func wireFindings(t *testing.T) {
	t.Helper()
	findings.SetInvariantGuard(AssertInvariantsVerified)
	findings.SetNormalizeInvID(NormalizeInvID)
	findings.SetLoadInvariantLinks(LoadLinks)
	findings.SetDocumentedInvariants(docMap)
	findings.SetInvariantVerified(IsVerified)
	findings.SetIntentClaims(intentMap)
	t.Cleanup(func() {
		findings.SetInvariantGuard(func(*state.Campaign, validation.Value) error {
			return nil
		})
		findings.SetNormalizeInvID(findingsDefaultNormalizeInvID)
		findings.SetLoadInvariantLinks(
			func(*state.Campaign) (validation.Value, error) {
				return validation.VObj(), nil
			})
		findings.SetDocumentedInvariants(
			func(*state.Campaign) (map[string]validation.Value, error) {
				return map[string]validation.Value{}, nil
			})
		findings.SetInvariantVerified(
			func(validation.Value, *state.Campaign, string,
				[]validation.Value) bool {
				return false
			})
		findings.SetIntentClaims(
			func(*state.Campaign) (map[string]validation.Value, error) {
				return map[string]validation.Value{}, nil
			})
	})
}

// hypoWithEvidence is the structured test's _hypo_with_evidence.
func hypoWithEvidence(invID string, evidence []validation.Value) validation.Value {
	return validation.VObj(
		kv("title", validation.VStr("fee accumulator rewound")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("description", validation.VStr(
				"unauthorized setter rewinds the accumulator")),
		)),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("setFee")),
		))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()),
		)),
		kv("security_invariants", validation.VArr(validation.VObj(
			kv("id", validation.VStr(invID)),
			kv("statement", validation.VStr(
				"fee accumulator cannot be set backwards")),
		))),
		kv("evidence", validation.VArr(evidence...)),
	)
}

// e2Note is the structured test's _e2_note: above the HYPOTHESIS baseline.
func e2Note(eid string) validation.Value {
	return validation.VObj(
		kv("evidence_id", validation.VStr(eid)),
		kv("level", validation.VStr("E2")),
		kv("type", validation.VStr("reasoning")),
		kv("description", validation.VStr(
			"reachability walkthrough of the setter path")),
	)
}

func TestIngestBlocksRiseOnUnverifiedModelInvariant(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	_, err := findings.IngestHypothesis(c,
		hypoWithEvidence("INV-2", []validation.Value{e2Note("EV-pre")}),
		"code", "", "")
	wantErr(t, err, "verify the statement against code")
	if !strings.Contains(err.Error(), "INV-2") {
		t.Errorf("error does not name the invariant: %v", err)
	}
}

func TestIngestBlocksRiseOnUnknownInvariant(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	_, err := findings.IngestHypothesis(c,
		hypoWithEvidence("INV-999", []validation.Value{e2Note("EV-pre")}),
		"code", "", "")
	wantErr(t, err, "not in registry")
}

func TestIngestAcceptsLowLevelEvidenceOnDocumentedInvariant(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	readmeSnap(t, c, "INV-2: fee accumulator cannot be set backwards.\n")
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	f, err := findings.IngestHypothesis(c,
		hypoWithEvidence("INV-2", []validation.Value{e2Note("EV-pre")}),
		"code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := findings.FindingLevel(f)
	if err != nil {
		t.Fatal(err)
	}
	if got != "E2" {
		t.Errorf("level = %q, want E2", got)
	}
}

func TestIngestAcceptsLevelNeutralNoteOnUnverifiedInvariant(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	f, err := findings.IngestHypothesis(c,
		hypoWithEvidence("INV-2", []validation.Value{
			manualNote("EV-note", "E0")}), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := findings.FindingLevel(f)
	if err != nil {
		t.Fatal(err)
	}
	if got != "E0" {
		t.Errorf("level = %q, want E0", got)
	}
}

func TestGuardrailBlocksLevelRiseOnUnverifiedModelInvariant(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	f := findingWithInvariant(t, c, "INV-2")
	fid := objStr(f, "finding_id")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage",
		"", "", false); err != nil {
		t.Fatal(err)
	}
	rec := testExec(t, c, "docker-networkless", fid, 0, "PASS: test_exploit\n")
	_, err := findings.AddEvidence(c, fid,
		evidenceItem(rec, "E4", "foundry-test", "EV-1"))
	wantErr(t, err, "invariant")
}

func TestGuardrailPassesAfterVerification(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	f := findingWithInvariant(t, c, "INV-2")
	fid := objStr(f, "finding_id")
	artID := registeredArtifact(t, c, "inv-check.md", "checked\n")
	if _, err := VerifyInvariantStatement(c, "INV-2", artID); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage",
		"", "", false); err != nil {
		t.Fatal(err)
	}
	rec := testExec(t, c, "docker-networkless", fid, 0, "PASS: test_exploit\n")
	out, err := findings.AddEvidence(c, fid,
		evidenceItem(rec, "E4", "foundry-test", "EV-1"))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(objAt(out, "evidence").A); got != 1 {
		t.Errorf("evidence count = %d, want 1", got)
	}
}

func TestGuardrailExemptsDocumentedInvariants(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	readmeSnap(t, c, "INV-2: fee accumulator cannot be set backwards.\n")
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	f := findingWithInvariant(t, c, "INV-2") // now source == documented
	fid := objStr(f, "finding_id")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage",
		"", "", false); err != nil {
		t.Fatal(err)
	}
	rec := testExec(t, c, "docker-networkless", fid, 0, "PASS: test_exploit\n")
	out, err := findings.AddEvidence(c, fid,
		evidenceItem(rec, "E4", "foundry-test", "EV-1"))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(objAt(out, "evidence").A); got != 1 {
		t.Errorf("evidence count = %d, want 1", got)
	}
}

func TestLevelNeutralAddOnUnverifiedModelInvariantAllowed(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	f := findingWithInvariant(t, c, "INV-2")
	out, err := findings.AddEvidence(c, objStr(f, "finding_id"),
		manualNote("EV-note", "E0"))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(objAt(out, "evidence").A); got != 1 {
		t.Errorf("evidence count = %d, want 1", got)
	}
}

func TestSubE4RiseOnUnverifiedModelInvariantBlocked(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	f := findingWithInvariant(t, c, "INV-2")
	fid := objStr(f, "finding_id")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage",
		"", "", false); err != nil {
		t.Fatal(err)
	}
	_, err := findings.AddEvidence(c, fid, manualNote("EV-note", "E2"))
	wantErr(t, err, "invariant")
}

// ---- CONFIRMED gate half -------------------------------------------------

func gateIDs(gates []findings.GateFailure) []string {
	out := make([]string, 0, len(gates))
	for _, g := range gates {
		out = append(out, g.CheckID)
	}
	return out
}

func gateByID(gates []findings.GateFailure, id string) *findings.GateFailure {
	for i := range gates {
		if gates[i].CheckID == id {
			return &gates[i]
		}
	}
	return nil
}

func TestConfirmationGateReportsInvariantUnverified(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	f := findingWithInvariant(t, c, "INV-2")
	gates, err := findings.ConfirmationGateDetail(c, f)
	if err != nil {
		t.Fatal(err)
	}
	entry := gateByID(gates, "invariant-unverified")
	if entry == nil {
		t.Fatalf("gate ids = %v, want invariant-unverified", gateIDs(gates))
	}
	if entry.Remediation == "" {
		t.Error("remediation is empty; a clearing command must be on the record")
	}
}

func TestContradictedInvariantBlocksConfirmationGate(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	if _, err := ContradictInvariantStatement(c, "INV-2", "src/V.sol#L40"); err != nil {
		t.Fatal(err)
	}
	f := findingWithInvariant(t, c, "INV-2")
	gates, err := findings.ConfirmationGateDetail(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if gateByID(gates, "invariant-unverified") == nil {
		t.Errorf("gate ids = %v, want invariant-unverified", gateIDs(gates))
	}
}

func TestGateExemptsDocumentedInvariants(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	readmeSnap(t, c, "INV-2: fee accumulator cannot be set backwards.\n")
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	f := findingWithInvariant(t, c, "INV-2")
	gates, err := findings.ConfirmationGateDetail(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if gateByID(gates, "invariant-unverified") != nil {
		t.Errorf("gate ids = %v, documented invariant must be exempt",
			gateIDs(gates))
	}
}

func TestHandEditedCheckedWithRegisteredArtifactBlocked(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	artID := registeredArtifact(t, c, "inv-check.md", "checked\n")
	links, err := LoadLinks(c)
	if err != nil {
		t.Fatal(err)
	}
	reg := objAt(links, "invariants")
	entry := objAt(reg, "INV-2")
	entry.O = setOrAppend(entry.O, "status",
		validation.VStr("CHECKED_AGAINST_CODE"))
	entry.O = setOrAppend(entry.O, "verified_by", validation.VStr(artID))
	reg.O = setOrAppend(reg.O, "INV-2", entry)
	links.O = setOrAppend(links.O, "invariants", reg)
	if _, err := SaveLinks(c, links); err != nil {
		t.Fatal(err)
	}
	f := findingWithInvariant(t, c, "INV-2")
	gates, err := findings.ConfirmationGateDetail(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if gateByID(gates, "invariant-unverified") == nil {
		t.Errorf("gate ids = %v, hand-edited CHECKED must not pass",
			gateIDs(gates))
	}
}

func TestUnknownInvariantIDBlocksBothHalves(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	f := findingWithInvariant(t, c, "INV-999")
	fid := objStr(f, "finding_id")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage",
		"", "", false); err != nil {
		t.Fatal(err)
	}
	rec := testExec(t, c, "docker-networkless", fid, 0, "PASS: test_exploit\n")
	_, err := findings.AddEvidence(c, fid,
		evidenceItem(rec, "E4", "foundry-test", "EV-1"))
	wantErr(t, err, "not in registry")
	gates, err := findings.ConfirmationGateDetail(c, f)
	if err != nil {
		t.Fatal(err)
	}
	hit := gateByID(gates, "invariant-unverified")
	if hit == nil {
		t.Fatalf("gate ids = %v, want invariant-unverified", gateIDs(gates))
	}
	if !strings.Contains(hit.Message, "not in registry") {
		t.Errorf("gate message = %q, want the not-in-registry remediation",
			hit.Message)
	}
}

func TestLegacyEntryMigratesOnRead(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	artID := registeredArtifact(t, c, "fuzz.md", "fuzz run\n")
	legacy := validation.VObj(kv("invariants", validation.VObj(kv("INV-9",
		validation.VObj(
			kv("statement", validation.VStr("legacy claim")),
			kv("status", validation.VStr("held")),
			kv("findings", validation.VArr()),
			kv("tests", validation.VArr()),
			kv("detectors", validation.VArr()))))))
	if _, err := SaveLinks(c, legacy); err != nil {
		t.Fatal(err)
	}
	e, err := LinkTest(c, "INV-9", artID) // must not raise KeyError
	if err != nil {
		t.Fatal(err)
	}
	if got := objStr(e, "test_status"); got != "held" {
		t.Errorf("test_status = %q, want held (old axis preserved)", got)
	}
	if got := objStr(e, "status"); got != "UNVERIFIED" {
		t.Errorf("status = %q, want UNVERIFIED", got)
	}
	if got := objStr(e, "source"); got != "model" {
		t.Errorf("source = %q, want model", got)
	}
	events := mustEvents(t, c)
	if !hasMigrated(events, "INV-9") {
		t.Errorf("no invariant.migrated event for INV-9")
	}
	if _, err := LoadLinks(c); err != nil { // second read: no re-migration
		t.Fatal(err)
	}
	events = mustEvents(t, c)
	if n := countMigrated(events); n != 1 {
		t.Errorf("invariant.migrated events = %d, want 1", n)
	}
	f := findingWithInvariant(t, c, "INV-9")
	fid := objStr(f, "finding_id")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage",
		"", "", false); err != nil {
		t.Fatal(err)
	}
	rec := testExec(t, c, "docker-networkless", fid, 0, "PASS: test_exploit\n")
	_, err = findings.AddEvidence(c, fid,
		evidenceItem(rec, "E4", "foundry-test", "EV-1"))
	wantErr(t, err, "invariant")
}

func mustEvents(t *testing.T, c *state.Campaign) []validation.Value {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func hasMigrated(events []validation.Value, ref string) bool {
	for _, ev := range events {
		if objStr(ev, "type") == "invariant.migrated" &&
			objStr(ev, "ref") == ref {
			return true
		}
	}
	return false
}

func countMigrated(events []validation.Value) int {
	n := 0
	for _, ev := range events {
		if objStr(ev, "type") == "invariant.migrated" {
			n++
		}
	}
	return n
}

// ---- F2: canonical INV ids ------------------------------------------------

func TestZeroPaddedCitationGetsDocumentedExemption(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	readmeSnap(t, c, "INV-1: totalAssets never decreases except via withdraw.\n")
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	payload := validation.VObj(
		kv("title", validation.VStr("drain via sweep")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("access-control")),
			kv("description", validation.VStr("unguarded sweep drains the pool")),
		)),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("sweep")),
		))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()),
		)),
		kv("security_invariants", validation.VArr(validation.VObj(
			kv("id", validation.VStr("INV-001")),
			kv("statement", validation.VStr(
				"totalAssets never decreases except via withdraw")),
		))),
	)
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := objStr(f, "finding_id")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage",
		"", "", false); err != nil {
		t.Fatal(err)
	}
	rec := testExec(t, c, "docker-networkless", fid, 0, "PASS: test_exploit\n")
	out, err := findings.AddEvidence(c, fid,
		evidenceItem(rec, "E4", "foundry-test", "EV-1"))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(objAt(out, "evidence").A); got != 1 {
		t.Errorf("evidence count = %d, want 1", got)
	}
}

func TestZeroPaddedCitationStillBlockedWhenUnverified(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	f := findingWithInvariant(t, c, "INV-001")
	_, err := findings.AddEvidence(c, objStr(f, "finding_id"),
		manualNote("EV-note", "E1"))
	wantErr(t, err, "invariant")
}

func TestZeroPaddedRegistryKeyMatchesNormalizedDoc(t *testing.T) {
	c := invCamp(t)
	wireFindings(t)
	readmeSnap(t, c, "INV-1: totalAssets never decreases except via withdraw.\n")
	links, err := SeedFromModel(c, invModel("INV-001"))
	if err != nil {
		t.Fatal(err)
	}
	entry := objAt(objAt(links, "invariants"), "INV-001")
	if got := objStr(entry, "source"); got != "documented" {
		t.Fatalf("INV-001 source = %q, want documented", got)
	}
	for _, cited := range []string{"INV-001", "INV-1"} {
		f := findingWithInvariant(t, c, cited)
		eid := "EV-" + strings.ReplaceAll(cited, "-", "")
		out, err := findings.AddEvidence(c, objStr(f, "finding_id"),
			manualNote(eid, "E1"))
		if err != nil {
			t.Fatal(err)
		}
		if got := len(objAt(out, "evidence").A); got != 1 {
			t.Errorf("%s: evidence count = %d, want 1", cited, got)
		}
	}
}

// ---- byte-exact guard messages -------------------------------------------

// guardCamp rebuilds the twin campaign the guard goldens were emitted from.
func guardCamp(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "vec program",
		state.InitOpts{CampaignID: "C-vec00005"})
	if err != nil {
		t.Fatal(err)
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	st.O = setOrAppend(st.O, "active_snapshot_id", validation.VStr("SNAPX"))
	st.O = setOrAppend(st.O, "artifacts", validation.VArr(
		fixedArtifact("OTH-fixed001", filepath.Join(c.ArtifactsDir, "inv-check.md"))))
	if err := validation.WriteJson(c.StatePath, st, "campaign_state"); err != nil {
		t.Fatal(err)
	}
	snapDir := filepath.Join(c.Dir, "snapshots", "SNAPX")
	if err := os.MkdirAll(snapDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapDir, "README.md"),
		[]byte("INV-1 totalAssets never decreases except via withdraw\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	return c
}

func invCite(id string) validation.Value {
	return validation.VObj(kv("security_invariants",
		validation.VArr(validation.VObj(kv("id", validation.VStr(id))))))
}

// guardCase is one golden guard row: a finding shape and its label.
type guardCase struct {
	label   string
	finding validation.Value
}

// guardCases is the twin's case list, in order (verified_passes is last and
// runs only after INV-2 is verified).
func guardCases() []guardCase {
	return []guardCase{
		{"unverified_model", invCite("INV-2")},
		{"unknown_id", invCite("INV-999")},
		{"zero_padded_unknown", invCite("INV-9990")},
		{"documented_exempt", invCite("INV-1")},
		{"documented_zero_padded", invCite("INV-01")},
		{"no_invariants", validation.VObj(kv("security_invariants",
			validation.VArr()))},
		{"singular_invariant", validation.VObj(kv("invariant",
			validation.VObj(kv("id", validation.VStr("INV-2")))))},
		{"both_halves", validation.VObj(
			kv("invariant", validation.VObj(kv("id", validation.VStr("INV-2")))),
			kv("security_invariants", validation.VArr(
				validation.VObj(kv("id", validation.VStr("INV-2"))),
				validation.VObj(kv("id", validation.VStr("INV-1"))))))},
		{"non_dict_entries", validation.VObj(kv("security_invariants",
			validation.VArr(validation.VStr("INV-2"), validation.VInt(5),
				validation.VNull())))},
		{"no_sec_key", validation.VObj(kv("title", validation.VStr("x")))},
	}
}

func TestGuardMessagesMatchPythonTwin(t *testing.T) {
	c := guardCamp(t)
	wireFindings(t)
	model := goldenValue(t, "scenario_model.json")
	if _, err := SeedFromModel(c, model); err != nil {
		t.Fatal(err)
	}
	want := goldenValue(t, "guard_messages.json")
	cases := guardCases()
	if len(want.A) != len(cases)+1 {
		t.Fatalf("golden has %d rows, want %d", len(want.A), len(cases)+1)
	}
	for i, tc := range cases {
		row := want.A[i]
		if got := objStr(row, "label"); got != tc.label {
			t.Fatalf("golden row %d label = %q, want %q", i, got, tc.label)
		}
		got := ""
		if err := AssertInvariantsVerified(c, tc.finding); err != nil {
			got = err.Error()
		}
		if expect := errText(row); got != expect {
			t.Errorf("guard[%s]\n got: %q\nwant: %q", tc.label, got, expect)
		}
	}
	if _, err := VerifyInvariantStatement(c, "INV-2", "OTH-fixed001"); err != nil {
		t.Fatal(err)
	}
	last := want.A[len(want.A)-1]
	if got := objStr(last, "label"); got != "verified_passes" {
		t.Fatalf("last golden label = %q, want verified_passes", got)
	}
	if err := AssertInvariantsVerified(c, invCite("INV-2")); err != nil {
		t.Errorf("guard[verified_passes] = %v, want nil", err)
	}
	compareTwinFile(t, linksPath(c), "guard_links.json")
	compareTwinFile(t, c.EventsPath, "guard_events.jsonl")
}

// errText reads a {label, error} golden row, mapping JSON null to "".
func errText(row validation.Value) string {
	v := objAt(row, "error")
	if v.Kind != validation.Str {
		return ""
	}
	return v.S
}

// PORT-NOTE (unported, needs another module): the audit half of
// test_hand_edited_checked_with_registered_artifact_blocked and the whole of
// test_audit_flags_unregistered_verification_artifact assert
// AU.audit_campaign's "invariant_verification" section (audit section 11),
// which internal/audit does not implement yet. The gate halves of both
// scenarios are ported above; re-add the audit assertions when section 11
// lands.
//
// PORT-NOTE (excluded by the task): test_ingest_rejects_preloaded_execution_
// evidence is covered by internal/findings' own ingest tests.

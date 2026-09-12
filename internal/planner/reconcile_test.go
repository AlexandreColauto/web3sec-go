package planner

// reconcile_test.go — FIX-6: the lens-closure falsifiability gate. The
// operator's G-02 miss: the L-04 attestation reconciled 42 divergences with
// prose and not a single file#L cite. Every test here pins one refusal path
// (uncited row, ghost finding, symbol not on the row, uncovered member), the
// two legal exits, the no-mutation law of a refusal, and the idempotent
// re-attestation.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// reconRowJSON is one divergence surface row (the G-02 shape: the forward
// path burns while the drop path transfers out). The cite vocabulary the gate
// checks against lives on the row's own entry: contract, consumer, base,
// forward.
const reconRowJSON = `{"row_id":"divrow1","probe":"custody-primitive",` +
	`"contract":"L2Gateway","consumer":"drop","base":"L1Gateway",` +
	`"forward":["deposit"],"divergence":"funding-mismatch",` +
	`"family":"L1Gateway","direction":"drop","asset":"erc20",` +
	`"expected":"burn","observed":"transfer-out",` +
	`"members":["L1Gateway.deposit","L2Gateway.drop"]}`

// reconRow2JSON is a second divergence row (member-disagreement), so the
// every-row law has two rows to count.
const reconRow2JSON = `{"row_id":"divrow2","probe":"custody-primitive",` +
	`"contract":"L1ReverseCustomGateway","consumer":"_depositByTransfer",` +
	`"base":"L1Gateway","forward":["deposit","_deposit"],` +
	`"divergence":"member-disagreement","family":"L1Gateway",` +
	`"direction":"deposit","asset":"erc20","expected":"transfer-in",` +
	`"observed":"transfer-out",` +
	`"members":["L1Gateway._deposit","L1ReverseCustomGateway._depositByTransfer"]}`

// reconPlainRowJSON is a non-divergence custody row (the rule is row-scoped).
const reconPlainRowJSON = `{"row_id":"plainrow","probe":"custody-primitive",` +
	`"contract":"ShareVault","consumer":"withdraw","base":"ShareVault",` +
	`"forward":["deposit"]}`

// reconGoodSpec reconciles divrow1 per member: the observed payout site and
// the crediting forward primitive, each a file#L cite naming a row symbol.
const reconGoodSpec = "divrow1=transfer-out:L2Gateway.drop#L77|" +
	"burn:L1Gateway.deposit#L42"

// reconSpec parses spec under t (spec must parse; a parse failure fails the
// test — refusal-shape cases get their own test).
func reconSpec(t *testing.T, spec string) *[]validation.Value {
	t.Helper()
	recs, err := ParseReconcile(&spec)
	if err != nil {
		t.Fatalf("parse reconcile %q: %v", spec, err)
	}
	return &recs
}

// reconSurfacePtr builds a probe surface carrying the given raw row JSON
// rows.
func reconSurfacePtr(t *testing.T, rows ...string) *validation.Value {
	t.Helper()
	items := make([]string, 0, len(rows))
	for _, r := range rows {
		items = append(items, r)
	}
	surface := jsonValue(t, `{"rows":[`+strings.Join(items, ",")+`]}`)
	return &surface
}

// reconLens reads one lens entry back off a plan.
func reconLens(t *testing.T, plan validation.Value, lid string) validation.Value {
	t.Helper()
	for _, l := range listOf(plan, "lenses") {
		if objStr(l, "id") == lid {
			return l
		}
	}
	t.Fatalf("lens %s not in the plan", lid)
	return validation.VNull()
}

// TestParseReconcileShape pins the two legal value forms and the malformed
// entries the parser refuses.
func TestParseReconcileShape(t *testing.T) {
	spec := "divrow1=F-1a2b3c4d5e6f"
	recs, err := ParseReconcile(&spec)
	if err != nil {
		t.Fatalf("finding form: %v", err)
	}
	if len(recs) != 1 || objStr(recs[0], "row_id") != "divrow1" ||
		objStr(recs[0], "finding") != "F-1a2b3c4d5e6f" {
		t.Fatalf("finding record = %s", validation.CanonCompact(recs[0]))
	}
	if got := listOf(recs[0], "cites"); len(got) != 0 {
		t.Fatalf("finding record carries %d cites", len(got))
	}
	spec = "divrow1=transfer-out:L2Gateway.drop#L77|burn:L1Gateway.deposit#L42"
	recs, err = ParseReconcile(&spec)
	if err != nil {
		t.Fatalf("cite form: %v", err)
	}
	if len(recs) != 1 || objStr(recs[0], "finding") != "" {
		t.Fatalf("cite record finding = %q", objStr(recs[0], "finding"))
	}
	if got := listOf(recs[0], "cites"); len(got) != 2 {
		t.Fatalf("cite record carries %d cites", len(got))
	}
	if objStr(recs[0], "row_id") != "divrow1" {
		t.Fatalf("row_id = %q", objStr(recs[0], "row_id"))
	}
	// two entries, ';' separated
	spec = reconGoodSpec + ";divrow2=F-1a2b3c4d5e6f"
	recs, err = ParseReconcile(&spec)
	if err != nil {
		t.Fatalf("two entries: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("entries = %d, want 2", len(recs))
	}
	// nil and empty specs parse to nothing
	recs, err = ParseReconcile(nil)
	if err != nil || recs != nil {
		t.Fatalf("nil spec = %v, %v", recs, err)
	}
	empty := ""
	recs, err = ParseReconcile(&empty)
	if err != nil || recs != nil {
		t.Fatalf("empty spec = %v, %v", recs, err)
	}
	// malformed: no '='
	bad := "divrow1"
	if _, err := ParseReconcile(&bad); err == nil ||
		!strings.Contains(err.Error(), "must be ROWID=VALUE") {
		t.Fatalf("no '=': err = %v", err)
	}
	// malformed: cite without a line anchor
	bad = "divrow1=transfer-out:L2Gateway.drop"
	if _, err := ParseReconcile(&bad); err == nil ||
		!strings.Contains(err.Error(), "primitive:Symbol#L<line>") {
		t.Fatalf("cite without #L: err = %v", err)
	}
}

// TestLensReconciliationAccepted is the positive path: every divergence row
// cited, the attestation lands with the reconciliation on the lens entry.
func TestLensReconciliationAccepted(t *testing.T) {
	withProbes(t, probeEnv{surface: reconSurfacePtr(t, reconRowJSON)})
	c := newCampaign(t, "recon-ok")
	reconOnRecord(t, c)
	plan, err := DefaultPlanFromModel(c, validation.VObj())
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	plan, err = MarkLens(c, plan, "L-04", "answered", LensOpts{
		Reason: strPtr("the drop path's payout is funded by the burned " +
			"deposits; each member named with its primitive"),
		Actor:     "operator",
		Reconcile: reconSpec(t, reconGoodSpec)})
	if err != nil {
		t.Fatalf("attested closure refused: %v", err)
	}
	l := reconLens(t, plan, "L-04")
	if got := objStr(l, "status"); got != "answered" {
		t.Fatalf("status = %q", got)
	}
	recs := listOf(l, "reconciliation")
	if len(recs) != 1 || objStr(recs[0], "row_id") != "divrow1" {
		t.Fatalf("reconciliation = %s", validation.CanonCompact(
			objAt(l, "reconciliation")))
	}
	if got := listOf(recs[0], "cites"); len(got) != 2 {
		t.Fatalf("recorded cites = %d, want 2", len(got))
	}
}

// TestLensReconciliationFindingExit pins exit (b): a real filed finding id
// satisfies the row; a ghost id is refused as one.
func TestLensReconciliationFindingExit(t *testing.T) {
	withProbes(t, probeEnv{surface: reconSurfacePtr(t, reconRowJSON)})
	c := newCampaign(t, "recon-ghost")
	reconOnRecord(t, c)
	plan, err := DefaultPlanFromModel(c, validation.VObj())
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	_, err = MarkLens(c, plan, "L-04", "answered", LensOpts{
		Reason:    strPtr("the mismatch is filed as a finding"),
		Actor:     "operator",
		Reconcile: reconSpec(t, "divrow1=F-111111111111")})
	if err == nil || !strings.Contains(err.Error(),
		"F-111111111111 does not exist in this campaign") {
		t.Fatalf("ghost finding: err = %v", err)
	}
	// the same id as a real finding file: accepted
	if err := os.MkdirAll(c.FindingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.FindingsDir,
		"F-111111111111.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err = MarkLens(c, plan, "L-04", "answered", LensOpts{
		Reason:    strPtr("the mismatch is filed as a finding"),
		Actor:     "operator",
		Reconcile: reconSpec(t, "divrow1=F-111111111111")})
	if err != nil {
		t.Fatalf("filed finding refused: %v", err)
	}
	l := reconLens(t, plan, "L-04")
	recs := listOf(l, "reconciliation")
	if len(recs) != 1 || objStr(recs[0], "finding") != "F-111111111111" {
		t.Fatalf("recorded finding = %s", validation.CanonCompact(
			objAt(l, "reconciliation")))
	}
	// a malformed id is answered AS one, not as a shape error at the gate —
	// a library caller can hand the gate a record past ParseReconcile
	malformed := jsonValue(t, `{"row_id":"divrow1","cites":[],"finding":`+
		`"F-not-a-finding-id"}`)
	malformedRecs := []validation.Value{malformed}
	_, err = MarkLens(c, plan, "L-04", "answered", LensOpts{
		Reason:    strPtr("the mismatch is filed as a finding"),
		Actor:     "operator",
		Reconcile: &malformedRecs})
	if err == nil || !strings.Contains(err.Error(),
		"is not a finding id (F-<12 hex digits>)") {
		t.Fatalf("malformed finding: err = %v", err)
	}
}

// TestLensReconciliationRefusesUncitedRow is the core negative: one row left
// uncited refuses the attestation, names it and the two exits, and leaves the
// plan and the event log untouched.
func TestLensReconciliationRefusesUncitedRow(t *testing.T) {
	withProbes(t, probeEnv{surface: reconSurfacePtr(t, reconRowJSON,
		reconRow2JSON)})
	c := newCampaign(t, "recon-refuse")
	reconOnRecord(t, c)
	plan, err := DefaultPlanFromModel(c, validation.VObj())
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	// the plan is a real artifact before the attempt: the refusal must leave
	// it byte-identical
	if _, err := SavePlan(c, plan); err != nil {
		t.Fatalf("save plan: %v", err)
	}
	_, err = MarkLens(c, plan, "L-04", "answered", LensOpts{
		Reason:    strPtr("narrated the divergences as benign duals"),
		Actor:     "operator",
		Reconcile: reconSpec(t, reconGoodSpec)})
	if err == nil {
		t.Fatal("uncited row accepted")
	}
	msg := err.Error()
	for _, want := range []string{"divrow2", "member-disagreement",
		"L1ReverseCustomGateway", "_depositByTransfer",
		"no reconciliation on record", "--reconcile 'RID=primitive:Symbol#L<line>|...'",
		"--reconcile 'RID=F-<12 hex digits>'"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "divrow1 (funding-mismatch, L1Gateway drop:erc20): no reconciliation") {
		t.Errorf("the cited row was named unreconciled:\n%s", msg)
	}
	// the refusal is a decision that did not happen: the plan on disk is
	// byte-identical, the lens untouched, the event log silent
	planPath := filepath.Join(c.ArtifactsDir, "campaign_plan.json")
	before, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	plan, err = validation.ReadJson(planPath)
	if err != nil {
		t.Fatal(err)
	}
	l := reconLens(t, plan, "L-04")
	if got := objStr(l, "status"); got != "open" {
		t.Fatalf("refused attestation changed the status to %q", got)
	}
	if hasKey(l, "reconciliation") {
		t.Fatalf("refused attestation recorded a reconciliation")
	}
	after, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatalf("refused attestation rewrote campaign_plan.json")
	}
	evts, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evts {
		if objStr(e, "type") == "plan.lens_status" {
			t.Fatalf("refused attestation logged %s", objStr(e, "type"))
		}
	}
}

// TestLensReconciliationCiteNotOnRow: a cite naming a symbol the row's own
// surface entry does not carry is refused with the row's real symbols named.
func TestLensReconciliationCiteNotOnRow(t *testing.T) {
	withProbes(t, probeEnv{surface: reconSurfacePtr(t, reconRowJSON)})
	c := newCampaign(t, "recon-symbol")
	reconOnRecord(t, c)
	plan, err := DefaultPlanFromModel(c, validation.VObj())
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	_, err = MarkLens(c, plan, "L-04", "answered", LensOpts{
		Reason: strPtr("cited something the row never mentioned"),
		Actor:  "operator",
		Reconcile: reconSpec(t, "divrow1=burn:UnrelatedContract#L9|"+
			"burn:L1Gateway.deposit#L42")})
	if err == nil || !strings.Contains(err.Error(),
		"names no symbol from the row's own surface entry") {
		t.Fatalf("off-row symbol: err = %v", err)
	}
	if !strings.Contains(err.Error(), "L2Gateway") {
		t.Fatalf("refusal does not name the row's own symbols: %v", err)
	}
}

// TestLensReconciliationMissingMember: the per-member law — cites that skip a
// member of the row refuse with the missing member named.
func TestLensReconciliationMissingMember(t *testing.T) {
	withProbes(t, probeEnv{surface: reconSurfacePtr(t, reconRowJSON)})
	c := newCampaign(t, "recon-member")
	reconOnRecord(t, c)
	plan, err := DefaultPlanFromModel(c, validation.VObj())
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	_, err = MarkLens(c, plan, "L-04", "answered", LensOpts{
		Reason:    strPtr("cited one member and waved at the other"),
		Actor:     "operator",
		Reconcile: reconSpec(t, "divrow1=burn:L1Gateway.deposit#L42")})
	if err == nil || !strings.Contains(err.Error(),
		"do not name the funding primitive per member "+
			"(missing: L2Gateway.drop)") {
		t.Fatalf("missing member: err = %v", err)
	}
}

// TestLensReconciliationIdempotent: the same attestation twice records the
// reconciliation once (no double-fire), a re-attestation without the flag
// stays legal on the stored record, and a REOPENED lens — whose stored
// reconciliation the reopen dropped — refuses until it is re-attested.
func TestLensReconciliationIdempotent(t *testing.T) {
	withProbes(t, probeEnv{surface: reconSurfacePtr(t, reconRowJSON)})
	c := newCampaign(t, "recon-idem")
	reconOnRecord(t, c)
	plan, err := DefaultPlanFromModel(c, validation.VObj())
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	spec := reconSpec(t, reconGoodSpec)
	reason := strPtr("the drop path's payout is funded by the burned deposits")
	plan, err = MarkLens(c, plan, "L-04", "answered", LensOpts{Reason: reason,
		Actor: "operator", Reconcile: spec})
	if err != nil {
		t.Fatalf("first attestation: %v", err)
	}
	plan, err = MarkLens(c, plan, "L-04", "answered", LensOpts{Reason: reason,
		Actor: "operator", Reconcile: spec})
	if err != nil {
		t.Fatalf("re-attestation refused: %v", err)
	}
	if got := len(listOf(reconLens(t, plan, "L-04"), "reconciliation")); got != 1 {
		t.Fatalf("re-attestation recorded %d reconciliations, want 1", got)
	}
	// re-attest WITHOUT the flag: the stored record stays legal
	plan, err = MarkLens(c, plan, "L-04", "answered", LensOpts{Reason: reason,
		Actor: "operator"})
	if err != nil {
		t.Fatalf("re-attestation without the flag refused: %v", err)
	}
	// reopen drops the reconciliation; closing again without it refuses
	plan, err = MarkLens(c, plan, "L-04", "open", LensOpts{Actor: "operator"})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if hasKey(reconLens(t, plan, "L-04"), "reconciliation") {
		t.Fatalf("reopen kept the reconciliation")
	}
	_, err = MarkLens(c, plan, "L-04", "answered", LensOpts{Reason: reason,
		Actor: "operator"})
	if err == nil || !strings.Contains(err.Error(), "divrow1") {
		t.Fatalf("reopened lens closed without reconciliation: err = %v", err)
	}
}

// TestLensReconciliationScoped pins the rule's scope: a non-primitive-symmetry
// lens closes with the same surface present and no reconciliation, and a
// surface whose rows carry no divergence kind demands nothing.
func TestLensReconciliationScoped(t *testing.T) {
	withProbes(t, probeEnv{surface: reconSurfacePtr(t, reconRowJSON)})
	c := newCampaign(t, "recon-scope")
	reconOnRecord(t, c)
	plan, err := DefaultPlanFromModel(c, validation.VObj())
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	plan, err = MarkLens(c, plan, "L-02", "answered", LensOpts{
		Reason: strPtr("the inverted incentive is priced in the model"),
		Actor:  "operator"})
	if err != nil {
		t.Fatalf("non-symmetry lens refused: %v", err)
	}
	// a surface with no divergence rows: L-04 needs no reconciliation
	withProbes(t, probeEnv{surface: reconSurfacePtr(t, reconPlainRowJSON)})
	c2 := newCampaign(t, "recon-plain")
	reconOnRecord(t, c2)
	plan2, err := DefaultPlanFromModel(c2, validation.VObj())
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	plan2, err = MarkLens(c2, plan2, "L-04", "answered", LensOpts{
		Reason: strPtr("no divergence row exists in this surface"),
		Actor:  "operator"})
	if err != nil {
		t.Fatalf("divergence-free surface refused: %v", err)
	}
}

// TestLensReconciliationNoSurface: the grandfather case — a campaign with no
// probe artifact has nothing to reconcile, so the closure passes without the
// flag (and records nothing), while a --reconcile naming rows the campaign
// cannot check is refused with the emit command.
func TestLensReconciliationNoSurface(t *testing.T) {
	c := newCampaign(t, "recon-nosurface")
	reconOnRecord(t, c)
	plan, err := DefaultPlanFromModel(c, validation.VObj())
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	plan, err = MarkLens(c, plan, "L-04", "answered", LensOpts{
		Reason: strPtr("the plan predates the probe surface"),
		Actor:  "operator"})
	if err != nil {
		t.Fatalf("no-surface closure refused: %v", err)
	}
	if hasKey(reconLens(t, plan, "L-04"), "reconciliation") {
		t.Fatalf("reconciliation recorded with nothing to reconcile")
	}
	_, err = MarkLens(c, plan, "L-04", "answered", LensOpts{
		Reason:    strPtr("the plan predates the probe surface"),
		Actor:     "operator",
		Reconcile: reconSpec(t, reconGoodSpec)})
	if err == nil || !strings.Contains(err.Error(),
		"the campaign has no probe surface, so there is nothing to "+
			"reconcile") || !strings.Contains(err.Error(), "run --emit") {
		t.Fatalf("no-surface --reconcile: err = %v", err)
	}
}

// TestLensReconciliationUnknownRow: a --reconcile entry naming a row that is
// not a divergence row in the surface is refused with the real rows named.
func TestLensReconciliationUnknownRow(t *testing.T) {
	withProbes(t, probeEnv{surface: reconSurfacePtr(t, reconRowJSON,
		reconPlainRowJSON)})
	c := newCampaign(t, "recon-unknownrow")
	reconOnRecord(t, c)
	plan, err := DefaultPlanFromModel(c, validation.VObj())
	if err != nil {
		t.Fatalf("default plan: %v", err)
	}
	_, err = MarkLens(c, plan, "L-04", "answered", LensOpts{
		Reason: strPtr("reconciled a row that never diverged"),
		Actor:  "operator",
		Reconcile: reconSpec(t, "plainrow=burn:ShareVault.withdraw#L9|"+
			"burn:ShareVault.deposit#L42")})
	if err == nil || !strings.Contains(err.Error(),
		"which is not a funding-mismatch or member-disagreement divergence "+
			"row in the current surface") || !strings.Contains(err.Error(),
		"divrow1 (funding-mismatch, L1Gateway drop:erc20)") {
		t.Fatalf("unknown row: err = %v", err)
	}
}

// TestValidateReconcileRecordMalformed pins the malformed-record arm a
// library caller can reach past ParseReconcile: a record with neither exit.
func TestValidateReconcileRecordMalformed(t *testing.T) {
	withProbes(t, probeEnv{surface: reconSurfacePtr(t, reconRowJSON)})
	surface, err := PB().CampaignSurface(nil)
	if err != nil || surface == nil {
		t.Fatalf("fake surface missing: %v", err)
	}
	row := listOf(*surface, "rows")[0]
	c := newCampaign(t, "recon-malformed")
	reconOnRecord(t, c)
	rec := jsonValue(t, `{"row_id":"divrow1","cites":[],"finding":null}`)
	if got := validateReconcileRecord(c, row, rec); got == "" ||
		!strings.Contains(got, "records neither a per-member cite nor a "+
			"filed finding id") {
		t.Fatalf("malformed record reason = %q", got)
	}
}

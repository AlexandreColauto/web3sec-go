package regression

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

const (
	shaPre  = "1111111111111111111111111111111111111111"
	shaPost = "2222222222222222222222222222222222222222"
)

func controlTarget(t *testing.T, c *state.Campaign) string {
	t.Helper()
	target, err := AddTarget(c, TargetSpec{
		Kind: "control", Program: "Exploited Protocol",
		RecordID: "exploited-protocol", Repo: "org/exploited-protocol",
		Shape: "already-exploited", CommitHint: shaPre,
	})
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(target, "target_id")
}

// controlPayload is the hypothesis payload the handoff tests ingest and the
// CONFIRMED-finding helper stamps. It lives in one place because two copies of a
// fifteen-line literal is how two tests drift apart.
func controlPayload() validation.Value {
	return validation.VObj(
		kv("title", validation.VStr("Reentrancy drains the vault")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("reentrancy")),
			kv("description", validation.VStr("the mechanism described in detail here")),
		)),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("withdraw")),
		))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()),
		)),
	)
}

// controlMut is one row of the control record's refusal table: it mutates a
// valid spec and names the substring the refusal must carry.
type controlMut struct {
	name string
	mut  func(*ControlSpec)
	want string
}

// controlRefusalCases is that table, kept out of the test function so the test
// reads as the loop it is.
func controlRefusalCases() []controlMut {
	return []controlMut{
		{"no loss citation", func(s *ControlSpec) { s.LossSource = "" }, "loss_source"},
		{"no incident url", func(s *ControlSpec) { s.IncidentURL = "" }, "incident"},
		{"zero loss", func(s *ControlSpec) { s.LossUSD = 0 }, "loss_usd"},
		{"no pre-patch pin", func(s *ControlSpec) { s.PrePatchSHA = "main" }, "pre-patch"},
		{"missing pre-patch pin", func(s *ControlSpec) { s.PrePatchSHA = "" }, "pre-patch"},
		{"no patch pin", func(s *ControlSpec) { s.PatchSHA = "" }, "patch"},
		{"pre-patch equals patch", func(s *ControlSpec) { s.PatchSHA = shaPre }, "same commit"},
		{"no harness", func(s *ControlSpec) { s.HarnessRunner = "" }, "harness"},
	}
}

func TestRecordControlRefusesAnUncitedOrUnpinnedIncident(t *testing.T) {
	c := regressionCampaign(t, "C-regctlrefuse1")
	tid := controlTarget(t, c)
	good := ControlSpec{
		TargetID: tid, IncidentURL: "https://example.test/incident",
		IncidentDate: "2025-09-01", LossUSD: 12500000,
		LossSource:  "post-mortem §2 (recovered funds excluded)",
		PrePatchSHA: shaPre, PatchSHA: shaPost,
		HarnessRunner: "foundry", HarnessCommand: "forge test --match-test test_exploit",
	}
	cases := controlRefusalCases()
	for _, tc := range cases {
		spec := good
		tc.mut(&spec)
		if _, err := RecordControl(c, spec); err == nil ||
			!strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want a refusal naming %q", tc.name, err, tc.want)
		}
	}
	doc, err := RecordControl(c, good)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(validation.ObjAt(doc, "control"), "pre_patch_sha"); got != shaPre {
		t.Fatalf("pre_patch_sha = %q, want %q", got, shaPre)
	}
	if got := validation.ObjAt(validation.ObjAt(doc, "incident"), "loss_usd"); got.F != 12500000 {
		t.Fatalf("loss_usd = %v, want 12500000", got)
	}
}

// TestRecordControlRefusesANonControlTarget pins the other half of the kind
// guard: the block belongs to the control target, so a scabench target cannot
// carry one (and the valid record above proves the guard is not simply
// refusing everything).
func TestRecordControlRefusesANonControlTarget(t *testing.T) {
	c := regressionCampaign(t, "C-regctlrefuse2")
	other, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = RecordControl(c, ControlSpec{
		TargetID:    validation.ObjStr(other, "target_id"),
		IncidentURL: "https://example.test/incident", IncidentDate: "2025-09-01",
		LossUSD: 1, LossSource: "s", PrePatchSHA: shaPre, PatchSHA: shaPost,
		HarnessRunner: "foundry",
	})
	if err == nil || !strings.Contains(err.Error(), "control") {
		t.Fatalf("err = %v, want a refusal naming the control kind", err)
	}
	if _, err := RecordControl(c, ControlSpec{
		TargetID: "T-000000000000", IncidentURL: "https://example.test/i",
		IncidentDate: "2025-09-01", LossUSD: 1, LossSource: "s",
		PrePatchSHA: shaPre, PatchSHA: shaPost, HarnessRunner: "foundry",
	}); err == nil || !strings.Contains(err.Error(), "no target") {
		t.Fatalf("err = %v, want a refusal naming the missing target", err)
	}
}

// TestRecordHandoffRequiresAConfirmedFinding is the P1 dependency as a test:
// the spike needs "one already-confirmed finding", so a handoff naming a
// finding that is not CONFIRMED is refused. The positive case stamps CONFIRMED
// through the store's own writer — reaching it through findings.Transition
// needs E5 evidence and a sandbox, which is the operator step's job, not this
// test's; what is under test here is the shape of a CONFIRMED finding.
// ingestControlFinding ingests the shared payload and returns the finding.
func ingestControlFinding(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	finding, err := findings.IngestHypothesis(c, controlPayload(), "code", "control", "")
	if err != nil {
		t.Fatal(err)
	}
	return finding
}

// confirmFinding stamps a finding CONFIRMED through the store's own writer.
func confirmFinding(t *testing.T, c *state.Campaign, finding validation.Value) {
	t.Helper()
	moved := finding
	moved.O = validation.SetOrAppend(moved.O, "status", validation.VStr("CONFIRMED"))
	if err := findings.SaveFinding(c, &moved); err != nil {
		t.Fatal(err)
	}
}

// assertHandoffRefused asserts RecordHandoff refuses and that the refusal names
// want — a refusal that does not name the field is a refusal the operator
// cannot act on.
func assertHandoffRefused(t *testing.T, c *state.Campaign, tid, fid string, usd float64, want string) {
	t.Helper()
	_, err := RecordHandoff(c, HandoffSpec{
		TargetID: tid, FindingID: fid, ExtractableUSD: usd,
		Source: "s", RecordedBy: "operator",
	})
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("extractable_usd=%v: err = %v, want a refusal naming %q", usd, err, want)
	}
}

// assertHandoffAccepted records a valid handoff and pins its two leaves: the
// finding it names and the figure it carries.
func assertHandoffAccepted(t *testing.T, c *state.Campaign, tid, fid string) {
	t.Helper()
	doc, err := RecordHandoff(c, HandoffSpec{
		TargetID: tid, FindingID: fid, ExtractableUSD: 900000,
		Source: "reproduction on the pre-patch commit", RecordedBy: "operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	ho := validation.ObjAt(doc, "handoff")
	if got := validation.ObjStr(ho, "finding_id"); got != fid {
		t.Fatalf("handoff.finding_id = %q, want %q", got, fid)
	}
	if got := validation.ObjAt(ho, "extractable_usd").F; got != 900000 {
		t.Fatalf("handoff.extractable_usd = %v, want 900000", got)
	}
}

func TestRecordHandoffRequiresAConfirmedFinding(t *testing.T) {
	c := regressionCampaign(t, "C-reghandoff001")
	tid := controlTarget(t, c)
	// The control block first: the handoff is the control target's own
	// artefact and RecordHandoff refuses a target whose incident and pre-patch
	// pin were never recorded (the plan's own draft test skipped this step,
	// which its own implementation refuses).
	recordControlForHandoff(t, c, tid)
	finding := ingestControlFinding(t, c)
	fid := validation.ObjStr(finding, "finding_id")

	// Not CONFIRMED yet: refused, and the refusal names the status.
	assertHandoffRefused(t, c, tid, fid, 900000, "status")

	// Stamp CONFIRMED through the store's writer, then the figure is the only
	// thing left that can be wrong.
	confirmFinding(t, c, finding)
	for _, bad := range []float64{0, -1} {
		assertHandoffRefused(t, c, tid, fid, bad, "extractable_usd")
	}
	assertHandoffAccepted(t, c, tid, fid)
	// A handoff on a non-control target is refused: the handoff is the control
	// target's own artefact, not a general-purpose note.
	other, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RecordHandoff(c, HandoffSpec{
		TargetID: validation.ObjStr(other, "target_id"), FindingID: fid,
		ExtractableUSD: 1, Source: "s", RecordedBy: "operator",
	}); err == nil || !strings.Contains(err.Error(), "control") {
		t.Fatalf("err = %v, want a refusal naming the control kind", err)
	}
}

// TestRecordHandoffRefusesAnUnknownFindingAndAnUncitedSource covers the two
// refusals the confirmed-finding test cannot reach: a finding id the campaign
// does not have, and a handoff whose extractable figure carries no source.
// The control block must exist first (that refusal has its own test below).
func TestRecordHandoffRefusesAnUnknownFindingAndAnUncitedSource(t *testing.T) {
	c := regressionCampaign(t, "C-reghandoff002")
	tid := controlTarget(t, c)
	if _, err := RecordHandoff(c, HandoffSpec{
		TargetID: tid, FindingID: "F-000000000000", ExtractableUSD: 1,
		Source: "s", RecordedBy: "operator",
	}); err == nil || !strings.Contains(err.Error(), "control block") {
		t.Fatalf("err = %v, want a refusal naming the missing control block", err)
	}
	recordControlForHandoff(t, c, tid)
	if _, err := RecordHandoff(c, HandoffSpec{
		TargetID: tid, FindingID: "F-000000000000", ExtractableUSD: 1,
		Source: "s", RecordedBy: "operator",
	}); err == nil || !strings.Contains(err.Error(), "does not have") {
		t.Fatalf("err = %v, want a refusal naming the unknown finding", err)
	}
	fid := confirmedFinding(t, c)
	if _, err := RecordHandoff(c, HandoffSpec{
		TargetID: tid, FindingID: fid, ExtractableUSD: 1,
		Source: "", RecordedBy: "operator",
	}); err == nil || !strings.Contains(err.Error(), "--source") {
		t.Fatalf("err = %v, want a refusal naming --source", err)
	}
	if _, err := RecordHandoff(c, HandoffSpec{
		TargetID: tid, FindingID: fid, ExtractableUSD: 1,
		Source: "derived from the post-mortem figure", RecordedBy: "operator",
	}); err != nil {
		t.Fatalf("a valid handoff was refused: %v", err)
	}
}

// recordControlForHandoff writes the control block through the real writer.
func recordControlForHandoff(t *testing.T, c *state.Campaign, tid string) {
	t.Helper()
	if _, err := RecordControl(c, ControlSpec{
		TargetID: tid, IncidentURL: "https://example.test/incident",
		IncidentDate: "2025-09-01", LossUSD: 12500000, LossSource: "post-mortem",
		PrePatchSHA: shaPre, PatchSHA: shaPost, HarnessRunner: "foundry",
	}); err != nil {
		t.Fatal(err)
	}
}

// TestCheckControlSpecRefusesEachRuleDirectly calls checkControlSpec in
// isolation — no campaign, no schema, no ledger — to pin the Go layer's own
// messages. RecordControl's tests run the pair, and the schema that
// writeThenLog validates enforces some of the same invariants: the mutation
// run showed that deleting only the Go check leaves those tests green, because
// the record is still refused, by the schema. Defence in depth is the right
// architecture; untested code is not, so this test is what stops the Go checks
// rotting behind the schema.
func TestCheckControlSpecRefusesEachRuleDirectly(t *testing.T) {
	base := ControlSpec{
		IncidentURL: "https://example.test/incident", IncidentDate: "2025-09-01",
		LossUSD: 12500000, LossSource: "post-mortem §2",
		PrePatchSHA: shaPre, PatchSHA: shaPost,
		HarnessRunner: "foundry", HarnessCommand: "forge test",
	}
	if err := checkControlSpec(base); err != nil {
		t.Fatalf("a complete spec was refused: %v", err)
	}
	for _, tc := range controlRefusalCases() {
		spec := base
		tc.mut(&spec)
		err := checkControlSpec(spec)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want a refusal naming %q", tc.name, err, tc.want)
		}
	}
}

// confirmedFinding ingests one finding and stamps it CONFIRMED through the
// store's own writer, returning its id.
func confirmedFinding(t *testing.T, c *state.Campaign) string {
	t.Helper()
	payload := controlPayload()
	finding, err := findings.IngestHypothesis(c, payload, "code", "control", "")
	if err != nil {
		t.Fatal(err)
	}
	finding.O = validation.SetOrAppend(finding.O, "status", validation.VStr("CONFIRMED"))
	if err := findings.SaveFinding(c, &finding); err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(finding, "finding_id")
}

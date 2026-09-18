package boundary

import (
	"regexp"
	"testing"

	"websec/internal/findings"
	"websec/internal/learning"
	"websec/internal/playbooks"
	"websec/internal/roles"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/trajectory"
	"websec/internal/validation"
)

// t35BundleSetup is test_model_integration.py's camp + fully_loaded_finding
// + ev1: a pinned campaign with one POSSIBLE finding carrying E1 evidence.
func t35BundleSetup(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	c := newCamp(t)
	pin(t, c)
	f := mustIngest(t, c, validHypothesis())
	fid := validation.ObjStr(f, "finding_id")
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "", "",
		false); err != nil {
		t.Fatal(err)
	}
	ev1(t, c, fid)
	return c, fid
}

// Port of tests/test_model_integration.py::test_role_bundles_agree_with_boundary_role_contract.
func TestRoleBundlesAgreeWithBoundaryRoleContract(t *testing.T) {
	c, fid := t35BundleSetup(t)
	cls := "oracle-manipulation"
	proposer, err := roles.BuildProposerContext(c, &cls)
	if err != nil {
		t.Fatal(err)
	}
	critic, err := roles.BuildCriticContext(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	reproducer, err := roles.BuildReproducerContext(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	// the bundles' requested response schema(s) ⊆ ROLE_RESPONSES[role].
	own, _ := roleKinds("proposer")
	for _, s := range strList(validation.ObjAt(validation.ObjAt(proposer, "request"),
		"response_schemas")) {
		if !containsStr(own, s) {
			t.Errorf("proposer requests %q outside ROLE_RESPONSES", s)
		}
	}
	criticKinds, _ := roleKinds("critic")
	if got := validation.ObjStr(validation.ObjAt(critic, "task"), "response_schema"); !containsStr(
		criticKinds, got) {
		t.Errorf("critic response_schema = %q, want %v", got, criticKinds)
	}
	reproKinds, _ := roleKinds("reproducer")
	if got := validation.ObjStr(validation.ObjAt(reproducer, "task"), "response_schema"); !containsStr(
		reproKinds, got) {
		t.Errorf("reproducer response_schema = %q, want %v", got, reproKinds)
	}
	// every role's grant is non-empty and role-distinct.
	for role, want := range map[string]string{
		"proposer": "hypothesis,plan", "critic": "critic_verdict",
		"reproducer": "reproducer_request",
	} {
		kinds, ok := roleKinds(role)
		if !ok || joinStrings(kinds, ",") != want {
			t.Errorf("ROLE_RESPONSES[%s] = %v, want %s", role, kinds, want)
		}
	}
	// critic bundle: permitted checks ⊆ tool registry.
	checks := strList(validation.ObjAt(critic, "permitted_checks"))
	if len(checks) == 0 {
		t.Fatal("critic bundle surfaces no permitted checks")
	}
	reg := ToolRegistry()
	for _, chk := range checks {
		if !containsStr(reg, chk) {
			t.Errorf("permitted check %q outside the tool registry", chk)
		}
	}
	// reproducer bundle: permitted execution profiles ⊆ sandbox.Profiles.
	profiles := strList(validation.ObjAt(reproducer, "permitted_execution_profiles"))
	if len(profiles) == 0 {
		t.Fatal("reproducer bundle surfaces no execution profiles")
	}
	for _, p := range profiles {
		if !containsStr(sandbox.Profiles, p) {
			t.Errorf("permitted profile %q outside sandbox.Profiles", p)
		}
	}
	// the boundary's registry is exactly the two halves the bundles draw from.
	if len(reg) != len(AnalysisTools)+len(sandbox.Profiles) {
		t.Errorf("tool_registry size = %d, want %d analysis + %d profiles",
			len(reg), len(AnalysisTools), len(sandbox.Profiles))
	}
	for _, p := range sandbox.Profiles {
		if !containsStr(reg, p) {
			t.Errorf("registry omits sandbox profile %q", p)
		}
	}
	for _, a := range AnalysisTools {
		if !containsStr(reg, a) {
			t.Errorf("registry omits analysis tool %q", a)
		}
	}
}

// Port of tests/test_model_integration.py::test_role_kind_matrix_end_to_end.
func TestRoleKindMatrixEndToEnd(t *testing.T) {
	c, fid := t35BundleSetup(t)
	payloads := map[string]validation.Value{
		"hypothesis": validHypothesis(),
		"plan": validation.VObj(
			kv("finding_id", validation.VStr(fid)),
			kv("steps", validation.VArr(validation.VObj(
				kv("step", validation.VInt(1)),
				kv("tool_id", validation.VStr("callgraph")),
				kv("target_assumptions", validation.VArr(
					validation.VStr("A1"))),
				kv("expected_observation", validation.VStr(
					"redeem() has no modifier")))))),
		"critic_verdict":     validCriticVerdict(fid),
		"reproducer_request": validReproducerRequest(fid),
	}
	for _, role := range []string{"proposer", "critic", "reproducer"} {
		own, _ := roleKinds(role)
		for _, kind := range ResponseKinds {
			err := ValidateResponse(role, kind, payloads[kind], c)
			if containsStr(own, kind) {
				if err != nil {
					t.Errorf("%s/%s must be accepted: %v", role, kind, err)
				}
				continue
			}
			if err == nil || !containsString(err.Error(), "may not emit") {
				t.Errorf("%s/%s err = %v, want may-not-emit", role, kind, err)
			}
		}
	}
}

// containsString is a substring check (containsStr is the slice one).
func containsString(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// joinStrings joins with sep (strings.Join without the import).
func joinStrings(xs []string, sep string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += sep
		}
		out += x
	}
	return out
}

// t35PinWithID is the model-integration pin fixture (explicit snapshot id).
func t35PinWithID(t *testing.T, c *state.Campaign, id string) {
	t.Helper()
	if _, err := c.PinSnapshot(validation.VObj(
		kv("snapshot_id", validation.VStr(id)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("created_at", validation.VStr("2026-01-01T00:00:00Z")),
		kv("source", validation.VObj(
			kv("ladder", validation.VStr("artifact")),
			kv("content_hash", validation.VStr(joinStrings(
				[]string{"a"}, ""))))))); err != nil {
		t.Fatal(err)
	}
}

// Port of tests/test_model_integration.py::test_negative_memory_staleness_end_to_end.
func TestNegativeMemoryStalenessEndToEnd(t *testing.T) {
	const snapA, snapB = "SNAP-A-11111", "SNAP-B-22222"
	c := newCamp(t)
	t35PinWithID(t, c, snapA)
	cls := "oracle-manipulation"
	mid := validation.ObjStr(mustQueueMemory(t, c, learning.QueueOpts{
		Kind:            "disproved",
		Status:          "DISPROVED",
		Pattern:         "TWAP oracle manipulation via flash loan on the redemption path",
		BugClass:        &cls,
		EvidenceSummary: "pushed price reverts before redemption settles",
		DecidingPropositions: []validation.Value{validation.VObj(
			kv("type", validation.VStr("temporal")),
			kv("statement", validation.VStr("the TWAP window is shorter than "+
				"the flash-loan manipulation horizon, so the pushed price "+
				"reverts before redemption settles")))},
	}), "memory_id")
	rows, err := learning.AllMemory(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("no queued memory row")
	}
	row := rows[0]
	if got := validation.ObjStr(row, "snapshot_id"); got != snapA {
		t.Errorf("snapshot_id = %q, want %q", got, snapA)
	}
	if got := validation.ObjAt(row, "schema_version").I; got != 2 {
		t.Errorf("schema_version = %v, want 2", got)
	}
	if got := validation.ObjStr(row, "rejection_class"); got != "invalid-hypothesis" {
		t.Errorf("rejection_class = %q, want invalid-hypothesis (derived)", got)
	}

	// pin snapshot B (divergence): the prior's pin is no longer active.
	t35PinWithID(t, c, snapB)
	bundle, err := roles.BuildProposerContext(c, &cls)
	if err != nil {
		t.Fatal(err)
	}
	block := validation.ObjAt(bundle, "negative_memory")
	if validation.ObjAt(block, "authoritative").Kind != validation.Bool ||
		validation.ObjAt(block, "authoritative").B {
		t.Errorf("authoritative = %v, want false", validation.ObjAt(block, "authoritative"))
	}
	if validation.ObjStr(block, "staleness_note") == "" {
		t.Error("staleness_note is empty")
	}
	prior := t35PriorByID(t, block, mid)
	if !validation.ObjAt(prior, "pin_diverged").B {
		t.Error("pin_diverged = false, want true")
	}
	propType := validation.ObjAt(validation.ObjAt(prior, "deciding_propositions").A[0], "type")
	if propType.S != "temporal" {
		t.Errorf("deciding_propositions[0].type = %v", propType)
	}

	// ingest a matching hypothesis (no override) -> the prior re-raises.
	mustIngest(t, c, validHypothesis())
	data := utilityEvent(t, c)
	if got := strList(validation.ObjAt(data, "re_raised")); joinStrings(got, ",") != mid {
		t.Errorf("re_raised = %v, want [%s]", got, mid)
	}
	if got := strList(validation.ObjAt(data, "override_declared")); len(got) != 0 {
		t.Errorf("override_declared = %v, want []", got)
	}
	if got := strList(validation.ObjAt(data, "not_matched")); len(got) != 0 {
		t.Errorf("not_matched = %v, want []", got)
	}

	// queue a NON-ECONOMIC row against B: the class is derived.
	mid2 := validation.ObjStr(mustQueueMemory(t, c, learning.QueueOpts{
		Kind:            "reflection",
		Status:          "NON-ECONOMIC",
		Pattern:         "the price push clears the fees but lands below the program payout threshold",
		BugClass:        &cls,
		EvidenceSummary: "net extraction under the threshold at pinned TVL",
	}), "memory_id")
	rows, err = learning.AllMemory(c)
	if err != nil {
		t.Fatal(err)
	}
	var row2 validation.Value
	for _, r := range rows {
		if validation.ObjStr(r, "memory_id") == mid2 {
			row2 = r
		}
	}
	if row2.Kind != validation.Obj {
		t.Fatalf("queued row %s missing", mid2)
	}
	if got := validation.ObjStr(row2, "rejection_class"); got != "below-threshold" {
		t.Errorf("rejection_class = %q, want below-threshold", got)
	}
	if got := validation.ObjStr(row2, "snapshot_id"); got != snapB {
		t.Errorf("snapshot_id = %q, want %q", got, snapB)
	}

	bundle2, err := roles.BuildProposerContext(c, &cls)
	if err != nil {
		t.Fatal(err)
	}
	block2 := validation.ObjAt(bundle2, "negative_memory")
	fresh := t35PriorByID(t, block2, mid2)
	stale := t35PriorByID(t, block2, mid)
	if !validation.ObjAt(fresh, "policy_contingent").B {
		t.Error("fresh policy_contingent = false, want true")
	}
	if got := validation.ObjStr(fresh, "rejection_class"); got != "below-threshold" {
		t.Errorf("fresh rejection_class = %q", got)
	}
	if validation.ObjAt(fresh, "pin_diverged").B {
		t.Error("fresh pin_diverged = true, want false")
	}
	if validation.ObjAt(stale, "policy_contingent").B {
		t.Error("stale policy_contingent = true, want false")
	}
	if got := validation.ObjStr(stale, "rejection_class"); got != "invalid-hypothesis" {
		t.Errorf("stale rejection_class = %q", got)
	}
	if !validation.ObjAt(stale, "pin_diverged").B {
		t.Error("stale pin_diverged = false, want true")
	}
	if validation.ObjAt(block2, "authoritative").B {
		t.Error("authoritative = true, want false")
	}
}

// mustQueueMemory queues one negative-memory row.
func mustQueueMemory(t *testing.T, c *state.Campaign,
	o learning.QueueOpts) validation.Value {
	t.Helper()
	row, err := learning.QueueMemory(c, o)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// t35PriorByID finds one known_non_issues row.
func t35PriorByID(t *testing.T, block validation.Value,
	memoryID string) validation.Value {
	t.Helper()
	for _, p := range validation.ObjAt(block, "known_non_issues").A {
		if validation.ObjStr(p, "memory_id") == memoryID {
			return p
		}
	}
	t.Fatalf("prior %s missing from %s", memoryID,
		validation.CanonCompact(validation.ObjAt(block, "known_non_issues")))
	return validation.VNull()
}

// Port of tests/test_model_integration.py::test_trajectory_integrity_end_to_end.
func TestTrajectoryIntegrityEndToEnd(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	cls := "oracle-manipulation"
	bundle, err := roles.BuildProposerContext(c, &cls)
	if err != nil {
		t.Fatal(err)
	}
	promptStamp, err := PromptVersion(joinPath("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	req := validation.VObj(
		kv("role", validation.VStr("proposer")),
		kv("model_id", validation.VStr("qwen3-14b")),
		kv("prompt_version", validation.VStr(promptStamp)),
		kv("response_schema", validation.VStr("hypothesis")),
		kv("context_hash", validation.VStr(ContextHash(bundle))))

	// one rejected generation (a first-class event).
	bad := setKV(validHypothesis(), "bug_class", validation.VStr("Not-A-Class"))
	if _, err := IngestModelHypothesis(c, bad, HypothesisOpts{}); err == nil {
		t.Fatal("Not-A-Class must be rejected")
	}
	f, err := IngestModelHypothesis(c, validHypothesis(),
		HypothesisOpts{Request: req})
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	ev1(t, c, fid)
	if _, err := ApplyCriticVerdict(c, fid, validCriticVerdict(fid),
		""); err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Transition(c, fid, "POSSIBLE", "triage", "", "",
		false); err != nil {
		t.Fatal(err)
	}
	rreq := validReproducerRequest(fid)
	if _, err := SubmitReproducerRequest(c, rreq); err != nil {
		t.Fatal(err)
	}

	traj, err := trajectory.ModelTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	types := []string{}
	seqs := []int64{}
	byType := map[string][]validation.Value{}
	for _, e := range traj {
		types = append(types, validation.ObjStr(e, "type"))
		seqs = append(seqs, validation.ObjAt(e, "seq").I)
		byType[validation.ObjStr(e, "type")] = append(byType[validation.ObjStr(e, "type")], e)
	}
	want := "model.rejected,model.request,model.plan_received," +
		"model.reproducer_request"
	if joinStrings(types, ",") != want {
		t.Fatalf("trajectory types = %v, want %s", types, want)
	}
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1] {
			t.Errorf("seq order broken: %v", seqs)
		}
	}
	reqEv := byType["model.request"][0]
	if got := validation.ObjStr(validation.ObjAt(reqEv, "data"), "prompt_version"); got != promptStamp {
		t.Errorf("prompt_version = %q, want the prompt stamp %q", got,
			promptStamp)
	}
	if got := validation.ObjStr(validation.ObjAt(reqEv, "data"), "context_hash"); got !=
		ContextHash(bundle) {
		t.Errorf("context_hash = %q, want the bundle's hash", got)
	}
	rejEv := byType["model.rejected"][0]
	rejData := validation.ObjAt(rejEv, "data")
	if got := validation.ObjStr(rejData, "role"); got != "proposer" {
		t.Errorf("rejected role = %q", got)
	}
	if got := validation.ObjStr(rejData, "kind"); got != "hypothesis" {
		t.Errorf("rejected kind = %q", got)
	}
	if got := validation.ObjStr(rejData, "payload_sha256"); !regexpHex64.MatchString(got) {
		t.Errorf("payload_sha256 = %q, want 64 hex chars", got)
	}
	if got := validation.ObjStr(rejData, "action"); !containsString(got, "re-request") {
		t.Errorf("action = %q, want a re-request instruction", got)
	}
	rpEv := byType["model.reproducer_request"][0]
	if got := validation.ObjStr(validation.ObjAt(rpEv, "data"), "request_sha256"); got !=
		ContextHash(rreq) {
		t.Errorf("request_sha256 = %q, want the validated request's hash", got)
	}
	if got := validation.ObjStr(rpEv, "ref"); got != fid {
		t.Errorf("reproducer_request ref = %q, want %q", got, fid)
	}
	if got := validation.ObjStr(validation.ObjAt(rpEv, "data"), "min_evidence_level"); got != "E5" {
		t.Errorf("min_evidence_level = %q, want E5", got)
	}
	if got := validation.ObjStr(validation.ObjAt(rpEv, "data"), "execution_profile"); got !=
		"fork-runner" {
		t.Errorf("execution_profile = %q, want fork-runner", got)
	}
	report, err := trajectory.VerifyTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(report, "ok").Kind != validation.Bool || !validation.ObjAt(report, "ok").B {
		t.Errorf("verify_trajectory ok = %v", validation.ObjAt(report, "ok"))
	}
	if got := validation.ObjAt(report, "events").I; got != 4 {
		t.Errorf("events = %d, want 4", got)
	}
	if got := validation.ObjAt(report, "problems"); len(got.A) != 0 {
		t.Errorf("problems = %v", got)
	}
	if v, err := c.VerifyLog(); err != nil || !v.OK {
		t.Errorf("hash chain not ok: %v %v", v, err)
	}
}

// joinPath is filepath.Join without the import.
func joinPath(parts ...string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += "/"
		}
		out += p
	}
	return out
}

// regexpHex64 is ^[0-9a-f]{64}$.
var regexpHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Port of tests/test_model_integration.py::test_end_to_end_campaign_walkthrough.
func TestEndToEndCampaignWalkthrough(t *testing.T) {
	c := newCamp(t)
	pin(t, c)
	active, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		t.Fatal(err)
	}
	if active == nil || *active != snapID {
		t.Fatalf("active snapshot = %v, want %s", active, snapID)
	}
	cls := "oracle-manipulation"
	pb, found, err := playbooks.PlaybookForClass(cls)
	if err != nil || !found {
		t.Fatalf("playbook_for_class: found=%v err=%v", found, err)
	}
	if got := validation.ObjStr(pb, "bug_class"); got != cls {
		t.Errorf("playbook bug_class = %q", got)
	}
	if len(validation.ObjAt(pb, "assumption_templates").A) == 0 ||
		len(validation.ObjAt(pb, "hunt_order").A) == 0 {
		t.Error("playbook lacks assumption_templates / hunt_order")
	}
	pbundle, err := roles.BuildProposerContext(c, &cls)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(validation.ObjAt(pbundle, "playbook"), "bug_class"); got != cls {
		t.Errorf("bundle playbook bug_class = %q", got)
	}
	if validation.ObjAt(validation.ObjAt(pbundle, "negative_memory"), "authoritative").B {
		t.Error("negative_memory.authoritative = true, want false")
	}

	// boundary ingest: the request record is stamped from the built bundle.
	promptStamp, err := PromptVersion(joinPath("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	req := validation.VObj(
		kv("role", validation.VStr("proposer")),
		kv("model_id", validation.VStr("qwen3-14b")),
		kv("prompt_version", validation.VStr(promptStamp)),
		kv("response_schema", validation.VStr("hypothesis")),
		kv("context_hash", validation.VStr(ContextHash(pbundle))))
	f, err := IngestModelHypothesis(c, validHypothesis(),
		HypothesisOpts{Request: req})
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	if got := validation.ObjStr(f, "status"); got != "HYPOTHESIS" {
		t.Errorf("status = %q, want HYPOTHESIS", got)
	}
	for _, a := range validation.ObjAt(f, "assumptions").A {
		if got := validation.ObjStr(a, "status"); got != "UNKNOWN" {
			t.Errorf("assumption %s status = %q, want UNKNOWN",
				validation.ObjStr(a, "id"), got)
		}
	}
	if got := validation.ObjAt(f, "claim_version").I; got != 1 {
		t.Errorf("claim_version = %v, want 1", got)
	}

	// E1 evidence, then the critic bundle over the fresh claim.
	ev1(t, c, fid)
	cbundle, err := roles.BuildCriticContext(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	evIDs := []string{}
	for _, e := range validation.ObjAt(cbundle, "evidence").A {
		evIDs = append(evIDs, validation.ObjStr(e, "evidence_id"))
	}
	if joinStrings(evIDs, ",") != "EV-1" {
		t.Errorf("critic evidence = %v, want [EV-1]", evIDs)
	}
	for _, chk := range strList(validation.ObjAt(cbundle, "permitted_checks")) {
		if !containsStr(ToolRegistry(), chk) {
			t.Errorf("permitted check %q outside the registry", chk)
		}
	}

	// the critic verdict applies: A1 SUPPORTED, A2 REFUTED, disproved.
	f2, err := ApplyCriticVerdict(c, fid, validCriticVerdict(fid), "")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]validation.Value{}
	for _, a := range validation.ObjAt(f2, "assumptions").A {
		byID[validation.ObjStr(a, "id")] = a
	}
	if got := validation.ObjStr(byID["A1"], "status"); got != "SUPPORTED" {
		t.Errorf("A1 status = %q", got)
	}
	if got := validation.ObjStr(byID["A2"], "status"); got != "REFUTED" {
		t.Errorf("A2 status = %q", got)
	}
	if got := strList(validation.ObjAt(byID["A1"], "support")); joinStrings(got, ",") !=
		"EV-1" {
		t.Errorf("A1 support = %v, want [EV-1]", got)
	}
	if got := strList(validation.ObjAt(byID["A2"], "contradictions")); joinStrings(got, ",") != "EV-1" {
		t.Errorf("A2 contradictions = %v, want [EV-1]", got)
	}
	if got := validation.ObjStr(validation.ObjAt(f2, "verification"), "critic_verdict"); got != "disproved" {
		t.Errorf("verification.critic_verdict = %q", got)
	}

	// the disproved claim becomes queued negative memory (class derived).
	cwe := "CWE-20"
	mem, err := learning.QueueMemory(c, learning.QueueOpts{
		Kind:      "disproved",
		Status:    "DISPROVED",
		Pattern:   "TWAP oracle manipulation via flash-loan price push",
		FindingID: &fid,
		BugClass:  &cls,
		CWE:       &cwe,
		EvidenceSummary: "critic refuted profitability on the callgraph and " +
			"balance-delta evidence",
		DecidingPropositions: []validation.Value{validation.VObj(
			kv("type", validation.VStr("economic")),
			kv("statement", validation.VStr("the flash-loan round trip nets "+
				"below the premium at the pinned TVL, so the price push "+
				"cannot clear the payout threshold")))},
	})
	if err != nil {
		t.Fatal(err)
	}
	mid := validation.ObjStr(mem, "memory_id")
	if got := validation.ObjStr(mem, "promotion_status"); got != "pending" {
		t.Errorf("promotion_status = %q, want pending", got)
	}
	if got := validation.ObjStr(mem, "rejection_class"); got != "invalid-hypothesis" {
		t.Errorf("rejection_class = %q, want invalid-hypothesis", got)
	}
	if got := validation.ObjStr(mem, "finding_id"); got != fid {
		t.Errorf("finding_id = %q, want %q", got, fid)
	}
	if got := validation.ObjStr(mem, "snapshot_id"); got != snapID {
		t.Errorf("snapshot_id = %q, want %q", got, snapID)
	}

	// human approval is the only path to promotable.
	approved, err := learning.ApproveMemory(c, mid, "operator-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(approved, "promotion_status"); got != "human-approved" {
		t.Errorf("promotion_status = %q, want human-approved", got)
	}
	if got := validation.ObjStr(approved, "approved_by"); got != "operator-fixture" {
		t.Errorf("approved_by = %q", got)
	}
	cmds, err := learning.PromotionCommands(c, mid, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cmds) == 0 {
		t.Fatal("promotion surface is empty")
	}
	if got := validation.ObjStr(cmds[0], "substrate"); got != "shared-memory-store" {
		t.Errorf("substrate = %q", got)
	}
	if got := validation.ObjStr(cmds[0], "command"); !containsString(got,
		"webv2 publish "+c.CampaignID) {
		t.Errorf("command = %q", got)
	}

	// integrity at the end of the walkthrough.
	if v, err := c.VerifyLog(); err != nil || !v.OK {
		t.Errorf("hash chain not ok: %v %v", v, err)
	}
	report, err := trajectory.VerifyTrajectory(c)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(report, "ok").Kind != validation.Bool || !validation.ObjAt(report, "ok").B {
		t.Errorf("verify_trajectory ok = %v", validation.ObjAt(report, "ok"))
	}
	if got := validation.ObjAt(report, "problems"); len(got.A) != 0 {
		t.Errorf("problems = %v", got)
	}

	// no model-side state writer was bypassed: every assumption status
	// change is backed by a finding.assumption_transition log event.
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	transitions := []validation.Value{}
	for _, e := range events {
		if validation.ObjStr(e, "type") == "finding.assumption_transition" &&
			validation.ObjStr(e, "ref") == fid {
			transitions = append(transitions, e)
		}
	}
	if len(transitions) != 2 {
		t.Errorf("assumption_transition events = %d, want exactly 2",
			len(transitions))
	}
	for _, a := range validation.ObjAt(f2, "assumptions").A {
		backed := false
		for _, tr := range transitions {
			d := validation.ObjAt(tr, "data")
			if validation.ObjStr(d, "assumption") == validation.ObjStr(a, "id") &&
				validation.ObjStr(d, "to") == validation.ObjStr(a, "status") {
				backed = true
			}
		}
		if !backed {
			t.Errorf("assumption %s is %s with no assumption_transition event",
				validation.ObjStr(a, "id"), validation.ObjStr(a, "status"))
		}
	}
}

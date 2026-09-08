package findings

import (
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// ---- byte-exact gate vectors (generated from the Python twin) ----

// TestConfirmationGateDetailExactVector pins the ordered check ids, messages
// and remediations for a bare POSSIBLE finding: the six failures a first-time
// operator sees.
func TestConfirmationGateDetailExactVector(t *testing.T) {
	c := ingestCamp(t)
	got := pos(t, c)
	detail, err := ConfirmationGateDetail(c, got)
	if err != nil {
		t.Fatal(err)
	}
	want := []GateFailure{
		{"critic-verdict",
			"hostile critic verdict is None, need 'confirmed'",
			"webv2 verdict <fid> confirmed '<reasoning>' --actor <you>"},
		{"memory-check",
			"no verified graph-memory recall recorded — none recorded, or " +
				"every recorded check is stale (a referenced row changed or " +
				"left the store) — run `webv2 recall " + c.CampaignID +
				" --finding " + objStr(got, "finding_id") + "`",
			"webv2 recall <campaign> --finding <fid>   (records a " +
				"graph-memory consultation)"},
		{"reproduction-reproduced",
			"reproduction status is None, need 'reproduced'",
			"webv2 mint <fid> --exec <EXEC-ID>   (a reproduced attempt, sandboxed)"},
		{"evidence-floor",
			"evidence level E0 < required E5 for CONFIRMED",
			"webv2 mint <fid> --exec <EXEC-ID>   (or, for a NAMED " +
				"decision: webv2 floors set — an override, logged, never a " +
				"silent edit). Economic-class E7: when no USD figure is " +
				"defensible, record the decision instead — webv2 impact " +
				"<campaign> <fid> --unpriceable --ceiling '<capacity basis>' " +
				"--reason '<why>' --actor <you>"},
		{"evidence-floor-unreachable",
			"structurally unreachable in this campaign: no deployment/chain " +
				"pin on the active snapshot — fork evidence (E5+) has no fork " +
				"target, for single-call PoCs and multi-tx sequence PoCs " +
				"(`webv2 sequence run`) alike; pin one (`webv2 snap`) or " +
				"record a floor override (`webv2 floors set`); FORK_RPC_URL is " +
				"not set — the fork-runner profile cannot reach a chain — if " +
				"the target truly cannot produce that evidence, record the " +
				"decision with `webv2 floors set` instead of editing the " +
				"framework's floor table",
			"webv2 snap / export FORK_RPC_URL   (make the evidence reachable) " +
				"— or webv2 floors set to record the override as a decision"},
		{"reproduction-tier",
			"evidence floor E5 demands a fork-level reproduction (T3+), but " +
				"tier_reached is 'none' — record the fork-tier attempt " +
				"(record_attempt / attempt_and_mint) before confirming",
			"webv2 mint <campaign> <fid> --exec <fork exec> --description " +
				"'...' --tier T3   (record the fork-tier attempt the evidence " +
				"is based on)"},
	}
	if len(detail) != len(want) {
		t.Fatalf("failures = %d, want %d", len(detail), len(want))
	}
	for i, w := range want {
		if detail[i] != w {
			t.Errorf("failure %d =\n  %#v\nwant\n  %#v", i, detail[i], w)
		}
	}
	// Value() renders the Python dict in key order
	v := detail[0].Value()
	if got := strings.Join([]string{objStr(v, "check_id"), objStr(v, "message"),
		objStr(v, "remediation")}, "|"); got != want[0].CheckID+"|"+
		want[0].Message+"|"+want[0].Remediation {
		t.Fatalf("GateFailure.Value = %q", got)
	}
}

// TestReachabilityDiagnosticVectors pins the three structural messages.
func TestReachabilityDiagnosticVectors(t *testing.T) {
	c := ingestCamp(t)
	// below E5: nothing structural to say
	got, err := ReachabilityDiagnostic(c, "E4", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("E4 diagnostic = %v, want empty", got)
	}
	// E5 on a source-only pin: no fork target + no RPC
	got, err = ReachabilityDiagnostic(c, "E5", strPtr("precision-rounding"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("E5 diagnostic = %v, want 2 lines", got)
	}
	if !strings.HasPrefix(got[0], "no deployment/chain pin on the active "+
		"snapshot — fork evidence (E5+) has no fork target") {
		t.Errorf("diag[0] = %q", got[0])
	}
	if got[1] != "FORK_RPC_URL is not set — the fork-runner profile cannot "+
		"reach a chain" {
		t.Errorf("diag[1] = %q", got[1])
	}
	// E6, single-chain class: no cross-chain-witness demand
	got, err = ReachabilityDiagnostic(c, "E6", strPtr("share-price-inflation"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range got {
		if strings.Contains(line, "cross-chain witnesses") {
			t.Errorf("single-chain E6 class got a chain-pin demand: %q", line)
		}
	}
	// E6, cross-chain class: the chain pin is demanded
	got, err = ReachabilityDiagnostic(c, "E6", strPtr("bridge-message"))
	if err != nil {
		t.Fatal(err)
	}
	chainPin := false
	for _, line := range got {
		if line == "no chain pin on the active snapshot — cross-chain "+
			"witnesses (E6) need one" {
			chainPin = true
		}
	}
	if !chainPin {
		t.Fatalf("cross-chain class missing the chain-pin demand: %v", got)
	}
	// an unknown level is a ValueError, not a silent pass
	if _, err := ReachabilityDiagnostic(c, "E9", nil); err == nil {
		t.Error("unknown level must error")
	}
}

func strPtr(s string) *string { return &s }

// TestGateReproductionTierVector pins the T2 message.
func TestGateReproductionTierVector(t *testing.T) {
	c := ingestCamp(t)
	got := pos(t, c)
	fid := objStr(got, "finding_id")
	rec := testExec(t, c, "docker-networkless", fid, 0, "PASS: test_exploit\n")
	if _, err := AddEvidence(c, fid, execEvidenceItem(rec, "E5", "fork-test",
		"fork repro extracts value", "EV-2")); err != nil {
		t.Fatal(err)
	}
	vf, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := asDict(objAt(vf, "verification"))
	ver.O = setOrAppend(ver.O, "reproduction", validation.VObj(
		kv("tier_reached", validation.VStr("T2")),
		kv("status", validation.VStr("reproduced")),
		kv("attempts", validation.VArr()),
	))
	vf.O = setOrAppend(vf.O, "verification", ver)
	if err := SaveFinding(c, &vf); err != nil {
		t.Fatal(err)
	}
	detail, err := ConfirmationGateDetail(c, vf)
	if err != nil {
		t.Fatal(err)
	}
	want := "evidence floor E5 demands a fork-level reproduction (T3+), but " +
		"tier_reached is 'T2' — record the fork-tier attempt (record_attempt " +
		"/ attempt_and_mint) before confirming"
	found := false
	for _, f := range detail {
		if f.CheckID == "reproduction-tier" {
			found = true
			if f.Message != want {
				t.Fatalf("message = %q, want %q", f.Message, want)
			}
		}
	}
	if !found {
		t.Fatalf("reproduction-tier failure missing: %v", detail)
	}
}

// TestGateSequenceCoverageFailsClosed: a declared multi-tx sequence with no
// covering attempt blocks CONFIRMED.
func TestGateSequenceCoverageFailsClosed(t *testing.T) {
	c := ingestCamp(t)
	got := pos(t, c)
	fid := objStr(got, "finding_id")
	prevReq, prevVer := onchainSequenceRequiredFunc, verifySequenceCoverageFunc
	onchainSequenceRequiredFunc = func(*state.Campaign, validation.Value) bool {
		return true
	}
	verifySequenceCoverageFunc = func(*state.Campaign, validation.Value,
		validation.Value) (bool, []string) {
		return false, []string{"no assertions"}
	}
	defer func() {
		onchainSequenceRequiredFunc, verifySequenceCoverageFunc = prevReq, prevVer
	}()
	detail, err := ConfirmationGateDetail(c, got)
	if err != nil {
		t.Fatal(err)
	}
	want := "declared exploit_sequence needs a multi-tx PoC — no recorded " +
		"attempt traces to an exec with verified sequence coverage " +
		"(single-call PoCs cannot cover it)"
	found := false
	for _, f := range detail {
		if f.CheckID == "sequence-coverage" {
			found = true
			if f.Message != want {
				t.Fatalf("message = %q, want %q", f.Message, want)
			}
		}
	}
	if !found {
		t.Fatal("sequence-coverage failure missing")
	}
	// once an attempt traces to a covered exec, the check clears
	rec := testExec(t, c, "docker-networkless", fid, 0, "PASS\n")
	vf, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	ver := asDict(objAt(vf, "verification"))
	ver.O = setOrAppend(ver.O, "reproduction", validation.VObj(
		kv("status", validation.VStr("reproduced")),
		kv("attempts", validation.VArr(validation.VObj(
			kv("artifact_id", objAt(rec, "exec_id"))))),
	))
	vf.O = setOrAppend(vf.O, "verification", ver)
	verifySequenceCoverageFunc = func(*state.Campaign, validation.Value,
		validation.Value) (bool, []string) {
		return true, nil
	}
	detail, err = ConfirmationGateDetail(c, vf)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range detail {
		if f.CheckID == "sequence-coverage" {
			t.Fatal("a covered sequence must clear the check")
		}
	}
}

// TestGateShieldAdjudicationVector: a documented-as-intended invariant
// demands an explicit extraction adjudication.
func TestGateShieldAdjudicationVector(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(
		kv("invariant", validation.VObj(
			kv("id", validation.VStr("INV-005")),
			kv("statement", validation.VStr(
				"the exchange rate must not move for existing shares"))))),
		"code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	prev := intentClaimsFunc
	intentClaimsFunc = func(*state.Campaign) (map[string]validation.Value, error) {
		return map[string]validation.Value{"INV-5": validation.VObj(
			kv("intent_line", validation.VStr("INV-5: excess value transferred "+
				"to the vault is intended to accrue to existing stakers; this "+
				"is by design and documented.")),
		)}, nil
	}
	defer func() { intentClaimsFunc = prev }()
	detail, err := ConfirmationGateDetail(c, f)
	if err != nil {
		t.Fatal(err)
	}
	want := "invariant INV-005 is documented as intended (INV-5: excess value " +
		"transferred to the vault is intended to accrue to existing stakers; " +
		"this is by d) — record the extraction adjudication before CONFIRMED"
	found := false
	for _, g := range detail {
		if g.CheckID == "shield-adjudication" {
			found = true
			if g.Message != want {
				t.Fatalf("message = %q, want %q", g.Message, want)
			}
		}
	}
	if !found {
		t.Fatalf("shield-adjudication failure missing: %v", detail)
	}
	// recording the adjudication clears it
	if _, err := SetShieldAdjudication(c, objStr(f, "finding_id"), true,
		"the effect is extraction despite the documented intent", "operator"); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadFinding(c, objStr(f, "finding_id"))
	if err != nil {
		t.Fatal(err)
	}
	detail, err = ConfirmationGateDetail(c, reloaded)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range detail {
		if g.CheckID == "shield-adjudication" {
			t.Fatal("a recorded adjudication must clear the check")
		}
	}
}

// TestGateInvariantUnverifiedVectors: unknown ids and unverified registry
// entries block; documented sources are exempt.
func TestGateInvariantUnverifiedVectors(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, hypoPayload(
		kv("invariant", validation.VObj(
			kv("id", validation.VStr("INV-009")),
			kv("statement", validation.VStr(
				"the exchange rate must not move for existing shares"))))),
		"code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	prevLinks := loadInvariantLinksFunc
	loadInvariantLinksFunc = func(*state.Campaign) (validation.Value, error) {
		return validation.VObj(kv("invariants", validation.VObj())), nil
	}
	defer func() { loadInvariantLinksFunc = prevLinks }()
	detail, err := ConfirmationGateDetail(c, f)
	if err != nil {
		t.Fatal(err)
	}
	want := "invariant-unverified: INV-9 not in registry — seed it or correct the id"
	got := checksWithID(detail, "invariant-unverified")
	if len(got) != 1 || got[0].Message != want {
		t.Fatalf("unregistered invariant detail = %v", got)
	}
	// an unverified registry entry names its status
	loadInvariantLinksFunc = func(*state.Campaign) (validation.Value, error) {
		return validation.VObj(kv("invariants", validation.VObj(
			kv("INV-9", validation.VObj(
				kv("status", validation.VStr("UNVERIFIED")),
				kv("source", validation.VStr("model"))))))), nil
	}
	detail, err = ConfirmationGateDetail(c, f)
	if err != nil {
		t.Fatal(err)
	}
	want = "invariant INV-9 has status 'UNVERIFIED' — verify it against code " +
		"before CONFIRMED"
	got = checksWithID(detail, "invariant-unverified")
	if len(got) != 1 || got[0].Message != want {
		t.Fatalf("unverified invariant detail = %v", got)
	}
	// a documented source is exempt even when unverified
	loadInvariantLinksFunc = func(*state.Campaign) (validation.Value, error) {
		return validation.VObj(kv("invariants", validation.VObj(
			kv("INV-9", validation.VObj(
				kv("status", validation.VStr("UNVERIFIED")),
				kv("source", validation.VStr("documented"))))))), nil
	}
	detail, err = ConfirmationGateDetail(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if got := checksWithID(detail, "invariant-unverified"); len(got) != 0 {
		t.Fatalf("documented source must be exempt, got %v", got)
	}
	// a verified entry passes through the log-anchored verifier
	loadInvariantLinksFunc = func(*state.Campaign) (validation.Value, error) {
		return validation.VObj(kv("invariants", validation.VObj(
			kv("INV-9", validation.VObj(
				kv("status", validation.VStr("CHECKED_AGAINST_CODE")),
				kv("source", validation.VStr("model"))))))), nil
	}
	prevVerified := invariantVerifiedFunc
	invariantVerifiedFunc = func(validation.Value, *state.Campaign, string,
		[]validation.Value) bool {
		return true
	}
	defer func() { invariantVerifiedFunc = prevVerified }()
	detail, err = ConfirmationGateDetail(c, f)
	if err != nil {
		t.Fatal(err)
	}
	if got := checksWithID(detail, "invariant-unverified"); len(got) != 0 {
		t.Fatalf("verified invariant must pass, got %v", got)
	}
}

// checksWithID is the gate failures carrying one check id.
func checksWithID(detail []GateFailure, id string) []GateFailure {
	var out []GateFailure
	for _, f := range detail {
		if f.CheckID == id {
			out = append(out, f)
		}
	}
	return out
}

// TestGateClaimDriftWiring: the claim-vs-measurement check rides the gate.
func TestGateClaimDriftWiring(t *testing.T) {
	c := ingestCamp(t)
	payload := hypoPayload(
		kv("title", validation.VStr("Drain 90% of the vault")),
		kv("economic_impact", validation.VObj(
			kv("extraction_ratio", validation.VFloat(0.5)))))
	f, err := IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	detail, err := ConfirmationGateDetail(c, f)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range detail {
		if g.CheckID == "claim-drift" {
			found = true
			if !strings.Contains(g.Message, "claim says 90% extraction") {
				t.Errorf("claim-drift message = %q", g.Message)
			}
		}
	}
	if !found {
		t.Fatalf("claim-drift failure missing: %v", detail)
	}
}

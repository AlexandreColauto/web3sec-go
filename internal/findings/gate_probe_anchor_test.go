package findings

// gate_probe_anchor_test.go: the B10(a) regression suite. The rule is one
// checker (ProbeAnchorBlindSpots) consumed by BOTH the dry run and the
// enforcing CONFIRMED transition, so the tests below drive the clause set (the
// dry run's source) and the transition (the enforcement) and assert they agree.
//
// The presence gate is the byte-discipline pin: a campaign that lacks the
// protocol model, the probe surface or the campaign plan gets EXACTLY the
// clause set it had before this check existed — asserted as canonical JSON of
// the whole clause list, per missing artifact, including a model anchorlink
// rejects.
//
// Fixtures are written as raw artifact JSON (os.WriteFile), not as constructed
// values: the check reads the ARTIFACTS, so the fixture has to be the artifact
// shape an operator's campaign really carries.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// probeAnchorRowID is the firing fixture's tier-0 row (the §5 replay's G-01
// row id, so a failure message reads like the campaign it was designed on).
const probeAnchorRowID = "34589e8588"

// probeAnchorModel is the protocol model: Rollup on its snapshot path, plus an
// ambiguous NAME (L1ERC20Gateway on two paths) so the collision rule is
// exercised rather than assumed.
const probeAnchorModel = `{
  "contracts": [
    {"name": "Rollup", "path": "l1/rollup/Rollup.sol"},
    {"name": "Vault", "path": "src/Vault.sol"},
    {"name": "L1ERC20Gateway", "path": "l1/gateways/L1ERC20Gateway.sol"},
    {"name": "L1ERC20Gateway", "path": "l2/gateways/L1ERC20Gateway.sol"}
  ],
  "state_machines": []
}
`

// probeAnchorSurfaceFiring is the surface: one tier-0 row citing Rollup's
// commitBatch/finalizeBatch pair — the row shape the §5 replay found the gold
// finding sitting on.
const probeAnchorSurfaceFiring = `{
  "rows": [
    {"row_id": "34589e8588", "axis": "enforcement-timing",
     "contract": "Rollup", "consumer": "commitBatch", "consumer_line": 204,
     "asserter": "finalizeBatch", "asserter_line": 496,
     "tier": 0, "assertion_gap": 0}
  ]
}
`

// probeAnchorPlanOpen is a plan that claims the row with an OPEN priority —
// the "emitted but never answered" case.
const probeAnchorPlanOpen = `{
  "priorities": [
    {"id": "Q-008", "question": "is commitBatch's guard real?",
     "status": "open", "probe": {"row_id": "34589e8588", "probe_id": "p"}}
  ]
}
`

// probeAnchorPlanEmpty is a plan that never emitted the row at all (the morph
// handoff's common case: 40 rows, 0 dispositioned).
const probeAnchorPlanEmpty = `{"priorities": []}
`

// probeAnchorAffected is the repo-prefixed spelling the morph findings carry,
// which the model path has to absorb by the suffix rule.
const probeAnchorAffected = "contracts/l1/rollup/Rollup.sol"

// probeAnchorFinding ingests the finding whose affected[] names the anchor.
func probeAnchorFinding(t *testing.T, c *state.Campaign,
	affected string) validation.Value {
	t.Helper()
	payload := hypoPayload(kv("affected", validation.VArr(validation.VObj(
		kv("path", validation.VStr(affected)),
		kv("function", validation.VStr("commitBatch")),
		kv("lines", validation.VArr(validation.VInt(204))),
	))))
	f, err := IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// probeAnchorCampaign is a fresh campaign carrying the finding and the three
// artifacts the check is gated on.
func probeAnchorCampaign(t *testing.T, surface, plan string) (*state.Campaign,
	validation.Value) {
	t.Helper()
	c := ingestCamp(t)
	f := probeAnchorFinding(t, c, probeAnchorAffected)
	writeGateArtifact(t, c, "protocol_model.json", probeAnchorModel)
	writeGateArtifact(t, c, "probe_surface.json", surface)
	writeGateArtifact(t, c, "campaign_plan.json", plan)
	return c, f
}

// writeGateArtifact writes one raw artifact body into the campaign's artifacts
// directory.
func writeGateArtifact(t *testing.T, c *state.Campaign, name, body string) {
	t.Helper()
	path := filepath.Join(c.ArtifactsDir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// dropGateArtifact removes one artifact.
func dropGateArtifact(t *testing.T, c *state.Campaign, name string) {
	t.Helper()
	if err := os.Remove(filepath.Join(c.ArtifactsDir, name)); err != nil {
		t.Fatal(err)
	}
}

// clauseSetJSON is the WHOLE clause list as canonical JSON — the bytes the
// dry run renders and the transition reads. Comparing this is what makes the
// presence-gate pin byte-level rather than count-level.
func clauseSetJSON(t *testing.T, c *state.Campaign, f validation.Value) string {
	t.Helper()
	clauses, err := ConfirmationGateClauses(c, f)
	if err != nil {
		t.Fatal(err)
	}
	vals := make([]validation.Value, 0, len(clauses))
	for _, cl := range clauses {
		vals = append(vals, cl.Value())
	}
	return validation.CanonCompact(validation.VArr(vals...))
}

// probeAnchorClauseIDs is every clause id, in gate order.
func probeAnchorClauseIDs(t *testing.T, c *state.Campaign,
	f validation.Value) []string {
	t.Helper()
	clauses, err := ConfirmationGateClauses(c, f)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(clauses))
	for _, cl := range clauses {
		out = append(out, cl.ID())
	}
	return out
}

// TestProbeAnchorAbsentArtifactsLeavesClauseSetIdentical is the presence-gate
// pin: no model, no surface or no plan — and a model anchorlink refuses — each
// leave the clause set byte-identical, while all three present add EXACTLY one
// clause, qualified by the row id.
func TestProbeAnchorAbsentArtifactsLeavesClauseSetIdentical(t *testing.T) {
	c := ingestCamp(t)
	f := probeAnchorFinding(t, c, probeAnchorAffected)
	base := clauseSetJSON(t, c, f)
	if strings.Contains(base, ProbeAnchorCheckID) {
		t.Fatalf("baseline already carries %s: %s", ProbeAnchorCheckID, base)
	}
	if got, ran := ProbeAnchorBlindSpots(c, f); ran || got != nil {
		t.Fatalf("no artifacts must skip the check, got %v ran=%v", got, ran)
	}

	// All three present and firing: exactly one new clause, subject = row id.
	writeGateArtifact(t, c, "protocol_model.json", probeAnchorModel)
	writeGateArtifact(t, c, "probe_surface.json", probeAnchorSurfaceFiring)
	writeGateArtifact(t, c, "campaign_plan.json", probeAnchorPlanOpen)
	fired := clauseSetJSON(t, c, f)
	if fired == base {
		t.Fatal("a tier-0 undispositioned row citing the finding's own " +
			"anchor must add a clause")
	}
	ids := probeAnchorClauseIDs(t, c, f)
	want := ProbeAnchorCheckID + "[" + probeAnchorRowID + "]"
	seen := 0
	for _, id := range ids {
		if id == want {
			seen++
		}
	}
	if seen != 1 {
		t.Fatalf("clause ids = %v, want exactly one %s", ids, want)
	}
	baseCount := len(probeAnchorClauseIDs(t, c, f)) - 1
	// Every missing artifact takes the clause set straight back to the
	// baseline bytes — one artifact at a time.
	for _, missing := range []string{"protocol_model.json",
		"probe_surface.json", "campaign_plan.json"} {
		body, err := os.ReadFile(filepath.Join(c.ArtifactsDir, missing))
		if err != nil {
			t.Fatal(err)
		}
		dropGateArtifact(t, c, missing)
		if got := clauseSetJSON(t, c, f); got != base {
			t.Errorf("without %s the clause set moved:\n got %s\nwant %s",
				missing, got, base)
		}
		writeGateArtifact(t, c, missing, string(body))
	}
	if got := len(probeAnchorClauseIDs(t, c, f)); got != baseCount+1 {
		t.Fatalf("restored clause count = %d, want %d", got, baseCount+1)
	}

	// A model anchorlink.Open rejects (not an object) skips the check too.
	writeGateArtifact(t, c, "protocol_model.json", `[]`)
	if got := clauseSetJSON(t, c, f); got != base {
		t.Errorf("an unindexable model must skip the check:\n got %s\nwant %s",
			got, base)
	}
	if _, ran := ProbeAnchorBlindSpots(c, f); ran {
		t.Error("anchorlink.Open must have refused the model")
	}
}

// probeAnchorSurface is a one-row surface with the given row body (the fields
// row_id/tier/assertion_gap are appended by the caller).
func probeAnchorSurface(rowID, rowBody string) string {
	return `{"rows": [{"row_id": "` + rowID + `", ` + rowBody + `}]}`
}

// probeAnchorPlanStatus is a one-priority plan claiming rowID at status.
func probeAnchorPlanStatus(rowID, status string) string {
	return `{"priorities": [{"id": "Q-008", "status": "` + status +
		`", "probe": {"row_id": "` + rowID + `", "probe_id": "p"}}]}`
}

// rollupRow is the firing coordinate: Rollup's commitBatch/finalizeBatch pair.
const rollupRow = `"contract": "Rollup", "consumer": "commitBatch", ` +
	`"consumer_line": 204, "asserter": "finalizeBatch", "asserter_line": 496`

// TestProbeAnchorFiringRules is the rule table: which rows the check bites on,
// and — just as load-bearing — which it leaves alone.
func TestProbeAnchorFiringRules(t *testing.T) {
	for _, tc := range []struct {
		name     string
		surface  string
		plan     string
		affected string
		want     []string
	}{
		{"tier0 row no priority claims it", probeAnchorSurfaceFiring,
			probeAnchorPlanEmpty, probeAnchorAffected, []string{probeAnchorRowID}},
		{"gap3 row on an open priority",
			probeAnchorSurface("gap3", rollupRow+`, "tier": 2, "assertion_gap": 3`),
			probeAnchorPlanStatus("gap3", "open"), probeAnchorAffected,
			[]string{"gap3"}},
		{"tier5 gap10 is still high-risk",
			probeAnchorSurface("gap10", rollupRow+`, "tier": 5, "assertion_gap": 10`),
			probeAnchorPlanEmpty, probeAnchorAffected, []string{"gap10"}},
		{"blocked is not a disposition",
			probeAnchorSurfaceFiring,
			probeAnchorPlanStatus(probeAnchorRowID, "blocked"), probeAnchorAffected,
			[]string{probeAnchorRowID}},
		{"missing tier reads as tier 0 (caution)",
			probeAnchorSurface("notier", rollupRow),
			probeAnchorPlanEmpty, probeAnchorAffected, []string{"notier"}},
		{"low-risk row is left alone",
			probeAnchorSurface("low", rollupRow+`, "tier": 1, "assertion_gap": 2`),
			probeAnchorPlanEmpty, probeAnchorAffected, nil},
		{"answered row is discharged",
			probeAnchorSurfaceFiring,
			probeAnchorPlanStatus(probeAnchorRowID, "answered"), probeAnchorAffected,
			nil},
		{"deprioritized row is discharged",
			probeAnchorSurfaceFiring,
			probeAnchorPlanStatus(probeAnchorRowID, "deprioritized"),
			probeAnchorAffected, nil},
		{"not-applicable row is discharged",
			probeAnchorSurfaceFiring,
			probeAnchorPlanStatus(probeAnchorRowID, "not-applicable"),
			probeAnchorAffected, nil},
		{"row citing another anchor is left alone",
			probeAnchorSurface("other", `"contract": "Vault", `+
				`"consumer": "withdraw", "consumer_line": 10, "tier": 0`),
			probeAnchorPlanEmpty, probeAnchorAffected, nil},
		{"a sibling citation reaches the anchor",
			probeAnchorSurface("sib", `"contract": "Vault", `+
				`"consumer": "withdraw", "consumer_line": 10, "tier": 0, `+
				`"siblings": [{"contract": "Rollup", "line": 210}]`),
			probeAnchorPlanEmpty, probeAnchorAffected, []string{"sib"}},
		{"unknown contract name resolves to nothing",
			probeAnchorSurface("ghost", `"contract": "NotAContract", `+
				`"consumer": "f", "consumer_line": 1, "tier": 0`),
			probeAnchorPlanEmpty, probeAnchorAffected, nil},
		{"ambiguous name reaches the pinned path",
			probeAnchorSurface("gw", `"contract": "L1ERC20Gateway", `+
				`"consumer": "onDropMessage", "consumer_line": 74, "tier": 0`),
			probeAnchorPlanEmpty, "contracts/l1/gateways/L1ERC20Gateway.sol",
			[]string{"gw"}},
		{"finding anchor unknown to the model", probeAnchorSurfaceFiring,
			probeAnchorPlanEmpty, "elsewhere/Unknown.sol", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, f := probeAnchorCampaign(t, tc.surface, tc.plan)
			if tc.affected != probeAnchorAffected {
				f = probeAnchorFinding(t, c, tc.affected)
			}
			spots, ran := ProbeAnchorBlindSpots(c, f)
			if !ran {
				t.Fatal("artifacts are present: the check must RUN")
			}
			got := make([]string, 0, len(spots))
			for _, s := range spots {
				got = append(got, s.RowID)
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("spots = %v, want %v", got, tc.want)
			}
			// The clause set agrees with the checker: one FAILING clause per
			// spot, and a satisfied clause when there is nothing to answer.
			failing, satisfied := probeAnchorClauseCounts(t, c, f)
			if failing != len(tc.want) {
				t.Fatalf("clause ids = %v, want %d failing %s clause(s)",
					probeAnchorClauseIDs(t, c, f), len(tc.want),
					ProbeAnchorCheckID)
			}
			if len(tc.want) == 0 && !satisfied {
				t.Fatalf("no spots must leave a SATISFIED clause, not a skip: %v",
					probeAnchorClauseIDs(t, c, f))
			}
		})
	}
}

// probeAnchorClauseCounts is the check's own clause verdicts: how many are
// failing, and whether the satisfied one is present.
func probeAnchorClauseCounts(t *testing.T, c *state.Campaign,
	f validation.Value) (int, bool) {
	t.Helper()
	clauses, err := ConfirmationGateClauses(c, f)
	if err != nil {
		t.Fatal(err)
	}
	failing, satisfied := 0, false
	for _, cl := range clauses {
		if cl.CheckID != ProbeAnchorCheckID {
			continue
		}
		if cl.OK {
			satisfied = true
		} else {
			failing++
		}
	}
	return failing, satisfied
}

// TestProbeAnchorSpotNamesItsRowAndHeal pins the spot's own record: the
// anchor path, the row's coordinates, and the priority the heal must name.
func TestProbeAnchorSpotNamesItsRowAndHeal(t *testing.T) {
	c, f := probeAnchorCampaign(t, probeAnchorSurfaceFiring,
		probeAnchorPlanOpen)
	spots, ran := ProbeAnchorBlindSpots(c, f)
	if !ran || len(spots) != 1 {
		t.Fatalf("spots = %v ran=%v", spots, ran)
	}
	s := spots[0]
	if s.RowID != probeAnchorRowID || s.Path != "l1/rollup/Rollup.sol" ||
		s.Tier != 0 || s.AssertionGap != 0 || s.PriorityID != "Q-008" ||
		s.Disposition != "open" {
		t.Fatalf("spot = %+v", s)
	}
	want := "webv2 answered " + c.CampaignID + " Q-008 answered --reason " +
		"'<why row " + probeAnchorRowID + " is safe — cite the row's own " +
		"code>' --anchor <field>"
	if got := s.Heal(c.CampaignID); got != want {
		t.Fatalf("heal =\n %q\nwant %q", got, want)
	}
	if !strings.Contains(s.Message(), probeAnchorRowID) ||
		!strings.Contains(s.Message(), "l1/rollup/Rollup.sol") ||
		!strings.Contains(s.Message(), "tier 0") {
		t.Fatalf("message = %q", s.Message())
	}
	// The clause carries exactly that message and heal, subject = row id.
	clauses, err := ConfirmationGateClauses(c, f)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, cl := range clauses {
		if cl.CheckID != ProbeAnchorCheckID {
			continue
		}
		found = true
		if cl.OK || cl.ID() != ProbeAnchorCheckID+"["+probeAnchorRowID+"]" {
			t.Fatalf("clause = %+v (id %s)", cl, cl.ID())
		}
		if cl.Message != s.Message() || cl.Remediation != s.Heal(c.CampaignID) {
			t.Fatalf("clause message/remediation = %q / %q", cl.Message,
				cl.Remediation)
		}
	}
	if !found {
		t.Fatal("no clause emitted")
	}
}

// TestProbeAnchorHealMintsThePriorityWhenNoneClaimsTheRow: a row no priority
// claims has no Q-* id to answer, so the heal has to start with the emit.
func TestProbeAnchorHealMintsThePriorityWhenNoneClaimsTheRow(t *testing.T) {
	c, f := probeAnchorCampaign(t, probeAnchorSurfaceFiring,
		probeAnchorPlanEmpty)
	spots, ran := ProbeAnchorBlindSpots(c, f)
	if !ran || len(spots) != 1 {
		t.Fatalf("spots = %v ran=%v", spots, ran)
	}
	s := spots[0]
	if s.PriorityID != "" || s.Disposition != "undispositioned" {
		t.Fatalf("spot = %+v", s)
	}
	heal := s.Heal(c.CampaignID)
	if !strings.HasPrefix(heal, "webv2 probes "+c.CampaignID+" run --emit") {
		t.Fatalf("heal = %q", heal)
	}
	if !strings.Contains(heal, "webv2 answered "+c.CampaignID+" <Q-id> answered") {
		t.Fatalf("heal = %q", heal)
	}
}

// TestProbeAnchorRefusesConfirmedMoveFromTheSameChecker is the enforcement
// half: the CONFIRMED transition reads the same clause set the dry run prints,
// so the refusal names the subject-qualified check id and records it for the
// next delta — and with the artifacts absent, the refusal does NOT.
func TestProbeAnchorRefusesConfirmedMoveFromTheSameChecker(t *testing.T) {
	for _, tc := range []struct {
		name      string
		artifacts bool
		wantID    string
	}{
		{"artifacts present", true,
			ProbeAnchorCheckID + "[" + probeAnchorRowID + "]"},
		{"artifacts absent", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ingestCamp(t)
			f := probeAnchorFinding(t, c, probeAnchorAffected)
			fid := validation.ObjStr(f, "finding_id")
			if tc.artifacts {
				writeGateArtifact(t, c, "protocol_model.json", probeAnchorModel)
				writeGateArtifact(t, c, "probe_surface.json",
					probeAnchorSurfaceFiring)
				writeGateArtifact(t, c, "campaign_plan.json",
					probeAnchorPlanEmpty)
			}
			if _, err := Transition(c, fid, "POSSIBLE", "advance to the "+
				"confirmation rung", "operator", "", false); err != nil {
				t.Fatalf("move POSSIBLE: %v", err)
			}
			_, err := Transition(c, fid, "CONFIRMED", "gate attempt",
				"operator", "", false)
			if err == nil {
				t.Fatal("CONFIRMED must be refused while the row is open")
			}
			if !strings.Contains(err.Error(), "CONFIRMED gate failed") {
				t.Fatalf("refusal = %q", err.Error())
			}
			ids := recordedGateAttemptIDs(t, c, fid)
			has := false
			for _, id := range ids {
				if id == ProbeAnchorCheckID ||
					strings.HasPrefix(id, ProbeAnchorCheckID+"[") {
					has = true
				}
			}
			if tc.wantID == "" {
				if has {
					t.Fatalf("no artifacts: the check must not fire, ids = %v",
						ids)
				}
				return
			}
			if !has {
				t.Fatalf("recorded check ids = %v, want %s", ids, tc.wantID)
			}
			// The transition's own message is "<check_id>: <message>" (the
			// shape every check uses), so the row is named by the MESSAGE and
			// the subject rides the recorded id the delta renders.
			if !strings.Contains(err.Error(), ProbeAnchorCheckID+": ") ||
				!strings.Contains(err.Error(), probeAnchorRowID) {
				t.Fatalf("refusal %q must name %s and its row", err.Error(),
					ProbeAnchorCheckID)
			}
		})
	}
}

// recordedGateAttemptIDs is the check_ids of the latest recorded refusal for
// findingID (the same projection `gate --dry-run` renders as its delta).
func recordedGateAttemptIDs(t *testing.T, c *state.Campaign,
	fid string) []string {
	t.Helper()
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if validation.ObjStr(e, "type") != "finding.gate_attempt" ||
			validation.ObjStr(e, "ref") != fid {
			continue
		}
		out := []string{}
		for _, x := range validation.ObjAt(asDict(validation.ObjAt(e, "data")),
			"check_ids").A {
			if x.Kind == validation.Str {
				out = append(out, x.S)
			}
		}
		return out
	}
	t.Fatalf("no finding.gate_attempt recorded for %s", fid)
	return nil
}

// promote_close_test.go: morph pass-1 review §6.4 / §7.4 — the
// promote-before-close obligation at the discovery exit. The pass closed with
// a critic-confirmed POSSIBLE candidate at rank #8 while ninety queue rounds
// of mechanical work ran: draining the queue is not the same as promoting the
// candidate the sheet ranks highest. The discovery proof now demands, for the
// top-K critic-confirmed POSSIBLE findings, either a recorded exec-backed
// reproduction attempt or a WRITTEN deprioritization (the stage's own
// "promote-before-close" waiver row).
package completion

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// promotedCandidate writes one stored POSSIBLE finding with the critic's
// confirmation — the shape the arm fires on.
func promotedCandidate(t *testing.T, c *state.Campaign, fid, band,
	createdAt string) {
	t.Helper()
	f := validation.VObj(
		kv("finding_id", validation.VStr(fid)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("status", validation.VStr("POSSIBLE")),
		kv("created_at", validation.VStr(createdAt)),
		kv("updated_at", validation.VStr(createdAt)),
		kv("title", validation.VStr("the top-sheet candidate nobody executed")),
		kv("verification", validation.VObj(
			kv("critic_verdict", validation.VStr("confirmed")))),
	)
	if band != "" {
		f.O = validation.SetOrAppend(f.O, "risk", validation.VObj(
			kv("validated", validation.VObj(kv("band", validation.VStr(band))))))
	}
	if err := validation.WriteJson(findings.FindingPath(c, fid), f, ""); err != nil {
		t.Fatal(err)
	}
}

// promotedFixture is the queue-drained, divergence-closed campaign the
// promotion demand rides on (the t35 baseline the adversarial-game arm uses):
// nothing else blocks the discovery proof, so a refusal can only be the new
// arm.
func promotedFixture(t *testing.T) *state.Campaign {
	t.Helper()
	c := t35LensCampaign(t)
	t35PlanClosedExcept(t, c, "")
	if res := t35DiscoveryProof(t, c); !isDone(t, res) {
		t.Fatalf("baseline discovery proof must be done: %s",
			validation.CanonCompact(res))
	}
	promotedCandidate(t, c, "F-0000000000bb", "", "2026-01-02T03:00:00+00:00")
	return c
}

// missingContains is `any missing[] entry contains needle`.
func missingContains(res validation.Value, needle string) bool {
	miss, ok := fieldAt(res, "missing")
	if !ok || miss.Kind != validation.Arr {
		return false
	}
	for _, m := range miss.A {
		if strings.Contains(m.S, needle) {
			return true
		}
	}
	return false
}

// missingSubjects lists, in order, the subject prefix of every missing[]
// entry (the text before the first ": ").
func missingSubjects(t *testing.T, res validation.Value) []string {
	t.Helper()
	out := []string{}
	for _, m := range missingOf(t, res) {
		if i := strings.Index(m, ": "); i >= 0 {
			out = append(out, m[:i])
		}
	}
	return out
}

// TestDiscoveryRefusesUnpromotedTopCandidate: morph pass-1 review §6.4 — the
// G-01 candidate sat at #8, critic-confirmed, unexecuted, while the queue
// drained for 90 rounds. Before discovery closes, the top-5 critic-confirmed
// POSSIBLE findings each owe a recorded repro attempt — or a written
// deprioritization (a waiver names actor+reason).
func TestDiscoveryRefusesUnpromotedTopCandidate(t *testing.T) {
	c := promotedFixture(t)
	// state.go already holds a POSSIBLE, critic-confirmed finding with no
	// verification.reproduction.attempts and no evidence item whose
	// exec_ref is non-empty.
	res, err := ProofStatus(c, "discovery")
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjAt(res, "done").B {
		t.Fatalf("discovery closed over an unpromoted candidate: %v", res)
	}
	if !missingContains(res, "promote-before-close") {
		t.Fatalf("missing[] has no promote arm: %v", res)
	}
	// The waiver is the WRITTEN deprioritization — one subject row clears it.
	if _, err := Waive(c, "promote-before-close", "F-0000000000bb",
		"impact ceiling below the program floor; documented in report", "op"); err != nil {
		t.Fatal(err)
	}
	res, _ = ProofStatus(c, "discovery")
	if !validation.ObjAt(res, "done").B {
		t.Fatalf("waived candidate still blocks: %v", res)
	}
}

// TestDiscoveryPromotionAcceptsExecBackedCandidate: the promotion exits are
// the SAME arms proofReproduction honors, widened with one exec-backed
// evidence item (a fresh exec IS the promotion) — a candidate carrying any of
// them must not block, and the demand must not double-fire on a second
// evaluation.
func TestDiscoveryPromotionAcceptsExecBackedCandidate(t *testing.T) {
	c := promotedFixture(t)
	if isDone(t, t35DiscoveryProof(t, c)) {
		t.Fatal("precondition: the unpromoted candidate must block")
	}
	f, err := findings.LoadFinding(c, "F-0000000000bb")
	if err != nil {
		t.Fatal(err)
	}
	f.O = validation.SetOrAppend(f.O, "evidence", validation.VArr(validation.VObj(
		kv("artifact_id", validation.VStr("EXEC-0000000001")),
		kv("exec_ref", validation.VStr("EXEC-0000000001")))))
	if err := validation.WriteJson(findings.FindingPath(c, "F-0000000000bb"),
		f, ""); err != nil {
		t.Fatal(err)
	}
	res := t35DiscoveryProof(t, c)
	if !isDone(t, res) || missingContains(res, "F-0000000000bb") {
		t.Fatalf("an exec-backed candidate must not block: %s",
			validation.CanonCompact(res))
	}
	again := t35DiscoveryProof(t, c)
	if got, want := validation.CanonCompact(again),
		validation.CanonCompact(res); got != want {
		t.Errorf("second evaluation differs (double fire?)\n got %s\nwant %s",
			want, got)
	}
}

// TestDiscoveryPromotionAcceptsRecordedAttempt: a recorded attempt — even a
// FAILED one, the attempt is the work — promotes the candidate too.
func TestDiscoveryPromotionAcceptsRecordedAttempt(t *testing.T) {
	c := promotedFixture(t)
	f, err := findings.LoadFinding(c, "F-0000000000bb")
	if err != nil {
		t.Fatal(err)
	}
	f.O = validation.SetOrAppend(f.O, "verification", validation.VObj(
		kv("critic_verdict", validation.VStr("confirmed")),
		kv("reproduction", validation.VObj(
			kv("attempts", validation.VArr(validation.VObj(
				kv("outcome", validation.VStr("failed")),
				kv("note", validation.VStr("harness could not reach the state")))))))))
	if err := validation.WriteJson(findings.FindingPath(c, "F-0000000000bb"),
		f, ""); err != nil {
		t.Fatal(err)
	}
	res := t35DiscoveryProof(t, c)
	if !isDone(t, res) {
		t.Fatalf("a recorded attempt must not block: %s",
			validation.CanonCompact(res))
	}
}

// TestPromotionRanksBandThenNewestThenIDAndCapsAtFive pins the ranking key the
// arm uses — risk.validated.band descending, created_at descending, then
// finding_id ascending — and the top-5 window: the informational candidate is
// the one that falls off the sheet.
func TestPromotionRanksBandThenNewestThenIDAndCapsAtFive(t *testing.T) {
	c := t35LensCampaign(t)
	t35PlanClosedExcept(t, c, "")
	promotedCandidate(t, c, "F-0000000000a1", "low", "2026-01-02T03:00:01+00:00")
	promotedCandidate(t, c, "F-0000000000a2", "critical", "2026-01-02T03:00:00+00:00")
	promotedCandidate(t, c, "F-0000000000a3", "critical", "2026-01-02T03:00:02+00:00")
	promotedCandidate(t, c, "F-0000000000a4", "medium", "2026-01-02T03:00:05+00:00")
	promotedCandidate(t, c, "F-0000000000a5", "high", "2026-01-02T03:00:03+00:00")
	promotedCandidate(t, c, "F-0000000000a6", "informational", "2026-01-02T03:00:04+00:00")
	res := t35DiscoveryProof(t, c)
	want := []string{"F-0000000000a3", "F-0000000000a2", "F-0000000000a5",
		"F-0000000000a4", "F-0000000000a1"}
	if got := missingSubjects(t, res); len(got) != len(want) {
		t.Fatalf("promotion subjects = %v, want %v", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("promotion order = %v, want %v", got, want)
			}
		}
	}
	if missingContains(res, "F-0000000000a6") {
		t.Errorf("the informational candidate is below the top-5 window: %v",
			missingOf(t, res))
	}
}

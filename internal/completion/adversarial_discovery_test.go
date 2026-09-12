// adversarial_discovery_test.go: FIX-7 — the adversarial-game clause is
// enforced at the discovery exit. The runbook says the clause is "required
// of a live liveness finding" and "the check fails without it", yet a
// campaign whose findings claimed economic_impact.kind == "liveness" sailed
// through discovery with no clause and no complaint: the discovery
// completion proof (the gate that closes the divergence era) now refuses to
// report done until every live liveness finding carries the recorded
// adversarial_game clause. Trigger is findings.IsLivenessFinding — the same
// shared predicate the bounty-gate check15 fires on (class in
// LivenessClasses, or economic_impact.kind == "liveness", or a granted
// liveness-terminal capability), so a chain-freeze-class finding with no
// economic_impact object is caught too. Waiver stage is the clause's own
// "adversarial-game", so one recorded decision covers every gate.
package completion

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// The three clause answers, each well past the 20-rune floor (the same
// incentive argument the bounty-gate matrix uses).
const (
	f7Who   = "the sequencer operator — every frozen hour pays their uptime fees while rival bridges lose the deposits in transit"
	f7Mech  = "freezing withdrawals lets the operator's own staked position absorb the fee flow while the halted bridge bleeds TVL to competitors"
	f7Inter = "the timelock challenge path expires into a no-op once the upgrade queue is blocked, so the freeze cannot be voted away before the challenge window closes"
)

// f7Payload is the discovery-slot ingestBare shape: a schema-valid
// hypothesis, with `over` applied on top.
func f7Payload(over ...validation.KV) validation.Value {
	base := validation.VObj(
		kv("title", validation.VStr(
			"Withdrawals can be frozen indefinitely by blocking finalize")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("logic-error")),
			kv("description", validation.VStr(
				"the challenge window closes without a finalize path")),
		)),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/Rollup.sol")),
			kv("function", validation.VStr("finalizeBatch")),
		))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()),
		)),
	)
	for _, o := range over {
		base.O = validation.SetOrAppend(base.O, o.K, o.V)
	}
	return base
}

// f7Ingest files one hypothesis into the campaign and returns it.
func f7Ingest(t *testing.T, c *state.Campaign,
	over ...validation.KV) validation.Value {
	t.Helper()
	f, err := findings.IngestHypothesis(c, f7Payload(over...), "code", "05", "")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// f7IngestLiveness files a liveness-impact finding (economic_impact.kind ==
// "liveness") with no adversarial_game clause.
func f7IngestLiveness(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	return f7Ingest(t, c, kv("economic_impact", validation.VObj(
		kv("kind", validation.VStr("liveness")))))
}

// f7IngestFreeze files a chain-freeze-class finding with NO economic_impact
// object — the shape the kind-only trigger let slip past discovery.
func f7IngestFreeze(t *testing.T, c *state.Campaign) validation.Value {
	t.Helper()
	return f7Ingest(t, c, kv("root_cause", validation.VObj(
		kv("class", validation.VStr("chain-freeze")),
		kv("description", validation.VStr(
			"the challenge window closes without a finalize path")),
	)))
}

// f7ClauseMissing finds the missing[] entry that names fid.
func f7Entry(t *testing.T, res validation.Value, fid string) string {
	t.Helper()
	for _, m := range missingOf(t, res) {
		if strings.HasPrefix(m, fid+": ") {
			return m
		}
	}
	return ""
}

// f7Baseline is the divergence-closed, queue-drained campaign the clause
// demand rides on: nothing else blocks the discovery proof.
func f7Baseline(t *testing.T) *state.Campaign {
	t.Helper()
	c := t35LensCampaign(t)
	t35PlanClosedExcept(t, c, "")
	if res := t35DiscoveryProof(t, c); !isDone(t, res) {
		t.Fatalf("baseline discovery proof must be done: %s",
			validation.CanonCompact(res))
	}
	return c
}

// TestDiscoveryExitRefusesLivenessWithoutClause: the divergence gate is
// closed and the queue drained, yet a HYPOTHESIS whose economic_impact.kind
// is "liveness" keeps the discovery proof open — the missing[] entry names
// the finding id, the exact missing artifact, and the exact recording
// command. No double-fire: a second evaluation renders identically.
func TestDiscoveryExitRefusesLivenessWithoutClause(t *testing.T) {
	c := f7Baseline(t)
	f := f7IngestLiveness(t, c)
	fid := objStr(f, "finding_id")
	res := t35DiscoveryProof(t, c)
	if isDone(t, res) {
		t.Fatal("discovery exit must refuse a liveness finding without " +
			"its clause: " + validation.CanonCompact(res))
	}
	entry := f7Entry(t, res, fid)
	if entry == "" {
		t.Fatalf("missing does not name %s: %v", fid, missingOf(t, res))
	}
	for _, want := range []string{
		"adversarial_game clause (who profits from the freeze)",
		"webv2 adversarial-game " + c.CampaignID + " " + fid,
		"webv2 waive " + c.CampaignID + " adversarial-game --subject " + fid,
	} {
		if !strings.Contains(entry, want) {
			t.Errorf("entry missing %q:\n%s", want, entry)
		}
	}
	if !strings.Contains(objStr(res, "note"), "adversarial_game clause") {
		t.Errorf("note = %q, want it to name the clause", objStr(res, "note"))
	}
	again := t35DiscoveryProof(t, c)
	if got, want := validation.CanonCompact(again),
		validation.CanonCompact(res); got != want {
		t.Errorf("second evaluation differs (double fire?)\n got %s\nwant %s",
			want, got)
	}
}

// TestDiscoveryExitRefusesClassFreezeWithoutClause: a finding whose
// root_cause.class is "chain-freeze" — with no economic_impact object at
// all — owes the clause at the discovery exit, because IsLivenessFinding
// (the shared check15 predicate) fires on the class. The refusal names the
// exact same artifact and commands; it passes once the real setter records
// the clause; a second evaluation renders identically (no double-fire).
func TestDiscoveryExitRefusesClassFreezeWithoutClause(t *testing.T) {
	c := f7Baseline(t)
	f := f7IngestFreeze(t, c)
	fid := objStr(f, "finding_id")
	res := t35DiscoveryProof(t, c)
	if isDone(t, res) {
		t.Fatal("discovery exit must refuse a chain-freeze finding " +
			"without its clause: " + validation.CanonCompact(res))
	}
	entry := f7Entry(t, res, fid)
	if entry == "" {
		t.Fatalf("missing does not name %s: %v", fid, missingOf(t, res))
	}
	for _, want := range []string{
		"adversarial_game clause (who profits from the freeze)",
		"webv2 adversarial-game " + c.CampaignID + " " + fid,
		"webv2 waive " + c.CampaignID + " adversarial-game --subject " + fid,
	} {
		if !strings.Contains(entry, want) {
			t.Errorf("entry missing %q:\n%s", want, entry)
		}
	}
	if _, err := findings.SetAdversarialGame(c, fid, f7Who, f7Mech,
		f7Inter); err != nil {
		t.Fatal(err)
	}
	res = t35DiscoveryProof(t, c)
	if !isDone(t, res) || f7Entry(t, res, fid) != "" {
		t.Fatalf("discovery proof must pass once the clause is recorded: %s",
			validation.CanonCompact(res))
	}
}

// TestDiscoveryExitStillRefusesConfirmedLiveness: a liveness finding that
// sits at CONFIRMED while discovery is still closing owes the clause too —
// the gate never upgrades a demand because the status moved first. The
// status is stamped on the stored finding (the proof reads the stored
// shape); the CONFIRMED transition's own gate is the bounty gate's job, not
// this proof's.
func TestDiscoveryExitStillRefusesConfirmedLiveness(t *testing.T) {
	c := f7Baseline(t)
	f := f7IngestLiveness(t, c)
	fid := objStr(f, "finding_id")
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	vf.O = validation.SetOrAppend(vf.O, "status",
		validation.VStr("CONFIRMED"))
	if err := validation.WriteJson(findings.FindingPath(c, fid), vf, ""); err != nil {
		t.Fatal(err)
	}
	res := t35DiscoveryProof(t, c)
	if isDone(t, res) || f7Entry(t, res, fid) == "" {
		t.Fatalf("confirmed liveness finding must still block the exit: %s",
			validation.CanonCompact(res))
	}
}

// TestDiscoveryExitPassesOnceClauseRecorded: the real setter writes the real
// recorded shape — every field past the floor — and the proof closes without
// lingering entries.
func TestDiscoveryExitPassesOnceClauseRecorded(t *testing.T) {
	c := f7Baseline(t)
	fid := objStr(f7IngestLiveness(t, c), "finding_id")
	if isDone(t, t35DiscoveryProof(t, c)) {
		t.Fatal("precondition: the missing clause must block")
	}
	if _, err := findings.SetAdversarialGame(c, fid, f7Who, f7Mech,
		f7Inter); err != nil {
		t.Fatal(err)
	}
	res := t35DiscoveryProof(t, c)
	if !isDone(t, res) {
		t.Fatalf("discovery proof must pass once the clause is recorded: %s",
			validation.CanonCompact(res))
	}
	if f7Entry(t, res, fid) != "" {
		t.Errorf("clause recorded but the finding still blocks: %v",
			missingOf(t, res))
	}
}

// TestDiscoveryExitRefusesShortClause: a hand-edited clause (written
// straight to disk, past the setter's floor) cannot sneak past — the entry
// names the short field, not just the missing clause.
func TestDiscoveryExitRefusesShortClause(t *testing.T) {
	c := f7Baseline(t)
	f := f7IngestLiveness(t, c)
	fid := objStr(f, "finding_id")
	vf, err := findings.LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	vf.O = validation.SetOrAppend(vf.O, "adversarial_game", validation.VObj(
		kv("who_profits", validation.VStr(f7Who)),
		kv("profit_mechanism", validation.VStr("short")),
		kv("challenge_interplay", validation.VStr(f7Inter))))
	if err := validation.WriteJson(findings.FindingPath(c, fid), vf, ""); err != nil {
		t.Fatal(err)
	}
	res := t35DiscoveryProof(t, c)
	entry := f7Entry(t, res, fid)
	if entry == "" {
		t.Fatalf("hand-edited short clause must block the exit: %s",
			validation.CanonCompact(res))
	}
	if !strings.Contains(entry, "profit_mechanism") {
		t.Errorf("entry does not name the short field:\n%s", entry)
	}
}

// TestDiscoveryExitWaiverClearsTheClause: the clause's own waiver stage
// ("adversarial-game") removes the block — a named, recorded decision that
// the incentive answer lives elsewhere, exactly like the bounty gate reads
// it.
func TestDiscoveryExitWaiverClearsTheClause(t *testing.T) {
	c := f7Baseline(t)
	fid := objStr(f7IngestLiveness(t, c), "finding_id")
	if isDone(t, t35DiscoveryProof(t, c)) {
		t.Fatal("precondition: the missing clause must block")
	}
	if _, err := Waive(c, "adversarial-game", fid,
		"the incentive argument lives in the chain narrative: the operator is paid per frozen hour",
		"pytest"); err != nil {
		t.Fatal(err)
	}
	res := t35DiscoveryProof(t, c)
	if !isDone(t, res) || f7Entry(t, res, fid) != "" {
		t.Fatalf("waived finding must not block the exit: %s",
			validation.CanonCompact(res))
	}
}

// TestDiscoveryExitIgnoresNonLivenessAndGhosts: a finding without
// economic_impact (the ghost/orphan shape) and one whose economic_impact
// names no kind are both unaffected — IsLivenessFinding has no other
// trigger to fire on (no liveness class, no liveness terminal capability).
func TestDiscoveryExitIgnoresNonLivenessAndGhosts(t *testing.T) {
	c := f7Baseline(t)
	f7Ingest(t, c) // no economic_impact at all
	f7Ingest(t, c, kv("economic_impact", validation.VObj()))
	res := t35DiscoveryProof(t, c)
	if !isDone(t, res) {
		t.Fatalf("findings without the liveness kind must not block: %s",
			validation.CanonCompact(res))
	}
}

// TestDiscoveryExitIgnoresDeadLiveness: a liveness finding whose claim died
// (DISPROVED) no longer owes the incentive answer — the gate refuses to
// demand work on a statement the campaign already dispositioned.
func TestDiscoveryExitIgnoresDeadLiveness(t *testing.T) {
	c := f7Baseline(t)
	fid := objStr(f7IngestLiveness(t, c), "finding_id")
	if isDone(t, t35DiscoveryProof(t, c)) {
		t.Fatal("precondition: the missing clause must block")
	}
	if _, err := findings.Transition(c, fid, "DISPROVED",
		"disproved by the fixture: finalize is reachable", "pytest", "",
		false); err != nil {
		t.Fatal(err)
	}
	res := t35DiscoveryProof(t, c)
	if !isDone(t, res) || f7Entry(t, res, fid) != "" {
		t.Fatalf("disproved liveness finding must not block the exit: %s",
			validation.CanonCompact(res))
	}
}

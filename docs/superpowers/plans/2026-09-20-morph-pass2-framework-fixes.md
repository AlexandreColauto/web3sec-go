# Morph Pass-2 Framework Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the six ranked gaps the Morph pass-1 framework review (`../morph/FRAMEWORK_REVIEW.md` §6–§7) measured against the `webv2` control plane, in descending cost order.

**Architecture:** Every fix is a deterministic gate/proof/schema change in the Go control plane (`internal/…`) plus the matching agent-facing prompt/runbook lines (`assets/…`). No model-in-the-loop logic: each rule forces a question onto the record and refuses silent passes, exactly like the existing B4 dismissal gate and B2 adversarial-game clause.

**Tech Stack:** Go 1.26 (`go.mod` floor `go 1.26.2`), stdlib only; JSON-schema-validated campaign artifacts; `testing` package tests; the repo's own gates (`go vet`, `go test ./...`, `scripts/golden.sh`).

## Global Constraints

- Go toolchain floor `go 1.26.2` (module `websec`); **no new dependencies** — stdlib only.
- Tests must never hit Docker, a network, or the model: gates are deterministic reads/writes over a `t.TempDir()` campaign.
- Several CLI/help strings are **byte-pinned by tests** (`internal/bounty/bounty_test.go` JSON vectors, `internal/cli/*_test.go` stdout constants). When you change a pinned string, update the pin in the same commit and say so in the commit message.
- `validation.SetOrAppend` returns a NEW slice — always write it back: `v.O = validation.SetOrAppend(v.O, k, val)` (see `docs` learnings: SetOrAppend write-back trap).
- Every mutation path keeps the house discipline: state file write + `campaign.Log` event are one unit (existing helpers `SaveThenLog`, `planThenLog`, `writeThenLog` already do this — do not hand-roll a new pair).
- Schema files are embedded assets: after editing anything under `assets/`, the asset-manifest check (`scripts/verify-full.sh` step "asset-pack manifest") must be green; regenerate per `scripts/golden.sh` guidance if the manifest test names a hash drift.
- Commit after every task: `git add <files> && git commit -m "<type>(<scope>): <summary>"` (house style, e.g. `feat(planner): …`, `fix(cli): …`).
- Run before each commit: `go build ./... && go vet ./... && go test ./internal/<touched pkg>/... -count=1`. Run `go test ./... -count=1` once in Task 8.

**Task order matters:** Tasks 1–3 are independent; Task 4's test uses Task 3's floor table being stable; Tasks 5–7 independent; Task 8 is the full gate.

---

### Task 1: Enforcement-timing rows lose the "asserted downstream → Safe" escape (review §6.1 / §7.1 — the G-01 miss)

**Why:** In morph pass 1, probe row `34589e8588` (axis `enforcement-timing`, lens L-03, tier 0, `assertion_gap` 4) was dispositioned **Safe** with the reason "the truth of the prev state root is asserted downstream by finalizeBatch". The existing deferred-consequence gate (FIX-5, `internal/planner/disposition_deferred.go`) triggers only on the `asserter` ANCHOR or on consequence WORDS in the reason (`DeferredConsequenceTokens`) — a rephrased safety-mode answer passes both triggers untouched. The fix is structural, not lexical: a high-risk row **on the enforcement-timing axis** always owes the liveness-mode pricing.

**Files:**
- Modify: `internal/planner/disposition_deferred.go` (gate body + trigger)
- Test: `internal/planner/disposition_deferred_enforcement_test.go` (create)

**Interfaces:**
- Consumes: `checkDeferredConsequenceRow(campaign, priorityID, outcome, prov, hasProv, opts, dry)` (existing), surface rows as built by `internal/probes` (`axis`, `tier`, `assertion_gap`, `consumer`, `asserter` fields — see `internal/probes/testdata/golden/surface_assertion_buggy.json`).
- Produces: same signature; no new exported names outside package `planner`. Task 4 does not depend on this.

- [ ] **Step 1: Write the failing tests**

Create `internal/planner/disposition_deferred_enforcement_test.go`. Copy the campaign + plan fixture helpers from `internal/planner/disposition_test.go` (read it first; it builds a campaign via the package's existing test helpers and a plan whose priority carries `probe: {row_id: …}`). The new file:

```go
package planner

// A high-risk enforcement-timing row closed as answered WITHOUT the asserter
// anchor and with a clean (non-vocabulary) reason — the exact morph pass-1
// shape: "asserted downstream by finalizeBatch" — must still be refused until
// the interim window is priced (morph review §6.1: late enforcement is the
// freeze primitive, not protection).
func TestEnforcementTimingRowPricedWithoutWords(t *testing.T) {
	camp, plan, prioID := enforcementFixture(t, validation.VObj(
		kv("row_id", validation.VStr("34589e8588")),
		kv("axis", validation.VStr("enforcement-timing")),
		kv("tier", validation.VInt(0)),
		kv("assertion_gap", validation.VInt(4)),
		kv("consumer", validation.VStr("commitBatch")),
		kv("asserter", validation.VStr("finalizeBatch")),
	))
	reason := "the check is asserted downstream by finalizeBatch:508, any bad " +
		"value is caught before corruption"
	anchor := "prev_state_root" // a legal non-asserter anchor
	_, err := MarkAnswered(camp, plan, prioID, "answered", AnsweredOpts{
		Reason: &reason, Anchor: &anchor})
	if err == nil {
		t.Fatal("enforcement-timing row closed unpriced — the gate must refuse")
	}
	if !strings.Contains(err.Error(), "enforcement-timing") {
		t.Fatalf("refusal must name the axis trigger, got: %v", err)
	}
	// The refusal must offer both pricing exits.
	for _, want := range []string{"--finding", "--interim"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not offer %s: %v", want, err)
		}
	}
}

// The pricing exits stay open: an --interim statement citing a row symbol
// passes, and the logged override passes (and records
// probe.dismissal_overridden) — the FIX-5 contract, unchanged for the new
// trigger.
func TestEnforcementTimingRowPricingExits(t *testing.T) {
	camp, plan, prioID := enforcementFixture(t, enforcementRow())
	interim := "commitBatch persists prev_state_root that finalizeBatch can " +
		"never chain from — finalization halts forever"
	if _, err := MarkAnswered(camp, plan, prioID, "answered", AnsweredOpts{
		Reason: ptr("checked elsewhere"), Anchor: ptr("prev_state_root"),
		Interim: &interim}); err != nil {
		t.Fatalf("--interim pricing must pass the gate: %v", err)
	}
	camp2, plan2, prio2 := enforcementFixture(t, enforcementRow())
	over := "lens already answered in liveness mode on the sibling row"
	logged := false
	if _, err := MarkAnswered(camp2, plan2, prio2, "answered", AnsweredOpts{
		Reason: ptr("checked elsewhere"), Anchor: ptr("prev_state_root"),
		OverrideDismissal: true, OverrideReason: &over,
		OverrideLogged: &logged}); err != nil {
		t.Fatalf("logged override must pass the gate: %v", err)
	}
	if !logged {
		t.Fatal("override did not record probe.dismissal_overridden")
	}
}
```

(`ptr` is a local `func ptr(s string) *string`; `enforcementRow()` returns the 6-field surface object from the first test.) Implement `enforcementFixture`/`enforcementRow` locally in the test file: the fixture writes the row into the campaign's `probe_surface.json` via the same path `disposition_test.go` uses, and builds a plan priority with `probe: {probe_id: "assertion-strength", row_id: "34589e8588"}`. Reuse, do not reinvent: follow `disposition_test.go`'s fixture construction exactly, changing only the row object.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/planner/ -run TestEnforcementTiming -v`
Expected: FAIL — first test: "enforcement-timing row closed unpriced — the gate must refuse" (the gate currently stands down: anchor ≠ asserter, no vocabulary tokens).

- [ ] **Step 3: Add the structural trigger**

In `internal/planner/disposition_deferred.go`:

```go
// enforcementTimingAxis is the L-03 surface axis. Morph pass-1 review §6.1:
// the miss was a high-risk row on THIS axis answered "the check exists, it is
// asserted downstream" — every fact true, the conclusion gold-inverted. The
// safety-mode reading ("bad values get caught before corruption") and the
// liveness-mode reading ("catching it at finalize means the batch committed,
// its challenge window ran, and finalization reverts forever") are both
// available from the same lines; the vocabulary triggers let an author pick
// the safe-sounding one. For enforcement-timing rows the choice is taken away:
// late enforcement is not protection, it is the freeze primitive, so the
// pricing (--finding / --interim) is demanded whatever the reason says.
const enforcementTimingAxis = "enforcement-timing"
```

In `checkDeferredConsequenceRow`, after the `HighRiskRow(row)` early-return, widen the trigger:

```go
	anchorTriggered := opts.Anchor != nil && *opts.Anchor == deferredAnchor
	tokens := []string{}
	if opts.Reason != nil {
		tokens = DeferredHits(*opts.Reason)
	}
	enforcement := validation.ObjStr(row, "axis") == enforcementTimingAxis
	if !anchorTriggered && !enforcement && len(tokens) == 0 {
		return nil
	}
```

Pass `enforcement` into `checkDeferredConsequence` (extend its parameter list after `anchorTriggered`), and add its refusal branch BEFORE the vocabulary branch (after the `anchorTriggered` one) in `checkDeferredConsequence`:

```go
	if enforcement {
		where := validation.ObjStr(row, "asserter")
		if where == "" {
			where = "a later lifecycle stage"
		}
		consumer := validation.ObjStr(row, "consumer")
		consumerPhrase := ""
		if consumer != "" {
			consumerPhrase = ", while " + consumer + " already acts on the value"
		}
		symbolsPhrase := ""
		if len(syms) > 0 {
			symbolsPhrase = " — a consequence statement citing the row's own " +
				"surface entry (" + strings.Join(syms, ", ") + ")"
		}
		return errValue(head + ": the row sits on the enforcement-timing axis " +
			"— the check exists, but " + where + " enforces it" + consumerPhrase +
			". Safety mode is not the whole answer: enumerate the liveness mode — " +
			"if the downstream assertion is what protects, what is the state of "+
			"the system when it fires, and who can force the system into that "+
			"state before it does? Price the consequence: --finding F-<id> "+
			"(a filed finding that records the window) or --interim STATEMENT" +
			symbolsPhrase + " — or override explicitly: --override-dismissal "+
			"--override-reason R")
	}
```

The (b) `--finding` and (a) `--interim` exits already run above all trigger branches — no other change. The override arm (`overrideDeferredConsequence`) runs unchanged: it keys on the returned error, not on the trigger.

**KNOWN RIPPLE (decided, do not re-litigate):** the structural trigger fires on EVERY high-risk enforcement-timing row closure — any anchor, exec-ref included. An exec refutes the safety-mode claim ("bad values get caught"); it does not answer the liveness-mode question (what happens in the window before they are caught) — that is the whole point of §7.1. So surface-draining test helpers and gate-matrix fixtures (e.g. `internal/probes/emit_test.go:emitAnswerProbeRows`, the exec-backed arms of `TestDismissalGateMatrix`, `TestMarkAnswered*`, sentinel/ghost-citation tests whose fixture rows are enforcement-timing and tier 0) must price the window with an `Interim:` statement that cites the row's own surface symbols (the v3 citation rule rejects prose naming none — read each fixture's surface row first and quote one of its `concept_keys`/`consumer`/`asserter`). Add the morph-§ comment once per file.

- [ ] **Step 4: Run tests green**

Run: `go test ./internal/planner/ -run TestEnforcementTiming -v` → PASS.
Run: `go test ./internal/planner/ -count=1` → PASS (watch `disposition_test.go`/`r3_answered_test.go` fixtures: if any existing fixture row carries `axis: enforcement-timing` and closes unpriced, it now needs pricing — fix the FIXTURE only if it is a non-enforcement row that got the axis by copy-paste; otherwise the refusal is correct and the test must be updated to price it, with a comment saying why).

- [ ] **Step 5: Commit**

```bash
git add internal/planner/disposition_deferred.go internal/planner/disposition_deferred_enforcement_test.go
git commit -m "feat(planner): enforcement-timing rows owe interim pricing whatever the reason words (morph §7.1)"
```

---

### Task 2: The adversarial-game clause gains a mandatory strongest-attacker arm, cross-examined by the critic (review §6.2 / §7.2)

**Why:** F-e9461aa406cd carried a **wrong** `challenge_interplay` ("the challenge path DOES undo it") straight through the gate into the report. The clause is write-only: nothing checks the interplay claim against the strongest attacker variant (proof-**valid** bad state vs proof-invalid). Fix: a fourth clause field, forced in the same `SetAdversarialGame` write, surfaced into the critic's bundle, and made the critic's named duty.

**Files:**
- Modify: `internal/findings/adversarial.go` (field list + setter)
- Modify: `assets/schema/finding.schema.json` (`definitions.adversarial_game`)
- Modify: `internal/cli/cmd_adversarial.go` (flag + help/usage)
- Modify: `internal/bounty/bounty.go` (check15 "complete" detail string)
- Modify: `internal/report/report_finding_section.go` (render 4th line)
- Modify: `internal/roles/context_critic.go` (bundle `game_audit` block)
- Modify: `assets/prompts/48_critic_system.md` (cross-examination rule)
- Modify: `internal/adapter/adapter_context.go` (heal-hint line), `internal/planner/planner.go` (ingest hint text if it quotes the fields), `assets/runbook/RUNBOOK.md:1259,1721`, `assets/runbook/AGENT_BOOTSTRAP.md` (any `--interplay` command line)
- Tests: `internal/findings/adversarial_test.go`, `internal/bounty/bounty_test.go` (fixture + byte-pinned vectors), `internal/report/report_adversarial_test.go`, `internal/cli/cmd_adversarial_test.go`, `internal/completion/adversarial_discovery_test.go`

**Interfaces:**
- Consumes/Produces: `findings.AdversarialGameFields = []string{"who_profits", "profit_mechanism", "challenge_interplay", "strongest_attacker"}`; `SetAdversarialGame(campaign, findingID, whoProfits, profitMechanism, challengeInterplay, strongestAttacker string)` — one new trailing param. All existing callers are in this repo; update every one.

- [ ] **Step 1: Failing findings tests**

In `internal/findings/adversarial_test.go` extend `TestAdversarialGameDeficits` cases to four fields and add:

```go
// The morph pass-1 lesson: a three-field clause whose interplay claim is
// "the challenge path undoes it" passed the gate unexamined. The fourth
// field — the claim under the STRONGEST attacker variant (a proof-VALID bad
// batch wins the challenge) — is what forces the half-step.
func TestAdversarialGameStrongestAttackerRequired(t *testing.T) {
	partial := validation.VObj(
		kv("adversarial_game", validation.VObj(
			kv("who_profits", validation.VStr(agWho)),
			kv("profit_mechanism", validation.VStr(agMech)),
			kv("challenge_interplay", validation.VStr(agInter)))))
	if got := AdversarialGameDeficits(partial); len(got) != 1 ||
		got[0] != "strongest_attacker" {
		t.Fatalf("deficits = %v, want [strongest_attacker]", got)
	}
}
```

Update `TestSetAdversarialGame` (+ the short-field matrix, unknown-finding, overwrite tests) to the 6-arg call; assert the stored clause has 4 keys in order and the `finding.adversarial_game_set` event carries `strongest_attacker_chars`.

Run `go test ./internal/findings/ -run TestAdversarialGame -v` → compile failure / FAIL.

- [ ] **Step 2: Implement the field**

`internal/findings/adversarial.go`:

```go
// AdversarialGameFields is the clause's field order (schema, setter, gate,
// report all walk it). strongest_attacker was added after morph pass 1
// (review §6.2): the run filed a WRONG challenge_interplay ("the challenge
// path DOES undo it") and nothing forced the question the gold finding turns
// on — does the interplay claim hold against the strongest attacker variant,
// the one whose bad state transition is itself proof-VALID (a fake-root
// batch that WINS its challenge)? A claim true only of proof-invalid batches
// is not an interplay argument; it is the bug.
var AdversarialGameFields = []string{"who_profits", "profit_mechanism",
	"challenge_interplay", "strongest_attacker"}
```

`SetAdversarialGame`: add `strongestAttacker string` after `challengeInterplay`, map key `"strongest_attacker": strongestAttacker`. The deficits loop already walks the field list — no other body change.

`assets/schema/finding.schema.json` `definitions.adversarial_game.properties`: add

```json
"strongest_attacker": {
  "type": "string",
  "minLength": 20,
  "description": "whether the challenge_interplay claim survives the STRONGEST attacker variant: a bad state whose transition is itself proof-valid (e.g. a fake prev-root batch that wins its challenge by proving a valid transition FROM the fake root). Say which variant defeats the claim, or why none does."
}
```

- [ ] **Step 3: CLI + gate + report + hint strings**

`internal/cli/cmd_adversarial.go`: add `--strongest-attacker` exactly mirroring the `--interplay` arm (bare/`=`/missing-value cases) into `adversarialParseArgs`, `pa.strongest`, required-args check (`if pa.strongest == "" { missing = append(missing, "--strongest-attacker") }`), `adversarialRecord` call, and BOTH `adversarialUsage` and `adversarialHelp` (usage line: `--interplay INTERPLAY --strongest-attacker ATTACKER`; options block: `  --strongest-attacker ATTACKER  whether the interplay answer survives a proof-valid bad state`). Update `internal/cli/cmd_adversarial_test.go` call sites.

`internal/bounty/bounty.go` check15: the complete-clause `g.add` detail becomes `"incentive clause complete (who_profits / profit_mechanism / challenge_interplay / strongest_attacker)"` (keep the exact concat form; byte-pinned vectors in `bounty_test.go` update in Step 4).

`internal/report/report_finding_section.go`: after the challenge-interplay line append

```go
		out = append(out, fmt.Sprintf("-   strongest attacker: %s",
			validation.PyStr(validation.ObjAt(ag, "strongest_attacker"))))
```

`internal/adapter/adapter_context.go:31` and `internal/planner/planner.go:48`: extend the quoted `webv2 adversarial-game …` heal command with `--strongest-attacker 'does a proof-valid bad batch still win the challenge?'`. `assets/runbook/RUNBOOK.md` lines 1259 and 1721: same extension (keep the surrounding prose intact; the runbook is asset-embedded and manifest-checked).

- [ ] **Step 4: Fixtures + byte-pinned strings**

- `internal/bounty/bounty_test.go`: add a `strongest_attacker` entry (≥20 chars, real argument) to `adversarialClause()`; regenerate the three `vectorAdversarialCases` JSON pinworts ONLY as needed (`adversarial_missing` / `adversarial_short` / `adversarial_waived` blocking/detail strings) — the check15 pass/fail semantics per case must not change.
- `internal/completion/adversarial_discovery_test.go` + `internal/report/report_adversarial_test.go`: extend clause texts and expected render/deficit strings.
- Run `go test ./internal/findings/ ./internal/cli/ ./internal/bounty/ ./internal/report/ ./internal/completion/ -count=1`; fix pins until green. Any failure naming a `lacks the adversarial_game` phrase: the deficits list now prints 4 fields — update the expectation, not the code.

- [ ] **Step 5: Critic bundle + critic duty**

`internal/roles/context_critic.go` `BuildCriticContext`: in the `bundle` literal, before `task`, add (presence-gated — a finding with no clause carries no block, so the bundle bytes for non-liveness claims are unchanged):

```go
		validation.KV{K: "game_audit", V: gameAuditBlock(finding)},
```

```go
// gameAuditBlock is the morph §7.2 cross-examination input: when the claim
// carries an adversarial_game clause, the critic gets the clause verbatim
// (it is claim-side data, not proposer narrative) so the interplay answer
// can be checked against the strongest attacker variant before the claim
// travels. Empty object when the finding owes no clause.
func gameAuditBlock(finding validation.Value) validation.Value {
	ag := validation.ObjAt(finding, "adversarial_game")
	if ag.Kind != validation.Obj || len(ag.O) == 0 {
		return validation.VObj()
	}
	out := validation.VObj()
	for _, k := range findings.AdversarialGameFields {
		if v := validation.ObjAt(ag, k); v.Kind != validation.Null {
			out.O = append(out.O, validation.KV{K: k, V: v})
		}
	}
	return out
}
```

In the same bundle's `task` object, add the KV:

```go
			validation.KV{K: "game_interrogation", V: validation.VStr(
				"if game_audit is present, re-derive challenge_interplay " +
					"under the strongest attacker variant the code allows; " +
					"a claim true only of proof-invalid transitions is a " +
					"refutation, not a defense — record it in " +
					"missing_proof")}),
```

(`roles` already imports `findings`; if not, add the import.)

`assets/prompts/48_critic_system.md`: in §3 "Universal rules", append one bullet:

```markdown
- **Game-clause cross-examination (hard).** When the bundle carries a
  non-empty `game_audit`, `challenge_interplay` is a claim under test like
  any assumption: name the strongest attacker variant the CLAIMED state
  admits — including a transition that is itself proof-VALID from the bad
  state (a fake root whose batch wins its challenge by proving a valid
  step from that root) — and check whether the interplay answer survives
  it. If it survives only proof-invalid variants, the claim is
  un-refuted, not defended: verdict downgrades, and `missing_proof` names
  the variant that defeats the interplay answer.
```

Also §1 "What you receive" bullet list: add `game_audit` (present only when the finding carries an adversarial-game clause).

- [ ] **Step 6: Test the bundle + commit**

Add `TestCriticBundleCarriesGameAudit` to the existing critic-context test file in `internal/roles/` (find it: `ls internal/roles | grep -i critic`): a finding with the 4-field clause → bundle `game_audit` has all 4 keys; a finding without → `game_audit` is `{}`.
Run `go test ./internal/roles/ ./internal/findings/ ./internal/cli/ ./internal/bounty/ ./internal/report/ ./internal/completion/ -count=1` → green.

```bash
git add -A && git commit -m "feat(findings): adversarial_game gains mandatory strongest_attacker arm, cross-examined by the critic (morph §7.2)"
```

---

### Task 3: Liveness classes confirm on a local lifecycle harness (E4), not on fork reality (review §6.3 / §7.3)

**Why:** G-01's PoC needed no fork: `Rollup.t.sol` + `MockZkEvmVerifier` reproduce commit→challenge→finalize in-sandbox. The framework's default CONFIRMED floor for `chain-freeze` / `sequencer-halt` / `liveness` is E5 (the class-map default), which additionally arms `reproduction-tier` (T3 fork demand) in `gate_checks.go` — so "no fork" became the evidence ceiling. A local harness proves sequential-finalization semantics entirely; liveness is the *most* locally provable class.

**Files:**
- Modify: `internal/findings/levels.go` (`CLASS_CONFIRM_FLOOR`)
- Tests: `internal/findings/levels_test.go` (extend), ripple fixes anywhere a scenario pins liveness-class E5

**Interfaces:**
- Consumes: existing `RequiredLevelFor` / `ClassConfirmFloor`.
- Produces: `CLASS_CONFIRM_FLOOR["chain-freeze"|"sequencer-halt"|"liveness"] == "E4"`. Ripple consumers (auto): `floors.FloorTableReport` rows, gate `evidence-floor` (floor < E5 → no `reproduction-tier`, no unreachable diagnostic), report/briefing "reachable locally" wording (`ReachableLocally` cap reads unchanged).

- [ ] **Step 1: Failing test**

`internal/findings/levels_test.go` (append):

```go
// Morph pass-1 review §6.3: the liveness family is the MOST locally provable
// class — sequential finalization, queue ordering and challenge windows run
// end-to-end on a repo's own foundry harness. E5 (fork reality) made the
// missing fork the evidence ceiling on a bug the sandbox could prove.
func TestLivenessClassesConfirmAtE4(t *testing.T) {
	for _, cls := range []string{"chain-freeze", "sequencer-halt", "liveness"} {
		if got := ClassConfirmFloor(cls); got != "E4" {
			t.Errorf("ClassConfirmFloor(%q) = %s, want E4", cls, got)
		}
		if !ReachableLocally(cls, "E4") {
			t.Errorf("%s must be locally reachable at cap E4", cls)
		}
	}
}
```

Run: `go test ./internal/findings/ -run TestLivenessClassesConfirmAtE4 -v` → FAIL (E5 default).

- [ ] **Step 2: Implement**

`internal/findings/levels.go`, in `CLASS_CONFIRM_FLOOR` after `"share-price-accounting"`:

```go
		// Liveness family (morph pass-1 review §7.3): the impact lives in
		// SEQUENCE semantics — commit, challenge window, finalize order —
		// which a repo's own unit harness reproduces without mainnet
		// state. Mirror dos-griefing's E4: a local lifecycle PoC is the
		// proof; fork reality adds nothing the harness cannot decide.
		"chain-freeze":    "E4",
		"sequencer-halt":  "E4",
		"liveness":        "E4",
```

- [ ] **Step 3: Ripples**

`go test ./... -count=1`. Expected breakage sites and their honest resolutions:
- Any `internal/planner/testdata/scenario_oracles.json` / golden row that prices a `chain-freeze`/`liveness` finding at E5: only update a pin when it encodes the FLOOR itself (evidence-rung text); if it encodes an EXPECTATION the framework should still hold, adjust the fixture finding instead. Document each edited pin inline with `// morph §7.3: liveness floor E5->E4`.
- `internal/floors` table-report tests that print the built-in defaults: update expected rows.
Do NOT touch `floors` override mechanics — campaign-level overrides still win.

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "feat(findings): liveness classes confirm on a local lifecycle harness at E4 (morph §7.3)"
```

---

### Task 4: Promote-before-close at the discovery exit (review §6.4 / §7.4)

**Why:** The pass closed with a critic-confirmed POSSIBLE at rank #8 while 90 queue rounds of mechanical work ran. The forcing function: the top-K critic-confirmed open findings must each have a recorded reproduction attempt (exec-backed) or an explicit written deprioritization (waiver) before `discovery` — the divergence-era exit the campaign already passes through — closes.

**Files:**
- Modify: `internal/completion/proofs.go` (proofDiscovery arms)
- Test: `internal/completion/promote_close_test.go` (create)

**Interfaces:**
- Consumes: `findingsWith(c, []string{"POSSIBLE"})`, `verification.critic_verdict`, `verification.reproduction` (same shapes `proofReproduction` reads at proofs.go:455+), existing `waiverMap(c, "promote-before-close")`, `unwaived`, `proofItem`.
- Produces: a third `missing[]` arm inside the `discovery` proof (subject = finding id), covered by its own waiver stage string `"promote-before-close"`.

- [ ] **Step 1: Failing test**

`internal/completion/promote_close_test.go`:

```go
package completion

// Morph pass-1 review §6.4: the G-01 candidate sat at #8, critic-confirmed,
// unexecuted, while the queue drained for 90 rounds. Before discovery closes,
// the top-5 critic-confirmed POSSIBLE findings each owe a recorded repro
// attempt — or a written deprioritization (a waiver names actor+reason).
func TestDiscoveryRefusesUnpromotedTopCandidate(t *testing.T) {
	c := promotedFixture(t) // campaign with drained queue + closed divergence
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
```

Build the fixture so the OTHER discovery arms pass (empty work queue, divergence status `done: true`, no liveness clause deficits) — copy the queue-drained fixture from `completion_test.go`/`zz_r38_test.go` (read them; reuse their plan/state helpers). An exec-backed candidate is NOT missing: `evidence[].exec_ref != ""` OR `verification.reproduction.attempts` non-empty OR `verification.reproduction.status == "reproduced"` (the same acceptance `proofReproduction` uses, plus the exec_ref half so a fresh exec satisfies it).

- [ ] **Step 2: Implement**

`internal/completion/proofs.go` — add near `livenessOwedStatuses`:

```go
// promoteTopK is the morph §7.4 window: the K highest-ranked critic-confirmed
// POSSIBLE findings the campaign must disposition before the discovery exit
// closes. K=5 because a pass reports a ranked top sheet; below the sheet the
// queue's own ordering decides what "top" means.
const promoteTopK = 5
```

New method on `proofDiscoveryState` + call it in `proofDiscovery` after `proofDiscoveryLiveness`, and fold its items into `proofDiscoveryFinish` with its own waiver map (`waiverMap(s.campaign, "promote-before-close")` — the same two-map pattern `agWaived` uses):

```go
// proofDiscoveryPromote collects the top-K critic-confirmed POSSIBLE findings
// with no promotion evidence: no recorded repro attempt and no evidence item
// carrying an exec_ref. Rank = the validated-risk acceptance band when the
// finding has one (risk.validated.acceptance_likelihood), else severity band
// then created_at — deterministic, total order, no model in the loop.
func (s *proofDiscoveryState) proofDiscoveryPromote(cid string) error {
	possible, err := findingsWith(s.campaign, []string{"POSSIBLE"})
	if err != nil {
		return err
	}
	cands := []validation.Value{}
	for _, f := range possible {
		ver := orEmpty(validation.ObjAt(f, "verification"))
		if validation.ObjStr(ver, "critic_verdict") != "confirmed" {
			continue
		}
		if promoted(f, ver) {
			continue
		}
		cands = append(cands, f)
	}
	sort.SliceStable(cands, func(i, j int) bool {
		return promotionRankKey(cands[i]) > promotionRankKey(cands[j]) // see note
	})
	if len(cands) > promoteTopK {
		cands = cands[:promoteTopK]
	}
	s.promoteItems = []proofItem{}
	for _, f := range cands {
		fid := validation.ObjStr(f, "finding_id")
		s.promoteItems = append(s.promoteItems, proofItem{fid,
			"critic-confirmed candidate has no exec-backed promotion — run a " +
				"repro attempt (webv2 attempt / webv2 mint --exec) or record " +
				"the deprioritization: webv2 waive " + cid +
				" promote-before-close --subject " + fid +
				" --reason '<why it is not worth the cycle>'"})
	}
	return nil
}

// promoted is the acceptance: the SAME evidence arms proofReproduction honors
// (status reproduced / non-empty attempts), widened with one exec-backed
// evidence item — a fresh exec IS the promotion.
func promoted(f, ver validation.Value) bool {
	repro := orEmpty(validation.ObjAt(ver, "reproduction"))
	if validation.ObjStr(repro, "status") == "reproduced" ||
		pyTruthyBigNonEmpty(validation.ObjAt(repro, "attempts")) {
		return true
	}
	for _, e := range listAt(f, "evidence") {
		if validation.ObjStr(e, "exec_ref") != "" {
			return true
		}
	}
	return false
}
```

`promotionRankKey`: return a comparable string `fmt.Sprintf("%08.4f|%s", likelihood, created_at)` where `likelihood` is `risk.validated.acceptance_likelihood` (float, 0 when absent) — invert so higher ranks first, or sort descending in the comparator (pick one, stay consistent, keep the tie-break deterministic on `finding_id`). Add `promoteItems []proofItem` + `promoteWaived` to `proofDiscoveryState`; in `proofDiscoveryFinish` append their `missing` like `clauseMissing`; extend the `note` chain: before the liveness clause note, `if len(promoteMissing) > 0 { note = "work queue drained — critic-confirmed candidates await promotion or a written deprioritization" }`.

- [ ] **Step 3: Green + commit**

`go test ./internal/completion/ -count=1` (watch `golden_test.go` scenario pins — the new arm only fires on critic-confirmed POSSIBLE findings; scenario fixtures that have one and expect discovery DONE must gain a repro attempt or a waiver row; prefer adding the attempt to the fixture).
`go build ./... && go vet ./...` green.

```bash
git add -A && git commit -m "feat(completion): discovery exit owes top-K critic-confirmed findings an exec or a written deprioritization (morph §7.4)"
```

---

### Task 5: Content-hash idempotent ingest (review §6.5 / §7.5 first half)

**Why:** The same agent output re-submitted creates a new finding each time; the dedup stage then spends cycles marking them DUPLICATE — 258 duplicates of ingest clutter in morph pass 1, and the learning stage demanded a memory row per terminal DUPLICATE. Idempotency belongs at the door: a payload whose content digest already exists IS the finding it would have created.

**Files:**
- Modify: `internal/findings/ingest.go`
- Modify: `assets/schema/finding.schema.json` (`definitions.dedup` properties)
- Test: `internal/findings/ingest_idempotent_test.go` (create)

**Interfaces:**
- Consumes: `validation.DumpsOrdered` (deterministic canonical bytes), `validation.Sha12Hex` (16-hex, same derivation as ingest's case ids), `findings.LoadAllFindings`, `campaign.Log`.
- Produces: `finding.dedup.content_sha` (16-hex, stable for a given payload content); re-ingest returns the EXISTING finding unchanged and logs `finding.ingest_idempotent` `{finding_id, content_sha, actor}`; the orchestrator's priority-closure/stage-note half still runs on the returned finding.

- [ ] **Step 1: Failing test**

`internal/findings/ingest_idempotent_test.go` (build payloads like `adversarial_test.go`'s `hypoPayload`):

```go
// Re-ingesting the SAME payload is the same claim, not a new one: the first
// ingest creates the finding, the second returns it with the ledger saying so
// (morph §6.5: 258 duplicate ingests, one per re-submitted agent row).
func TestIngestIsContentIdempotent(t *testing.T) {
	c := newTestCampaign(t)
	payload := idemPayload() // title + root_cause(mechanism) + affected(path,function)
	f1, err := IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	sha := validation.ObjStr(validation.ObjAt(f1, "dedup"), "content_sha")
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(sha) {
		t.Fatalf("content_sha = %q, want 16-hex", sha)
	}
	f2, err := IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(f2, "finding_id") != validation.ObjStr(f1, "finding_id") {
		t.Fatalf("second ingest minted %s, want idempotent hit on %s",
			validation.ObjStr(f2, "finding_id"), validation.ObjStr(f1, "finding_id"))
	}
	// exactly one finding file, and the idempotent hit is on the ledger
	live, _ := LoadAllFindings(c)
	if len(live) != 1 {
		t.Fatalf("findings = %d, want 1", len(live))
	}
	if !hasEvent(c, "finding.ingest_idempotent") {
		t.Fatal("no finding.ingest_idempotent event")
	}
	// a DIFFERENT mechanism is a different claim — never folded
	other := idemPayload()
	// (set root_cause.mechanism to a different >=20-char text)
	f3, err := IngestHypothesis(c, mutated(other), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(f3, "finding_id") == validation.ObjStr(f1, "finding_id") {
		t.Fatal("a changed mechanism folded into the first finding")
	}
}
```

(`hasEvent` exists in findings tests as a helper or is 5 lines: read `campaign.Events()` and scan `type`.)
Run → FAIL (no content_sha / second id mints).

- [ ] **Step 2: Implement**

In `internal/findings/ingest.go`:

```go
// contentDigest is the ingest door's idempotency key (morph §7.5): the
// payload's semantic shape — title + root_cause + affected — over canonical
// ordered bytes. NOT the whole payload (status/evidence/history differ per
// call); NOT prose similarity (that is the dedup sweep's job). A re-submitted
// agent row is the SAME digest, so the same claim cannot become 258 findings.
func contentDigest(payload validation.Value) string {
	sem := validation.VObj(
		kv("title", validation.ObjAt(payload, "title")),
		kv("root_cause", validation.ObjAt(payload, "root_cause")),
		kv("affected", validation.ObjAt(payload, "affected")),
	)
	return validation.Sha12Hex([]byte(validation.DumpsOrdered(sem)))
}

// findContentTwin is the door's lookup: a LIVE finding already carrying this
// digest. Terminal rows do not block an ingest — a re-filed DISPROVED claim
// is an operator decision, not clutter to dedupe. O(n) over the store is the
// right size (campaigns carry hundreds of findings, not millions) —
// ponytail: revisit with an index if a campaign ever crosses ~10k.
func findContentTwin(campaign *state.Campaign, digest string) (validation.Value, bool, error) {
	live, err := LoadAllFindings(campaign)
	if err != nil {
		return validation.VNull(), false, err
	}
	for _, f := range live {
		if status := validation.ObjStr(f, "status"); status != "" {
			if _, terminal := TERMINAL[status]; terminal {
				continue
			}
		}
		if validation.ObjStr(validation.ObjAt(f, "dedup"), "content_sha") == digest {
			return f, true, nil
		}
	}
	return validation.VNull(), false, nil
}
```

`ingestBuildPayload`: stamp `content_sha` into the same dedup block the technical signature lands in (after the `sig` SetOrAppend, before `return p, fid, rootClass`):

```go
	dedup.O = validation.SetOrAppend(dedup.O, "content_sha",
		validation.VStr(contentDigest(payload)))
```

`ingestHypothesis`: between build and validate/gate, take the idempotent exit (after the digest exists on `p`):

```go
	p, fid, rootClass := ingestBuildPayload(campaign, payload, trajectory, stage)
	if !lint {
		if sha := validation.ObjStr(validation.ObjAt(p, "dedup"), "content_sha"); sha != "" {
			if twin, hit, terr := findContentTwin(campaign, sha); terr != nil {
				return validation.VNull(), terr
			} else if hit {
				// The door answers with the claim that exists. No second
				// finding file, no discovery slot charge, no re-validated
				// gate math — and the ledger records the hit so the
				// operator sees WHY nothing new appeared.
				data := validation.VObj(
					kv("finding_id", validation.VStr(fid)), // id NOT created
					kv("matched_finding", validation.VStr(validation.ObjStr(twin, "finding_id"))),
					kv("content_sha", validation.VStr(sha)),
					kv("actor", validation.VStr(orDefault(stage, "ingest"))),
				)
				ref := validation.ObjStr(twin, "finding_id")
				if _, lerr := campaign.Log("finding.ingest_idempotent", &ref, &data); lerr != nil {
					return validation.VNull(), lerr
				}
				return twin, nil
			}
		}
	}
```

(Exact placement: after `ingestBuildPayload`, before `ingestValidateAndGate` — the twin short-circuit runs no gate math. `--lint` skips the exit so lint keeps printing what a fresh ingest would decide.)

`assets/schema/finding.schema.json` `definitions.dedup.properties`:

```json
"content_sha": {
  "type": ["string", "null"],
  "pattern": "^[0-9a-f]{16}$",
  "description": "content-hash idempotency key (morph §7.5): digest of the payload's semantic shape (title + root_cause + affected) over canonical bytes, stamped at ingest. A re-submitted payload with an equal digest on a LIVE finding is answered with the existing finding + a finding.ingest_idempotent event instead of minting a duplicate."
}
```

- [ ] **Step 3: Green + commit**

`go test ./internal/findings/ ./internal/orchestrator/ ./internal/cli/ -count=1` (orchestrator's `Ingest` keeps working on the returned twin — `fid := strAt(f, "finding_id")` then notes/closes the priority with the EXISTING id, which is correct: the payload did answer the question).

```bash
git add -A && git commit -m "feat(findings): content-hash idempotent ingest answers a re-submitted payload with its twin (morph §7.5)"
```

---

### Task 6: SUPERSEDED no longer owes a memory row (review §6.6 / §7.6)

**Why:** The learning proof tracks SUPERSEDED as terminal and demands a memory row; `memory --queue-finding` (and `learning.MEMORY_STATUSES` / the memory schema enum) refuse the status — a catch-22 that forced per-finding waivers. Supersession is a BOOKKEEPING redirect: the successor finding carries the knowledge, the predecessor has nothing to remember. Fix on the demand side (one deletion), not by widening the memory vocabulary (three files + retrieval semantics for a status that encodes no judgment).

**Files:**
- Modify: `internal/completion/completion.go:33-35` (`TerminalStatuses`)
- Modify: `internal/completion/superseded_terminal_test.go` (invert — it pins the BUG)
- Check: `assets/prompts/42_learning_memory_reflection.md` (any line saying "every terminal finding, including SUPERSEDED")

**Interfaces:**
- Consumes/Produces: `completion.TerminalStatuses` (its only non-test consumer is `proofLearning` at proofs2.go:312 — verified).

- [ ] **Step 1: Invert the pinning test (red)**

Replace `superseded_terminal_test.go` body: build the same SUPERSEDED fixture, assert `learningProofMentions(res, fid)` is FALSE and, when it is the only open item, the proof is `done` (if the fixture campaign has no reflection line yet, append `learnings.jsonl` in the fixture or accept the reflection item and only assert the fid absence — assert BOTH: `!mentions(fid)` and `missing[]` contains no `F-0000000000aa`). Rename to `TestLearningProofIgnoresSuperseded`.

- [ ] **Step 2: One-line deletion**

`internal/completion/completion.go`:

```go
// TerminalStatuses are the finding statuses the learning proof tracks.
// SUPERSEDED is deliberately ABSENT (morph pass-1 review §7.6): supersession
// is a bookkeeping redirect — the successor carries the knowledge, the
// predecessor has nothing to remember — and the memory store's status
// vocabulary never accepted it, so demanding a row for it was a catch-22
// that forced a waiver per retired finding.
var TerminalStatuses = []string{"CONFIRMED", "DISPROVED", "DUPLICATE",
	"OUT_OF_SCOPE", "INFORMATIONAL", "CHAIN"}
```

- [ ] **Step 3: Green + commit**

`go test ./internal/completion/ ./internal/learning/ -count=1`; grep `SUPERSEDED` once more through `internal/completion/*_test.go` for any other pin; update `assets/prompts/42_learning_memory_reflection.md` wording if it promises superseded rows.

```bash
git add -A && git commit -m "fix(completion): SUPERSEDED owes no memory row — the redirect is the record (morph §7.6)"
```

---

### Task 7: `--live-only` clutter filter on brief and memory list (review §7.5 second half)

**Why:** With Task 5 stopping NEW duplicates, the operator still scrolls the existing DUPLICATE/INFORMATIONAL/SUPERSEDED noise in the cockpit. `webv2 brief C --live-only` and `webv2 memory C --list --live-only` drop the junk-status rows (and say how many).

**Files:**
- Modify: `internal/cli/cmd_brief.go` (flag + usage/help text + memory-list section)
- Modify: `internal/cli/cmd_memory.go` (`--list` branch)
- Tests: `internal/cli/cmd_brief_test.go` (or the nearest brief test file) + `internal/cli/cmd_memory_learn_test.go`

**Interfaces:**
- Consumes: status strings only. Produces: a tiny shared helper in package `cli`:

```go
// junkStatuses are the ingest-clutter statuses --live-only hides: a
// DUPLICATE/SUPERSEDED/INFORMATIONAL row is bookkeeping, not a claim the
// operator triages. OUT_OF_SCOPE stays visible: scope is a judgment the
// operator re-checks, not clutter.
var junkStatuses = map[string]bool{"DUPLICATE": true, "SUPERSEDED": true,
	"INFORMATIONAL": true}
```

- [ ] **Step 1: Failing tests** — brief: fixture with one DUPLICATE finding in the findings/memory listing; default output contains it, `--live-only` omits it and prints `live-only: N rows hidden`. memory list: same pattern via the existing memory-list stdout-pinning test style in `cmd_memory_learn_test.go`.

- [ ] **Step 2: Implement** — `cmd_brief.go`: add `{name: "--live-only"}` to the `boolOpt` slice at line ~123, extend `briefUsage`/`briefHelp` (`--json`, `--deep`, `--live-only  hide DUPLICATE/SUPERSEDED/INFORMATIONAL rows`), thread the bool into the print path (the memory/finding row loops in `printBrief`, e.g. the rows printed around `cmd_brief.go:269,445`) with `if liveOnly && junkStatuses[status] { hidden++; continue }` + the summary line. `cmd_memory.go`: parse `--live-only` in the list branch, same filter. Keep stdout byte-stable otherwise (tests pin whole blocks).

- [ ] **Step 3: Green + commit**

```bash
git add -A && git commit -m "feat(cli): --live-only hides ingest-clutter rows in brief and memory list (morph §7.5)"
```

---

### Task 8: Full gate + runbook coherence

- [ ] **Step 1:** `go build ./... && go vet ./... && go test ./... -count=1` → green. Fix every failure at its root (a pin that encoded the OLD behavior gets the update + a comment naming the morph section; a genuine break gets fixed in code).
- [ ] **Step 2:** Asset manifest + golden: follow `scripts/verify-full.sh` steps for the asset-pack manifest and run `scripts/golden.sh` if any golden asset hashes changed (schema + prompt edits touch embedded assets).
- [ ] **Step 3:** `scripts/runbook-walkthrough.sh` green (runbook commands changed in Tasks 2/5/7 — update the `RUNBOOK.md`/`AGENT_BOOTSTRAP.md` lines you touched, keeping command examples exactly executable).
- [ ] **Step 4:** Append a dated section to `docs/IMPROVEMENTS.md` (house changelog): one bullet per review recommendation with its commit scope.
- [ ] **Step 5:** Final commit if docs changed: `docs: morph pass-2 review fixes recorded (framework review §7 map)`.

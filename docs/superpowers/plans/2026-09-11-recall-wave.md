# Recall Wave (operator post-mortem) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the four recall gaps and the hygiene batch from the operator post-mortem (0/2 gold miss): sentinel-form probe rows, falsifiable "covered" dispositions, discovery-slot reform, payout-funding questions, planner bug_class fill, plan --json truth, and CLI hygiene — without bloating the framework.

**Architecture:** Seven small, independently testable changes layered onto existing seams (probe rows, the B4 disposition linter, the discovery-slot counter, symmetry divergence rows, the divergence gate, the plan JSON branch). No new subsystems, no campaign_state keys, no semantic "correctness" scorer. The design principle throughout: make falsifiable statements cheap to file and expensive to skip; the framework forces questions, it never pretends to answer them.

**Tech Stack:** Go 1.2x, embedded JSON schemas under `assets/schema/`, byte-pinned golden fixtures, `internal/structidx` (structural index), `internal/probes` (probe surface), `internal/planner` (plan/gates/dispositions), `internal/findings` (ingest/transitions).

## Global Constraints

Every task implicitly includes all of these:

- Build/test env: all `go` commands need `GOCACHE=$PWD/.scratch/gocache` (sandbox has no default cache). Run tests from the repo root `/home/xand/Projects/dsh-plugins/websec2/web3sec-go`.
- Test a single package: `GOCACHE=$PWD/.scratch/gocache go test ./internal/<pkg>/ -run '<TestName>' -count=1`.
- Full suite: `GOCACHE=$PWD/.scratch/gocache go test ./... -count=1` (should stay fast; no >1000-event log loops in the default suite).
- The Python twin is RETIRED. Never run pytest; there is no cross-twin harness anymore.
- Any change under `assets/` (schemas included) requires re-syncing `assets/testdata/asset_manifest.json` with `python3 scripts/sync-asset-manifest.py`, else `TestAssetsEmbeddedCount`/`TestAssetPackManifest` fail. `scripts/release.sh` greps for the `embedded assets ok:` line.
- `campaign_state.schema.json` top-level keys are FORBIDDEN in this wave (each one churns 3 byte-compared fixture files). No task adds one.
- New schema properties must be OPTIONAL (absent = old behavior) so existing fixtures stay byte-identical.
- Byte-pinned probe goldens: `internal/probes/testdata/golden/*.json` (15 trees x 6 probes) must remain byte-identical unless a task explicitly says otherwise. Tasks 1/4 are designed for zero churn: new fields/values only appear on NEW row shapes (sentinel-flagged / funding-mismatch rows), never on rows the shipped fixtures already produce.
- Every new refusal branch needs BOTH a negative control (mutate the expectation and watch the test go red) and an accepting closure path on the same fixture tier. Every new refusal reuses the gate family's existing escape hatch (`--override-dismissal` + `--override-reason`) — one escape hatch per family, never a new one.
- CLI flags that consume a value must guard against option-looking tokens: `case a == "--x" && i+1 < len(args) && !looksLikeOption(args[i+1]):` (standing source test `TestNoUnguardedValueConsumption` in internal/cli).
- Never pin evolving counts (row totals, command counts, schema counts) in gate/release scripts or test assertions — assert the line/format, not the number.
- Commits: conventional commits (`feat:`, `fix:`, `test:`, `chore:`), one logical change per commit, committed on the current `main` branch (established convention for this repo; binary stamps come from HEAD).
- Error messages follow the house style: name the exact repairing command, like existing gates do (`webv2 budget C --set-discovery N --actor NAME` style).
- No test may import another websec package's test helpers across packages; in-package tests may not import other websec packages when the package under test already imports them (harness rule).

---

### Task 1: Sentinel-form probe rows (`own_form` + adversarial why)

The operator closed the gold pair (commitBatch write → finalizeBatch read) as "covered" because an assertion existed. The probe layer must distinguish *what kind* of check guards a consumer: a sentinel check (`!= 0`, `!= bytes32(0)`, `> 0`, `.length > 0`) cannot express "this value is true", so a row whose consumer-side guard is sentinel-form must say so and demand the falsifiable answer. The structural index already stores each guard's raw condition text (`internal/structidx/parser.go` `guardsValue` emits `text`), and `guardStrength` already matches the sentinel patterns (`pyGuard1`/`reGuard1`). This task classifies the form at probe time — **no index schema change**.

**Files:**
- Create: `internal/structidx/guardform.go`
- Test: `internal/structidx/guardform_test.go`
- Modify: `internal/probes/probe_assertion.go` (compute the consumer's strongest own guard per key: class AND text)
- Modify: `internal/probes/collapse.go` (post-render why override for sentinel rows)
- Modify: `assets/schema/probe_surface.schema.json` (optional `own_form`, `own_guard_text` on assertion-strength rows)
- Test: `internal/probes/probes_test.go` (new fixture-driven test) + new fixture tree `internal/probes/testdata/probes/assertion_strength/sentinel/`
- Re-sync: `assets/testdata/asset_manifest.json`

**Interfaces:**
- Consumes: `guardsOf(entry)` entries carrying `class` (int), `text` (string), `concept_keys` (string list) — already in every index; `guardStrength`'s sentinel regex set in `internal/structidx/parser.go` (`pyGuard1`, `reGuard1`).
- Produces: `structidx.GuardForm(text string) string` → `"sentinel"` or `"substantive"`. Assertion-strength rows gain two conditional fields, present ONLY when the consumer's own strongest guard for the consumed concept key is sentinel-form: `own_form: "sentinel"` and `own_guard_text: "<the guard condition>"`. Downstream (Task 2) reads `own_form` off surface rows.

- [ ] **Step 1: Write the GuardForm vector test**

`internal/structidx/guardform_test.go`:

```go
package structidx

import "testing"

// TestGuardForm pins the sentinel/substantive split. The sentinel set is
// exactly guardStrength's class-1 set (pyGuard1/reGuard1): zero-checks,
// length checks. Everything else — equality to persisted state, ownership,
// membership, inequality of two names — is substantive.
func TestGuardForm(t *testing.T) {
	cases := map[string]string{
		"prevStateRoot != bytes32(0)":           "sentinel",
		"amount > 0":                            "sentinel",
		"inputs.length > 0":                     "sentinel",
		"token != address(0)":                   "sentinel",
		"x != 0":                                "sentinel",
		"prevStateRoot[batchIndex] == stateRoot": "substantive",
		"msg.sender == owner":                   "substantive",
		"balanceOf(user) >= amount":             "substantive",
		"root == keccak256(data)":               "substantive",
		"":                                      "substantive",
	}
	for cond, want := range cases {
		if got := GuardForm(cond); got != want {
			t.Errorf("GuardForm(%q) = %q, want %q", cond, got, want)
		}
	}
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/structidx/ -run TestGuardForm -count=1`
Expected: FAIL — `undefined: GuardForm`.

- [ ] **Step 3: Implement GuardForm**

`internal/structidx/guardform.go`:

```go
package structidx

// GuardForm classifies a guard condition by WHAT IT CAN EXPRESS:
//
//   "sentinel"    — the condition only rules out the zero value (or a empty
//                   collection): != 0, != bytes32(0), != address(0), > 0,
//                   .length > 0. A sentinel check cannot assert the truth of
//                   a value — any non-zero lie passes it.
//   "substantive" — everything else: equality to persisted state, ownership,
//                   membership, inequality between two named values.
//
// The sentinel set is exactly guardStrength's class-1 set (the same two
// matchers guardStrength uses), so the two never disagree about what a
// sentinel is.
func GuardForm(cond string) string {
	if _, ok := pyGuard1.search(cond, 0); ok {
		return "sentinel"
	}
	if reGuard1.MatchString(cond) {
		return "sentinel"
	}
	return "substantive"
}
```

(If `pyGuard1`/`reGuard1` are not package-visible at that spot, place `GuardForm` in `parser.go` next to `guardStrength` instead — same code.)

- [ ] **Step 4: Run the structidx tests**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/structidx/ -count=1`
Expected: PASS (vector test green; existing tests untouched).

- [ ] **Step 5: Carry the own guard text in probe_assertion.go**

In `internal/probes/probe_assertion.go`, `ownGuardClasses` keeps only the class. Add a sibling that also keeps the winning guard's text, and use it when emitting the joined row:

```go
// ownGuardSite is the entry's own strongest guard for one concept key:
// (class, text). Ties on class keep the first in guard order.
type ownGuardSite struct {
	class int
	text  string
}

// ownGuardSites is ownGuardClasses extended with the winning guard's text.
func ownGuardSites(e validation.Value) map[string]ownGuardSite {
	own := map[string]ownGuardSite{}
	for _, g := range guardsOf(e) {
		for _, key := range vStrList(g, "concept_keys") {
			c := guardClass(g)
			if cur, ok := own[key]; !ok || c > cur.class {
				own[key] = ownGuardSite{class: c, text: vStr(g, "text")}
			}
		}
	}
	return own
}
```

In `assertionConsumers`, switch `own := ownGuardClasses(e)` to `ownSites := ownGuardSites(e)` (derive `own[key]` as `ownSites[key].class`), and when appending the joined raw row add the two conditional fields:

```go
if site := ownSites[key]; structidx.GuardForm(site.text) == "sentinel" {
	mods = nil // (keep the existing mods variable; see note)
}
```

Concretely — compute once, before `*raw = append(...)`:

```go
site := ownSites[key]
ownForm := structidx.GuardForm(site.text)
extra := []validation.KV{
	kv("asserter", validation.VStr(st.name)),
	kv("asserter_line", validation.VInt(int64(st.line))),
	kv("assert_class", validation.VInt(int64(st.class))),
	kv("own_class", validation.VInt(int64(ownSites[key].class))),
}
if ownForm == "sentinel" {
	extra = append(extra,
		kv("own_form", validation.VStr("sentinel")),
		kv("own_guard_text", validation.VStr(site.text)))
}
*raw = append(*raw, rawRow(cname, vStr(e, "name"), vInt(e, "line"),
	key, TierOfGate(mods, model), GateLabel(mods, model),
	4-ownSites[key].class, vStr(e, "name"), extra...))
```

The fields are conditional, so every row the shipped fixtures already produce keeps its exact byte shape (parity goldens untouched).

- [ ] **Step 6: Override the why for sentinel rows**

`internal/probes/collapse.go:309` renders `why` with `formatMap(spec.whyTemplate, row)`. After that line, add:

```go
if vStr(row, "own_form") == "sentinel" {
	vSet(&row, "why", validation.VStr(sentinelWhy(row)))
}
```

and in the same file:

```go
// sentinelWhy replaces the template why for a sentinel-guarded row: the
// generic "asserted there, consumed here" question is not the question this
// row raises. The check the consumer runs cannot express the property the
// asserter asserts, so the disposition has to name the value that passes it.
func sentinelWhy(row validation.Value) string {
	return vStr(row, "consumer") + "#" + vStr(row, "consumer_line") +
		" guards " + vStr(row, "concept_keys") + " with a SENTINEL check (" +
		vStr(row, "own_guard_text") + ") — any non-zero value passes it. " +
		"Name the value that passes and who asserts its truth before " +
		"calling this pair covered."
}
```

- [ ] **Step 7: Schema + fixture + probe test**

1. `assets/schema/probe_surface.schema.json`: in the assertion-strength row object, add optional `"own_form": {"const": "sentinel"}` and `"own_guard_text": {"type": "string", "minLength": 1}`. (If the schema models rows as one object with `additionalProperties: false` per probe, add the properties to the assertion-strength branch; leave every other probe untouched.)
2. Run `python3 scripts/sync-asset-manifest.py` and commit the manifest delta.
3. New fixture tree `internal/probes/testdata/probes/assertion_strength/sentinel/` — mirror the layout of the sibling `buggy/` tree (copy its file set; check `internal/probes/probes_test.go` helpers `t29Index`/`t29Raw` for how a tree is loaded). The Solidity source must produce exactly the gold shape: an entry point that WRITES the concept key under a sentinel guard, and a second function asserting the same key at class 4, e.g.

```solidity
contract RollupSentinel {
    bytes32 public prevStateRoot;

    function commitBatch(bytes32 root) external {
        require(root != bytes32(0)); // sentinel: any non-zero lie passes
        prevStateRoot = root;
    }

    function finalizeBatch(bytes32 claimed) external view {
        require(claimed == prevStateRoot); // class-4 asserter
    }
}
```

4. Probe test appended to `internal/probes/probes_test.go`:

```go
// TestAssertionStrengthSentinelGuard pins the sentinel clause: a consumer
// whose own guard is a zero-check carries own_form=own_guard_text and the
// adversarial why; the class-4 join still happens (the row is emitted) —
// the point is that "covered" now demands the passing value.
func TestAssertionStrengthSentinelGuard(t *testing.T) {
	idx := t29Index(t, filepath.Join(t29ProbesDir, "assertion_strength", "sentinel"))
	out := t29Raw(t, idx, validation.VNull(), "assertion-strength")
	if len(out) != 1 {
		t.Fatalf("rows = %d, want 1: %s", len(out), t29JSON(validation.VArr(out...)))
	}
	row := out[0]
	if vStr(row, "own_form") != "sentinel" {
		t.Errorf("own_form = %q, want sentinel", vStr(row, "own_form"))
	}
	if !strings.Contains(vStr(row, "own_guard_text"), "!= bytes32(0)") {
		t.Errorf("own_guard_text = %q", vStr(row, "own_guard_text"))
	}
	if !strings.Contains(vStr(row, "why"), "SENTINEL check") ||
		!strings.Contains(vStr(row, "why"), "Name the value that passes") {
		t.Errorf("why = %q — want the adversarial sentinel why", vStr(row, "why"))
	}
}
```

(Adapt helper names to the actual ones in `probes_test.go` if `t29Raw`'s signature differs — read the file first; keep the assertions exactly.)

5. Zero-churn guard: run the full probes suite — `GOCACHE=$PWD/.scratch/gocache go test ./internal/probes/ -count=1`. `parity_test.go` and the golden-vector tests must stay green WITHOUT regenerating anything. If any pinned vector moved, your field is not conditional — fix that, do not re-record.

- [ ] **Step 8: Commit**

```bash
git add internal/structidx/guardform.go internal/structidx/guardform_test.go \
  internal/probes/probe_assertion.go internal/probes/collapse.go \
  internal/probes/probes_test.go internal/probes/testdata/probes/assertion_strength/sentinel \
  assets/schema/probe_surface.schema.json assets/testdata/asset_manifest.json
git commit -m "feat(probes): sentinel-form rows — a zero-check cannot assert truth (own_form + adversarial why)"
```

---

### Task 2: Falsifiable "covered" — closing a sentinel row demands the passing value

The B4 disposition linter (`internal/planner/disposition.go`, plumbed through `planner/answered.go` `MarkAnswered` and `internal/cli/cmd_answered.go`) already refuses anchorless probe dispositions and flags weak dismissal language, with `--override-dismissal/--override-reason` as the family's single escape hatch. This task adds the B4 v3 rule: a CLOSING disposition (outcome `answered` or `not-applicable`) of a probe row whose surface row carries `own_form == "sentinel"` must name the value that passes the check (`--passes VALUE`) or take the explicit override. "An assertion exists" stops being a sufficient answer for sentinel-guarded pairs.

**Files:**
- Modify: `internal/planner/disposition.go` (the lint rule + priority payload field)
- Modify: `internal/planner/answered.go` (`AnsweredOpts` gains `PassesValue *string`; thread to the lint)
- Modify: `internal/cli/cmd_answered.go` (`--passes` flag, guarded parsing, help text)
- Modify: `assets/schema/campaign_plan.schema.json` (optional `passes` string on priority items)
- Test: `internal/planner/disposition_test.go`, `internal/cli/cmd_answered_disposition_test.go`
- Re-sync: `assets/testdata/asset_manifest.json`

**Interfaces:**
- Consumes: `own_form` on surface rows (Task 1); `AnsweredOpts{Anchor, OverrideDismissal, OverrideReason, ...}`; the surface-row lookup the anchorless check already performs (the lint sees the row value).
- Produces: `AnsweredOpts.PassesValue *string`; priority field `passes` (string, optional). Refusal message (exact, used by tests):

  `sentinel-guarded probe row <row_id>: a closing disposition must name the value that passes its check (--passes VALUE) — or override explicitly (--override-dismissal --override-reason R)`

- [ ] **Step 1: Write the failing planner test**

Append to `internal/planner/disposition_test.go` (reuse the file's existing campaign/surface fixtures — read the file first and mirror how `TestDispositionLint…` builds a surface with one probe row):

```go
// TestDispositionLintSentinelRowDemandsPasses: a closing disposition of a
// sentinel-guarded row (own_form=sentinel from the surface) is refused
// without --passes, accepted with it, and the stored priority carries it.
func TestDispositionLintSentinelRowDemandsPasses(t *testing.T) {
	// Fixture: the disposition_test.go surface builder, with the one row's
	// object extended by own_form:"sentinel", own_guard_text:"root != bytes32(0)".
	camp, surface, rowID := sentinelDispositionFixture(t)

	_, _, err := plannerMarkAnsweredForTest(t, camp, rowID, "answered",
		&AnsweredOpts{Anchor: strPtr("consumer")})
	if err == nil || !strings.Contains(err.Error(),
		"a closing disposition must name the value that passes its check") {
		t.Fatalf("err = %v, want the sentinel --passes refusal", err)
	}

	passes := "any non-zero root; its truth is asserted at finalizeBatch"
	_, _, err = plannerMarkAnsweredForTest(t, camp, rowID, "answered",
		&AnsweredOpts{Anchor: strPtr("consumer"), PassesValue: &passes})
	if err != nil {
		t.Fatalf("with --passes: %v", err)
	}
	prio := storedPriority(t, camp, rowID)
	if objStr(prio, "passes") != passes {
		t.Errorf("passes = %q", objStr(prio, "passes"))
	}
}
```

Write the three helpers the test names (`sentinelDispositionFixture`, `plannerMarkAnsweredForTest`, `storedPriority`) in the same file, modeled on the existing fixture helpers at the top of `disposition_test.go` — the existing tests already show how a campaign + surface + one row are built and how `MarkAnswered` is invoked in-package.

- [ ] **Step 2: Run it to see it fail**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/planner/ -run TestDispositionLintSentinelRowDemandsPasses -count=1`
Expected: FAIL — no refusal happens (rule does not exist).

- [ ] **Step 3: Implement the rule**

In `internal/planner/disposition.go`, inside the lint path that already receives the surface row for a probe disposition (where `checkAnchorless` resolves the row), add:

```go
// checkSentinelPasses is the B4 v3 rule: a closing disposition of a
// sentinel-guarded row (own_form=sentinel) must name the value that passes
// the check. Existence of an assertion is not correctness; the disposition
// has to be falsifiable. The family escape hatch (--override-dismissal with
// --override-reason) stays the only way around it.
func checkSentinelPasses(row validation.Value, outcome string,
	opts AnsweredOpts) error {
	if outcome != "answered" && outcome != "not-applicable" {
		return nil
	}
	if vStr(row, "own_form") != "sentinel" {
		return nil
	}
	if opts.PassesValue != nil && len(strings.TrimSpace(*opts.PassesValue)) >= 3 {
		return nil
	}
	return errValue("sentinel-guarded probe row " + rowIDOf(row) +
		": a closing disposition must name the value that passes its check " +
		"(--passes VALUE) — or override explicitly (--override-dismissal " +
		"--override-reason R)")
}
```

(`rowIDOf` = however the existing lint code names the row — reuse its accessor. Wire the call next to `checkAnchorless` so both run in the same place, and store `*opts.PassesValue` on the priority as `passes` where the disposition stamp is written. When `OverrideDismissal` is true the rule passes — the override reason is the record.)

In `internal/planner/answered.go`: add `PassesValue *string` to `AnsweredOpts`; in `internal/cli/cmd_answered.go`: parse `--passes` with the guarded value case (`case a == "--passes" && i+1 < len(args) && !looksLikeOption(args[i+1]):`), extend both usage/help blocks (the file has two — the short usage and the long help; add one line to each: `--passes VALUE       sentinel-guarded rows only: the value that passes the check`), and pass it into `AnsweredOpts`.

- [ ] **Step 4: Schema + manifest**

`assets/schema/campaign_plan.schema.json`: priority items gain optional `"passes": {"type": "string", "minLength": 3}`. Run `python3 scripts/sync-asset-manifest.py`.

- [ ] **Step 5: CLI-level test + accepting path**

Append to `internal/cli/cmd_answered_disposition_test.go`, mirroring the file's existing CLI invocation pattern:

```go
// TestAnsweredCLISentinelPassesFlag: the CLI refuses the closing disposition
// of a sentinel row without --passes (naming both exits), accepts it with
// the flag, and the refusal leaves the priority untouched.
func TestAnsweredCLISentinelPassesFlag(t *testing.T) {
	// Build the same fixture shape the file's override test uses, with the
	// surface row carrying own_form/own_guard_text.
	// (1) refusal: run the verb with outcome answered, no --passes; expect
	//     exit 2 and stderr containing "must name the value that passes".
	// (2) accept: same call plus --passes "any non-zero root; asserted at finalizeBatch";
	//     expect exit 0 and the priority JSON to carry "passes".
	// (3) negative control: in a throwaway copy, assert the refusal text is
	//     gone when the surface row drops own_form (the rule is row-scoped).
}
```

Implement the three sub-cases concretely in the file's established style (the file already shows how to drive the verb end-to-end and read the priority back).

- [ ] **Step 6: Run the package suites**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/planner/ ./internal/cli/ -count=1`
Expected: PASS. If any existing disposition test now refuses (a fixture row that turns out to be sentinel-shaped), that fixture row is exactly the class of prose-closure this rule exists to stop — update the fixture to carry `--passes` and note it in the report.

- [ ] **Step 7: Commit**

```bash
git add internal/planner/disposition.go internal/planner/answered.go \
  internal/planner/disposition_test.go internal/cli/cmd_answered.go \
  internal/cli/cmd_answered_disposition_test.go \
  assets/schema/campaign_plan.schema.json assets/testdata/asset_manifest.json
git commit -m "feat(planner): B4 v3 — closing a sentinel-guarded row demands the value that passes"
```

---

### Task 3: Discovery-slot reform — suspicion is free, confirmation is metered

Today every `ingest_hypothesis` consumes a discovery slot at E0 and is refused at the ceiling (`internal/findings/ingest.go:258-263` refusal, `:342` unconditional consume). That prices paranoia above tidiness — the exact inverse of what discovery needs. Reform: the slot is consumed once per finding, at the moment the finding first rises above the E0 baseline (first above-E0 evidence or first status promotion above E0), never at bare-hypothesis ingest. The budget counter (`budget.discovery_findings_so_far`), its ceiling (`budget.max_discovery_findings`), and both key names stay exactly as they are — only the consumption point and one display word move.

**Files:**
- Create: `internal/findings/slot.go`
- Modify: `internal/findings/ingest.go` (remove the ingest-time check + consume; call the new helper on pre-loaded rises)
- Modify: `internal/findings/transitions.go` (consume on promotion above E0)
- Modify: `internal/findings/levels_test.go` or `internal/findings/ingest_test.go` (new tests)
- Modify: `internal/cli/cmd_budget.go` (display word), `internal/cli/cmd_budget_test.go`
- Modify: `internal/briefing/briefing.go:~1556` (remaining-budget arithmetic comment/wording only if it lies)
- Modify: `assets/schema/finding.schema.json` (optional boolean `discovery_slot_consumed`)
- Re-sync: `assets/testdata/asset_manifest.json`

**Interfaces:**
- Consumes: `campaign.ConsumeDiscoverySlot()` (`internal/state/phases.go:131`), `Budget()`, `LevelIndex(level)` + `"E0"` baseline, `LoadFinding`/`SaveFinding`.
- Produces: `findings.ConsumeSlotOnce(campaign *state.Campaign, finding *validation.Value) error` — idempotent per finding via the finding's own `discovery_slot_consumed` flag; the budget-exhausted error text is EXACTLY the current ingest text: `discovery budget exhausted — raise the ceiling (webv2 budget <campaign> --set-discovery N --actor NAME) or plan a new pass`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/findings/ingest_test.go` (reuse the file's campaign fixture helpers; read the file first):

```go
// TestDiscoverySlotConsumedOnRiseNotIngest: a bare hypothesis costs no slot;
// the first above-E0 evidence consumes exactly one; a second item consumes
// no more; a finding that ingests WITH pre-loaded above-E0 evidence pays at
// ingest.
func TestDiscoverySlotConsumedOnRiseNotIngest(t *testing.T) {
	c := ingestCampaign(t)
	f := ingestBare(t, c) // existing helper shape: schema-valid HYPOTHESIS
	assertSlotCount(t, c, 0)
	if objBool(f, "discovery_slot_consumed") {
		t.Fatal("bare hypothesis must not carry the slot flag")
	}

	f = addEvidenceOfLevel(t, c, f, "E1") // whatever the file's add_evidence helper is
	assertSlotCount(t, c, 1)
	if !objBool(f, "discovery_slot_consumed") {
		t.Fatal("first above-E0 evidence must set the slot flag")
	}
	f = addEvidenceOfLevel(t, c, f, "E2")
	assertSlotCount(t, c, 1) // idempotent

	c2 := ingestCampaign(t)
	ingestWithEvidence(t, c2, "E1") // pre-loaded rise
	assertSlotCount(t, c2, 1)
}
```

Also append a refusal test: with `max_discovery_findings` set to 1 and the slot already consumed by finding A, adding above-E0 evidence to finding B fails with the exact ingest-era text (the ceiling still gates rises, not hypotheses).

Write `assertSlotCount` as: load campaign state, read `budget.discovery_findings_so_far`, compare.

- [ ] **Step 2: Run them to see them fail**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/findings/ -run TestDiscoverySlot -count=1`
Expected: FAIL — the bare ingest currently consumes a slot (count 1, not 0).

- [ ] **Step 3: Implement `slot.go` and rewire the seams**

`internal/findings/slot.go`:

```go
package findings

import (
	"fmt"

	"websec/internal/state"
	"websec/internal/validation"
)

// ConsumeSlotOnce charges the campaign's discovery budget for one finding,
// exactly once per finding, and only when the caller has established the
// finding ROSE above the E0 baseline. Bare hypotheses (HYPOTHESIS at E0 with
// no above-baseline evidence) never reach this — suspicion is free, the
// ceiling meters confirmed work instead. The finding carries the flag so the
// idempotency survives snapshots and re-loads.
func ConsumeSlotOnce(campaign *state.Campaign, finding *validation.Value) error {
	if objBool(*finding, "discovery_slot_consumed") {
		return nil
	}
	budget, err := campaign.Budget()
	if err != nil {
		return err
	}
	if objAt(budget, "discovery_findings_so_far").I >=
		objAt(budget, "max_discovery_findings").I {
		return fmt.Errorf("%s",
			"discovery budget exhausted — raise the ceiling (webv2 budget "+
				campaign.CampaignID+" --set-discovery N --actor NAME) or plan a new pass")
	}
	if err := campaign.ConsumeDiscoverySlot(); err != nil {
		return err
	}
	finding.O = validation.SetOrAppend(finding.O,
		"discovery_slot_consumed", validation.VBool(true))
	return nil
}

// risesAboveBaseline reports whether adding an item of this level (or
// promoting to this status) lifts the finding above E0 for the first time.
func risesAboveBaseline(finding validation.Value, level string) bool {
	li, err := LevelIndex(level)
	if err != nil {
		return false
	}
	e0, _ := LevelIndex("E0")
	if li <= e0 {
		return false
	}
	for _, it := range objAt(finding, "evidence").A {
		prev, err := LevelIndex(objStr(it, "level"))
		if err == nil && prev > e0 {
			return false // already rose before
		}
	}
	return !objBool(finding, "discovery_slot_consumed")
}
```

Rewire:
1. `ingest.go` `IngestHypothesis`: DELETE the ceiling check at lines 254-263 and the `ConsumeDiscoverySlot()` call at line 342. After the existing pre-loaded-evidence guardrail block (where `FindingLevel(p)` is computed), if the payload's top evidence level is above E0, call `ConsumeSlotOnce(campaign, &p)` and return its error.
2. `ingest.go` `AddEvidence`: after `enforceRiseGuardrail` (line ~521) and before the evidence append, call:

```go
if risesAboveBaseline(finding, level) {
	if err := ConsumeSlotOnce(campaign, &finding); err != nil {
		return validation.VNull(), err
	}
}
```

3. `transitions.go`: in the move/promotion path (find where a legal transition validates and saves — search `TransitionAllowed` usage), after validation and before save: if the new status's level index is above the old status's AND above E0, call `ConsumeSlotOnce(campaign, &finding)` (load the finding Value the function already holds). If the move path constructs a fresh payload rather than holding a Value, set the flag on the saved object the same way the history entry is appended — read the function first and follow its pattern.

- [ ] **Step 4: Schema + display**

1. `assets/schema/finding.schema.json`: add optional `"discovery_slot_consumed": {"type": "boolean"}` (top level of the finding object; absent = pre-reform findings, which is the point). Run `python3 scripts/sync-asset-manifest.py`.
2. `internal/cli/cmd_budget.go` (lines ~187-190 and ~238): the human text says `(N recorded so far; ceiling M)` — "recorded" is now a lie. Change the noun to `risen so far` in BOTH render sites. Update `cmd_budget_test.go:91`'s expected string to match.
3. `internal/briefing/briefing.go` ~1556: the remaining-arithmetic reads the same two keys — semantics unchanged, so no code change unless a nearby string says "recorded"; fix the noun there too if so.

- [ ] **Step 5: Run the findings + cli + briefing suites**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/findings/ ./internal/cli/ ./internal/briefing/ -count=1`
Expected: PASS. `ingest_test.go:158` asserts `discovery_findings_so_far == 1` after a plain ingest — that assertion is the old behavior: change it to 0 and extend the test with the rise path (that edit is part of Step 1/3, listed here so it is not missed). Any other test that relied on ingest-time consumption gets the same treatment: assert at the rise, not the ingest.

- [ ] **Step 6: Commit**

```bash
git add internal/findings/slot.go internal/findings/ingest.go \
  internal/findings/transitions.go internal/findings/ingest_test.go \
  internal/cli/cmd_budget.go internal/cli/cmd_budget_test.go \
  internal/briefing/briefing.go assets/schema/finding.schema.json \
  assets/testdata/asset_manifest.json
git commit -m "feat(findings): discovery slot charged at first rise above E0, not at hypothesis ingest"
```

---

### Task 4: Payout-funding sub-question on funding-mismatch divergences

The G-02 miss: the custody matrix printed the mint/burn cells adjacently and the operator still never asked "what funds the refund payout, from which balance?" The framework cannot know deployment funding statically — but it CAN attach the question to every row that already reports a funding mismatch, so dismissing the row requires answering it. This is deliberately a forced question, not a computed verdict (a static "unfunded" detector would be wrong for escrow deployments).

**Files:**
- Modify: `internal/probes/symmetry.go` (`SymQuestion` and/or `symDivergenceValues` — where the funding-mismatch kind's question string is built)
- Test: `internal/probes/symmetry_test.go`

**Interfaces:**
- Consumes: the existing `SymFundingMismatch` divergence kind and its question rendering (`internal/probes/symmetry.go:484` `SymQuestion`, `symDivergenceValues`).
- Produces: funding-mismatch divergence rows whose `question` (and therefore the rendered `why`/CLI text via `cmd_symmetry.go`) ends with the exact sub-question:

  ` Who funds the observed payout — name the primitive that credits the paying balance for this asset; if none exists, the payout draws from an unfunded balance.`

  No other divergence kind changes; rows without a funding mismatch are byte-identical.

- [ ] **Step 1: Write the failing test**

Append to `internal/probes/symmetry_test.go` (the file already has a funding-mismatch fixture — the test at line ~115 asserts a row with `divergence == SymFundingMismatch`; reuse its builder):

```go
// TestFundingMismatchCarriesPayoutQuestion: the funding-mismatch question
// ends with the payout-funding sub-question, so dismissing the row requires
// naming the crediting primitive (or recording that none exists).
func TestFundingMismatchCarriesPayoutQuestion(t *testing.T) {
	rows := fundingMismatchRows(t) // the existing fixture builder
	if len(rows) == 0 {
		t.Fatal("fixture lost its funding-mismatch row")
	}
	const suffix = " Who funds the observed payout — name the primitive that " +
		"credits the paying balance for this asset; if none exists, the payout " +
		"draws from an unfunded balance."
	if !strings.HasSuffix(vStr(rows[0], "question"), suffix) {
		t.Errorf("question = %q\nwant suffix %q", vStr(rows[0], "question"), suffix)
	}
	// Non-mismatch divergences stay unchanged.
	for _, r := range nonMismatchDivergenceRows(t) {
		if strings.Contains(vStr(r, "question"), "Who funds the observed payout") {
			t.Errorf("sub-question leaked into a %q row", vStr(r, "divergence"))
		}
	}
}
```

Write the two small builders by refactoring the existing funding-mismatch test's setup into shared helpers if needed (the fixture exists; do not rebuild the corpus).

- [ ] **Step 2: Run it to see it fail**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/probes/ -run TestFundingMismatchCarriesPayoutQuestion -count=1`
Expected: FAIL — the suffix is missing.

- [ ] **Step 3: Implement**

In `internal/probes/symmetry.go`, find where the funding-mismatch divergence's question string is composed (follow `SymFundingMismatch` to its construction site). Append the constant sub-question exactly as specified, e.g.:

```go
// payoutFundingQuestion is the forced question every funding-mismatch row
// carries: the matrix shows the primitive divergence, but the miss that
// matters is the payout path — what credits the balance the payout draws
// from. The framework cannot know deployment funding; it can refuse to let
// the question go unasked.
const payoutFundingQuestion = " Who funds the observed payout — name the " +
	"primitive that credits the paying balance for this asset; if none " +
	"exists, the payout draws from an unfunded balance."
```

- [ ] **Step 4: Reconcile pinned strings and run**

The existing symmetry tests pin exact question strings for the funding-mismatch row(s) (search `symmetry_test.go` for the fixture's expected question text) — update those `want` strings by appending the same suffix. Then:

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/probes/ ./internal/cli/ -count=1`
Expected: PASS. Zero golden churn: the shipped probe fixtures produce no funding-mismatch rows (verify — `parity_test.go` green untouched). If one does, STOP and report: the fixture corpus has a funding mismatch the goldens pin, and the re-record must be reviewed, not waved through.

- [ ] **Step 5: Commit**

```bash
git add internal/probes/symmetry.go internal/probes/symmetry_test.go
git commit -m "feat(probes): funding-mismatch rows force the payout-funding question"
```

---

### Task 5: Divergence diversity gate counts findings — planner stops blocking on its own output

The gate demands >= 4 distinct canonical `bug_class` values across `priorities[]` (`internal/planner/gates.go:76-83`, `MinDistinctClasses = 4` in `internal/planner/planner.go:27`), but auto-generated priorities carry no `bug_class`, so the gate is unsatisfiable without hand-patching the artifact — a gate bug. Two halves, both cheap: (a) the campaign-aware wrapper feeds the classes the campaign's own findings already name, (b) the plan builder stamps `bug_class` on priorities when the source row names one.

**Files:**
- Modify: `internal/planner/gates.go` (`DivergenceOpts` gains `CampaignClasses []string`; `namedClasses` unions them)
- Modify: `internal/planner/gates.go` (`DivergenceStatusFor` collects classes from the campaign's findings)
- Modify: `internal/planner/plan.go` (the priority builder at ~line 150-230: stamp `bug_class` from the source row when it carries a canonical class)
- Test: `internal/planner/gates_test.go`, `internal/planner/plan_test.go` (or the file holding builder tests)

**Interfaces:**
- Consumes: `namedClasses(plan)`; the campaign findings store (`internal/findings` LoadAll-style accessor the planner already uses elsewhere — check how `DivergenceStatusFor`'s siblings read findings; if none does, read findings via the state campaign dir listing with `validation.ListPrefixed` semantics through the findings package's public loader).
- Produces: `DivergenceOpts.CampaignClasses []string`. Pure `DivergenceStatus` output shape is UNCHANGED when `CampaignClasses` is nil (oracles stay byte-identical); with it, `named_classes` is the sorted union and the diversity `what` text reads `"<n> distinct bug class(es) named (…); min 4 — set priorities[].bug_class or file findings naming them"`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/planner/gates_test.go` (mirror the file's `DivergenceStatus` table style):

```go
// TestDivergenceDiversityCountsCampaignFindings: an empty-class plan is no
// longer unsatisfiable when the campaign's findings name 4 canonical classes;
// with fewer the gate stays open and the hint names both exits.
func TestDivergenceDiversityCountsCampaignFindings(t *testing.T) {
	plan := noClassPlan(t) // the file's fixture: priorities without bug_class
	open := DivergenceStatus(plan, DivergenceOpts{
		CampaignClasses: []string{"access-control", "reentrancy"}})
	if closed(open) {
		t.Fatal("2 classes must stay open")
	}
	if !strings.Contains(divWhat(open, "diversity"),
		"or file findings naming them") {
		t.Errorf("hint = %s", divWhat(open, "diversity"))
	}
	closedG := DivergenceStatus(plan, DivergenceOpts{
		CampaignClasses: []string{"a", "b", "c", "d"}})
	// (use real canonical classes in the actual test)
	if !closed(closedG) {
		t.Fatal("4 distinct classes must close the diversity clause")
	}
	if len(listAt(asObj(closedG), "missing")) != 0 {
		t.Errorf("missing = %s", t29JSON(objAt(closedG, "missing")))
	}
}
```

Plus a builder test in the plan-builder test file: a priority built from a source row that names `bug_class: "logic-error"` carries `bug_class: "logic-error"`; a source row without one stays empty (no invented classes).

- [ ] **Step 2: Run them to see them fail**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/planner/ -run 'TestDivergenceDiversity|TestPlanBuilder' -count=1`
Expected: FAIL.

- [ ] **Step 3: Implement**

`gates.go`:

```go
// In DivergenceOpts:
// CampaignClasses carries the canonical bug classes the campaign's own
// findings already name. The diversity clause unions them with the plan's
// priorities: a shape the model dispositioned by filing a finding was named
// whether or not the planner stamped the priority. nil (the pure function)
// keeps the plan-only behavior byte-identical.
	CampaignClasses []string
```

`namedClasses` becomes:

```go
func namedClasses(plan validation.Value, campaign []string) []string {
	seen := map[string]struct{}{}
	for _, p := range listOf(plan, "priorities") {
		if bc := objAt(p, "bug_class"); pyTruthyBigNonEmpty(bc) {
			seen[pyStr(bc)] = struct{}{}
		}
	}
	for _, c := range campaign {
		if c != "" {
			seen[c] = struct{}{}
		}
	}
	return sortedKeys(seen)
}
```

Update the call in `DivergenceStatus` (`named := namedClasses(plan, opts.CampaignClasses)`) and the diversity `what` text to the new hint. In `DivergenceStatusFor`, collect the classes before the call:

```go
classes, err := PB().CampaignBugClasses(campaign)
```

implement `CampaignBugClasses` on the planner's port boundary (the same file/registry where `PB().CampaignSurface` lives): iterate the campaign's findings, collect `root_cause.class` values that are canonical (reuse the canonical-class check `save_plan` uses — `internal/findings/transitions.go:411-415` shows the validation seam), sorted, deduped. In `plan.go`'s builder loop (~line 177 `b.priorities = append(...)`), stamp `bug_class` when the builder's source row has one:

```go
if bc := objAt(src, "bug_class"); pyTruthyBigNonEmpty(bc) {
	prio.O = validation.SetOrAppend(prio.O, "bug_class", bc)
}
```

(read the actual loop variable names first; only stamp CANONICAL classes — if the source class is not canonical, leave it empty rather than poisoning the gate.)

- [ ] **Step 4: Run the planner suite + watch the golden surface**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/planner/ ./internal/briefing/ ./internal/completion/ -count=1`
Expected: PASS. Pure `DivergenceStatus` calls (nil opts) are byte-identical — the planner scenario oracles (`planner_scenario_test.go`) must not move. The campaign-aware path only ever ADDS classes, so a gate that was open can close: run `bash scripts/golden.sh` once (single instance — no concurrent golden runs) and if any step's divergence lines changed, the capture updates are part of this task; the delta must be exactly gate-lines moving open→closed, nothing else. If a golden step relied on the gate being open for a campaign whose findings name >= 4 classes, that step's expectation updates with a note in the commit message.

- [ ] **Step 5: Commit**

```bash
git add internal/planner/gates.go internal/planner/gates_test.go \
  internal/planner/plan.go internal/planner/<port-file>.go \
  internal/planner/<builder-test-file>.go
git commit -m "fix(planner): diversity gate counts findings' classes; builder stamps canonical bug_class"
```

---

### Task 6: plan --json stops lying

The text view prints `plan: N queued priorities` from `res.work_queue`, but the `--json` branch's machine view underreports (the operator saw `priorities: 0` against a 24-priority text view). In an agent-facing tool, machine-readable output that lies is worse than none. Fix: the JSON branch emits the SAME work queue the text view prints, plus the priorities count, and a test pins text/json agreement.

**Files:**
- Modify: `internal/cli/cmd_plan.go` (`planOutputJSON`)
- Test: `internal/cli/cmd_plan_test.go`

**Interfaces:**
- Consumes: `orchestrator.New(c).Plan(...)` response (`res`), `planner.LoadPlanReadonly`.
- Produces: `plan --json` output containing, at minimum and consistent with the text view: `work_queue` (the same array `planOutputQueue` prints), `lenses`, `divergence`, and `priorities` (integer, `len(work_queue)` source of truth — the plan's `priorities` array length, matching what the text view queues). The keys already present stay; no key is removed.

- [ ] **Step 1: Write the failing test**

Extend `internal/cli/cmd_plan_test.go` (the file already builds a campaign with a seeded plan and asserts the text view at lines ~35-123 — read it, reuse its fixture):

```go
// TestPlanJSONMatchesTextQueue: --json is the machine view of the SAME data
// the text view prints — the work queue must be present and non-empty when
// the text view queues priorities, and every count must agree.
func TestPlanJSONMatchesTextQueue(t *testing.T) {
	c, planFile := t14SeededPlanCampaign(t) // the existing fixture helper
	outJSON := runPlanCapture(t, c, "--json", planFile)
	outText := runPlanCapture(t, c, planFile)

	var doc map[string]any
	if err := json.Unmarshal([]byte(outJSON), &doc); err != nil {
		t.Fatalf("plan --json not JSON: %v", err)
	}
	wq, ok := doc["work_queue"].([]any)
	if !ok || len(wq) == 0 {
		t.Fatalf("work_queue missing/empty in --json: %s", outJSON)
	}
	want := fmt.Sprintf("plan: %d queued priorities", len(wq))
	if !strings.Contains(outText, want) {
		t.Fatalf("text view %q does not agree with json queue %d", want, len(wq))
	}
	if n, ok := doc["priorities"].(float64); !ok || int(n) != len(wq) {
		t.Fatalf("priorities = %v, want %d", doc["priorities"], len(wq))
	}
}
```

Implement `runPlanCapture` per the file's existing CLI-runner helper pattern. If the fixture helper names differ, adapt names, keep assertions exactly.

- [ ] **Step 2: Run it to see it fail**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/cli/ -run TestPlanJSONMatchesTextQueue -count=1`
Expected: FAIL — the JSON branch drops or empties the queue/count.

- [ ] **Step 3: Fix the JSON branch**

In `planOutputJSON`, before dumping, make the machine view complete and self-consistent:

```go
queue := objAt(res, "work_queue")
res.O = validation.SetOrAppend(res.O, "work_queue", queue)
res.O = validation.SetOrAppend(res.O, "priorities",
	validation.VInt(int64(t14PyLen(queue))))
```

If the diagnosis shows the empty queue comes from `orchestrator.Plan` (read-only path returning no queue rather than cmd_plan dropping it), fix it at the cmd_plan layer by deriving the queue from the loaded plan (`p`) instead of changing orchestrator semantics: build the `work_queue` array from `plan.priorities` entries the same filter `planOutputQueue`'s source uses (read `orchestrator`'s queue construction and mirror its filter). Document which case it was in the report — the test does not care where the fix lands, only that text and JSON agree.

- [ ] **Step 4: Run the cli suite**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/cli/ -count=1`
Expected: PASS (existing `--json` assertions in `cmd_plan_test.go` may need their expected document extended with the new keys — extend, never delete).

- [ ] **Step 5: Commit**

```bash
git add internal/cli/cmd_plan.go internal/cli/cmd_plan_test.go
git commit -m "fix(cli): plan --json carries the real work queue and priorities count"
```

---

### Task 7: Hygiene batch — truncation, WEBV2_ROOT, targeted DUPLICATE, register notice

Four small operator-facing fixes from the post-mortem's sharp-edge list. Each is independently committable; land them as one task with four commits.

**Files:**
- Modify: `internal/cli/cmd_probes.go` (row-table console cap), `internal/cli/cmd_snap.go` (path dump cap — find the exact verb file by `rg -l "snap" internal/cli/cmd_*.go`)
- Modify: `internal/cli/cli.go` (`splitRoot`: `WEBV2_ROOT` env + ancestor walk-up)
- Modify: `internal/cli/cmd_move.go` + `internal/findings/transitions.go` (`--of` required for DUPLICATE; `DUPLICATE -> HYPOTHESIS` reopen clears the target)
- Modify: `internal/cli/cmd_register.go` (post-registration immutability notice)
- Test: the four files' `_test.go` siblings

**Interfaces:**
- Consumes: `RowDispositions`/surface rows in `cmd_probes.go`'s print loop (~line 640-692); `splitRoot` (`cli.go:212-226`); `MarkDuplicate` (`internal/findings/transitions.go:734`); `ALLOWED_TRANSITIONS` (`internal/findings/levels.go`).
- Produces: (a) console tables longer than 40 rows print the first 40 then exactly one line `  … +<K> more rows — use --json for the full table`; (b) root resolution order: `--root` flag > `WEBV2_ROOT` env > walk-up (nearest ancestor of cwd containing a `campaigns/` directory, max 5 levels) > `.`; (c) `move <c> <f> DUPLICATE` without `--of <fid>` refuses with `move to DUPLICATE must name the duplicate of (--of <finding-id>)`; `move <c> <f> HYPOTHESIS` from DUPLICATE is a legal reopen that clears the recorded duplicate target; (d) every successful `register` prints `note: registered artifacts are immutable — to revise, register a new artifact (the old one stays for provenance)` after the success line.

- [ ] **Step 1: Truncation — failing tests first**

In the probes CLI test file, drive a surface with >40 rows (the file's 10-row fixtures are too small — extend the existing multi-row fixture by duplicating rows in the fixture builder, or lower nothing: the cap is a constant `consoleRowCap = 40` in `cmd_probes.go`, and the test uses a 45-row fixture). Assert stdout contains row lines for exactly the first 40, then the `… +5 more rows — use --json for the full table` line, and NOT the 41st row's anchor. Same pattern for the snap verb's path dump (its own test file, same constant name local to that file). Keep `--json` output untouched (full rows).

- [ ] **Step 2: Implement the caps**

In each print loop, after the loop index reaches `consoleRowCap`, stop printing rows and print the single summary line with the remaining count. Constants:

```go
// consoleRowCap bounds the console table; --json stays complete.
const consoleRowCap = 40
```

- [ ] **Step 3: WEBV2_ROOT + walk-up — failing test, then splitRoot**

Test in the cli package (pure function, no campaign needed):

```go
func TestSplitRootWalkUp(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "c")
	if err := os.MkdirAll(filepath.Join(dir, "campaigns"), 0o755); err != nil { t.Fatal(err) }
	if err := os.MkdirAll(nested, 0o755); err != nil { t.Fatal(err) }
	t.Setenv("WEBV2_ROOT", "")
	if got := resolveRoot(nested); got != dir {
		t.Errorf("walk-up = %q, want %q", got, dir)
	}
	t.Setenv("WEBV2_ROOT", nested)
	if got := resolveRoot(nested); got != nested {
		t.Errorf("env root = %q, want %q", got, nested)
	}
}
```

Implement `resolveRoot(cwd string) string` and call it from `splitRoot`'s default arm (`root := "."` becomes `root := resolveRoot(cwd)` — `splitRoot` needs the cwd; use `os.Getwd()` at the call site if `splitRoot` has no cwd parameter). Walk-up: from cwd, ascend at most 5 levels; the first ancestor containing a `campaigns/` directory wins; none → "." (today's behavior). `--root` flag still wins over everything.

- [ ] **Step 4: Targeted DUPLICATE — failing tests, then transitions**

Findings tests: (1) `move … DUPLICATE` without `--of` refuses with the exact message above; (2) with `--of F2`, the stored finding records the target (the field `MarkDuplicate` already writes — read it and assert it); (3) `move <dup> HYPOTHESIS --reason R` succeeds (extend `ALLOWED_TRANSITIONS["DUPLICATE"]` to `setOf("HYPOTHESIS")` in `internal/findings/levels.go`), clears the recorded duplicate target, and the evidence/history stay attached (the operator's lost-evidence complaint); (4) terminal-state audits that count DUPLICATEs still see the reopened finding as HYPOTHESIS (run the findings + audit suites to prove no invariant assumes DUPLICATE is forever). CLI test in `cmd_move_test.go` mirrors (1)-(3) through the verb, with `--of` guarded value parsing (`!looksLikeOption`). If the `move` CLI already accepts a target flag for DUPLICATE, keep its name and only add the refusal + reopen.

- [ ] **Step 5: Register notice — failing test, then one line**

CLI test: successful `register` output ends with the exact notice line. Implement: one `fmt.Fprintln(r.Out, …)` after the existing success output in `cmd_register.go`.

- [ ] **Step 6: Run the affected suites + the standing guards**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/cli/ ./internal/findings/ ./internal/audit/ -count=1`
Expected: PASS. `TestNoUnguardedValueConsumption` must stay green (the new `--of` case is guarded). If a golden capture pins the old un-truncated probe table or the register output, update the capture in the same commit and say so in the message.

- [ ] **Step 7: Four commits**

```bash
git add internal/cli/cmd_probes.go internal/cli/cmd_probes_test.go   # + snap files
git commit -m "feat(cli): cap console row/path dumps at 40 with a --json pointer"
git add internal/cli/cli.go internal/cli/cli_test.go
git commit -m "feat(cli): WEBV2_ROOT env + ancestor walk-up for the default root"
git add internal/cli/cmd_move.go internal/findings/transitions.go internal/findings/levels.go internal/cli/cmd_move_test.go internal/findings/<test>.go
git commit -m "feat(findings): targeted DUPLICATE (--of) and reopen to HYPOTHESIS"
git add internal/cli/cmd_register.go internal/cli/cmd_register_test.go
git commit -m "feat(cli): register prints the immutability notice"
```

---

### Task 8: Full gates, golden, release binary

**Files:**
- No source changes (fixture/capture reconciliation only if a gate surfaces drift).

**Interfaces:**
- Consumes: everything Tasks 1-7 landed.
- Produces: green `verify-full`, green golden suite, a freshly stamped binary at `dist/webv2` installed to `~/.local/bin/webv2` whose `--version` equals `git rev-parse --short=12 HEAD` with no `+dirty`.

- [ ] **Step 1: Full unit suite**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./... -count=1`
Expected: PASS. Any red here is a Task 1-7 defect — go back to that task's fix loop; do not patch forward in this task.

- [ ] **Step 2: Golden suite (single instance — never two concurrent runs)**

Run: `bash scripts/golden.sh`
Expected: MATCH. If captures moved from Tasks 3/5/7 (display text, gate lines), the moving steps' captures are updated ONLY with a diff review proving the delta is exactly the expected lines; note each moved step in the commit message.

- [ ] **Step 3: verify-full**

Run: `bash scripts/verify-full.sh`
Expected: all steps green (reference pytest step skips by default — leave it skipped).

- [ ] **Step 4: Release build + install + stamp proof**

Run: `bash scripts/release.sh && install -m755 dist/webv2 ~/.local/bin/webv2`
Then verify, in order (all three must hold):

```bash
test "$(~/.local/bin/webv2 --version | awk '{print $1}')" = "$(git rev-parse --short=12 HEAD)" && echo STAMP-OK
sha256sum dist/webv2 ~/.local/bin/webv2  # the two digests must be equal
~/.local/bin/webv2 adjudicate 2>&1 | head -1   # new-verb smoke: usage text
```

Expected: `STAMP-OK`, equal digests, usage line. The tree must be clean (no `+dirty` in the stamp) — commit anything the gates reconciled BEFORE running release.sh.

- [ ] **Step 5: Commit (only if reconciliations happened)**

```bash
git add -A && git commit -m "chore: golden/release reconciliation for the recall wave"
```

---

## Execution Handoff

Subagent-Driven Development, in task order 1 → 8. Implementer model: `deepseek-official/deepseek-flash` (provider `deepseek-official`, model `deepseek-flash`) via workflow `agent()` overrides — NEVER omit provider/model (silent local fallback). Reviewer model for every task review and re-review: `opencode-go-responses/muse-spark-1.3-contributor`. The final whole-branch review also uses the reviewer model per the user's standing directive. Never dispatch two implementation subagents in parallel; reviewers run only against completed diffs.

## Self-Review Record

- Spec coverage: post-mortem wish 1 → Tasks 1+2; wish 2 (adversarial-game artifact) → deliberately NOT built as machinery (anti-bloat); the funding question (G-02) → Task 4; wish 3 (cheap-hypothesis rail) → Task 3; wish 4 (fork-lite) → explicitly out of scope; wish 5 hygiene → Tasks 6+7; the plan-gate bug (#4 of their broken list) → Task 5; release/verification → Task 8.
- Placeholder scan: Task 2's `plannerMarkAnsweredForTest`/`storedPriority` and Task 4's `fundingMismatchRows` are named helpers the implementer extracts from EXISTING fixtures in the named files (the plan says exactly which file and which existing test to mirror — the code to write is the test body given). Task 5's port-boundary method follows `PB().CampaignSurface`'s existing pattern. No "TBD" steps.
- Type consistency: `structidx.GuardForm(string) string` (Task 1) is consumed as `own_form == "sentinel"` (Tasks 1/2); `AnsweredOpts.PassesValue *string` (Task 2) matches the `--passes` CLI flag; `ConsumeSlotOnce(campaign, *validation.Value) error` (Task 3) is the only new findings API; `DivergenceOpts.CampaignClasses []string` (Task 5) is the only gates API change.


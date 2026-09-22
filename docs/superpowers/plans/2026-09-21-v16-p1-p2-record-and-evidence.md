# v1.6 Phase 1–2: Record Trust and Evidence Tiers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the unbuilt half of `framework-plan-v1.6.md` Phases 1–2 in the `webv2` Go control plane: the policy-boolean↔gate consistency check, declared model-stage input artifact sets with out-of-set refusal, the file-drop handoff, `review_session` and deployment-fact records, two-tier PoC evidence, the replayability calculator, per-hypothesis `fork_dependence`, and the Phase 2 maximization spike.

**Architecture:** Every addition is a deterministic record-or-refuse change in `internal/…` plus the matching schema key in `assets/schema/` and the agent-facing line in `assets/runbook/RUNBOOK.md`. No model is in the loop; no new dependency; every new write is one hash-chained ledger event with projection unwind on failure. Where the spec names a CLI verb the repo already uses for something else (`mint --tier`, `impact`), the plan adds a *new* flag beside the pinned one rather than redefining it — the pinned surfaces are byte-asserted by tests.

**Tech Stack:** Go 1.26 (module `websec`, floor `go 1.26.2`), stdlib only; draft-07 JSON Schema validated through `internal/validation`; plain-Go same-package tests over `t.TempDir()` campaigns; the repo's own gates (`go vet`, `go test ./...`, `scripts/verify-full.sh`).

## Global Constraints

- **Go floor** `go 1.26.2`, module `websec`; **stdlib only** — no new dependency, ever.
- **Asset manifest:** any edit under `assets/` requires `python3 scripts/sync-asset-manifest.py` in the same change, or `assets.TestAssetPackManifest` fails.
- **Schema discipline:** `additionalProperties: false`; every new key is added to the schema *and* validated on the write path with `validation.Validate(v, name, 1)`.
- **Ledger law:** exactly one hash-chained event per mutation, written through `findings.SaveThenLog` or `(*state.Campaign).Log(eventType string, ref *string, data *validation.Value) (validation.Value, error)`; the projection write unwinds if the log write fails.
- **Determinism pins:** `WEBV2_NOW`, `WEBV2_UUID`, `WEBV2_FINDING_IDS`. Never call `time.Now()` or mint a raw UUID in a new record — route through `state.NowIso()` / `state.NewID`.
- **Byte-pinned surfaces:** CLI help/usage/error text is asserted verbatim in `internal/cli/*_test.go`; a new verb registers via `register(command{ord: N, name: "...", line: "...", run: ...})` in its own `cmd_*.go` `init()`, with `ord` = current maximum + 1. Copy the argparse shape of a neighbouring verb; do not invent one.
- **Gate checks** carry a `BountyRemediation` entry (`internal/bounty/remediation.go`) or `gate explain` regresses.
- **Audit sections** are appended at the end of `internal/audit/sections/register.go`, never interleaved.
- **Tests** are plain Go, same package, `t.TempDir()` campaigns, never Docker, never a network, never a model. Full gate: `go test ./... -count=1`, then `scripts/verify-full.sh`.
- **Small helpers are duplicated on purpose.** `orDefault`-style defaults, `strValues` (`[]string → []validation.Value`) and `pyTrunc`-style truncation appear in more than one package after this plan, because Go has no package-private sharing and exporting a four-line helper widens an API for no gain. Copy them; do not export them across packages. (`pyTrunc` already exists at `internal/boundary/boundary_values.go:45` — reuse that one rather than adding a second inside the package.)
- **No low-severity farming, never mainnet** (spec Part 6): every fact recorded under this plan names a pinned block or says it did not.

## Step 0 — re-verify this plan's premises before touching anything

This plan was written against the tree as of 2026-09-21 and every "the repo already has X" claim below is a *premise*, not a fact, by the time you read it. Four of them carry the whole plan; check them first, mechanically, and stop if any is false:

```bash
rg -n 'func ValidateRequest' internal/boundary/boundary.go
rg -n 'ValidateRequest\(' internal --glob '!*_test.go'          # expect exactly one caller: logHypothesisRequest
rg -n 'func fieldAt' internal/findings/ingest_evidence_gate.go  # Task 8's helper
rg -n 'func \(c \*Campaign\) SaveState' internal/state/campaign.go
rg -o 'ord: [0-9]+' internal/cli/*.go | rg -o '[0-9]+' | sort -n | tail -1   # expect 92
rg -n 'register\("price_table"' internal/audit/sections/register.go           # the last audit section
go test ./... -count=1
```

If the ord maximum moved, take the next free slots in Task order; if a caller of `ValidateRequest` appeared, Task 2's inventory is stale and its migration step needs that caller too; if `go test ./...` is not green before you start, that is the first thing to fix — not something to discover at Task 10.

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `internal/bounty/policy_gate_bindings.go` | the schema-boolean → gate-check binding table | 1 |
| `internal/bounty/policy_gate_bindings_test.go` | the Phase 1 consistency criterion, both directions | 1 |
| `internal/bounty/gate_evidence.go` *(modify)* | `check6ExploitContract` — the one unread policy boolean | 1 |
| `internal/boundary/boundary.go` *(modify)* | declared-input-set refusal in `ValidateRequest` | 2 |
| `assets/schema/model_request.schema.json` *(modify)* | `input_artifacts[]` declaration | 2 |
| `internal/cli/cmd_run.go` *(modify)* | `--feed FILE` drop-file handoff | 3 |
| `internal/feed/feed.go` | stage output-schema registry + ingest of a drop file (its own package: `internal/pipeline` cannot import `internal/boundary` — boundary already reaches pipeline transitively) | 3 |
| `internal/reviewsession/reviewsession.go` | `review_session` start/end records | 4 |
| `internal/cli/cmd_review_session.go` | the `review-session` verb | 4 |
| `internal/findings/fact_read.go` | deployment-fact records | 5 |
| `internal/cli/cmd_fact_read.go` | the `fact-read` verb | 5 |
| `internal/findings/poc_tier.go` | two-tier PoC evidence + ordering refusal | 6 |
| `internal/cli/cmd_mint.go` *(modify)* | `--poc-tier {existence,maximized}` | 6 |
| `internal/risk/replay.go` | the replayability calculator | 7 |
| `internal/cli/cmd_impact.go` *(modify)* | `--replayable` flag family | 7 |
| `internal/findings/fork_dependence.go` | per-hypothesis `fork_dependence` + existence-funding formula | 8 |
| `internal/cli/cmd_fork_dependence.go` | the `fork-dependence` verb | 8 |
| `internal/audit/sections/v16coverage.go` | the one reader of the eight new fields | 9 |
| `scripts/v16-spike.sh` | the Phase 2 spike driver | 10 |
| `docs/gates/v16-P2-spike.md` | the spike's recorded result | 10 |
| `docs/gates/v16-P1.md` | the Phase 1 gate record | 11 |

---

### Task 1: Policy-boolean ↔ gate consistency (Phase 1 exit criterion)

The spec's Phase 1 exit criterion: *"every policy boolean naming an evidence tier is referenced by that tier's gate, or the build fails."* Recon found the hole this criterion exists to catch: `require_exploit_contract` is declared in `assets/schema/bounty_policy.schema.json` and read by **nothing** — a policy can demand a runnable exploit contract today and the gate will pass a finding that has none.

**Files:**
- Create: `internal/bounty/policy_gate_bindings.go`
- Create: `internal/bounty/policy_gate_bindings_test.go`
- Modify: `internal/bounty/gate_evidence.go` (add `check6ExploitContract`, call it from `check6`)
- Modify: `internal/bounty/remediation.go` (add the `exploit-contract` remediation)

**Interfaces:**
- Consumes: `bountyFixture(t) (*state.Campaign, string)`, `testPolicy() validation.Value`, `checkRow(result validation.Value, name string) validation.Value`, `EvaluateBountyGate(c *state.Campaign, fid string, policy validation.Value, dryRun bool) (validation.Value, error)`, `(*gate).add(name, status, detail, remediation string)`, `BountyRemediation map[string]string`, `validation.ReadSchemaFile(name string) ([]byte, error)`, `validation.ObjAt`, `validation.SetOrAppend`, `pyTruthyBigNonEmpty`.
- Produces: `PolicyGateBinding struct{ Key, Check string }`, `PolicyGateBindings []PolicyGateBinding`, gate check id `"exploit-contract"`.

- [ ] **Step 1: Write the failing test**

Create `internal/bounty/policy_gate_bindings_test.go`:

```go
package bounty

// The Phase 1 consistency criterion (framework-plan-v1.6 Part 7): every policy
// boolean naming an evidence tier is referenced by that tier's gate, or the
// build fails. Three directions, all required: a schema boolean with no
// binding is red; a binding whose check never fires is red; and a check that
// fires with the boolean OFF is red too — that last one is what distinguishes
// "the gate reads the boolean" from "the gate always runs this check".

import (
	"encoding/json"
	"strings"
	"testing"

	"websec/internal/validation"
)

// policyBooleanKeys returns every boolean key under
// poc_requirements in the EMBEDDED policy schema, in document order.
func policyBooleanKeys(t *testing.T) []string {
	t.Helper()
	raw, err := validation.ReadSchemaFile("bounty_policy")
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse schema: %v", err)
	}
	props, _ := doc["properties"].(map[string]any)
	poc, _ := props["poc_requirements"].(map[string]any)
	fields, _ := poc["properties"].(map[string]any)
	if len(fields) == 0 {
		t.Fatal("bounty_policy schema has no poc_requirements.properties")
	}
	keys := make([]string, 0, len(fields))
	for key, spec := range fields {
		m, _ := spec.(map[string]any)
		if m["type"] == "boolean" {
			keys = append(keys, key)
		}
	}
	return keys
}

func TestPolicyBooleansAreReferencedByTheirGate(t *testing.T) {
	bound := map[string]PolicyGateBinding{}
	for _, b := range PolicyGateBindings {
		bound[b.Key] = b
	}
	for _, key := range policyBooleanKeys(t) {
		full := "poc_requirements." + key
		if _, ok := bound[full]; !ok {
			t.Errorf("%s is a policy boolean naming an evidence tier with no "+
				"gate binding — wire it to a check or delete it from the schema", full)
		}
	}
	for _, b := range PolicyGateBindings {
		if _, ok := BountyRemediation[b.Check]; !ok {
			t.Errorf("binding %s -> %q has no BountyRemediation entry", b.Key, b.Check)
		}
		// The binding must actually fire: set the boolean on the fixture
		// policy and require the check row to appear.
		c, fid := bountyFixture(t)
		p := testPolicy()
		req := validation.ObjAt(p, "poc_requirements")
		leaf := b.Key[strings.LastIndex(b.Key, ".")+1:]
		req.O = validation.SetOrAppend(req.O, leaf, validation.VBool(true))
		p.O = validation.SetOrAppend(p.O, "poc_requirements", req)
		result, err := EvaluateBountyGate(c, fid, p, true)
		if err != nil {
			t.Fatalf("%s: gate: %v", b.Key, err)
		}
		if row := checkRow(result, b.Check); row.Kind == validation.Null {
			t.Errorf("%s is bound to check %q, but the gate never emitted that row",
				b.Key, b.Check)
		}
		// The negative direction: with the boolean OFF the check must not run
		// at all. A row that appears either way means the binding is a label,
		// not a gate.
		cOff, fidOff := bountyFixture(t)
		pOff := testPolicy()
		reqOff := validation.ObjAt(pOff, "poc_requirements")
		reqOff.O = validation.SetOrAppend(reqOff.O, leaf, validation.VBool(false))
		pOff.O = validation.SetOrAppend(pOff.O, "poc_requirements", reqOff)
		offResult, err := EvaluateBountyGate(cOff, fidOff, pOff, true)
		if err != nil {
			t.Fatalf("%s: gate (off): %v", b.Key, err)
		}
		if row := checkRow(offResult, b.Check); row.Kind != validation.Null {
			t.Errorf("check %q ran with %s = false — the gate does not read the "+
				"boolean it is bound to", b.Check, b.Key)
		}
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/bounty -run TestPolicyBooleansAreReferencedByTheirGate -count=1`
Expected: FAIL to compile — `undefined: PolicyGateBindings`. After Step 3 the same test compiles and fails again, on the second half: `binding poc_requirements.require_exploit_contract -> "exploit-contract" has no BountyRemediation entry` and `is bound to check "exploit-contract", but the gate never emitted that row` — which is the hole Step 4 closes.

**The negative direction is already satisfied by the two existing clauses — verified, not assumed.** `check6Fork` (`internal/bounty/gate_evidence.go:61`) and `check6Economic` (`:78`) both open with `if !pyTruthyBigNonEmpty(...) { return nil }`, so with the boolean off they emit **no row at all**, and the new assertion passes. That matters because the alternative would turn Task 1 from "add one clause" into "change two existing checks", moving the 16-row count, `internal/orchestrator/testdata/oracles.json` and the report gate strings. Re-verify it before writing the test:

```bash
rg -n -A6 'func \(g \*gate\) check6(Fork|Economic|ExploitContract)' internal/bounty/gate_evidence.go
```

Every one of the three must open with the falsy-early-return. If any does not, stop and treat it as a deliberate behaviour change to an existing check: update the oracles and gate strings in the same commit, and say so in the message.

- [ ] **Step 3: Add the binding table**

Create `internal/bounty/policy_gate_bindings.go`:

```go
package bounty

// PolicyGateBindings binds every EVIDENCE-TIER boolean the policy schema
// offers to the gate check id that reads it. TestPolicyBooleansAreReferenced-
// ByTheirGate walks the embedded schema against this table, so a boolean with
// no gate — or a gate with no boolean — is a red test, not a silent no-op
// (framework-plan-v1.6 Part 7, Phase 1 exit criterion).
type PolicyGateBinding struct {
	Key   string // dotted path inside bounty_policy.schema.json
	Check string // gate check id this boolean turns on; must be in BountyRemediation
}

var PolicyGateBindings = []PolicyGateBinding{
	{Key: "poc_requirements.require_fork_repro", Check: "fork-repro"},
	{Key: "poc_requirements.require_economic_quantification", Check: "economic-quantified"},
	{Key: "poc_requirements.require_exploit_contract", Check: "exploit-contract"},
}
```

- [ ] **Step 4: Wire the unread boolean to a real clause**

In `internal/bounty/gate_evidence.go`, add below `check6Economic` and chain it from `check6` (the function currently ends `return g.check6Economic(req)` — change that line to call the new clause after it):

```go
// check6ExploitContract is the require_exploit_contract clause of check 6: the
// program asks for a RUNNABLE exploit contract a triager can execute, not a
// trace, a reasoning note or a static-analysis hit. Absent/false is a no-op,
// so no existing campaign's check set changes.
func (g *gate) check6ExploitContract(req validation.Value) error {
	if !pyTruthyBigNonEmpty(validation.ObjAt(req, "require_exploit_contract")) {
		return nil
	}
	for _, e := range validation.ObjAt(g.f, "evidence").A {
		switch validation.ObjStr(e, "type") {
		case "foundry-test", "fork-test":
			g.add("exploit-contract", "pass",
				"runnable contract "+validation.ObjStr(e, "evidence_id"), "")
			return nil
		}
	}
	g.add("exploit-contract", "fail", "no runnable exploit contract", "")
	g.blockers = append(g.blockers,
		"program requires a runnable exploit contract (foundry-test/fork-test evidence)")
	return nil
}
```

In `internal/bounty/remediation.go`, add one entry to `BountyRemediation`:

```go
	"exploit-contract":     "webv2 exec <campaign> --profile docker-networkless --command 'forge test --match-test test_exploit' --finding <fid>  then webv2 mint <fid> --exec <EXEC-ID> --type foundry-test   (the program asks for a contract a triager can run, not a trace)",
```

- [ ] **Step 5: Run it to verify it passes**

Run: `go test ./internal/bounty -run TestPolicyBooleansAreReferencedByTheirGate -count=1`
Expected: PASS.

- [ ] **Step 6: Prove nothing else moved**

Run: `go test ./internal/bounty ./internal/orchestrator ./internal/cli -count=1`
Expected: PASS. `TestFullSubmissionReady` still counts exactly 16 check rows — the new clause only fires when a policy sets `require_exploit_contract`, and no fixture does.

- [ ] **Step 7: Commit**

```bash
git add internal/bounty/policy_gate_bindings.go internal/bounty/policy_gate_bindings_test.go \
        internal/bounty/gate_evidence.go internal/bounty/remediation.go
git commit -m "feat(bounty): bind every evidence-tier policy boolean to its gate (v1.6 P1)"
```

---

### Task 2: Declared input artifact sets and out-of-set refusal

Spec Part 1: *"Each model stage declares its input artifact set at invocation; the declaration is recorded in the ledger; the framework refuses inputs outside it."* Non-negotiable 4: a model stage consuming an undeclared artifact is the same class of fabrication as a ghost id.

**The hole a hand-written list would leave.** A `context_artifacts` array that some caller fills in by hand is decorative: it can be empty, stale, or simply absent, and then the refusal can never fire. So the plan does not ask anyone to author it — `boundary.BuildRequest` **derives** it from the bundle that is actually sent, the same bundle `boundary.ContextHash` already hashes (`internal/boundary/boundary.go:108`). The declaration (`input_artifacts`) is authored by the stage; the cited set is mechanical; the refusal compares the two. No hand-written list can drift from what was sent.

**Inventory (verified 2026-09-21, re-verify in Step 0).** `ValidateRequest` has exactly one non-test caller — `logHypothesisRequest` (`internal/boundary/ingest.go:61`), reached from `IngestModelHypothesis` (`internal/boundary/ingest.go:23`). `IngestModelHypothesis` itself has **no non-test caller in this repo**: the request record is built outside the binary, by the harness, so *this refusal changes the harness contract*. The bundle is built by `roles.BuildProposerContext` / `BuildCriticContext` / `BuildReproducerContext` (`internal/roles/context.go:26`, `context_critic.go:163`, `context_reproducer.go:15`) and hashed by `boundary.ContextHash`.

**The schema is enforced in a second place, and that decides the migration.** `internal/trajectory/trajectory.go:34` maps `model.request` → the `model_request` definition, so **every already-logged request in every existing campaign is re-validated** by `verify_trajectory` against this schema. Today's `required` is `[role, model_id, prompt_version, response_schema, context_hash]`. Therefore:

- The two new keys stay **optional in the schema**. Making `input_artifacts` required would retroactively invalidate historical events and turn a green `verify_trajectory` red on old campaigns — a data-format change disguised as a feature.
- The **write path** is what requires the declaration: `ValidateRequest` refuses a request with no `input_artifacts`, so new requests must declare and old events keep validating. Refuse-new, grandfather-old, stated in the RUNBOOK line.

**Consequence for the in-repo callers:** every caller of `IngestModelHypothesis` is a test (`internal/boundary/boundary_test.go:251,280,317,352,367,386`, `internal/boundary/sweep_t35_test.go:365,368,529`, `internal/sft/sft_backfill_test.go:118`) and each needs the declaration added through `BuildRequest` in this task. `internal/sft/backfill.go` does *not* build a request record — it reads `model.request` events (`backfill.go:123`) and hashes bundles (`backfill.go:47`) — so it needs no change; if `go test ./...` says otherwise, trust the test over this paragraph.

**Files:**
- Modify: `assets/schema/model_request.schema.json` (`input_artifacts`, `context_artifacts` — both **optional**)
- Modify: `internal/boundary/boundary.go` (`BundleArtifacts`, `BuildRequest`, the `ValidateRequest` clauses)
- Modify: `internal/boundary/ingest.go` (record the refusal at the one call site)
- Create: `internal/boundary/input_artifacts_test.go`
- Modify: the three existing request fixtures — `internal/boundary/boundary_test.go`, `internal/boundary/sweep_t35_test.go`, `internal/sft/sft_backfill_test.go`
- Modify: `assets/runbook/RUNBOOK.md` (the harness migration note)

**Interfaces:**
- Consumes: `boundary.ContextHash(bundle validation.Value) string`, `boundary.ValidateRequest`, `boundary.BoundaryError`, `boundary.RecordRejection(c *state.Campaign, role, kind string, payload validation.Value, err error) (string, error)` (shape to mirror, `internal/boundary/boundary_rejection.go:15`), `roles.BuildProposerContext|BuildCriticContext|BuildReproducerContext`, `validation.Validate`.
- Produces: `boundary.BundleArtifacts(bundle validation.Value) []string`, `boundary.BuildRequest(bundle, declaration validation.Value, role, modelID, promptVersion, responseSchema string) validation.Value`, `boundary.DeclaredInputArtifacts(request validation.Value) []string`, `boundary.InputArtifactsOutsideDeclaration(request validation.Value) []string`, `boundary.RecordInputSetRefusal(c *state.Campaign, request validation.Value, why string) error`, refusal texts `"model request declares no input artifact set"` / `"model request cites artifact <ID> outside its declared input set"`.

- [ ] **Step 1: Write the failing test**

Create `internal/boundary/input_artifacts_test.go`:

```go
package boundary

// v1.6 Part 1: a model stage declares its input artifact set at invocation; the
// framework refuses inputs outside it. The declaration is part of the recorded
// request, so an out-of-set input is a refusal the ledger can show.

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// bundle is a stand-in for what roles.BuildProposerContext emits: nested
// objects and arrays carrying artifact ids — plus prose that happens to quote
// one, which must NOT be collected.
func bundle(ids ...string) validation.Value {
	rows := make([]validation.Value, 0, len(ids))
	for _, id := range ids {
		rows = append(rows, validation.VObj(
			validation.KV{K: "artifact_id", V: validation.VStr(id)},
			validation.KV{K: "note", V: validation.VStr("see ART-99999999 for context")}))
	}
	return validation.VObj(
		validation.KV{K: "role", V: validation.VStr("proposer")},
		validation.KV{K: "task", V: validation.VObj(
			validation.KV{K: "response_schema", V: validation.VStr("hypothesis")})},
		validation.KV{K: "context", V: validation.VArr(rows...)},
	)
}

func declaration(ids ...string) validation.Value {
	decl := make([]validation.Value, 0, len(ids))
	for _, id := range ids {
		decl = append(decl, validation.VObj(
			validation.KV{K: "kind", V: validation.VStr("artifact")},
			validation.KV{K: "id", V: validation.VStr(id)}))
	}
	return validation.VArr(decl...)
}

func builtRequest(t *testing.T, ids []string, declared []string) validation.Value {
	t.Helper()
	return BuildRequest(bundle(ids...), declaration(declared...),
		"proposer", "qwen3-14b:local", "0123456789abcdef", "hypothesis")
}

// TestBuildRequestDerivesTheCitedSet is the anti-decoration test: the cited
// set comes from the BUNDLE, so no caller can hand-write an empty list and
// make the refusal unreachable. It also pins the walk's SCOPE — the prose id
// in the bundle's `note` field is not a citation, and collecting it would make
// every declaration an "everything" declaration.
func TestBuildRequestDerivesTheCitedSet(t *testing.T) {
	req := builtRequest(t, []string{"ART-aaaa1111", "ART-bbbb2222"}, []string{"ART-aaaa1111"})
	got := validation.ObjAt(req, "context_artifacts")
	if len(got.A) != 2 {
		t.Fatalf("context_artifacts = %d entries, want the 2 ids the bundle cites "+
			"(and NOT the ART-99999999 quoted in prose): %s", len(got.A),
			validation.CanonSpaced(got))
	}
	for _, v := range got.A {
		if v.S == "ART-99999999" {
			t.Fatal("BundleArtifacts collected an id quoted in prose — the walk " +
				"must stay scoped to id-bearing keys")
		}
	}
	if err := ValidateRequest(req); err == nil ||
		!strings.Contains(err.Error(), "outside its declared input set") {
		t.Fatalf("err = %v, want the out-of-set refusal for ART-bbbb2222", err)
	}
}

func TestDeclaredInputSetIsRequired(t *testing.T) {
	// A MISSING declaration is the Go clause's job: the key is absent, so the
	// schema has nothing to check and ValidateRequest refuses by name.
	req := builtRequest(t, []string{"ART-aaaa1111"}, []string{"ART-aaaa1111"})
	req.O = withoutKey(req.O, "input_artifacts")
	err := ValidateRequest(req)
	if err == nil || !strings.Contains(err.Error(), "declares no input artifact set") {
		t.Fatalf("err = %v, want the missing-declaration refusal", err)
	}

	// An EMPTY declaration is the schema's job (minItems: 1). The two clauses
	// are complementary, not redundant: this one proves the schema fires, the
	// one above proves the Go clause fires when the schema cannot.
	empty := builtRequest(t, []string{"ART-aaaa1111"}, []string{"ART-aaaa1111"})
	empty.O = validation.SetOrAppend(empty.O, "input_artifacts", validation.VArr())
	if err := ValidateRequest(empty); err == nil ||
		strings.Contains(err.Error(), "declares no input artifact set") {
		t.Fatalf("err = %v, want the schema's minItems refusal (not the Go clause)", err)
	}
}

// withoutKey drops a key from an object (the tests need a request that never
// declared its input set, not one that declared an empty one).
func withoutKey(o []validation.KV, key string) []validation.KV {
	out := make([]validation.KV, 0, len(o))
	for _, kv := range o {
		if kv.K != key {
			out = append(out, kv)
		}
	}
	return out
}

func TestInSetRequestPasses(t *testing.T) {
	req := builtRequest(t, []string{"ART-aaaa1111", "ART-bbbb2222"},
		[]string{"ART-aaaa1111", "ART-bbbb2222"})
	if err := ValidateRequest(req); err != nil {
		t.Fatalf("in-set request refused: %v", err)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/boundary -run 'TestBuildRequestDerivesTheCitedSet|TestDeclaredInputSetIsRequired|TestInSetRequestPasses' -count=1`
Expected: FAIL to compile — `undefined: BuildRequest`.

- [ ] **Step 3: Add the schema keys**

In `assets/schema/model_request.schema.json`, add to `properties` (keep `additionalProperties: false` at the top level and **do not touch `required`** — see the inventory note: `required` is enforced against historical events by `internal/trajectory`, so making either key required retroactively breaks `verify_trajectory` on existing campaigns):

```json
    "input_artifacts": {
      "type": "array",
      "minItems": 1,
      "description": "The declared input artifact set for this stage invocation (v1.6 Part 1). The stage may consume nothing outside it; the declaration is recorded with the request, and an out-of-set input is refused at write time. minItems 1 covers the EMPTY array; the MISSING key is refused by boundary.ValidateRequest, which the schema cannot see. The two clauses are complementary — neither is decoration.",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["kind", "id"],
        "properties": {
          "kind": { "enum": ["artifact", "exec", "finding", "snapshot", "invariant", "plan"] },
          "id": { "type": "string", "minLength": 3, "maxLength": 64 }
        }
      }
    },
    "context_artifacts": {
      "type": "array",
      "description": "Every artifact id the assembled context bundle actually cites, DERIVED by boundary.BuildRequest from the bundle itself (never hand-written). Must be a subset of input_artifacts.",
      "items": { "type": "string", "minLength": 3, "maxLength": 64 }
    }
```

Then sync the manifest:

```bash
python3 scripts/sync-asset-manifest.py
```

- [ ] **Step 4: Implement the refusal**

In `internal/boundary/boundary.go`, add the derivation, the builder, and the two accessors:

```go
// artifactIDPattern matches every id shape the framework mints: artifacts,
// execs, evidence, findings, invariants, snapshots, prices.
var artifactIDPattern = regexp.MustCompile(
	`^(ART|EXEC|EV|F|INV|SNAP|PRC)-[0-9a-zA-Z_-]{4,48}$`)

// artifactKeyPattern matches the bundle keys that CARRY ids — the ones the
// role context builders actually emit (`internal/roles/context.go`,
// context_critic.go:163, context_reproducer.go:15).
var artifactKeyPattern = regexp.MustCompile(
	`^(artifact|evidence|finding|snapshot|exec|invariant|plan)_ids?$|^active_snapshot_id$`)

// BundleArtifacts returns every id the bundle carries under an id-bearing key,
// deduped in first-seen order. Derivation, not declaration: the set is read
// off the bytes that are actually sent.
//
// The walk is scoped to those keys on purpose. Scanning every leaf string
// would also match ids quoted in prose, diffs and pasted file contents — the
// bundle is full of them — and over-inclusion is not the safe direction it
// looks like: an operator who must declare everything the bundle happens to
// mention ends up declaring everything, and then the declaration means
// nothing. Over-inclusion trains the declaration out of existence.
func BundleArtifacts(bundle validation.Value) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(s string) {
		if artifactIDPattern.MatchString(s) && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	var walk func(v validation.Value)
	walk = func(v validation.Value) {
		switch v.Kind {
		case validation.Obj:
			for _, kv := range v.O {
				if artifactKeyPattern.MatchString(kv.K) {
					collectIDs(kv.V, add)
					continue
				}
				walk(kv.V)
			}
		case validation.Arr:
			for _, x := range v.A {
				walk(x)
			}
		}
	}
	walk(bundle)
	return out
}

// collectIDs adds the id(s) under one id-bearing key: a bare string, or an
// array of strings.
func collectIDs(v validation.Value, add func(string)) {
	switch v.Kind {
	case validation.Str:
		add(v.S)
	case validation.Arr:
		for _, x := range v.A {
			if x.Kind == validation.Str {
				add(x.S)
			}
		}
	}
}

// BuildRequest assembles a model_request from the bundle that is actually
// sent. context_hash pins the bytes; context_artifacts is DERIVED from those
// same bytes, so no caller can declare a narrow set and send a wide one.
func BuildRequest(bundle, declaration validation.Value, role, modelID,
	promptVersion, responseSchema string) validation.Value {
	return validation.VObj(
		validation.KV{K: "role", V: validation.VStr(role)},
		validation.KV{K: "model_id", V: validation.VStr(modelID)},
		validation.KV{K: "prompt_version", V: validation.VStr(promptVersion)},
		validation.KV{K: "response_schema", V: validation.VStr(responseSchema)},
		validation.KV{K: "context_hash", V: validation.VStr(ContextHash(bundle))},
		validation.KV{K: "input_artifacts", V: declaration},
		validation.KV{K: "context_artifacts", V: validation.VArr(
			strValues(BundleArtifacts(bundle))...)},
	)
}

// DeclaredInputArtifacts returns the ids in a request's declared input artifact
// set, in declaration order.
func DeclaredInputArtifacts(request validation.Value) []string {
	out := []string{}
	for _, a := range validation.ObjAt(request, "input_artifacts").A {
		if id := validation.ObjStr(a, "id"); id != "" {
			out = append(out, id)
		}
	}
	return out
}

// InputArtifactsOutsideDeclaration returns every id the context cites that the
// stage did not declare, in first-seen order. The declaration is the whole
// point: a stage that reads an artifact it did not declare is the same class
// of fabrication as a ghost id (v1.6 Part 8, non-negotiable 4).
func InputArtifactsOutsideDeclaration(request validation.Value) []string {
	declared := map[string]bool{}
	for _, id := range DeclaredInputArtifacts(request) {
		declared[id] = true
	}
	seen := map[string]bool{}
	out := []string{}
	for _, c := range validation.ObjAt(request, "context_artifacts").A {
		id := c.S
		if id == "" || declared[id] || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}
```

`strValues` is a three-line `[]string → []validation.Value` helper; add it in this file.

and inside `ValidateRequest`, immediately before it returns `nil` on success:

```go
	// The schema cannot see a MISSING key (the record is still valid without
	// it, which is what keeps historical requests validating); minItems covers
	// the empty array. This clause covers the absence.
	if len(DeclaredInputArtifacts(request)) == 0 {
		return &BoundaryError{Msg: "model request declares no input artifact set"}
	}
	if outside := InputArtifactsOutsideDeclaration(request); len(outside) > 0 {
		return &BoundaryError{Msg: fmt.Sprintf(
			"model request cites artifact %s outside its declared input set",
			outside[0])}
	}
```

- [ ] **Step 5: Run it to verify it passes**

Run: `go test ./internal/boundary -count=1`
Expected: PASS.

- [ ] **Step 6: Record the refusal at the one call site**

A refusal that is only returned is an orphan: the caller prints it and the next session never sees it. `ValidateRequest` has exactly one non-test caller (`logHypothesisRequest`, `internal/boundary/ingest.go:61`), so the recording belongs there. Add the recorder to `boundary.go`, mirroring `RecordRejection`'s event shape (`internal/boundary/boundary_rejection.go:15`) rather than inventing a second rejection vocabulary:

```go
// RecordInputSetRefusal logs the model.rejected event for a request whose
// input set is undeclared or violated, so the refusal is a ledger fact and not
// just a returned error. The ref is nil: at request time there is no finding
// id yet, and a fabricated empty-string ref is a ghost id.
func RecordInputSetRefusal(c *state.Campaign, request validation.Value,
	why string) error {
	data := validation.VObj(
		validation.KV{K: "role", V: validation.VStr(validation.ObjStr(request, "role"))},
		validation.KV{K: "kind", V: validation.VStr(validation.ObjStr(request, "response_schema"))},
		validation.KV{K: "error", V: validation.VStr(pyTrunc(why, 1000))},
		validation.KV{K: "context_hash", V: validation.VStr(validation.ObjStr(request, "context_hash"))},
		validation.KV{K: "declared", V: validation.VArr(strValues(DeclaredInputArtifacts(request))...)},
		validation.KV{K: "outside", V: validation.VArr(strValues(InputArtifactsOutsideDeclaration(request))...)},
		validation.KV{K: "action", V: validation.VStr(
			"re-declare the stage's input artifact set, or stop consuming the artifact")})
	_, err := c.Log("model.rejected", nil, &data)
	return err
}
```

Then wire it in `internal/boundary/ingest.go`:

```go
func logHypothesisRequest(campaign *state.Campaign,
	request validation.Value) error {
	if request.Kind != validation.Obj {
		return nil
	}
	if err := ValidateRequest(request); err != nil {
		if logErr := RecordInputSetRefusal(campaign, request, err.Error()); logErr != nil {
			return logErr
		}
		return err
	}
	_, err := campaign.Log("model.request", nil, &request)
	return err
}
```

Add the recording test in `input_artifacts_test.go`:

```go
func TestInputSetRefusalIsRecorded(t *testing.T) {
	c, err := state.Init(t.TempDir(), "smoke", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	req := builtRequest(t, []string{"ART-aaaa1111", "ART-bbbb2222"}, []string{"ART-aaaa1111"})
	if err := RecordInputSetRefusal(c, req, "out-of-set input"); err != nil {
		t.Fatalf("log: %v", err)
	}
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if validation.ObjStr(e, "type") != "model.rejected" {
			continue
		}
		if validation.ObjAt(e, "ref").Kind != validation.Null {
			t.Fatalf("ref = %s, want null (no finding id exists at request time)",
				validation.PyRepr(validation.ObjAt(e, "ref")))
		}
		if got := len(validation.ObjAt(validation.ObjAt(e, "data"), "outside").A); got != 1 {
			t.Fatalf("outside = %d entries, want 1", got)
		}
		return
	}
	t.Fatal("no model.rejected event recorded")
}
```

- [ ] **Step 7: Migrate the in-repo callers, then prove nothing else moved**

The refusal is a **harness-contract change**: any *new* request record without a declaration now fails. In-repo, the callers are the three test files named in the inventory — rebuild each request through `boundary.BuildRequest` with the declaration the role actually had:

```
internal/boundary/boundary_test.go:251,280,317,352,367,386
internal/boundary/sweep_t35_test.go:365,368,529
internal/sft/sft_backfill_test.go:118
```

Find the rest mechanically rather than by memory:

```bash
rg -n 'IngestModelHypothesis|HypothesisOpts\{' internal --glob '*_test.go'
rg -n 'model_request|"model.request"' internal assets --glob '!*_test.go'
go test ./... -count=1
```

Expected: PASS across the whole module, **including `internal/trajectory`** — that package is what re-validates logged requests, and it is the reason the two keys stay optional. Do **not** narrow this to `./internal/boundary`.

- [ ] **Step 8: Document the contract, sync the manifest, commit**

Add the RUNBOOK line: a model stage's request record must carry `input_artifacts`; `context_artifacts` is derived by `BuildRequest`, never authored; an undeclared or violated set is refused and logged as `model.rejected`. State the grandfathering explicitly — requests logged before this change have no declaration and still validate; requests written after it are refused without one. Then:

```bash
python3 scripts/sync-asset-manifest.py
go test ./internal/boundary ./internal/trajectory ./internal/sft ./internal/cli -count=1
git add assets/schema/model_request.schema.json assets/testdata/asset_manifest.json \
        assets/runbook/RUNBOOK.md internal/boundary/ internal/sft/sft_backfill_test.go
git commit -m "feat(boundary): declared input artifact sets with out-of-set refusal (v1.6 P1)"
```

---

### Task 3: `run --feed` — the non-interactive file-drop handoff

Spec Part 1: *"The non-interactive file-drop handoff is the only sanctioned transport — with stdout/stdin, context leaks by construction."* `run` already halts at a model stage and prints *"feed results back through the ingest APIs, then run again"* (`internal/cli/cmd_run.go:118`) — this task makes that sentence executable. `docs/CRITICAL_HUNTING_PLAN.md` §0.2 fixes the convention: the harness writes `campaigns/<C>/inbox/<stage>.json` and `webv2 run --feed <file>` validates it against the stage's contract and ingests.

The stage is read from the **file stem**, not a flag: the drop file's name *is* its declaration, so a mislabelled file cannot be ingested as another stage's output.

**The drop file carries the stage's request record AND the bundle it was built from** — and this is what makes Task 2 real. `IngestModelHypothesis` has no non-test caller today (see Task 2's inventory), so the input-artifact refusal would otherwise be a check nothing in production can trigger. If the drop merely *asserted* `context_artifacts`, the refusal would still be theatre: the file would declare X and cite X, and the check could never fire. So the drop carries the bundle, and the feed **derives** both the hash and the cited set from it:

```json
{
  "request": { "role": "proposer", "model_id": "...", "prompt_version": "...",
               "response_schema": "hypothesis", "context_hash": "...",
               "input_artifacts": [{"kind": "artifact", "id": "ART-..."}] },
  "context": { "...the exact bundle the stage was given...": null },
  "output":  { "...the stage's own payload, exactly as before..." }
}
```

The feed then: derives `context_artifacts` with `boundary.BundleArtifacts(context)`; checks `boundary.ContextHash(context) == request.context_hash` (so the hash is a fact about bytes the framework has, not a claim the file makes); runs `boundary.ValidateRequest` on the request *with the derived cited set* — so an undeclared or out-of-set drop is refused **and recorded** on the real path; and only then ingests `output`. `run --feed` is the production caller that Task 2's refusal was missing.

**Files:**
- Create: `internal/feed/feed.go`
- Modify: `internal/cli/cmd_run.go` (add `--feed FILE`, its usage/help text, and the feed branch in `runRun`)
- Create: `internal/feed/feed_test.go`
- Create: `internal/cli/cmd_run_feed_test.go`

**Interfaces:**
- Consumes: `validation.ReadJson(path string) (validation.Value, error)`, `boundary.ValidateRequest`, `boundary.RecordInputSetRefusal`, `boundary.BundleArtifacts`, `boundary.ContextHash` (all Task 2), `findings.IngestHypothesis(c *state.Campaign, payload validation.Value, trajectory, stage, model string) (validation.Value, error)`, `pipeline.Stages []Stage` / `pipeline.StageIDs []string` (`internal/pipeline/stages.go:24,42` — note both are vars, not funcs), `state.Open`, `t14Open`, `t14ExitErr`.
- Produces: `pipeline.FeedStage struct{ Stage, Schema, Note string; Ingest func(*state.Campaign, validation.Value) (string, error) }`, `pipeline.FeedStages []FeedStage`, `pipeline.FeedStageFor(stage string) (FeedStage, bool)`, `pipeline.FeedStageIDs() []string`, `pipeline.FeedUnwired map[string]string`.

- [ ] **Step 1: Write the failing test**

Create `internal/feed/feed_test.go`:

```go
package pipeline

// v1.6 Part 1: the drop file is the only sanctioned model-stage transport, and
// a stage with no wired ingest path is refused by name rather than ignored.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/boundary"
	"websec/internal/state"
	"websec/internal/validation"
)

// bundle is the context bundle a drop file ships: id-bearing keys plus prose
// that quotes an id, which the derivation must ignore.
func bundle(ids ...string) validation.Value {
	rows := make([]validation.Value, 0, len(ids))
	for _, id := range ids {
		rows = append(rows, validation.VObj(
			validation.KV{K: "artifact_id", V: validation.VStr(id)},
			validation.KV{K: "note", V: validation.VStr("see ART-99999999 for context")}))
	}
	return validation.VObj(
		validation.KV{K: "role", V: validation.VStr("proposer")},
		validation.KV{K: "context", V: validation.VArr(rows...)},
	)
}

// feedOutput is one hypothesis payload — exactly what the `output` key of a
// discovery drop carries.
func feedOutput() validation.Value {
	return validation.VObj(
		validation.KV{K: "title", V: validation.VStr("Attacker drains the vault")},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: validation.VStr("economic-invariant")},
			validation.KV{K: "description", V: validation.VStr("the mechanism described in detail")})},
		validation.KV{K: "affected", V: validation.VArr(validation.VObj(
			validation.KV{K: "path", V: validation.VStr("src/V.sol")},
			validation.KV{K: "function", V: validation.VStr("f")}))},
		validation.KV{K: "attacker", V: validation.VObj(
			validation.KV{K: "profile", V: validation.VStr("arbitrary EOA")},
			validation.KV{K: "capabilities", V: validation.VArr()})},
	)
}

// feedDoc is a complete stage invocation: the request record (with its
// declared input set), the context bundle the stage was given, and the output
// payload. context_artifacts is NOT written here — the feed derives it, which
// is the whole point.
func feedDoc(t *testing.T, declared ...string) validation.Value {
	t.Helper()
	return feedDocWithBundle(t, bundle(declared...), declared...)
}

// feedDocWithBundle is feedDoc with a caller-chosen bundle, so a test can ship
// a bundle that cites something the declaration does not cover.
func feedDocWithBundle(t *testing.T, context validation.Value,
	declared ...string) validation.Value {
	t.Helper()
	decl := make([]validation.Value, 0, len(declared))
	for _, id := range declared {
		decl = append(decl, validation.VObj(
			validation.KV{K: "kind", V: validation.VStr("artifact")},
			validation.KV{K: "id", V: validation.VStr(id)}))
	}
	request := validation.VObj(
		validation.KV{K: "role", V: validation.VStr("proposer")},
		validation.KV{K: "model_id", V: validation.VStr("qwen3-14b:local")},
		validation.KV{K: "prompt_version", V: validation.VStr("0123456789abcdef")},
		validation.KV{K: "response_schema", V: validation.VStr("hypothesis")},
		validation.KV{K: "context_hash", V: validation.VStr(boundary.ContextHash(context))},
		validation.KV{K: "input_artifacts", V: validation.VArr(decl...)},
	)
	return validation.VObj(
		validation.KV{K: "request", V: request},
		validation.KV{K: "context", V: context},
		validation.KV{K: "output", V: feedOutput()},
	)
}

func TestFeedStagesPartitionThePipeline(t *testing.T) {
	// Every MODEL or MIXED stage is either wired or explicitly declared
	// unwired with a reason. A stage that is neither has silently dropped out
	// of the handoff, which is the failure this test exists to catch.
	// Deterministic stages are excluded: code performs them, so there is no
	// model output to hand back and no drop file to write.
	modelStages := 0
	for _, s := range Stages {
		if s.Kind == "deterministic" {
			if _, wired := FeedStageFor(s.ID); wired {
				t.Fatalf("stage %q is deterministic but wired for a drop file", s.ID)
			}
			continue
		}
		modelStages++
		_, wired := FeedStageFor(s.ID)
		_, declared := FeedUnwired[s.ID]
		if wired == declared {
			t.Fatalf("stage %q (%s): wired=%v declared-unwired=%v — exactly one must hold",
				s.ID, s.Kind, wired, declared)
		}
	}
	if modelStages == 0 {
		t.Fatal("no model/mixed stages found — the Stage table moved")
	}
	for id, why := range FeedUnwired {
		if why == "" {
			t.Fatalf("stage %q is declared unwired with no reason", id)
		}
		if _, wired := FeedStageFor(id); wired {
			t.Fatalf("stage %q is both wired and declared unwired", id)
		}
	}
	for _, id := range FeedStageIDs() {
		if _, ok := FeedStageFor(id); !ok {
			t.Fatalf("FeedStageIDs advertises %q but FeedStageFor refuses it", id)
		}
	}
}

func TestFeedDiscoveryIngestsAHypothesis(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Acme", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	doc := feedDoc(t, "ART-aaaa1111")
	fs, ok := FeedStageFor("discovery")
	if !ok {
		t.Fatal("discovery must be wired")
	}
	fid, err := fs.Ingest(c, doc)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if fid == "" {
		t.Fatal("ingest returned no finding id")
	}
	if _, err := os.Stat(filepath.Join(root, "campaigns", c.CampaignID,
		"findings", fid+".json")); err != nil {
		t.Fatalf("finding not written: %v", err)
	}
}

// TestFeedRefusesAnUndeclaredRequest is the production reachability test for
// Task 2's refusal: a drop file whose request record declares nothing, or
// whose BUNDLE cites an artifact outside its declaration, is refused AND
// recorded, on the path an operator actually drives. The second case is the
// one that matters — it is unreachable if the file may assert its own cited
// set, which is why the feed derives it from the bundle instead.
func TestFeedRefusesAnUndeclaredRequest(t *testing.T) {
	root := t.TempDir()
	c, err := state.Init(root, "Acme", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	fs, _ := FeedStageFor("discovery")

	// No request record at all.
	bare := validation.VObj(validation.KV{K: "output", V: feedOutput()})
	if _, err := fs.Ingest(c, bare); err == nil ||
		!strings.Contains(err.Error(), "declare its input artifact set") {
		t.Fatalf("err = %v, want the missing-invocation refusal", err)
	}

	// A bundle that cites an artifact the declaration does not cover.
	doc := feedDocWithBundle(t, bundle("ART-aaaa1111", "ART-cccc3333"), "ART-aaaa1111")
	if _, err := fs.Ingest(c, doc); err == nil ||
		!strings.Contains(err.Error(), "outside its declared input set") {
		t.Fatalf("err = %v, want the out-of-set refusal", err)
	}

	// A request whose context_hash does not describe the bundle it shipped.
	lied := feedDoc(t, "ART-aaaa1111")
	req := validation.ObjAt(lied, "request")
	req.O = validation.SetOrAppend(req.O, "context_hash",
		validation.VStr(strings.Repeat("b", 64)))
	lied.O = validation.SetOrAppend(lied.O, "request", req)
	if _, err := fs.Ingest(c, lied); err == nil ||
		!strings.Contains(err.Error(), "does not describe its bundle") {
		t.Fatalf("err = %v, want the context-hash mismatch refusal", err)
	}

	// The first two refusals are ledger facts, not stderr lines: the bare drop
	// is the undeclared-consumption case, and the out-of-set drop is the
	// declaration violation. (The hash mismatch is refused before the boundary
	// check, so it logs nothing — a malformed file, not a fabrication attempt.)
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	rejections := 0
	for _, e := range evs {
		if validation.ObjStr(e, "type") == "model.rejected" {
			rejections++
		}
	}
	if rejections != 2 {
		t.Fatalf("model.rejected events = %d, want 2 (the bare drop and the "+
			"out-of-set drop; the hash mismatch logs nothing)", rejections)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/pipeline -run TestFeed -count=1`
Expected: FAIL to compile — `FeedStageFor` undefined.

- [ ] **Step 3: Implement the registry**

Create `internal/feed/feed.go`:

```go
package pipeline

// The non-interactive model-stage handoff (v1.6 Part 1: "the non-interactive
// file-drop handoff is the only sanctioned transport — with stdout/stdin,
// context leaks by construction"). A stage appears here only when its output
// has a real ingest path; a stage that does not is refused by name, never
// silently accepted. The drop file's STEM names the stage, so a file cannot
// masquerade as another stage's output.

import (
	"fmt"

	"websec/internal/boundary"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// strValues is []string -> []validation.Value, for the array fields.
func strValues(in []string) []validation.Value {
	out := make([]validation.Value, 0, len(in))
	for _, s := range in {
		out = append(out, validation.VStr(s))
	}
	return out
}

// FeedStage is one wired stage of the handoff.
type FeedStage struct {
	Stage  string // pipeline stage id (see Stages)
	Schema string // the contract the drop file must satisfy, for the error text
	Note   string // one line: what the drop file contains
	Ingest func(c *state.Campaign, doc validation.Value) (string, error)
}

// FeedStages is the wired set, in pipeline order.
var FeedStages = []FeedStage{
	{
		Stage:  "discovery",
		Schema: "model_request + finding",
		Note:   "a stage invocation: the request record (with its declared input set) plus one hypothesis payload",
		Ingest: func(c *state.Campaign, doc validation.Value) (string, error) {
			// The invocation is validated before its output is read: an
			// undeclared or out-of-set input set is refused AND recorded
			// here, on the only production path that reaches the boundary
			// check (boundary.IngestModelHypothesis has no CLI caller).
			request := validation.ObjAt(doc, "request")
			if request.Kind != validation.Obj {
				// A drop with output but no request record IS the
				// undeclared-consumption case non-negotiable 4 is about:
				// refused AND recorded, like the out-of-set refusal below.
				err := fmt.Errorf(
					"drop file has no request record: a stage invocation must " +
						"declare its input artifact set (v1.6 Part 1)")
				if logErr := boundary.RecordInputSetRefusal(c, validation.VObj(),
					err.Error()); logErr != nil {
					return "", logErr
				}
				return "", err
			}
			context := validation.ObjAt(doc, "context")
			if context.Kind != validation.Obj {
				return "", fmt.Errorf(
					"drop file has no context bundle: the cited artifact set is " +
						"derived from the bundle, never asserted by the file")
			}
			// The hash is checked against the bytes, not trusted: a request
			// whose context_hash does not describe the bundle it shipped is
			// the fabrication this whole path exists to catch.
			if got, want := validation.ObjStr(request, "context_hash"),
				boundary.ContextHash(context); got != want {
				return "", fmt.Errorf(
					"drop file context_hash %s does not describe its bundle (%s)",
					got, want)
			}
			// DERIVE the cited set; never read it from the file.
			request.O = validation.SetOrAppend(request.O, "context_artifacts",
				validation.VArr(strValues(boundary.BundleArtifacts(context))...))
			if err := boundary.ValidateRequest(request); err != nil {
				if logErr := boundary.RecordInputSetRefusal(c, request, err.Error()); logErr != nil {
					return "", logErr
				}
				return "", err
			}
			output := validation.ObjAt(doc, "output")
			if output.Kind != validation.Obj {
				return "", fmt.Errorf("drop file has no output payload")
			}
			f, err := findings.IngestHypothesis(c, output, "model",
				stageOf(request, "discovery"), validation.ObjStr(request, "model_id"))
			if err != nil {
				return "", err
			}
			return validation.ObjStr(f, "finding_id"), nil
		},
	},
}

// stageOf reads the stage from the request's role mapping, defaulting to the
// feed stage's own name; the drop file's stem already fixed the stage, so this
// only refines the attribution Task 8 records.
func stageOf(request validation.Value, fallback string) string {
	if s := validation.ObjStr(request, "stage"); s != "" {
		return s
	}
	return fallback
}

// FeedStageFor looks a stage up by id.
func FeedStageFor(stage string) (FeedStage, bool) {
	for _, fs := range FeedStages {
		if fs.Stage == stage {
			return fs, true
		}
	}
	return FeedStage{}, false
}

// FeedStageIDs lists the wired stage ids in declaration order.
func FeedStageIDs() []string {
	out := make([]string, 0, len(FeedStages))
	for _, fs := range FeedStages {
		out = append(out, fs.Stage)
	}
	return out
}

// FeedUnwired names every MODEL or MIXED pipeline stage with NO ingest path
// yet, and why. TestFeedStagesPartitionThePipeline requires the wired set and
// this map to partition the model/mixed rows of Stages (`internal/pipeline/
// stages.go:24`): a stage that is in neither has silently dropped out of the
// handoff, and a model stage added to the table without either entry fails the
// build. Deterministic stages are absent by design — code performs them, so
// there is no output to hand back. Delete an entry when its ingest path lands.
var FeedUnwired = map[string]string{
	"protocol-model":           "the protocol model is loaded by `webv2 model <file>`, not by a drop file",
	"campaign-planning":        "the plan is written by `webv2 plan`, which owns its own contract",
	"hostile-review":           "critic verdicts are applied by `webv2 adjudicate`, not by a drop file",
	"reproduction":             "reproduction requests are submitted through `webv2 sequence run`",
	"maximal-exploitation":     "no maximization loop exists yet (Phase 5)",
	"independent-verification": "no independent-verification ingest path exists yet (Phase 5)",
	"mainnet-fork-poc":         "fork PoCs are minted through `webv2 mint --type fork-test`",
	"learning":                 "memory rows are written through `webv2 memory`",
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/pipeline -run TestFeed -count=1`
Expected: PASS.

- [ ] **Step 5: Write the failing CLI test**

Create `internal/cli/cmd_run_feed_test.go`:

```go
package cli

// `run --feed` — the drop-file transport (v1.6 Part 1). The file stem names the
// stage; an unwired stage and a missing file are exit-2 refusals that say why.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/boundary"
	"websec/internal/state"
	"websec/internal/validation"
)

// inboxDrop writes a drop file where the convention says it lives —
// campaigns/<C>/inbox/<stage>.json — and returns its path.
func inboxDrop(t *testing.T, c *state.Campaign, stage, body string) string {
	t.Helper()
	dir := filepath.Join(c.Dir, "inbox")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, stage+".json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunFeedRefusesUnwiredStage(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	drop := inboxDrop(t, c, "hostile-review", "{}")
	code, _, errS := run(t, "--root", root, "run", "--feed", drop)
	if code != 2 {
		t.Fatalf("code = %d, want 2 (stderr: %s)", code, errS)
	}
	if !strings.Contains(errS, "no ingest path for stage") {
		t.Fatalf("stderr = %q, want the unwired-stage refusal", errS)
	}
}

func TestRunFeedRefusesADropOutsideTheInbox(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	stray := filepath.Join(t.TempDir(), "discovery.json")
	if err := os.WriteFile(stray, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errS := run(t, "--root", root, "run", "--feed", stray)
	if code != 2 {
		t.Fatalf("code = %d, want 2 (stderr: %s)", code, errS)
	}
	if !strings.Contains(errS, "must live in the campaign inbox") {
		t.Fatalf("stderr = %q, want the inbox-path refusal", errS)
	}
	_ = c
}

// discoveryDrop builds a complete drop file: the request record, the context
// bundle, and the output payload. The bundle's hash is real (computed, not
// pasted) and context_artifacts is absent — the feed derives it, so a drop
// file cannot assert its own cited set.
func discoveryDrop(t *testing.T, cited, declared []string) string {
	t.Helper()
	rows := make([]validation.Value, 0, len(cited))
	for _, id := range cited {
		rows = append(rows, validation.VObj(
			validation.KV{K: "artifact_id", V: validation.VStr(id)}))
	}
	context := validation.VObj(
		validation.KV{K: "role", V: validation.VStr("proposer")},
		validation.KV{K: "context", V: validation.VArr(rows...)})
	decl := make([]validation.Value, 0, len(declared))
	for _, id := range declared {
		decl = append(decl, validation.VObj(
			validation.KV{K: "kind", V: validation.VStr("artifact")},
			validation.KV{K: "id", V: validation.VStr(id)}))
	}
	doc := validation.VObj(
		validation.KV{K: "request", V: validation.VObj(
			validation.KV{K: "role", V: validation.VStr("proposer")},
			validation.KV{K: "model_id", V: validation.VStr("qwen3-14b:local")},
			validation.KV{K: "prompt_version", V: validation.VStr("0123456789abcdef")},
			validation.KV{K: "response_schema", V: validation.VStr("hypothesis")},
			validation.KV{K: "context_hash",
				V: validation.VStr(boundary.ContextHash(context))},
			validation.KV{K: "input_artifacts", V: validation.VArr(decl...)})},
		validation.KV{K: "context", V: context},
		validation.KV{K: "output", V: discoveryOutput()})
	return validation.DumpIndented(doc)
}

func discoveryOutput() validation.Value {
	return validation.VObj(
		validation.KV{K: "title", V: validation.VStr("Attacker drains the vault")},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: validation.VStr("economic-invariant")},
			validation.KV{K: "description", V: validation.VStr("the mechanism described in detail")})},
		validation.KV{K: "affected", V: validation.VArr(validation.VObj(
			validation.KV{K: "path", V: validation.VStr("src/V.sol")},
			validation.KV{K: "function", V: validation.VStr("f")}))},
		validation.KV{K: "attacker", V: validation.VObj(
			validation.KV{K: "profile", V: validation.VStr("arbitrary EOA")},
			validation.KV{K: "capabilities", V: validation.VArr()})},
	)
}

func TestRunFeedIngestsADiscoveryDrop(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	drop := inboxDrop(t, c, "discovery",
		discoveryDrop(t, []string{"ART-aaaa1111"}, []string{"ART-aaaa1111"}))
	code, out, errS := run(t, "--root", root, "run", "--feed", drop)
	if code != 0 {
		t.Fatalf("code = %d, want 0 (stderr: %s)", code, errS)
	}
	if !strings.Contains(out, "ingested F-") {
		t.Fatalf("stdout = %q, want the ingested line", out)
	}
}

func TestRunFeedRefusesAnOutOfSetDrop(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	// The bundle cites two artifacts, the declaration covers one: refused, and
	// the refusal is a ledger fact (the check Task 2 adds, on the path an
	// operator drives — and one the file cannot dodge, because the cited set
	// is derived from the bundle it shipped).
	drop := inboxDrop(t, c, "discovery",
		discoveryDrop(t, []string{"ART-aaaa1111", "ART-cccc3333"}, []string{"ART-aaaa1111"}))
	code, _, errS := run(t, "--root", root, "run", "--feed", drop)
	if code != 1 {
		t.Fatalf("code = %d, want 1 (stderr: %s)", code, errS)
	}
	if !strings.Contains(errS, "outside its declared input set") {
		t.Fatalf("stderr = %q, want the out-of-set refusal", errS)
	}
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	recorded := false
	for _, e := range evs {
		if validation.ObjStr(e, "type") == "model.rejected" {
			recorded = true
		}
	}
	if !recorded {
		t.Fatal("the refusal was not recorded as model.rejected")
	}
}
```

- [ ] **Step 6: Run it to verify it fails**

Run: `go test ./internal/cli -run TestRunFeed -count=1`
Expected: FAIL — `--feed` is an unrecognized argument (exit 2, wrong message).

- [ ] **Step 7: Add the flag**

In `internal/cli/cmd_run.go`, extend the pinned usage/help constants **and** their test expectations together:

```go
const t30RunUsage = `usage: webv2 run [-h] [--until UNTIL] [--max-stages MAX_STAGES] [--feed FEED] campaign
`

const t30RunHelp = `usage: webv2 run [-h] [--until UNTIL] [--max-stages MAX_STAGES] [--feed FEED] campaign

positional arguments:
  campaign

options:
  -h, --help            show this help message and exit
  --until UNTIL
  --max-stages MAX_STAGES
  --feed FEED           ingest one model-stage drop file (campaigns/<C>/inbox/<stage>.json)
`
```

add `{name: "--feed"}` to `sp.vals` (after `--max-stages`, so the existing positional indices are untouched), and branch in `runRun` right after `t14Open` succeeds. Resolve the flag **by name**, not by index — a positional index into `sp.vals` is a bug waiting for the next flag insertion — and refuse an empty value rather than falling through:

```go
	for _, v := range sp.vals {
		if v.name == "--feed" && v.seen {
			// `--feed ""` must not fall through to the normal run path: a
			// malformed invocation would silently become a full pipeline run.
			if v.val == "" {
				return t14ExitErr(2, "--feed requires a path\n")
			}
			return runFeed(c, v.val, r)
		}
	}
```

and implement, in the same file:

```go
// runFeed is `run --feed FILE`: the non-interactive model-stage handoff
// (v1.6 Part 1). The file's STEM names the pipeline stage; the file must live
// in the campaign's own inbox (a drop file from anywhere else is not a
// handoff); the drop carries the stage's request record — so the input-artifact
// declaration is validated, and a violation refused AND recorded — plus the
// output payload; a stage with no wired ingest path is refused by name.
//
// Exit codes: 0 ingested, 1 handled error (unreadable file, ingest or
// input-set refusal), 2 usage (unwired stage, drop outside the inbox). Exit 3
// belongs to the run path's model-stage halt and is never returned here.
func runFeed(c *state.Campaign, path string, r *Runner) error {
	stage := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	fs, ok := pipeline.FeedStageFor(stage)
	if !ok {
		why := pipeline.FeedUnwired[stage]
		if why == "" {
			why = "unknown stage"
		}
		return t14ExitErr(2, "no ingest path for stage %q (drop file %s): %s; "+
			"wired stages: %s\n", stage, path, why,
			strings.Join(pipeline.FeedStageIDs(), ", "))
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return t14ExitErr(1, "feed %s: %v\n", path, err)
	}
	inbox, err := filepath.Abs(filepath.Join(c.Dir, "inbox"))
	if err != nil {
		return t14ExitErr(1, "feed %s: %v\n", path, err)
	}
	if filepath.Dir(abs) != inbox {
		return t14ExitErr(2, "drop file must live in the campaign inbox "+
			"(%s), got %s\n", inbox, abs)
	}
	doc, err := validation.ReadJson(abs)
	if err != nil {
		return t14ExitErr(1, "feed %s: %v\n", path, err)
	}
	fid, err := fs.Ingest(c, doc)
	if err != nil {
		return t14ExitErr(1, "feed %s: %v\n", path, err)
	}
	fmt.Fprintf(r.Out, "ingested %s from %s (stage %s, contract %s)\n",
		fid, abs, fs.Stage, fs.Schema)
	return nil
}
```

- [ ] **Step 8: Run it to verify it passes**

Run: `go test ./internal/cli -run 'TestRunFeed|TestT30' -count=1`
Expected: PASS. If a pinned help/usage test for `run` exists elsewhere, update its expected bytes in the same step — the change is deliberate, not incidental.

- [ ] **Step 9: Document the transport, sync the manifest, commit**

Add to `assets/runbook/RUNBOOK.md`, next to the `run` entry: the drop-file convention (`campaigns/<C>/inbox/<stage>.json`, file stem = stage id, the file carries the request record *and* the bundle, `run --feed` validates and ingests), the feed exit codes, and the currently wired stage list. The exit table must match the tests exactly — 0 ingested, 1 handled error (**including the out-of-set refusal**, which is a handled refusal of a well-formed file, not a usage error), 2 usage (unwired stage, drop outside the inbox, empty `--feed`); exit 3 is the run path's model-stage halt and `--feed` never returns it. `internal/cli/runbook_test.go` fails if a registered command is undocumented, so the RUNBOOK line is part of this commit, not a follow-up.

```bash
python3 scripts/sync-asset-manifest.py
go test ./internal/pipeline ./internal/cli -count=1
git add internal/feed/feed.go internal/feed/feed_test.go \
        internal/cli/cmd_run.go internal/cli/cmd_run_feed_test.go \
        assets/runbook/RUNBOOK.md assets/testdata/asset_manifest.json
git commit -m "feat(run): --feed drop-file transport for model stages (v1.6 P1)"
```

---

### Task 4: `review_session` events

Spec Part 1: *"`review_session` telemetry. Start, end, artifacts covered, LOC — recorded per session, so the ~60-minute / 400-line budget is a measured soft target whose effect on catch rate is correlatable, not aspirational."* Phase 2 begins recording them; the Phase 2b operator sessions are the first data.

**Files:**
- Create: `internal/reviewsession/reviewsession.go`
- Create: `internal/reviewsession/reviewsession_test.go`
- Create: `internal/cli/cmd_review_session.go`
- Create: `internal/cli/cmd_review_session_test.go`
- Modify: `assets/schema/campaign_state.schema.json` (projection key `review_sessions`)

**Interfaces:**
- Consumes: `state.NewID(prefix string, n int) string`, `state.NowIso()`, `(*state.Campaign).State()`, `(*state.Campaign).SaveState(...)` *(use whichever projection-write helper the neighbouring packages use — `internal/planner/archive.go:119` shows the paired-write + unwind pattern)*, `(*state.Campaign).Log(...)`.
- Produces: `reviewsession.Start(c *state.Campaign, actor string, artifacts []string) (validation.Value, error)`, `reviewsession.End(c *state.Campaign, sessionID, actor string, loc int64) (validation.Value, error)`, `reviewsession.Open(c *state.Campaign) (validation.Value, bool)`, events `review_session.started` / `review_session.ended`.

- [ ] **Step 1: Write the failing test**

Create `internal/reviewsession/reviewsession_test.go`:

```go
package reviewsession

import (
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func campaign(t *testing.T) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestStartThenEndRecordsBothEvents(t *testing.T) {
	c := campaign(t)
	s, err := Start(c, "operator", []string{"ART-aaaa1111", "src/V.sol"})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	sid := validation.ObjStr(s, "session_id")
	if !strings.HasPrefix(sid, "RS-") {
		t.Fatalf("session_id = %q, want an RS- id", sid)
	}
	if _, err := End(c, sid, "operator", 412); err != nil {
		t.Fatalf("end: %v", err)
	}
	evs, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range evs {
		seen[validation.ObjStr(e, "type")] = true
	}
	for _, want := range []string{"review_session.started", "review_session.ended"} {
		if !seen[want] {
			t.Errorf("no %s event", want)
		}
	}
}

func TestEndRefusesAnUnknownOrDoubleClosedSession(t *testing.T) {
	c := campaign(t)
	if _, err := End(c, "RS-deadbeef", "operator", 10); err == nil ||
		!strings.Contains(err.Error(), "no open review session") {
		t.Fatalf("err = %v, want the unknown-session refusal", err)
	}
	s, err := Start(c, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	sid := validation.ObjStr(s, "session_id")
	if _, err := End(c, sid, "operator", 10); err != nil {
		t.Fatal(err)
	}
	if _, err := End(c, sid, "operator", 20); err == nil {
		t.Fatal("a second end on the same session must be refused")
	}
}

func TestStartRefusesASecondOpenSession(t *testing.T) {
	c := campaign(t)
	if _, err := Start(c, "operator", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Start(c, "operator", nil); err == nil ||
		!strings.Contains(err.Error(), "already open") {
		t.Fatalf("err = %v, want the one-open-session refusal", err)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/reviewsession -count=1`
Expected: FAIL — package does not exist.

- [ ] **Step 3: Implement the package**

Create `internal/reviewsession/reviewsession.go`:

```go
// Package reviewsession records operator review sessions as ledger events
// (framework-plan-v1.6 Part 1): start, end, artifacts covered, LOC. The
// ~60-minute / 400-line budget is a soft target whose effect on catch rate is
// correlatable only if the sessions are measured, so both ends of a session
// are events, never prose.
package reviewsession

import (
	"fmt"

	"websec/internal/state"
	"websec/internal/validation"
)

// projectionKey is the campaign-state key holding the session rows.
const projectionKey = "review_sessions"

// Start opens a session and records review_session.started. One session may be
// open at a time: two concurrent sessions are two contexts, and the whole
// point of the measurement is one operator's attention.
func Start(c *state.Campaign, actor string, artifacts []string) (validation.Value, error) {
	if _, open := Open(c); open {
		return validation.VNull(), fmt.Errorf("already open: close the current review session first")
	}
	sid := state.NewID("RS", 8)
	row := validation.VObj(
		validation.KV{K: "session_id", V: validation.VStr(sid)},
		validation.KV{K: "actor", V: validation.VStr(orDefault(actor, "operator"))},
		validation.KV{K: "started_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "artifacts_covered", V: validation.VArr(strValues(artifacts)...)},
		validation.KV{K: "open", V: validation.VBool(true)},
	)
	if err := appendRow(c, row, "review_session.started", sid); err != nil {
		return validation.VNull(), err
	}
	return row, nil
}

// End closes an open session, recording LOC and the artifacts covered.
func End(c *state.Campaign, sessionID, actor string, loc int64) (validation.Value, error) {
	row, ok := Open(c)
	if !ok || validation.ObjStr(row, "session_id") != sessionID {
		return validation.VNull(), fmt.Errorf("no open review session %s", sessionID)
	}
	if loc < 0 {
		return validation.VNull(), fmt.Errorf("--loc must be >= 0")
	}
	row.O = validation.SetOrAppend(row.O, "open", validation.VBool(false))
	row.O = validation.SetOrAppend(row.O, "ended_at", validation.VStr(state.NowIso()))
	row.O = validation.SetOrAppend(row.O, "loc", validation.VInt(loc))
	row.O = validation.SetOrAppend(row.O, "closed_by", validation.VStr(orDefault(actor, "operator")))
	if err := replaceRow(c, row, "review_session.ended", sessionID); err != nil {
		return validation.VNull(), err
	}
	return row, nil
}

// Open returns the currently open session row, if any.
func Open(c *state.Campaign) (validation.Value, bool) {
	st, err := c.State()
	if err != nil {
		return validation.VNull(), false
	}
	for _, row := range validation.ObjAt(st, projectionKey).A {
		if validation.ObjAt(row, "open").Kind == validation.Bool &&
			validation.ObjAt(row, "open").B {
			return row, true
		}
	}
	return validation.VNull(), false
}
```

Implement `appendRow` / `replaceRow` on the paired-write + unwind pattern of `internal/planner/archive.go:119` (`planWindow`): read the projection with `c.State()`, capture the previous bytes, mutate the `review_sessions` array, `c.SaveState(next)`, `c.Log(...)`, and on log failure `c.SaveState(prior)` before returning the error. `(*state.Campaign).SaveState` is `internal/state/campaign.go:242`. `orDefault` and `strValues` are four-line helpers that live unexported in `internal/findings` and `internal/boundary` — write local copies here rather than exporting them from a neighbour.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/reviewsession -count=1`
Expected: PASS.

- [ ] **Step 5: Allow the projection key**

In `assets/schema/campaign_state.schema.json`, add to `properties` (the file is `additionalProperties: false`):

```json
    "review_sessions": {
      "type": "array",
      "description": "Operator review sessions (v1.6 Part 1): start/end, artifacts covered, LOC. The ~60-minute / 400-line budget is a soft target measured here.",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["session_id", "actor", "started_at", "artifacts_covered", "open"],
        "properties": {
          "session_id": { "type": "string", "pattern": "^RS-[0-9a-zA-Z]{4,16}$" },
          "actor": { "type": "string", "minLength": 1 },
          "started_at": { "type": "string" },
          "ended_at": { "type": "string" },
          "closed_by": { "type": "string" },
          "artifacts_covered": { "type": "array", "items": { "type": "string" } },
          "loc": { "type": "integer", "minimum": 0 },
          "open": { "type": "boolean" }
        }
      }
    },
```

- [ ] **Step 6: Write the failing CLI test**

Create `internal/cli/cmd_review_session_test.go`:

```go
package cli

import (
	"strings"
	"testing"
)

func TestReviewSessionStartEnd(t *testing.T) {
	_, root := t15Campaign(t, "Acme")
	code, out, errS := run(t, "--root", root, "review-session", "start",
		"--actor", "operator", "--artifact", "src/V.sol")
	if code != 0 {
		t.Fatalf("start code = %d (stderr %s)", code, errS)
	}
	if !strings.Contains(out, "review session RS-") {
		t.Fatalf("stdout = %q", out)
	}
	code, out, errS = run(t, "--root", root, "review-session", "end", "--loc", "412")
	if code != 0 {
		t.Fatalf("end code = %d (stderr %s)", code, errS)
	}
	if !strings.Contains(out, "412 lines") {
		t.Fatalf("stdout = %q, want the LOC line", out)
	}
}

func TestReviewSessionEndWithoutStartIsExit2(t *testing.T) {
	_, root := t15Campaign(t, "Acme")
	code, _, errS := run(t, "--root", root, "review-session", "end", "--loc", "10")
	if code != 2 || !strings.Contains(errS, "no open review session") {
		t.Fatalf("code = %d stderr = %q", code, errS)
	}
}
```

The campaign id is not a positional here: `review-session` resolves it the way `brief`/`audit` do (open the single campaign in the root, or take `--campaign`); copy that resolution from `internal/cli/cmd_audit.go`. If the campaign must be positional, use `review-session <campaign> {start|end}` and update both tests — pick one and keep help, usage and tests in agreement.

- [ ] **Step 7: Implement the verb**

`End` takes an exact `sessionID`, and the verb's surface has no id positional — so `end` resolves the open session itself: `sess, open := reviewsession.Open(c)`; if `!open`, exit 2 with `"no open review session"`; otherwise pass `validation.ObjStr(sess, "session_id")` to `End`. The one-open-session rule is what makes that unambiguous, and it is the reason the rule exists: two open sessions would make `end` a guess.

Create `internal/cli/cmd_review_session.go` following `internal/cli/cmd_audit.go` for registration and `internal/cli/cmd_impact.go` for flag parsing (`argSpec` + `valOpt` with `{name: "--artifact", repeatable: true}` if the parser supports repeats — `--ref` on `assume` does; copy that mechanism). Register:

```go
func init() {
	register(command{ord: 93, name: "review-session",
		line: `review-session {start|end} [--actor A] [--artifact A]... [--loc N]   record an operator review session`,
		run:  runReviewSession})
}
```

`ord: 93` is the next free slot (the current maximum is 92); confirm with
`rg -o 'ord: [0-9]+' internal/cli/*.go | rg -o '[0-9]+' | sort -n | tail -1` before committing and bump if another verb landed first.

Three CLI-surface laws bind this verb, all test-enforced and all in this commit:

- `TestEveryCommandAnswersHelp` (`internal/cli/help_test.go:16`) requires `<verb> -h` and `<verb> --help` to print `usage: webv2 review-session` on **stdout, exit 0, with no campaign and no state access** — so the help branch must short-circuit before any argument validation or `state.Open`.
- `internal/cli/runbook_test.go` fails if a registered command is missing from `assets/runbook/RUNBOOK.md` (`runbookDocExempt` is empty on purpose), so add the RUNBOOK line here.
- `usageText()` is asserted by neighbouring tests (e.g. `cmd_immunize_test.go:433`); if any test asserts the verb list verbatim, update it deliberately in this commit.

- [ ] **Step 8: Run it to verify it passes**

Run: `go test ./internal/cli -run 'TestReviewSession|TestEveryCommandAnswersHelp|TestRunbook' -count=1`
Expected: PASS.

- [ ] **Step 9: Manifest, full package tests, commit**

The session timing is the whole measurement, so state it where an operator will read it: `WEBV2_NOW` is a *test* pin — an operator run must use real wall-clock, and a session recorded under a pinned clock is a fixture, not telemetry. Say so in the RUNBOOK line, and assert it with a test that cannot pass on a fixed date: with `WEBV2_NOW` unset, two `Start` calls ≥1s apart must produce **different** `started_at` values.

```go
func TestReviewSessionUsesRealWallClock(t *testing.T) {
	t.Setenv("WEBV2_NOW", "") // the pin must not be in play
	c, _ := sessionCampaign(t)
	first, err := Start(c, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := End(c, validation.ObjStr(first, "session_id"), "operator", 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	second, err := Start(c, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(first, "started_at") == validation.ObjStr(second, "started_at") {
		t.Fatal("two sessions a second apart share started_at — the clock is pinned")
	}
}
```

```bash
python3 scripts/sync-asset-manifest.py
go test ./internal/reviewsession ./internal/cli ./internal/state -count=1
git add internal/reviewsession/ internal/cli/cmd_review_session.go \
        internal/cli/cmd_review_session_test.go assets/schema/campaign_state.schema.json \
        assets/runbook/RUNBOOK.md assets/testdata/asset_manifest.json
git commit -m "feat(review-session): measured operator sessions on the ledger (v1.6 P2)"
```

---

### Task 5: Deployment-fact reads

Spec Part 8, non-negotiable 5: *"A value not read from the deployment is an assumption — the snapshot proves which code runs, never what the instance holds."* The rule is RUNBOOK prose today (`assets/runbook/RUNBOOK.md:534`); nothing records a read. This task makes a fact read a first-class record with its command, its raw value, and the block it was read at.

**Files:**
- Create: `internal/findings/fact_read.go`
- Create: `internal/findings/fact_read_test.go`
- Create: `internal/cli/cmd_fact_read.go`
- Create: `internal/cli/cmd_fact_read_test.go`
- Modify: `assets/schema/finding.schema.json` (`deployment_facts`)

**Interfaces:**
- Consumes: `findings.LoadFinding`, `findings.SaveThenLog`, `state.NowIso()`.
- Produces: `findings.RecordFactRead(c *state.Campaign, findingID, command, value, chain, actor string, block int64) (validation.Value, error)`; event `finding.fact_read`; finding key `deployment_facts[]`.

- [ ] **Step 1: Write the failing test**

Create `internal/findings/fact_read_test.go`:

```go
package findings

import (
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func factCampaign(t *testing.T) (*state.Campaign, string) {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	payload := validation.VObj(
		validation.KV{K: "title", V: validation.VStr("Attacker drains the vault")},
		validation.KV{K: "root_cause", V: validation.VObj(
			validation.KV{K: "class", V: validation.VStr("economic-invariant")},
			validation.KV{K: "description", V: validation.VStr("the mechanism described in detail")})},
		validation.KV{K: "affected", V: validation.VArr(validation.VObj(
			validation.KV{K: "path", V: validation.VStr("src/V.sol")},
			validation.KV{K: "function", V: validation.VStr("f")}))},
		validation.KV{K: "attacker", V: validation.VObj(
			validation.KV{K: "profile", V: validation.VStr("arbitrary EOA")},
			validation.KV{K: "capabilities", V: validation.VArr()})},
	)
	f, err := IngestHypothesis(c, payload, "code", "discovery", "")
	if err != nil {
		t.Fatal(err)
	}
	return c, validation.ObjStr(f, "finding_id")
}

func TestFactReadIsRecordedWithItsBlock(t *testing.T) {
	c, fid := factCampaign(t)
	f, err := RecordFactRead(c, fid,
		"cast call 0xC0FFEE 'cap()(uint256)' --block 21000000",
		"1000000000000000000000", "ethereum", "operator", 21000000, false)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	facts := validation.ObjAt(f, "deployment_facts")
	if len(facts.A) != 1 {
		t.Fatalf("deployment_facts = %d rows, want 1", len(facts.A))
	}
	if got := validation.ObjStr(facts.A[0], "value"); got != "1000000000000000000000" {
		t.Fatalf("value = %q", got)
	}
	if got := validation.ObjAt(facts.A[0], "block").I; got != 21000000 {
		t.Fatalf("block = %d", got)
	}
}

func TestFactReadRefusesAnUnpinnedOrMutatingCommand(t *testing.T) {
	c, fid := factCampaign(t)
	if _, err := RecordFactRead(c, fid, "cast call 0xC0FFEE 'cap()(uint256)'",
		"1", "ethereum", "operator", 0, false); err == nil ||
		!strings.Contains(err.Error(), "pinned block") {
		t.Fatalf("err = %v, want the pinned-block refusal", err)
	}
	if _, err := RecordFactRead(c, fid, "cast send 0xC0FFEE 'drain()'",
		"0x1", "ethereum", "operator", 21000000, false); err == nil ||
		!strings.Contains(err.Error(), "is a write") {
		t.Fatalf("err = %v, want the mutating-verb refusal", err)
	}
	// An unrecognized read is recordable, but only with the attestation —
	// a non-EVM chain must not force the operator to skip or fake the read.
	if _, err := RecordFactRead(c, fid, "solana account 0xC0FFEE",
		"1", "solana", "operator", 21000000, false); err == nil ||
		!strings.Contains(err.Error(), "--read-only") {
		t.Fatalf("err = %v, want the attestation refusal", err)
	}
	if _, err := RecordFactRead(c, fid, "solana account 0xC0FFEE",
		"1", "solana", "operator", 21000000, true); err != nil {
		t.Fatalf("attested non-EVM read refused: %v", err)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/findings -run TestFactRead -count=1`
Expected: FAIL to compile — `RecordFactRead` undefined.

- [ ] **Step 3: Implement the record**

Create `internal/findings/fact_read.go`:

```go
package findings

// Deployment-fact reads (framework-plan-v1.6 Part 8, non-negotiable 5): a
// value not read from the deployment is an assumption. The snapshot proves
// which CODE runs, never what the INSTANCE holds — so a config value the
// exploit depends on (a cap, an oracle address, a role grant) is recorded
// with the command that read it and the block it was read at, or it stays an
// assumption on the ladder.

import (
	"fmt"
	"regexp"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// mutatingPattern matches the verbs and flags that make a command a WRITE.
var mutatingPattern = regexp.MustCompile(`(?i)(^|\s)(cast\s+send|cast\s+mktx|` +
	`cast\s+publish|cast\s+wallet|forge\s+create|forge\s+script)(\s|$)` +
	`|--private-key|--ledger|--unlocked`)

// knownReadPattern is the recognized read shape: no attestation needed.
var knownReadPattern = regexp.MustCompile(
	`(?i)^(cast\s+(call|storage|code|balance|block|logs)|[a-z0-9_.-]+\s+query)\s`)

// pyTruncStr is a local three-line truncation for error text.
func pyTruncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// RecordFactRead appends one read to the finding's deployment_facts and logs
// finding.fact_read. Refused: a read with no pinned block (a mutable view of a
// mutable chain proves nothing), and any command carrying a mutating verb or a
// signing flag. The check is a DENYLIST, not an allowlist of `cast call` /
// `cast storage`: an unrecognized-but-harmless read on another chain must be
// recordable, or the operator skips it (or fakes it) and the fact never lands.
// An unrecognized command needs --read-only, an explicit attestation by the
// actor whose name goes on the row.
func RecordFactRead(c *state.Campaign, findingID, command, value, chain,
	actor string, block int64, readOnlyAttested bool) (validation.Value, error) {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return validation.VNull(), fmt.Errorf("--command is required")
	}
	if m := mutatingPattern.FindString(trimmed); m != "" {
		return validation.VNull(), fmt.Errorf(
			"fact reads are read-only: %q is a write", strings.TrimSpace(m))
	}
	if !knownReadPattern.MatchString(trimmed) && !readOnlyAttested {
		return validation.VNull(), fmt.Errorf(
			"unrecognized read command %q: pass --read-only to attest it writes nothing",
			pyTruncStr(trimmed, 80))
	}
	if block <= 0 {
		return validation.VNull(), fmt.Errorf(
			"a fact read needs a pinned block (--block N): an unpinned read is an assumption")
	}
	finding, err := LoadFinding(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	row := validation.VObj(
		validation.KV{K: "command", V: validation.VStr(trimmed)},
		validation.KV{K: "value", V: validation.VStr(value)},
		validation.KV{K: "chain", V: validation.VStr(orDefault(chain, "ethereum"))},
		validation.KV{K: "block", V: validation.VInt(block)},
		validation.KV{K: "read_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "actor", V: validation.VStr(orDefault(actor, "operator"))},
		validation.KV{K: "read_only_attested", V: validation.VBool(readOnlyAttested)},
	)
	facts := validation.ObjAt(finding, "deployment_facts")
	facts.A = append(facts.A, row)
	finding.O = validation.SetOrAppend(finding.O, "deployment_facts", facts)
	fid := validation.ObjStr(finding, "finding_id")
	if err := SaveThenLog(c, &finding, func() error {
		data := validation.VObj(
			validation.KV{K: "command", V: validation.VStr(trimmed)},
			validation.KV{K: "block", V: validation.VInt(block)},
		)
		_, lerr := c.Log("finding.fact_read", &fid, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}
```

`orDefault` already exists in this package (`internal/findings/ingest_payload.go:20`) — reuse it; do not add a second one.

- [ ] **Step 4: Add the schema key**

In `assets/schema/finding.schema.json`, add to the top-level `properties`:

```json
    "deployment_facts": {
      "type": "array",
      "description": "Values READ from the deployment (v1.6 Part 8): each carries the exact cast command, the raw value, and the pinned block. A value not recorded here is an assumption, not a fact.",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["command", "value", "chain", "block", "read_at"],
        "properties": {
          "command": { "type": "string", "minLength": 10 },
          "value": { "type": "string" },
          "chain": { "type": "string", "minLength": 1 },
          "block": { "type": "integer", "minimum": 1 },
          "read_at": { "type": "string" },
          "actor": { "type": "string" },
          "read_only_attested": {
            "type": "boolean",
            "description": "The actor's explicit attestation that an unrecognized command writes nothing (non-EVM reads). False for the recognized read shapes."
          }
        }
      }
    },
```

- [ ] **Step 5: Run it to verify it passes**

Run: `go test ./internal/findings -run TestFactRead -count=1`
Expected: PASS.

- [ ] **Step 6: Add the verb and its test**

Create `internal/cli/cmd_fact_read.go` (copy `cmd_impact.go`'s shape: `argSpec`, `t14Dispatch`, `t14Open`) registering:

```go
func init() {
	register(command{ord: 94, name: "fact-read",
		line: `fact-read <campaign> <finding> --command C --value V --block N [--chain C] [--actor A] [--read-only]   record a deployment read as a fact`,
		run:  runFactRead})
}
```

Success prints `fact read on <F-id> at block <N>: <value>`; a refusal maps to exit 2 with the refusal text verbatim. The help branch must short-circuit before argument validation and state access (`TestEveryCommandAnswersHelp`, `internal/cli/help_test.go:16`), and the verb needs its `assets/runbook/RUNBOOK.md` line in this commit or `internal/cli/runbook_test.go` fails.

Create `internal/cli/cmd_fact_read_test.go` asserting the happy path (exit 0, stdout line), both refusals (exit 2, exact text), and the attested non-EVM read, using `t15Campaign` + `t15Finding` from `internal/cli/cmd_dedup_test.go:28`.

- [ ] **Step 7: Manifest, tests, commit**

```bash
python3 scripts/sync-asset-manifest.py
go test ./internal/findings ./internal/cli -count=1
git add internal/findings/fact_read.go internal/findings/fact_read_test.go \
        internal/cli/cmd_fact_read.go internal/cli/cmd_fact_read_test.go \
        assets/schema/finding.schema.json assets/runbook/RUNBOOK.md \
        assets/testdata/asset_manifest.json
git commit -m "feat(findings): deployment-fact reads with a pinned block (v1.6 P2)"
```

---

### Task 6: Two-tier PoC evidence (`EXISTENCE` / `MAXIMIZED`)

Spec §2.2: fork evidence is produced in two tiers — `EXISTENCE` (E5-min: the state break on a pinned fork, any magnitude, non-optimized) and `MAXIMIZED` (the output of the maximization loop). The tier breaks the circularity where provisional severity needs a magnitude that only verification produces.

**The ordering rule is conditional, and it is not a CLI rule.** Two constraints that Task 8 makes load-bearing:

1. A hypothesis with `fork_dependence: none` is decidable on a local harness — it has no fork to demonstrate existence on, so a blanket "maximized requires existence" would make a locally-maximized, fork-independent finding unmintable. The rule is `ForkDependent(finding) && !HasPocTier(finding, "existence")`.
2. `reproduction.AttemptAndMint` (`internal/reproduction/reproduction_mint.go:82`) is the shared write path — `mint` and the ladder both go through it, and Phase 5's maximization loop will too. A spec-level invariant enforced at the argparse layer is not enforced, so the check lives in `findings.ValidatePocTierOrder` and is called from the write path; the CLI pre-check exists only to give a better message.

**Do not touch `mint --tier`.** That flag is the T1–T4 *claim* tier, mapped to evidence levels by `findings.MintEvidenceLevelType` and pinned in `mintHelp`. The PoC tier is a new, orthogonal flag.

**Files:**
- Create: `internal/findings/poc_tier.go`
- Create: `internal/findings/poc_tier_test.go`
- Create: `internal/findings/fork_dependence.go` (the predicate only — Task 8 extends this file; its test lives in `poc_tier_test.go`, beside the law that needs it)
- Modify: `internal/findings/exec_evidence.go` (`MintedExecEvidenceItem` gains `pocTier string`)
- Modify: `internal/findings/ingest.go:288` (pass `""`)
- Modify: `internal/reproduction/reproduction_mint.go:82` (pass the tier through)
- Modify: `internal/cli/cmd_mint.go` (`--poc-tier`, the ordering refusal, the help block)
- Modify: `assets/schema/finding.schema.json` (`evidence_item.poc_tier`)

**Interfaces:**
- Consumes: `findings.LoadFinding`, `findings.MintedExecEvidenceItem`, `reproduction.AttemptAndMint`.
- Produces: `findings.PocTiers = []string{"existence","maximized"}`, `findings.PocTierOf(f validation.Value) string`, `findings.HasPocTier(f validation.Value, tier string) bool`, `findings.MaximizedEvidence(f validation.Value) (validation.Value, bool)`, `findings.ValidatePocTierOrder(f validation.Value, tier string) error`, **`findings.ForkDependent(f validation.Value) bool`**; evidence-item key `poc_tier`.

**`ForkDependent` lands here, not in Task 8 — Task 6 must commit green.** The ordering law is conditional on fork dependence, so `ValidatePocTierOrder` cannot compile without the predicate, and every task in this plan leaves `go test ./... -count=1` green. Task 6 creates `internal/findings/fork_dependence.go` with the predicate and its test; Task 8 *extends that same file* with `ForkDependenceValues`, `ExistenceFundingRequired`, the setter and the verb. Splitting one small file across two tasks in build order is the cheap fix — reordering the tasks would drag the schema key, the verb and the ingest attribution into the PoC work for no benefit.

- [ ] **Step 1: Write the failing test**

Create `internal/findings/poc_tier_test.go`:

```go
package findings

import (
	"testing"

	"websec/internal/validation"
)

func TestPocTierOfReportsTheHighestTierPresent(t *testing.T) {
	f := validation.VObj(
		validation.KV{K: "evidence", V: validation.VArr(
			validation.VObj(validation.KV{K: "evidence_id", V: validation.VStr("EV-1")},
				validation.KV{K: "poc_tier", V: validation.VStr("existence")}),
			validation.VObj(validation.KV{K: "evidence_id", V: validation.VStr("EV-2")},
				validation.KV{K: "poc_tier", V: validation.VStr("maximized")}),
		)})
	if got := PocTierOf(f); got != "maximized" {
		t.Fatalf("PocTierOf = %q, want maximized", got)
	}
	if !HasPocTier(f, "existence") {
		t.Fatal("HasPocTier(existence) = false, want true")
	}
	if _, ok := MaximizedEvidence(f); !ok {
		t.Fatal("MaximizedEvidence = false, want true")
	}
}

func TestPocTierOfIsNoneWithoutTieredEvidence(t *testing.T) {
	f := validation.VObj(validation.KV{K: "evidence", V: validation.VArr(
		validation.VObj(validation.KV{K: "evidence_id", V: validation.VStr("EV-1")}))})
	if got := PocTierOf(f); got != "none" {
		t.Fatalf("PocTierOf = %q, want none", got)
	}
	if _, ok := MaximizedEvidence(f); ok {
		t.Fatal("MaximizedEvidence = true on untiered evidence")
	}
}

// TestForkDependentDefaultsToDependent pins the §2.2 default: absent is
// unknown is dependent, because a missing value must never defund the
// evidence that would correct it.
func TestForkDependentDefaultsToDependent(t *testing.T) {
	if ForkDependent(validation.VObj(
		validation.KV{K: "fork_dependence", V: validation.VStr("none")})) {
		t.Fatal("fork_dependence=none must not be fork-dependent")
	}
	for _, v := range []string{"external-protocol-state", "real-price-feed",
		"real-balances-liquidity", "proxy-implementation"} {
		if !ForkDependent(validation.VObj(
			validation.KV{K: "fork_dependence", V: validation.VStr(v)})) {
			t.Fatalf("fork_dependence=%s must be fork-dependent", v)
		}
	}
	if !ForkDependent(validation.VObj()) {
		t.Fatal("an absent fork_dependence must default to dependent")
	}
}

// TestValidatePocTierOrderIsConditionalOnForkDependence is the Task 6/Task 8
// compatibility law: a fork-independent hypothesis has no fork to break, so it
// may be maximized without an existence tier; a fork-dependent one may not.
func TestValidatePocTierOrderIsConditionalOnForkDependence(t *testing.T) {
	dependent := validation.VObj(
		validation.KV{K: "fork_dependence", V: validation.VStr("real-price-feed")},
		validation.KV{K: "evidence", V: validation.VArr()})
	if err := ValidatePocTierOrder(dependent, "maximized"); err == nil {
		t.Fatal("fork-dependent maximized mint without existence must be refused")
	}
	independent := validation.VObj(
		validation.KV{K: "fork_dependence", V: validation.VStr("none")},
		validation.KV{K: "evidence", V: validation.VArr()})
	if err := ValidatePocTierOrder(independent, "maximized"); err != nil {
		t.Fatalf("fork-independent maximized mint refused: %v", err)
	}
	if err := ValidatePocTierOrder(dependent, "existence"); err != nil {
		t.Fatalf("existence tier must always be allowed: %v", err)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/findings -run TestPocTier -count=1`
Expected: FAIL to compile — `PocTierOf` undefined.

- [ ] **Step 3: Implement the tier accessors**

Create `internal/findings/poc_tier.go`:

```go
package findings

// Two-tier fork evidence (framework-plan-v1.6 §2.2). EXISTENCE is the cheap
// tier: the state break on a pinned fork, at any magnitude, under
// non-optimized conditions. MAXIMIZED is the maximization loop's output.
// Severity's provisional pass consumes EXISTENCE; its final pass requires
// MAXIMIZED. The tier is a property of the EVIDENCE, never of the class —
// the same class can be decidable on a local harness for one hypothesis and
// need real protocol state for the next.

import (
	"fmt"

	"websec/internal/validation"
)

// PocTiers are the declared tiers, weakest first.
var PocTiers = []string{"existence", "maximized"}

// PocTierOf returns the strongest tier present on a finding's evidence, or
// "none" when no evidence item carries a tier.
func PocTierOf(f validation.Value) string {
	out := "none"
	for _, tier := range PocTiers {
		if HasPocTier(f, tier) {
			out = tier
		}
	}
	return out
}

// HasPocTier reports whether any evidence item carries this tier.
func HasPocTier(f validation.Value, tier string) bool {
	for _, e := range validation.ObjAt(f, "evidence").A {
		if validation.ObjStr(e, "poc_tier") == tier {
			return true
		}
	}
	return false
}

// MaximizedEvidence returns the first MAXIMIZED evidence item.
func MaximizedEvidence(f validation.Value) (validation.Value, bool) {
	for _, e := range validation.ObjAt(f, "evidence").A {
		if validation.ObjStr(e, "poc_tier") == "maximized" {
			return e, true
		}
	}
	return validation.VNull(), false
}

// ValidatePocTierOrder is the §2.2 ordering law, in the WRITE path so every
// caller obeys it — mint, the ladder, and Phase 5's maximization loop alike.
// MAXIMIZED requires an EXISTENCE tier first, but only where the hypothesis is
// fork-dependent: a fork-independent hypothesis has no fork to break, and
// demanding one would make it unmintable.
func ValidatePocTierOrder(f validation.Value, tier string) error {
	if tier != "maximized" {
		return nil
	}
	if !ForkDependent(f) {
		return nil
	}
	if !HasPocTier(f, "existence") {
		return fmt.Errorf("a maximized PoC requires an existence-tier PoC " +
			"first (v1.6 §2.2): mint the state break, then maximize it")
	}
	return nil
}
```

Then create `internal/findings/fork_dependence.go` with the predicate the law above calls (Task 8 extends this file; it does not create it):

```go
package findings

// ForkDependent reports whether a hypothesis needs real fork state (v1.6
// §2.2). Absent is unknown is DEPENDENT: an unrecorded value must never
// silently defund the evidence that would correct it. It lives here rather
// than with the rest of fork_dependence because ValidatePocTierOrder is
// conditional on it, and every task commits green.
func ForkDependent(f validation.Value) bool {
	return validation.ObjStr(f, "fork_dependence") != "none"
}
```

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/findings -run 'TestPocTier|TestForkDependent|TestValidatePocTierOrder' -count=1`
Expected: PASS.

- [ ] **Step 5: Carry the tier into the evidence item**

In `internal/findings/exec_evidence.go`, add a `pocTier string` parameter to `MintedExecEvidenceItem` and set the key only when non-empty (so pre-existing evidence items keep their exact bytes):

```go
	if pocTier != "" {
		item.O = validation.SetOrAppend(item.O, "poc_tier", validation.VStr(pocTier))
	}
```

Update both callers: `internal/findings/ingest.go:288` passes `""`, and `internal/reproduction/reproduction_mint.go:82` passes the tier from its options (thread a `PocTier string` field through `reproduction.RecordOpts`/the mint options struct it already carries).

Add the schema key in `assets/schema/finding.schema.json` under `definitions.evidence_item.properties`:

```json
        "poc_tier": {
          "enum": ["existence", "maximized"],
          "description": "Two-tier fork evidence (v1.6 §2.2). existence = the state break demonstrated on a pinned fork at any magnitude; maximized = the maximization loop's output. Absent = untiered (every pre-existing evidence item)."
        },
```

- [ ] **Step 6: Write the failing CLI test for the ordering refusal**

In `internal/cli/cmd_mint_test.go` (append; do not restructure the file):

```go
func TestMintMaximizedRequiresExistenceFirst(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	f := t15Finding(t, c, "Attacker drains the vault", "economic-invariant")
	fid := validation.ObjStr(f, "finding_id")
	execID := mintTestExec(t, c) // the helper the existing mint tests use to seed a SUCCEEDED exec
	code, _, errS := run(t, "--root", root, "mint", c.CampaignID, fid,
		"--exec", execID, "--description", "maximized drain",
		"--poc-tier", "maximized")
	if code != 2 {
		t.Fatalf("code = %d, want 2 (stderr %s)", code, errS)
	}
	if !strings.Contains(errS, "requires an existence-tier PoC first") {
		t.Fatalf("stderr = %q, want the ordering refusal", errS)
	}
}
```

If the existing mint tests seed execs another way, reuse *their* helper verbatim — do not invent a second one.

- [ ] **Step 7: Enforce the order in the write path, then surface it in the CLI**

In `internal/reproduction/reproduction_mint.go`, call the law before the evidence item is built — this is the enforcement point, and both the CLI and the ladder inherit it:

```go
	if err := findings.ValidatePocTierOrder(finding, pocTier); err != nil {
		return validation.VNull(), err
	}
```

Then, in `internal/cli/cmd_mint.go`, add the CLI pre-check so the operator gets an exit-2 usage error rather than a generic failure. Keep it as a *pre-check only* — it must not be the only enforcement:

```go
	if m.pocTier == "maximized" {
		finding, err := findings.LoadFinding(c, m.pos[1])
		if err != nil {
			return err
		}
		if err := findings.ValidatePocTierOrder(finding, "maximized"); err != nil {
			return t14ExitErr(2, "%v\n", err)
		}
	}
```

Both halves are tested: `TestValidatePocTierOrderIsConditionalOnForkDependence` (Step 1) covers the rule, `TestMintMaximizedRequiresExistenceFirst` (Step 6) covers the CLI surface, and a third test calls `reproduction.AttemptAndMint` directly to prove the write path refuses even when the CLI is bypassed — add it to `internal/reproduction/reproduction_test.go` next to `TestRollbackRestoresPriorAttemptState`.

- [ ] **Step 8: Run it to verify it passes**

Run: `go test ./internal/cli -run TestMint -count=1`
Expected: PASS, including the existing pinned `mintHelp` test — update that test's expected bytes in this step, deliberately, in the same commit. Add the `--poc-tier` line to the RUNBOOK's `mint` section in this commit too (`mint` is already documented, so `runbook_test.go` will not catch a missing flag description — a human reviewer has to).

- [ ] **Step 9: Manifest, wider tests, commit**

```bash
python3 scripts/sync-asset-manifest.py
go test ./internal/findings ./internal/reproduction ./internal/cli -count=1
git add internal/findings/poc_tier.go internal/findings/poc_tier_test.go \
        internal/findings/exec_evidence.go internal/findings/ingest.go \
        internal/reproduction/ internal/cli/cmd_mint.go internal/cli/cmd_mint_test.go \
        assets/schema/finding.schema.json assets/runbook/RUNBOOK.md \
        assets/testdata/asset_manifest.json
git commit -m "feat(mint): two-tier PoC evidence, existence before maximized (v1.6 P2)"
```

---

### Task 7: Replayability calculator (§2.4) — Phase 2 exit criterion

Spec §2.4: Sherlock's replayability rule as a declared impact transform — *a repeatable single-shot loss is scored as total loss, before banding*. **Demonstrated and computed impact are separate, labeled quantities, never conflated**: presenting a computed ceiling as a demonstrated extraction is what a triager reads as misrepresentation, and on Immunefi that is a zero-payout violation.

The arithmetic is deliberately small and total: rounds to exhaustion from the pool and the demonstrated per-round extraction; the ceiling is the pool; the attack cost is rounds × per-round gas.

**Files:**
- Create: `internal/risk/replay.go`
- Create: `internal/risk/replay_test.go`
- Modify: `internal/cli/cmd_impact.go` (the `--replayable` family)
- Modify: `assets/schema/finding.schema.json` (`replay`)

**Interfaces:**
- Consumes: `risk.RecordEconomicImpact`, `findings.SaveThenLog` (through the existing impact write path).
- Produces: `risk.ComputeReplay(demonstratedRounds int64, extractedPerRound, poolUSD, gasCostUSD float64, frequencyPerDay *float64) validation.Value`, `risk.RecordReplay(c *state.Campaign, findingID string, rec validation.Value, ruleCited, actor string) (validation.Value, error)`; finding key `replay`.

- [ ] **Step 1: Write the failing test**

Create `internal/risk/replay_test.go`:

```go
package risk

import (
	"math"
	"strings"
	"testing"

	"websec/internal/validation"
)

func TestComputeReplaySeparatesDemonstratedFromComputed(t *testing.T) {
	freq := 1000.0
	rec := ComputeReplay(2, 500, 1000000, 0.05, &freq)
	demo := validation.ObjAt(rec, "demonstrated")
	if got := validation.ObjAt(demo, "rounds_run").I; got != 2 {
		t.Fatalf("rounds_run = %d, want 2", got)
	}
	if got := validation.ObjAt(demo, "extracted_usd_per_round").F; got != 500 {
		t.Fatalf("extracted_usd_per_round = %v", got)
	}
	comp := validation.ObjAt(rec, "computed")
	if got := validation.ObjAt(comp, "rounds_to_exhaustion").I; got != 2000 {
		t.Fatalf("rounds_to_exhaustion = %d, want 2000", got)
	}
	if got := validation.ObjAt(comp, "ceiling_usd").F; got != 1000000 {
		t.Fatalf("ceiling_usd = %v, want the pool", got)
	}
	// 2000 rounds * 0.05 gas = 100 USD of attack cost.
	if got := validation.ObjAt(comp, "cumulative_attack_cost_usd").F; math.Abs(got-100) > 1e-9 {
		t.Fatalf("cumulative_attack_cost_usd = %v, want 100", got)
	}
	// 2000 rounds at 1000 rounds/day = 2 days.
	if got := validation.ObjAt(comp, "time_to_exhaustion_days").F; math.Abs(got-2) > 1e-9 {
		t.Fatalf("time_to_exhaustion_days = %v, want 2", got)
	}
	if got := validation.ObjStr(rec, "rule_cited"); got != "sherlock-replayability" {
		t.Fatalf("rule_cited = %q", got)
	}
}

func TestComputeReplayRoundsUpAPartialFinalRound(t *testing.T) {
	rec := ComputeReplay(2, 300, 1000, 0, nil)
	if got := validation.ObjAt(validation.ObjAt(rec, "computed"), "rounds_to_exhaustion").I; got != 4 {
		t.Fatalf("rounds_to_exhaustion = %d, want 4 (ceil(1000/300))", got)
	}
}

// TestReplayProfitabilityIsRequired: an attack that costs more than the pool
// cannot be scored as a total loss without a recorded blocker.
func TestReplayProfitabilityIsRequired(t *testing.T) {
	// 1 round to exhaust a 1000 USD pool, 5000 USD of gas: absurd.
	absurd := ComputeReplay(2, 1000, 1000, 5000, nil)
	if err := ValidateReplayProfitability(absurd); err == nil ||
		!strings.Contains(err.Error(), "unprofitable") {
		t.Fatalf("err = %v, want the profitability refusal", err)
	}
	absurd = SetReplayAssumptions(absurd, nil,
		[]string{"gas estimate assumes mainnet priority fees; measured 0.05/round"})
	if err := ValidateReplayProfitability(absurd); err != nil {
		t.Fatalf("blocked record refused: %v", err)
	}
	if err := ValidateReplayProfitability(ComputeReplay(2, 1000, 1000, 100, nil)); err != nil {
		t.Fatalf("profitable record refused: %v", err)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/risk -run TestComputeReplay -count=1`
Expected: FAIL to compile — `ComputeReplay` undefined.

- [ ] **Step 3: Implement the calculator**

Create `internal/risk/replay.go`:

```go
package risk

// The replayability calculator (framework-plan-v1.6 §2.4): Sherlock's rule as
// a declared impact transform — a single-shot loss repeatable without bound is
// scored as TOTAL loss, not per-shot magnitude. Two quantities come out of
// this and must never be conflated in a report: DEMONSTRATED (what the
// verification run actually extracted) and COMPUTED (the arithmetic
// extrapolation to the pool). Presenting the second as the first is
// misrepresentation, and on Immunefi that is a zero-payout violation.

import (
	"fmt"
	"math"

	"websec/internal/validation"
)

// ComputeReplay builds the §2.4 replay record. poolUSD is the value at stake
// (the finding's --max-loss): the ceiling a replay can reach. frequencyPerDay
// is optional; when absent the time-to-exhaustion figure is omitted rather
// than guessed.
func ComputeReplay(demonstratedRounds int64, extractedPerRound, poolUSD,
	gasCostUSD float64, frequencyPerDay *float64) validation.Value {
	rounds := int64(0)
	if extractedPerRound > 0 {
		rounds = int64(math.Ceil(poolUSD / extractedPerRound))
	}
	cost := float64(rounds) * gasCostUSD
	computed := validation.VObj(
		validation.KV{K: "rounds_to_exhaustion", V: validation.VInt(rounds)},
		validation.KV{K: "ceiling_usd", V: validation.VFloat(poolUSD)},
		validation.KV{K: "cumulative_attack_cost_usd", V: validation.VFloat(cost)},
	)
	if frequencyPerDay != nil && *frequencyPerDay > 0 {
		computed.O = validation.SetOrAppend(computed.O, "time_to_exhaustion_days",
			validation.VFloat(float64(rounds) / *frequencyPerDay))
	}
	return validation.VObj(
		validation.KV{K: "demonstrated", V: validation.VObj(
			validation.KV{K: "rounds_run", V: validation.VInt(demonstratedRounds)},
			validation.KV{K: "extracted_usd_per_round", V: validation.VFloat(extractedPerRound)},
		)},
		validation.KV{K: "computed", V: computed},
		validation.KV{K: "rule_cited", V: validation.VStr("sherlock-replayability")},
		validation.KV{K: "replay_assumptions", V: validation.VArr()},
		validation.KV{K: "replay_blockers", V: validation.VArr()},
	)
}
```

Add `SetReplayAssumptions(rec validation.Value, assumptions, blockers []string) validation.Value` filling the two arrays, `ValidateReplayProfitability(rec validation.Value) error`, and `RecordReplay` writing the block onto the finding under `replay` plus one `finding.replay_recorded` event (same `SaveThenLog` shape as `RecordFactRead` in Task 5).

**The profitability law.** A replay whose attack cost exceeds the value at stake is not a total-loss finding — it is a finding that loses money, and calling it a total loss is exactly the misrepresentation §2.4 exists to prevent. So a record with `cumulative_attack_cost_usd > ceiling_usd` is refused unless it carries at least one `replay_blocker`:

```go
// ValidateReplayProfitability refuses the absurd case: an attack that costs
// more than it extracts cannot be scored as a total loss. The escape is a
// recorded blocker (the cost figure is wrong, or the pool is not the ceiling),
// not silence.
func ValidateReplayProfitability(rec validation.Value) error {
	comp := validation.ObjAt(rec, "computed")
	cost := validation.ObjAt(comp, "cumulative_attack_cost_usd").F
	ceiling := validation.ObjAt(comp, "ceiling_usd").F
	if cost <= ceiling {
		return nil
	}
	if len(validation.ObjAt(rec, "replay_blockers").A) > 0 {
		return nil
	}
	return fmt.Errorf("replay is unprofitable: attack cost %.2f exceeds the "+
		"ceiling %.2f — record a replay_blocker or drop the total-loss claim", cost, ceiling)
}
```

`RecordReplay` calls it before writing, so the refusal happens on the write path like Task 6's ordering law.

**Float determinism.** `validation.VFloat` canonicalizes through the Python float repr, which is exactly how every existing USD field is stored (`economic_impact.extractable_usd`), so the hash of a replay record is stable. Two consequences for the tests: compare money with a tolerance (`math.Abs(got-want) > 1e-9`, as Step 1 already does) rather than byte equality, and do **not** add a golden fixture whose hash covers a replay record — a golden pins bytes, and money in bytes is a flake waiting for a float repr change.

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/risk -run TestComputeReplay -count=1`
Expected: PASS.

- [ ] **Step 5: Add the schema key**

In `assets/schema/finding.schema.json`, add to the top-level `properties`:

```json
    "replay": {
      "type": "object",
      "additionalProperties": false,
      "description": "Replayability (v1.6 §2.4). demonstrated and computed are SEPARATE, LABELED quantities: a report carries both and never presents the computed ceiling as an extraction.",
      "required": ["demonstrated", "computed", "rule_cited"],
      "properties": {
        "demonstrated": {
          "type": "object",
          "additionalProperties": false,
          "required": ["rounds_run", "extracted_usd_per_round"],
          "properties": {
            "rounds_run": { "type": "integer", "minimum": 2 },
            "extracted_usd_per_round": { "type": "number", "minimum": 0 }
          }
        },
        "computed": {
          "type": "object",
          "additionalProperties": false,
          "required": ["rounds_to_exhaustion", "ceiling_usd", "cumulative_attack_cost_usd"],
          "properties": {
            "rounds_to_exhaustion": { "type": "integer", "minimum": 0 },
            "ceiling_usd": { "type": "number", "minimum": 0 },
            "cumulative_attack_cost_usd": { "type": "number", "minimum": 0 },
            "time_to_exhaustion_days": { "type": "number", "minimum": 0 }
          }
        },
        "rule_cited": { "type": "string", "minLength": 3 },
        "replay_assumptions": { "type": "array", "items": { "type": "string" } },
        "replay_blockers": { "type": "array", "items": { "type": "string" } }
      }
    },
```

Note `rounds_run: minimum 2` — the schema enforces the two-round termination law, so a one-round claim cannot even be written.

- [ ] **Step 6: Write the failing CLI test**

Append to `internal/cli/cmd_impact_test.go`:

```go
func TestImpactReplayableComputesAndRefusesOneRound(t *testing.T) {
	c, root := t15Campaign(t, "Acme")
	f := t15Finding(t, c, "Repeated drain", "economic-invariant")
	fid := validation.ObjStr(f, "finding_id")
	code, out, errS := run(t, "--root", root, "impact", c.CampaignID, fid,
		"--replayable", "--extractable-per-round", "500", "--max-loss", "1000000",
		"--gas-cost", "0.05", "--frequency", "1000",
		"--replay-assumption", "no pause triggered",
		"--replay-blocker", "PAUSER_ROLE exists, unexercised")
	if code != 0 {
		t.Fatalf("code = %d (stderr %s)", code, errS)
	}
	if !strings.Contains(out, "demonstrated") || !strings.Contains(out, "computed") {
		t.Fatalf("stdout = %q, want both labeled quantities", out)
	}
	code, _, errS = run(t, "--root", root, "impact", c.CampaignID, fid,
		"--replayable", "--extractable-per-round", "500", "--max-loss", "1000",
		"--gas-cost", "0.05", "--rounds-run", "1")
	if code != 2 || !strings.Contains(errS, "two rounds") {
		t.Fatalf("code = %d stderr = %q, want the two-round refusal", code, errS)
	}
	// 1 round extracts 500 from a 500 ceiling, at 5000 of gas: unprofitable.
	code, _, errS = run(t, "--root", root, "impact", c.CampaignID, fid,
		"--replayable", "--extractable-per-round", "500", "--max-loss", "500",
		"--gas-cost", "5000")
	if code != 2 || !strings.Contains(errS, "unprofitable") {
		t.Fatalf("code = %d stderr = %q, want the profitability refusal", code, errS)
	}
}
```

- [ ] **Step 7: Implement the flags**

In `internal/cli/cmd_impact.go`, add to `impactArgs`: `replayable bool`, `perRound, gasCost *float64`, `frequency *float64`, `roundsRun int64` (default 2), `assumptions, blockers []string`. Parse `--replayable`, `--extractable-per-round`, `--gas-cost`, `--frequency`, `--rounds-run`, and repeatable `--replay-assumption` / `--replay-blocker` (copy the repeatable-flag mechanism from `assume --ref`). Refusals, all exit 2 and all before any write:

- `--replayable` without `--extractable-per-round`, `--max-loss` and `--gas-cost` → `"impact --replayable requires --extractable-per-round, --max-loss and --gas-cost\n"`.
- `--rounds-run < 2` → `"impact --replayable requires at least two rounds (the repeatability law, v1.6 §2.4)\n"`.
- `--extractable-per-round` or `--max-loss` ≤ 0 → `"impact --replayable requires positive --extractable-per-round and --max-loss\n"`.
- attack cost > ceiling with no `--replay-blocker` → the `ValidateReplayProfitability` text, exit 2 (an unprofitable "total loss" is the misrepresentation §2.4 forbids).

On success, build the record with `risk.ComputeReplay`, attach assumptions/blockers, write it with `risk.RecordReplay`, and print both halves as labeled lines (the CLI is the operator's view; the *report* rendering is Phase 5 work):

```
demonstrated: 2 rounds x $500.00 = $1000.00 extracted
computed:     2000 rounds to exhaustion, ceiling $1000000.00, attack cost $100.00
```

- [ ] **Step 8: Run it to verify it passes**

Run: `go test ./internal/cli -run TestImpact -count=1`
Expected: PASS.

- [ ] **Step 9: Manifest, tests, commit**

```bash
python3 scripts/sync-asset-manifest.py
go test ./internal/risk ./internal/cli ./internal/findings -count=1
git add internal/risk/replay.go internal/risk/replay_test.go \
        internal/cli/cmd_impact.go internal/cli/cmd_impact_test.go \
        assets/schema/finding.schema.json assets/testdata/asset_manifest.json
git commit -m "feat(risk): replayability calculator, demonstrated vs computed (v1.6 P2)"
```

---

### Task 8: `fork_dependence` and ingest attribution

Spec §2.2: *"Fork-dependence is a property of the hypothesis, not the class"* — an oracle-manipulation hypothesis may be decidable on a local harness with a mocked feed or may need real Chainlink state. `existence_funding = E4_satisfied AND fork_dependence != none`.

Spec Part 1/C2 also carries the attribution fields (`origin_stage`, `contributing_stages`); `ingest` already accepts `--stage` but uses it only for the history line's actor/reason (`internal/findings/ingest.go:140-141`) — this task makes it a recorded field.

**Files:**
- Modify: `internal/findings/fork_dependence.go` (Task 6 created it with `ForkDependent`; add the value set, `ExistenceFundingRequired` and the setter)
- Create: `internal/findings/fork_dependence_test.go`
- Modify: `internal/findings/ingest.go` (`origin_stage`, `contributing_stages` on the built payload)
- Create: `internal/cli/cmd_fork_dependence.go`
- Create: `internal/cli/cmd_fork_dependence_test.go`
- Modify: `assets/schema/finding.schema.json` (three keys)

**Interfaces:**
- Consumes: `findings.ForkDependent` (Task 6 — already in the tree; do not redefine it).
- Produces: `findings.ForkDependenceValues = []string{"external-protocol-state","real-price-feed","real-balances-liquidity","proxy-implementation","none"}`, `findings.ExistenceFundingRequired(f validation.Value, e4Satisfied bool) bool`, `findings.SetForkDependence(c *state.Campaign, findingID, value, reason, actor string) (validation.Value, error)`; finding keys `fork_dependence`, `origin_stage`, `contributing_stages`; event `finding.fork_dependence_set`.

- [ ] **Step 1: Write the failing test**

Create `internal/findings/fork_dependence_test.go`:

```go
package findings

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

func TestForkDependenceDrivesExistenceFunding(t *testing.T) {
	none := validation.VObj(validation.KV{K: "fork_dependence", V: validation.VStr("none")})
	if ForkDependent(none) {
		t.Fatal("fork_dependence=none must not be fork-dependent")
	}
	if ExistenceFundingRequired(none, true) {
		t.Fatal("a fork-independent hypothesis needs no existence tranche")
	}
	feed := validation.VObj(validation.KV{K: "fork_dependence",
		V: validation.VStr("real-price-feed")})
	if !ForkDependent(feed) {
		t.Fatal("fork_dependence=real-price-feed must be fork-dependent")
	}
	if ExistenceFundingRequired(feed, false) {
		t.Fatal("E4 must be satisfied before existence funding (v1.6 §2.2)")
	}
	if !ExistenceFundingRequired(feed, true) {
		t.Fatal("E4-satisfied + fork-dependent = existence funding")
	}
	// Absent means unknown, and unknown is not 'none'.
	if !ForkDependent(validation.VObj()) {
		t.Fatal("an unrecorded fork_dependence must default to dependent, not to none")
	}
}

func TestSetForkDependenceRequiresAReason(t *testing.T) {
	c, fid := factCampaign(t) // the Task 5 fixture
	if _, err := SetForkDependence(c, fid, "none", "", "operator"); err == nil ||
		!strings.Contains(err.Error(), "--reason") {
		t.Fatalf("err = %v, want the reason refusal", err)
	}
	if _, err := SetForkDependence(c, fid, "oracle-ish", "because", "operator"); err == nil ||
		!strings.Contains(err.Error(), "fork_dependence must be one of") {
		t.Fatalf("err = %v, want the enum refusal", err)
	}
	f, err := SetForkDependence(c, fid, "none", "the harness mocks the feed", "operator")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if got := validation.ObjStr(f, "fork_dependence"); got != "none" {
		t.Fatalf("fork_dependence = %q", got)
	}
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/findings -run 'TestForkDependence|TestSetForkDependence' -count=1`
Expected: FAIL to compile — `undefined: ExistenceFundingRequired` (`ForkDependent` already exists: Task 6 landed it).

- [ ] **Step 3: Implement the accessors and the setter**

Create `internal/findings/fork_dependence.go`:

```go
package findings

// Per-hypothesis fork dependence (framework-plan-v1.6 §2.2). Fork-dependence
// is a property of the HYPOTHESIS, never of the class: an oracle-manipulation
// hypothesis with a mocked feed is decidable locally; the same class against
// real Chainlink state is not. The class-level set survives only as a PRIOR
// (Phase 5's rubric), which a hypothesis overrides with a recorded reason.

import (
	"fmt"
	"slices"

	"websec/internal/state"
	"websec/internal/validation"
)

// ForkDependenceValues are the declared values, weakest first.
var ForkDependenceValues = []string{
	"external-protocol-state", "real-price-feed", "real-balances-liquidity",
	"proxy-implementation", "none",
}

// ForkDependent is defined in Task 6 — it is NOT redefined here. The
// predicate is what ValidatePocTierOrder is conditional on, so Task 6 had to
// land it to commit green; this task adds everything around it.

// ExistenceFundingRequired is §2.2's formula, verbatim:
// existence_funding = E4_satisfied AND fork_dependence != none.
func ExistenceFundingRequired(f validation.Value, e4Satisfied bool) bool {
	return e4Satisfied && ForkDependent(f)
}

// SetForkDependence records the hypothesis's fork dependence with the reason
// the author gives. One event per set, hash-chained, actor-attributed.
func SetForkDependence(c *state.Campaign, findingID, value, reason, actor string) (validation.Value, error) {
	if !slices.Contains(ForkDependenceValues, value) {
		return validation.VNull(), fmt.Errorf(
			"fork_dependence must be one of %v", ForkDependenceValues)
	}
	if reason == "" {
		return validation.VNull(), fmt.Errorf(
			"fork-dependence requires --reason: an override without a recorded reason is a guess")
	}
	finding, err := LoadFinding(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	prior := validation.ObjStr(finding, "fork_dependence") // "" when never set
	finding.O = validation.SetOrAppend(finding.O, "fork_dependence", validation.VStr(value))
	fid := validation.ObjStr(finding, "finding_id")
	if err := SaveThenLog(c, &finding, func() error {
		data := validation.VObj(
			validation.KV{K: "fork_dependence", V: validation.VStr(value)},
			validation.KV{K: "prior_fork_dependence", V: validation.VStr(prior)},
			validation.KV{K: "reason", V: validation.VStr(reason)},
			validation.KV{K: "actor", V: validation.VStr(orDefault(actor, "operator"))},
		)
		_, lerr := c.Log("finding.fork_dependence_set", &fid, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}
```

`prior_fork_dependence` is `""` when the field was never set, and the current value on a re-set — that is what makes the override rate measurable later ("how often did the classifier get it wrong?"). Without it, a re-set is indistinguishable from a first set.

- [ ] **Step 4: Record attribution at ingest**

In `internal/findings/ingest.go`'s `ingestBuildPayload`, next to the `trajectory` write:

```go
	if stage != "" {
		p.O = validation.SetOrAppend(p.O, "origin_stage", validation.VStr(stage))
		if _, ok := fieldAt(p, "contributing_stages"); !ok {
			p.O = validation.SetOrAppend(p.O, "contributing_stages",
				validation.VArr(validation.VStr(stage)))
		}
	}
```

**Omit, do not invent.** When the caller passes no stage, the keys are absent — never `"unknown"`. This is the same law Task 8 states for `fork_dependence` ("absent is not `none`"): a fake attribution value is worse than a missing one, because it silently counts as a real stage in any cost-per-confirmed grouping, while a missing key is visibly missing. A caller that already knows the contributing stages (the discovery trajectory dispatcher) may set `contributing_stages` on the payload; the default is the origin stage alone.

- [ ] **Step 5: Add the schema keys**

In `assets/schema/finding.schema.json`, add to the top-level `properties`:

```json
    "origin_stage": {
      "type": "string",
      "minLength": 1,
      "description": "The pipeline stage that authored this hypothesis (v1.6 C2). Attribution: cost-per-confirmed is uncomputable without it."
    },
    "contributing_stages": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Every stage that contributed to this hypothesis, origin first."
    },
    "fork_dependence": {
      "enum": ["external-protocol-state", "real-price-feed", "real-balances-liquidity", "proxy-implementation", "none"],
      "description": "Per-hypothesis fork dependence (v1.6 §2.2). Absent = unknown = dependent: an unrecorded value must never silently defund the evidence that would correct it."
    },
```

- [ ] **Step 6: Run the package tests**

Run: `go test ./internal/findings -count=1`
Expected: PASS. The schema does **not** require `origin_stage`/`contributing_stages` (they are omitted when the caller has no stage, per Step 4), so a golden finding fixture changes bytes only if it pins a payload that *has* a stage. Update those fixtures deliberately in this commit and say so in the message.

- [ ] **Step 7: Add the verb and its test**

Create `internal/cli/cmd_fork_dependence.go` registering ord 95 (confirm the next free slot — Step 0's `ord` check — before committing):

```go
func init() {
	register(command{ord: 95, name: "fork-dependence",
		line: `fork-dependence <campaign> <finding> --set V --reason R [--actor A]   declare a hypothesis's fork dependence`,
		run:  runForkDependence})
}
```

The same three CLI-surface laws as Task 4's verb apply and are all in this commit: `-h`/`--help` print `usage: webv2 fork-dependence` on stdout with exit 0 and no state access (`internal/cli/help_test.go:16`); the verb gets its `assets/runbook/RUNBOOK.md` line or `internal/cli/runbook_test.go` fails; and a re-set must be testable through the CLI (set `none`, then set `real-price-feed`, and assert `prior_fork_dependence` in the second event is `none`).

Success prints `fork_dependence <F-id>: <value> (<reason>)`. Create `internal/cli/cmd_fork_dependence_test.go` asserting the happy path and the two refusals (exit 2, exact text) with `t15Campaign`/`t15Finding`.

- [ ] **Step 8: Manifest, tests, commit**

```bash
python3 scripts/sync-asset-manifest.py
go test ./internal/findings ./internal/cli -count=1
git add internal/findings/fork_dependence.go internal/findings/fork_dependence_test.go \
        internal/findings/ingest.go internal/cli/cmd_fork_dependence.go \
        internal/cli/cmd_fork_dependence_test.go assets/schema/finding.schema.json \
        assets/testdata/asset_manifest.json
git commit -m "feat(findings): per-hypothesis fork dependence and ingest attribution (v1.6 P2)"
```

---

### Task 9: Coverage of the new record fields (one audit section, eight fields)

Tasks 2–8 write eight new fields — `input_artifacts`/`context_artifacts`, `review_sessions[]`, `deployment_facts[]`, `poc_tier` on evidence, `replay`, `fork_dependence`, `origin_stage`, `contributing_stages` — and without this task **nothing in the repo reads any of them**. That is exactly the "telemetry nobody correlates" failure this framework exists to prevent: eight fields written, unit-tested, and never looked at again, each one free to silently stop being populated. One audit section turns eight orphans into one measured number, and the section registry is already the extension point.

**Files:**
- Create: `internal/audit/sections/v16coverage.go`
- Create: `internal/audit/sections/v16coverage_test.go`
- Modify: `internal/audit/sections/register.go` (register **last**)
- Modify: `internal/audit/p1_sections_test.go` if its oracle pins the section list or order
- Modify: `assets/runbook/RUNBOOK.md`, `assets/testdata/asset_manifest.json`

**Coverage is all eight fields, or it is the same problem one level up.** `review_sessions` is a `campaign_state` array, not a finding field, and the input-artifact declaration is an *event* (`model.request`) — so a section that only walks findings reads six of eight and would not notice if the other two silently stopped being written. `review_sessions` is the likeliest to rot, because nothing produces one unless an operator runs the verb. The section counts all eight, and the problems list stays limited to the three impossible states.

**Interfaces:**
- Consumes: `sections.SectionFunc`, `state.Campaign` (`State()`, `Events()`), `findings.LoadFinding`/the projection's finding ids, `findings.PocTierOf` (Task 6), `findings.ForkDependent` (Task 6), `reviewsession.Open` (Task 4, test only), `validation.ObjAt`.
- Produces: audit section `v16_coverage` — `{checked, ok, problems[], coverage{}}`; problem strings prefixed `v16_coverage:`; a package-local `listedFindings(c) []validation.Value` helper (the projection's ids through `findings.LoadFinding`, skipping superseded rows).

- [ ] **Step 1: Write the failing test**

Create `internal/audit/sections/v16coverage_test.go`:

```go
package sections

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

func TestV16CoverageCountsWhatTheNewFieldsRecorded(t *testing.T) {
	c := coverageCampaign(t, coverageRow{
		confirmed: true, forkDependence: "real-price-feed",
		originStage: "discovery", pocTier: "existence", facts: 2, replay: true,
	}, coverageRow{confirmed: true}) // a bare finding: nothing recorded
	sec, err := V16Coverage(c)
	if err != nil {
		t.Fatal(err)
	}
	cov := validation.ObjAt(sec, "coverage")
	for _, want := range []struct {
		key  string
		got  int64
	}{
		{"findings", 2}, {"confirmed", 2},
		{"fork_dependence_set", 1}, {"origin_stage", 1}, {"contributing_stages", 1},
		{"deployment_facts", 1}, {"replay_recorded", 1},
		{"poc_tier_existence", 1}, {"poc_tier_maximized", 0},
	} {
		if got := validation.ObjAt(cov, want.key).I; got != want.got {
			t.Errorf("coverage.%s = %d, want %d", want.key, got, want.got)
		}
	}
	if len(validation.ObjAt(sec, "problems").A) != 0 {
		t.Fatalf("problems = %v, want none: coverage is a measurement, not a verdict",
			validation.ObjAt(sec, "problems"))
	}
}

// TestV16CoverageCountsTheNonFindingFields: review_sessions and the
// input-artifact declaration are not finding fields, and they are the two most
// likely to silently stop being written — a section that read only the six
// finding fields would not notice either.
func TestV16CoverageCountsTheNonFindingFields(t *testing.T) {
	c := coverageCampaign(t, coverageRow{confirmed: true})
	if _, err := reviewsession.Start(c, "operator", []string{"ART-aaaa1111"}); err != nil {
		t.Fatal(err)
	}
	sec, err := V16Coverage(c)
	if err != nil {
		t.Fatal(err)
	}
	cov := validation.ObjAt(sec, "coverage")
	if got := validation.ObjAt(cov, "review_sessions").I; got != 1 {
		t.Fatalf("review_sessions = %d, want 1", got)
	}
	if got := validation.ObjAt(cov, "review_sessions_closed").I; got != 0 {
		t.Fatalf("review_sessions_closed = %d, want 0 (the session is open)", got)
	}
	if got := validation.ObjAt(cov, "model_requests").I; got != 0 {
		t.Fatalf("model_requests = %d, want 0 for a campaign that logged none", got)
	}
}

// The three states that must never exist, whatever the coverage numbers say.
//
// These rows are written DIRECTLY — through findings.SaveThenLog on a
// hand-mutated finding, not through the public setters — and that is the
// point, not a shortcut. RecordReplay calls ValidateReplayProfitability and
// RecordFactRead refuses block <= 0, so the write paths cannot produce these
// states at all: that is exactly why the guards were put there. A fixture that
// went through the setters would either fail (the guards hold) or force
// someone to weaken a guard to make a test pass. The states remain reachable
// in the field from data that predates the guard or arrives from an older
// binary, which is what an audit section is for.
func TestV16CoverageFlagsImpossibleRecords(t *testing.T) {
	c := coverageCampaign(t,
		coverageRow{confirmed: true, forkDependence: "real-price-feed", pocTier: "maximized"},
		coverageRow{confirmed: true, replay: true, replayCost: 5000, replayCeiling: 1000},
		coverageRow{confirmed: true, facts: 1, factBlock: 0},
	)
	sec, err := V16Coverage(c)
	if err != nil {
		t.Fatal(err)
	}
	problems := validation.ObjAt(sec, "problems")
	if len(problems.A) != 3 {
		t.Fatalf("problems = %d, want 3: %s", len(problems.A), validation.CanonSpaced(problems))
	}
	joined := validation.CanonSpaced(problems)
	for _, want := range []string{"maximized", "unprofitable", "unpinned"} {
		if !strings.Contains(joined, want) {
			t.Errorf("problems do not mention %q: %s", want, joined)
		}
	}
}
```

`coverageCampaign`/`coverageRow` are a ~30-line fixture in the same file: init a campaign, ingest N findings through `findings.IngestHypothesis`, and apply each row's fields — through the public setters Tasks 5–8 added (`RecordFactRead`, `RecordReplay`, `SetForkDependence`, `AddExecEvidence`) for the *valid* rows, and by mutating the stored finding and re-saving it through `findings.SaveThenLog` for the impossible-state rows the setters refuse (see the note in `TestV16CoverageFlagsImpossibleRecords`). A row with `originStage` set also sets `contributing_stages` (the ingest default is the origin stage alone, Task 8 Step 4), which is why the count is asserted at 1. Build the fixture on `state.Init` the way `internal/audit/unpriceable_test.go:51` builds its section fixture; the test file imports `internal/reviewsession` for the non-finding-fields case.

- [ ] **Step 2: Run it to verify it fails**

Run: `go test ./internal/audit/sections -run TestV16Coverage -count=1`
Expected: FAIL to compile — `undefined: V16Coverage`.

- [ ] **Step 3: Implement the section**

Create `internal/audit/sections/v16coverage.go`. It reads the projection and counts, per finding, whether each v1.6 field is present — then flags only the states that are impossible by construction, because coverage is a measurement and a low number is not a defect:

```go
// V16Coverage is the v1.6 record-coverage section: the eight fields Phase 1–2
// added are written by five different code paths and read by none of them, so
// this section is the one place that notices when one of them stops being
// populated. All eight are counted — including the two that are NOT finding
// fields (review_sessions lives in campaign_state; the input-artifact
// declaration lives on model.request events) — because a field with no reader
// is the failure this section exists to catch, and a section that reads five
// of eight just moves the problem. The counts are reported, not judged: a
// campaign with no deployment reads is a campaign with no deployment reads.
// The problems are only the states that cannot be true.
func V16Coverage(c *state.Campaign) (validation.Value, error) {
	rows := listedFindings(c) // LoadFinding over the projection's ids
	proj, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	events, err := c.Events()
	if err != nil {
		return validation.VNull(), err
	}
	cov := map[string]int64{"findings": int64(len(rows))}
	problems := []validation.Value{}
	bump := func(k string) { cov[k]++ }
	for _, f := range rows {
		if validation.ObjStr(f, "status") == "confirmed" {
			bump("confirmed")
		}
		if validation.ObjStr(f, "fork_dependence") != "" {
			bump("fork_dependence_set")
		}
		if validation.ObjStr(f, "origin_stage") != "" {
			bump("origin_stage")
		}
		if len(validation.ObjAt(f, "contributing_stages").A) > 0 {
			bump("contributing_stages")
		}
		if len(validation.ObjAt(f, "deployment_facts").A) > 0 {
			bump("deployment_facts")
		}
		if validation.ObjAt(f, "replay").Kind == validation.Obj {
			bump("replay_recorded")
		}
		switch findings.PocTierOf(f) {
		case "existence":
			bump("poc_tier_existence")
		case "maximized":
			bump("poc_tier_maximized")
		}
		// ... the three impossible-state checks, appending
		// validation.VStr("v16_coverage: <finding_id> ...") to problems
	}
	// review_sessions is a campaign_state array, not a finding field — and it
	// is the field most likely to silently stop being written, because nothing
	// produces it unless an operator runs the verb.
	sessions := validation.ObjAt(proj, "review_sessions")
	cov["review_sessions"] = int64(len(sessions.A))
	closed := int64(0)
	for _, s := range sessions.A {
		if !validation.ObjAt(s, "open").B {
			closed++
		}
	}
	cov["review_sessions_closed"] = closed
	// The input-artifact declaration is counted from the ledger, because the
	// request record is an event, not a projection row: requests that declared
	// a set, and requests refused for not declaring one.
	requests, refusals := int64(0), int64(0)
	for _, e := range events {
		switch validation.ObjStr(e, "type") {
		case "model.request":
			requests++
			if len(validation.ObjAt(validation.ObjAt(e, "data"), "input_artifacts").A) > 0 {
				bump("requests_declared")
			}
		case "model.rejected":
			refusals++
		}
	}
	cov["model_requests"] = requests
	cov["model_rejections"] = refusals
	// checked/ok/problems/coverage, the standard section shape
}
```

Register it **last** in `register.go`, after `price_table`, with a comment saying why:

```go
	// v1.6: the record-coverage section. Registered LAST so the ported
	// audit.py sections keep their relative order (the P1 gate goldens pin
	// it) and so this new section is appended, never interleaved.
	register("v16_coverage", V16Coverage)
```

- [ ] **Step 4: Run it to verify it passes**

Run: `go test ./internal/audit/... -count=1`
Expected: PASS. If `p1_sections_test.go`'s oracle pins the full section list or its order, update that expectation in this commit — deliberately, as a visible diff — rather than reordering the new section to dodge it.

- [ ] **Step 5: Wire the section into the report and commit**

`webv2 audit` renders sections in registration order, so nothing else needs wiring; confirm by running `audit` on a fixture campaign and checking the section appears last. Add the RUNBOOK line (`audit` reports v1.6 record coverage; the three impossible states are problems), then:

```bash
python3 scripts/sync-asset-manifest.py
go test ./... -count=1
git add internal/audit/ assets/runbook/RUNBOOK.md assets/testdata/asset_manifest.json
git commit -m "feat(audit): v1.6 record-coverage section (v1.6 P1/P2)"
```

---

### Task 10a: The control target's finding — offline, source-level, end to end

**Why this is a task of its own, and why it goes first.** Tasks 1–9 built the P1 record set —
the feed transport, PoC tiers, replay, fork dependence, the boundary artifact sets — and every
one of them has only ever seen **fixtures**. Not one has carried a real bundle through the
whole path. 10a is that run: the control target's vulnerability from hypothesis to
`CONFIRMED`, using P1's own verbs, on a real pinned checkout. It is also the only one of the
three pieces of work here that is **guaranteed to finish**: it is source-level and offline, so
it needs nothing but the pinned checkout and `forge`. No Docker, no fork RPC, no model, no
operator.

**What it deliberately is not.** It is not the spike, and it produces **no dollar figure**.
Its PoC tier is `existence` — the guard is absent at the pin and the project's own tests say so
— and `existence` is exactly what the tier exists to name. A reader should come away knowing
the finding is real and confirmed, and knowing nothing about how much money is reachable. That
second question is 10b's, and 10b may legitimately refuse it.

**Files:**
- Create: `docs/sdd/v16-p1/task-10a-feed.json` (the authored discovery drop)
- Create: `docs/gates/v16-P1-10a.md` (the recorded run)
- No product code. **If a step here needs a code change, that is a finding about Tasks 1–9,
  and it is recorded as one rather than patched quietly mid-run.**

**Interfaces:**
- Consumes: `webv2 run --feed`, `webv2 exec --profile host-readonly`, `webv2 mint --type
  unit-test --poc-tier existence`, `webv2 move … CONFIRMED`, `webv2 audit`.
- Produces: one CONFIRMED finding on the control target, which is 10b's precondition.

- [ ] **Step 1: Author the discovery drop**

Hand-author the hypothesis as a feed JSON — this is the sanctioned path, and the reason P1's
Task 3 built `run --feed`: a discovery stage that needs no model is what makes this run
offline. The drop names the control target's own revision and the absent guard, and cites the
fix commit's parentage (`46e84022` is `e73bfb21`'s only parent — verified in the control
target's gate record §3.1).

- [ ] **Step 2: Drive it through the pipeline**

```bash
webv2 run C-xxxxxxxxxx --feed docs/sdd/v16-p1/task-10a-feed.json
webv2 exec C-xxxxxxxxxx --profile host-readonly --finding F-xxxxxxxxxx \
  --workdir /home/xand/webv2-p0/target/exactly-prepatch \
  --command "forge test --match-path test/DebtManager.t.sol --match-test testFakeMarket -vv"
```

The command is the project's own five tests at the pin, and the expected result is the
recorded **0/5** — every failure of the "the expected refusal never happened" kind. `exec`
must capture that output; the finding's evidence cites the EXEC id, not a pasted transcript.

- [ ] **Step 3: Mint, at `existence`**

```bash
webv2 mint C-xxxxxxxxxx F-xxxxxxxxxx --exec EXEC-xxxxxxxxxx --type unit-test \
  --poc-tier existence --description "checkMarket absent at the pin; the project's own five tests fail for want of the refusal"
```

`--type unit-test` is the honest member: the evidence is a test run, not a fork test and not a
balance delta. `--poc-tier existence` is the honest tier: it says the defect is demonstrably
present and stops there.

- [ ] **Step 4: Move it to CONFIRMED**

```bash
webv2 move C-xxxxxxxxxx F-xxxxxxxxxx CONFIRMED --reason "…" --actor "$USER"
```

The CONFIRMED transition enforces its own gate bundle. **If it refuses, the refusal is the
result of this step** — record it verbatim and fix whatever is actually missing (evidence,
exec binding, tier) rather than working around it. A refusal here is the most valuable thing
10a can produce, because it is the first time that gate has been asked a question with a real
bundle behind it.

- [ ] **Step 5: Audit, record, commit**

`webv2 audit C-xxxxxxxxxx` must come back clean and the finding must read `CONFIRMED`. Then
write `docs/gates/v16-P1-10a.md`: the campaign and finding ids, the EXEC id, the observed 0/5,
the tier and type chosen and why those are the honest members, the audit verdict, and a
paragraph on **what the P1 record set did not anticipate** — that paragraph is the actual
deliverable, because it is the first evidence about these records that does not come from a
fixture. If every record worked unchanged, say that too; it is a result.

- [ ] **Step 6: Commit**

```bash
git add docs/sdd/v16-p1/task-10a-feed.json docs/gates/v16-P1-10a.md
git commit -m "docs(v16): the control target's finding, confirmed end to end (P1 task 10a)"
```

---

### Task 10b: The Phase 2 maximization spike (operator-run)

> **RE-SCOPED 2026-09-22 — this task's premise does not exist yet, and it is two tasks.**
> As written it says "operator, on one already-CONFIRMED finding". P0's Task 2 deliberately
> did not ingest a finding on its control target (it pins the vulnerability and runs the
> project's own harness, then stops), so no campaign has a CONFIRMED finding on a real target.
> The gap between here and the spike is snap → discovery → repro → mint → impact on a real
> target — that is a **pipeline run**, not a spike. Driving it as one task would either skip
> TDD where TDD is possible or, worse, hand-author a finding that skips the very paths the
> spike exists to exercise. So:
>
> - **Task 10a — get a finding on the control target to CONFIRMED.** Hypothesis in via
>   `run --feed` (a hand-authored discovery drop is the sanctioned path, and is exactly why
>   P1's Task 3 exists — no model needed), then reproduce and mint. This is where P1's records
>   meet a real bundle for the first time.
> - **Task 10b — the original spike.** `exec --profile fork-runner` →
>   `mint --poc-tier existence` → maximized → `impact --replayable` → `audit`.
>
> **10b has a blocker this plan did not know about: a commit is not a fork pin.** The control
> target's harness forks at the height its own test file hardcodes — block 99,811,375, which
> is **three months before the 2023-08-18 exploit**. The CLI's `--fork-block-number` is inert
> against a `vm.createSelectFork(url, height)` inside the test: re-running with `108375557`
> still reports `(block: 99811375)` on every line. The measurement is in
> `docs/gates/v16-P0-control-target.md` §3.1. An `extractable_usd` computed at the wrong height
> describes a counterfactual, not the incident.
>
> **And the chain offers a real before/after pair that this harness does not reach.** The
> deployed DebtManager is an EIP-1967 proxy whose own bytecode never changes — hashing it
> proves nothing. Its implementation slot held `0x16748cb7…` through block **108,445,161** and
> was repointed to `0x910e91d2…` at **108,445,162** (2023-08-19), the fix commit recording the
> latter. At the harness's height the proxy has no code at all, so the harness exercises
> **neither** side (§3.2). Two consequences for 10b: the pair to fork around, if a before/after
> comparison is wanted, is `108,445,161`/`108,445,162`; and no fork run here can demonstrate
> anything about the deployed fix, because it never runs against either deployment. What the
> control target certifies is **source-level** detection.
>
> **Prerequisites, all three.**
>
> 1. **A CONFIRMED finding** — Task 10a's output. Without it there is nothing to spike.
> 2. **An RPC that can hold a fork for the run's duration.** `mainnet.optimism.io` served the
>    P0 harness; `optimism.drpc.org` rate-limited mid-run; publicnode wants a token; flashbots
>    prunes. This is a *configuration fact, not a capability* (§3's observation), which is why
>    prerequisite 3 exists.
> 3. **The fork-pin decision, made explicitly — do not silently take the passed flag.**
>    `internal/regression/forkpin.go` landed as a tested primitive and is **not wired into the
>    run record or the CLI**. Either wire it (so a run derives the height the harness actually
>    reported, refusing output that names none or two), or derive the height by hand and **say
>    so in the gate document**, naming where it was read from. Taking `--fork-block-number` as
>    the height is the one option that is not available: it is inert against `createSelectFork`,
>    so the flag is not evidence of the height that ran. Roadmap §4: *a fork run carries a
>    resolved block.*
>
> **10b's acceptance criterion is "measured, or refused with a recorded reason" — there is no
> number pressure.** If the public endpoint cannot hold a fork long enough to read a balance
> delta, the **refusal is the deliverable**: it is the real evidence justifying P5's
> runner-level fork pin, and a recorded refusal is worth more than a figure produced by
> retrying until something returned. Do not manufacture an `extractable_usd` to satisfy the
> task. A refusal must name what was attempted, what failed, and what would have to change.
>
> Everything below is 10b's original text; read it with 10a as its precondition.

Spec §2.7: *"A minimal spike (Phase 2) proves the loop produces a defensible number on one already-confirmed finding — no rubric/policy integration, no two-tier split — and, where that finding is replayable, demonstrates the two-round termination with arithmetic rounds-to-exhaustion and `cumulative_attack_cost_usd`."*

This is the only task in the plan that needs Docker and a real finding; everything it drives already exists after Tasks 1–9. It produces the Phase 2 exit evidence, not new product code.

**The Phase 2 exit criterion splits in two, and only one half waits for the operator.** "Two-round termination, arithmetic rounds-to-exhaustion and `cumulative_attack_cost_usd`" is pure arithmetic and is already deterministically covered by Task 7's `TestComputeReplay*` and `TestReplayProfitabilityIsRequired` — no Docker, no fork, no operator. Only *"a defensible `extractable_usd` on one already-confirmed finding"* needs a real fork and a human. Say exactly that in the gate document: the arithmetic half is **test-proven** (name the tests), the extraction half is **spike-proven** (name the finding). Otherwise Phase 2 reads as blocked on operator availability when three quarters of it is already green in CI.

**Files:**
- Create: `scripts/v16-spike.sh`
- Create: `internal/cli/spike_driver_test.go`
- Create: `docs/gates/v16-P2-spike.md` (the recorded result)

**Interfaces:**
- Consumes: `webv2 exec --profile fork-runner`, `webv2 mint --poc-tier`, `webv2 impact --replayable`, `webv2 ladder start|add|repro|complete`, `webv2 audit`.
- Produces: a recorded spike result; no new API.

- [ ] **Step 1: Write the driver**

Create `scripts/v16-spike.sh` (bash, `set -euo pipefail`), taking `<campaign> <finding> <fork-rpc> <block>`. **Every `webv2` call goes through one `run()` helper** — `run() { if [ "${DRY_RUN:-0}" = 1 ]; then echo "webv2 $*"; return 0; fi; webv2 "$@"; }` — because Step 2's offline test reads the driver's `run <verb>` lines to check the flags; a bare `webv2 …` anywhere defeats it.

1. `exec --profile fork-runner --command "forge test --fork-url $RPC --fork-block-number $BLOCK --match-test test_exploit" --finding "$FID"` → capture `EXEC-*`.
2. `mint "$FID" --exec "$EXEC" --type fork-test --poc-tier existence --description "state break on the pinned fork"`.
3. A second fork run at the same pin with the amplification (the `ladder add` rung the operator selects) → `mint --poc-tier maximized`.
4. If the finding is replayable: `impact --replayable --extractable-per-round X --max-loss POOL --gas-cost G --frequency F --rounds-run 2 --replay-assumption ... --replay-blocker ...`.
5. `audit "$C"` and print the exit code.
6. Print a machine-readable summary block (finding id, tiers reached, `rounds_to_exhaustion`, `ceiling_usd`, `cumulative_attack_cost_usd`) for the gate document.

- [ ] **Step 2: Prove the driver offline — dry run plus flag-name assertions**

`bash -n` proves the script parses and nothing else, and this script is the only place `exec --profile fork-runner`, `mint --poc-tier` and `impact --replayable` are driven together. A typo in a flag name would surface mid-spike, with Docker up and a fork pinned, so it is caught offline instead.

Add a `--dry-run` mode to the script: every `webv2` invocation goes through one `run()` function that echoes the command and returns 0 when `DRY_RUN=1`, so the whole driver can be walked without Docker, an RPC, or a campaign. Then create `internal/cli/spike_driver_test.go`:

```go
// TestSpikeDriverEmitsOnlyKnownFlags: the Phase 2 spike driver is
// operator-run, so its flag names are asserted offline. Assert against what
// the script's run() helper actually emits — a driver that invokes through a
// variable (WEBV2=${WEBV2:-webv2}) would otherwise match nothing and fail for
// the wrong reason, so the driver must go through run() and this test reads
// its source, not a regex guess about shell style.
func TestSpikeDriverEmitsOnlyKnownFlags(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "v16-spike.sh"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	// The driver is required to keep every invocation inside run(), which
	// takes the verb as its first argument.
	invocations := regexp.MustCompile(`(?m)^\s*run\s+([a-z][a-z0-9-]*)`).
		FindAllStringSubmatch(src, -1)
	if len(invocations) == 0 {
		t.Fatal("no `run <verb>` invocations found — the driver must route every " +
			"webv2 call through run(), or this test cannot check anything")
	}
	registered := map[string]bool{}
	for _, c := range registeredNames() {
		registered[c] = true
	}
	for _, m := range invocations {
		if !registered[m[1]] {
			t.Errorf("driver invokes unregistered verb %q", m[1])
		}
	}
	cliSrc := readCLISources(t) // concatenated internal/cli/*.go
	global := map[string]bool{"--root": true, "--json": true, "--help": true, "--dry-run": true}
	for _, f := range regexp.MustCompile(`--[a-z][a-z0-9-]+`).FindAllString(src, -1) {
		if global[f] {
			continue
		}
		if !strings.Contains(cliSrc, `"`+f+`"`) {
			t.Errorf("driver emits flag %q that no command declares", f)
		}
	}
}
```

`readCLISources` is a six-line helper over `filepath.Glob("cmd_*.go")`. If the registry exposes no name list, add `registeredNames()` as a three-line helper next to `registered` — the same pattern `help_test.go` uses.

Run: `DRY_RUN=1 bash scripts/v16-spike.sh C-xxxxxxxxxx F-xxxxxxxxxx http://localhost:8545 21000000`
Expected: exit 0, every command echoed, nothing executed. Then `go test ./internal/cli -run TestSpikeDriverEmitsOnlyKnownFlags -count=1` → PASS.

- [ ] **Step 3: Run the spike**

Operator, on one already-CONFIRMED finding with a pinned fork RPC:

```bash
scripts/v16-spike.sh C-xxxxxxxxxx F-xxxxxxxxxx "$FORK_RPC" 21000000 | tee /tmp/v16-spike.out
```

Expected: exit 0, `audit` clean, and a summary block carrying the two tiers and — where the finding is replayable — `rounds_run: 2` with a non-zero `rounds_to_exhaustion` and `cumulative_attack_cost_usd`.

- [ ] **Step 4: Record the result**

Write `docs/gates/v16-P2-spike.md` with: the campaign/finding ids, the pinned block and RPC host (never the full URL), the two EXEC ids, the `extractable_usd` the spike produced and how it was derived, the replay figures if applicable, the `audit` verdict, and one paragraph naming what the spike does **not** prove (no rubric integration, no class-metric funding, no status field — those are Phase 5). Record the two halves of the exit criterion separately, as the task header says: which tests prove the arithmetic, and which single finding the spike proves the extraction on.

- [ ] **Step 5: Commit**

```bash
git add scripts/v16-spike.sh internal/cli/spike_driver_test.go docs/gates/v16-P2-spike.md
git commit -m "chore(v16): Phase 2 maximization spike driver and its recorded result"
```

---

### Task 11: The Phase 1 gate record

Self-review 1b and the roadmap both require `docs/gates/v16-P1.md`, and nothing else in this plan writes it — Tasks 1–3 produce test evidence that otherwise exists only in a terminal scrollback. It is deliberately its own task and deliberately last: it cites Task 10b's spike result, and it must **not** be gated on Docker, an RPC or an operator, because three quarters of what it records is already green in CI.

**Files:**
- Create: `docs/gates/v16-P1.md`

**Interfaces:**
- Consumes: the test evidence of Tasks 1–9, Task 10a's `docs/gates/v16-P1-10a.md`, and Task 10b's `docs/gates/v16-P2-spike.md`.

- [ ] **Step 1: Re-run the gates and capture the exact output**

```bash
go test ./... -count=1
go vet ./...
scripts/verify-full.sh
```

Record the invocations verbatim and their results — not a summary of them.

- [ ] **Step 2: Write the document**

`docs/gates/v16-P1.md` carries, for each of the three Phase 1 exit criteria, the claim, the test that proves it, and the command that runs it:

| Criterion | Proof |
|---|---|
| Every policy boolean is referenced by its gate | `TestPolicyBooleansAreReferencedByTheirGate` (three directions), `internal/bounty` |
| Out-of-set input is refused **and recorded** | `TestBuildRequestDerivesTheCitedSet`, `TestDeclaredInputSetIsRequired`, `TestInputSetRefusalIsRecorded` (`internal/boundary`); `TestRunFeedRefusesAnOutOfSetDrop`, `TestFeedRefusesAnUndeclaredRequest` (the production path) |
| The file-drop is the only sanctioned transport | `TestFeedStagesPartitionThePipeline`, `TestRunFeedRefusesADropOutsideTheInbox`, `TestRunFeedRefusesUnwiredStage` |

Plus: the `v16_coverage` numbers for one real campaign, the grandfathering decision (requests logged before Task 2 keep validating; new ones are refused without a declaration), and the two halves of the Phase 2 exit criterion recorded separately, as Task 10b Step 4 requires — arithmetic **test-proven**, extraction **spike-proven**.

- [ ] **Step 3: Commit**

```bash
git add docs/gates/v16-P1.md
git commit -m "docs(v16): Phase 1 gate record"
```

---

## Self-review

Run this before declaring the plan executed; it is the same checklist the plan was written against.

**1. Spec coverage (Phases 1–2 only).**

| Spec item | Task |
|---|---|
| Phase 1: policy-field-vs-gate consistency test | 1 |
| Phase 1: model-stage input-artifact-set declaration + out-of-set refusal | 2 |
| Phase 1: file-drop is the only sanctioned transport | 3 |
| Phase 2: `review_session` event recording begins | 4 |
| Phase 2: deployment-fact reads | 5 |
| §2.2: two-tier fork evidence (`EXISTENCE`/`MAXIMIZED`) | 6 |
| Phase 2 exit: two-round termination, rounds-to-exhaustion, `cumulative_attack_cost_usd` | 7, 10 |
| §2.2: per-hypothesis `fork_dependence`, `existence_funding` | 8 |
| C2: `origin_stage` / `contributing_stages` | 8 |
| Phase 1–2: something reads the new fields (record coverage) | 9 |
| Phase 2: the maximization spike | 10 |
| Phase 1–2: the gate records | 10, 11 |

**Deliberately not in this plan** (they belong to later phases, per the roadmap): the maximization loop and its `status` field, tranche funding and vouchers, the `delta` evidence field, the severity engine, class metrics, the closure tier, the dual-arm critic, target scoring, acceptance telemetry. Do not smuggle them in — Phase 5's design depends on how Tasks 6–8 behave in the field.

**1b. Gate records.** Each phase gets one gate document, not just the spike: `docs/gates/v16-P1.md` (Task 11 — Task 1's consistency test, Task 2's refusal + its migration, Task 3's feed contract, with the exact `go test` invocations and their results) alongside `docs/gates/v16-P2-spike.md` (Task 10b) and `docs/gates/v16-P1-10a.md` (Task 10a). Tasks 1–9 produce test evidence; without a document it exists only in a terminal scrollback, which is the opposite of the D9 discipline the roadmap asks for. Task 11 is separate from Task 10 on purpose: the Phase 1 record must not wait on Docker or an operator.

**2. Placeholder scan.** Every code step carries runnable code; every run step carries an exact command and its expected result. Two steps deliberately defer to an existing helper rather than invent one (Task 6 Step 6's exec seeder, Task 4 Step 7's campaign resolution) — in both cases the instruction is to copy the neighbouring verb's mechanism, and the test in the same task fails if the choice is wrong.

**2b. What "verify it fails" can and cannot prove.** Several Step 2s fail to *compile* (`undefined: BuildRequest`, `undefined: ComputeReplay`), which proves the symbol is missing — not that the behaviour is wrong. That is unavoidable for schema-validated records and it is still worth running, but the behaviour proof is the **passing** test plus the refusal cases, so every task that adds a refusal also adds a test that a *valid* record is accepted (a refusal test alone passes trivially if the code refuses everything). Task 2 Step 6 is the one place the test is written after the implementation — the recording path is three lines over an existing API; do not read it as TDD.

**3. Type consistency.** `PocTierOf`/`HasPocTier`/`MaximizedEvidence`/`ValidatePocTierOrder` (Task 6) are the names Task 7's report work, Task 9's coverage section and Phase 5's severity passes will call. `ForkDependent`/`ExistenceFundingRequired` (Task 8) are the names §3.1's funding rule will call, and Task 9 is their first reader. `RecordFactRead` and `RecordReplay` both use `SaveThenLog` + one event. `validation.VFloat` is used for every new number, matching `economic_impact.extractable_usd`; tests compare money with a tolerance, never bytes.

**3b. The ledger law has no test in this plan.** Every task says "unwind on log failure" and none of them exercises it — the law is a global constraint, so it belongs to the shared suite rather than to nine copies. Either point the reviewer at the existing unwind test (`rg -n 'unwind|planWindow' internal/*/[a-z]*_test.go`) or add one shared test that makes `Log` fail and asserts the projection is restored, once, in the package that owns the helper.

**4. Exit criteria this plan does *not* satisfy.** Phase 1's "no `+dirty` release stamp" and Phase 2's "Docker e2e green" are pre-existing gates (`scripts/release.sh`, `scripts/p2-docker-e2e.sh`); run them, do not re-implement them. The Phase 2b shadow submission is operator work with no code deliverable.

**4b. Phase 2's exit criterion is half test-proven already.** The arithmetic half (two-round termination, rounds-to-exhaustion, `cumulative_attack_cost_usd`) is covered by Task 7's tests and needs no Docker, no fork and no operator; only "a defensible `extractable_usd` on one confirmed finding" needs Task 10's spike. Do not report Phase 2 as blocked on operator availability while three quarters of it is green in CI — report both halves separately, as Task 10b Step 4 requires.

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-09-21-v16-p1-p2-record-and-evidence.md`, with the phase map in `docs/superpowers/plans/2026-09-21-v16-roadmap.md`.

Two execution options:

1. **Subagent-driven (recommended)** — one fresh subagent per task, review between tasks, fast iteration.
2. **Inline execution** — execute tasks in this session with checkpoints for review.

Next plan to write: **P0** (the regression suite) in parallel, then **P2** (the closure tier) once P1's exit criteria have actually run — the closure tier's design should be informed by how the field-validation matrix behaves on real targets, and writing it before that measurement is the spec-iterating-faster-than-measurement failure the spec's D9 exists to stop.

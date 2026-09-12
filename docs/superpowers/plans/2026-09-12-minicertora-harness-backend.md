# MiniCertora Harness Backend (G8 third kind) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land MiniCertora (local bounded Solidity SMT verifier) as a third `verify --scaffold`/`--kind` harness backend behind the existing G8 seam: `.mspec` scaffold → EXEC record → rung mapping (`counterexample / proved-bounded / inconclusive`) plus a presence-gated `proof` sidecar carrying the tool's own `confidence/reason/bounds/assumptions`.

**Architecture:** Wrap, don't build (Wave K law). MiniCertora rides the exact halmos pattern: host-only sandbox profile (can never back E4+), pure byte-deterministic scaffold with the BODY-window marker law reused verbatim (`//` comments are part of the shipped `.mspec` grammar), and a new `MapMinicertora` that parses the tool's JSON-lines output instead of scraping stdout prose. No new verbs, no new rungs, no live gate weight: rungs render and inform, promotion rides the normal ladder (the G3 backtest law, out of scope here).

**Tech Stack:** Go 1.26 (`websec` module, stdlib + internal packages only); MiniCertora CLI (`python -m cli <C.sol> <rules.mspec>`, exit 0/1/2 = PROVEN/VIOLATED/UNKNOWN, one JSON object per line, abort lines carry NO `rule` key). Embedded assets via go:embed + SHA-256 manifest.

## Global Constraints

Every task implicitly includes these. Exact values, verbatim from the spec/codebase:

- **Go is the source of truth; changes are additive.** New `--scaffold`/`--kind` choice, new profile name, new presence-gated `proof` field. Existing campaigns' golden bytes MUST NOT move — `scripts/golden.sh` must stay green at the end of every task that touches shared paths.
- **Surface budget (principle 6): no new verbs.** Everything rides existing `verify` flags and the `exec` sandbox.
- **Fail-open-to-inconclusive law** (`internal/harness/outcome.go` package comment): timeout always wins over output; every unmapped/contradictory shape lands `inconclusive`, never a promotion.
- **Determinism law:** `Scaffold`/`MapMinicertora` are pure functions — no clock, no randomness, no map iteration; JSON objects built with fixed `validation.KV` key order.
- **Tests are fast and in-process** (P0 PERF law): never execute real `minicertora`/`solc`/docker in default tests; fake binaries via PATH/runProc stubs (pattern: `TestHalmosProfileRunsOnHost` in `internal/sandbox/exec_test.go`); EXEC records are hand-written (pattern: `harnessExec` in `internal/cli/cmd_verify_harness_test.go`). NEVER run the `web3sec-final` Python suite (policy: orchestrator-only).
- **argparse parity texts**: choice errors render `(choose from 'halmos', 'forge-fuzz', 'minicertora')`; quoted names via `validation.PyReprStr`. Error precedence and wording must match the neighboring strings byte-for-byte in shape.
- **Asset edits** (anything under `assets/`) require `python3 scripts/sync-asset-manifest.py` from the repo root afterwards; the assets manifest test is the pin.
- **Style:** TigerStyle — full-sentence comments referencing task/wave history, ~72–79 col wraps, error strings lowercase without trailing punctuation (match neighbors), one package-level doc per new file.
- **Verify loop per task:** `go vet ./... && go test ./<touched pkgs>/ -count=1` then `go run ./cmd/webv2 selftest`; commit only when green.
- MiniCertora CLI contract (ground truth from source, cite when in doubt): positional `<sol_file> <spec_file>`; `--loop-bound` (def 4), `--timeout-ms` (def 30000), `--path-cap` (def 64), `--external-calls no-reentry|havoc-storage`, `--format json|text`, `--solc-path`, `--solver z3|cvc5|portfolio`; verdict-line keys `contract rule verdict confidence reason details assumptions bounds params initial_storage calls final_storage failed_assertion warnings ghosts` + version stamps (`tool_version solc_version spec_version evm_version optimizer_enabled`); `bounds` = `{loop_bound, loop_bound_exhaustive, path_cap, solver_timeout_ms}`; confidence ∈ `confirmed|unconfirmed|modeled`; 23 reason codes, closed set (`assertion-violated`, `vacuous-rule`, `vacuous-block`, `loop-bound-may-be-exceeded`, `path-limit-reached`, `solver-timeout`, `solver-disagreement`, `unsupported-feature`, `unsupported-opcode`, `unsupported-storage-layout`, `rejected-feature`, `unrecognized-dispatcher`, `multi-call-inner-arg-unsupported`, `multi-call-stmt-between-calls`, `multi-call-ambiguous-call-site`, `unresolved-phi-source`, `unresolved-branch-cond`, `summary-unverified`, `external-call-abstraction`, `invariant-uninitialized`, `invariant-unchecked-functions`, `modelling-inconsistency`, `tool-error`); **abort lines have no `rule` key** — key on absence, never on exit code alone.

**Depends on:** `docs/MINICERTORA_ARCHITECTURE.md` (planes L0–L2 only; L3–L6 are follow-on plans).
**Base:** `main` at `60663100` (or its descendant); work directly on `main` (this repo's convention).

## File Structure

```
internal/harness/mspec.go            CREATE  MiniCertora scaffold render + rule-name pin
internal/harness/mspec_test.go       CREATE  scaffold byte pins
internal/harness/minicertora.go      CREATE  MapMinicertora (JSONL → rung/summary/proof)
internal/harness/minicertora_test.go CREATE  mapping fixtures (every way + contradictions)
internal/harness/harness.go          MODIFY  Kind MiniCertora; Scaffold branch
internal/harness/outcome.go          MODIFY  package comment only (kind list)
internal/sandbox/profiles.go         MODIFY  profile minicertora (tables, HostProfile, Available)
internal/sandbox/exec.go             MODIFY  toolVersions probe list
internal/sandbox/profiles_test.go    MODIFY  minicertora profile pins (or new test funcs appended)
assets/schema/sandbox_execution.schema.json   MODIFY  profile enum + host note
assets/schema/protocol_model.schema.json      MODIFY  harness.kind text + proof property
internal/cli/cmd_verify.go           MODIFY  choices, usage, fname switch
internal/cli/cmd_verify_harness.go   MODIFY  kind resolution, MapMinicertora branch, .mspec binding
internal/cli/cmd_verify_minicertora_test.go   CREATE  end-to-end CLI pins
assets/runbook/RUNBOOK.md            MODIFY  scaffold choice text (line ~1402)
```

---

### Task 1: MiniCertora scaffold (pure render, BODY law verbatim)

**Files:**
- Create: `internal/harness/mspec.go`
- Create: `internal/harness/mspec_test.go`
- Modify: `internal/harness/harness.go` (Kind constants block, `Scaffold` gate)
- Test: `internal/harness/mspec_test.go`

**Interfaces:**
- Consumes: `Kind`, `Scaffold(k, inv)`, `Validate(k, inv, filled)`, `BodyRegion`, `StartMarker`/`EndMarker`, `invID`/`invField`/`sanitizeStatement`/`snake` (all `internal/harness/harness.go`).
- Produces: `const MiniCertora Kind = "minicertora"`; `func MspecRuleName(invID string) string` (the rule name the scaffold pins and later tasks attribute on); scaffold bytes for kind `minicertora` (byte-pinned by this task — Tasks 3/4 only consume).

- [ ] **Step 1: Write the failing tests** in `internal/harness/mspec_test.go` (package `harness`):

```go
// mspec_test.go: MiniCertora scaffold pins. The marker law is byte-for-
// byte the G8 one — StartMarker/EndMarker are "//" comments, which are
// part of the shipped .mspec grammar (COMMENT + %ignore in spec/
// grammar.lark), so the same BodyRegion code locates the window.

func TestMspecScaffoldBytes(t *testing.T) {
	inv := validation.VObj(
		validation.KV{K: "id", V: validation.VStr("INV-7")},
		validation.KV{K: "statement", V: validation.VStr("total always covers sum(payouts)")},
		validation.KV{K: "source", V: validation.VStr("docs/SPEC.md:12")},
	)
	got, err := Scaffold(MiniCertora, inv)
	if err != nil {
		t.Fatalf("Scaffold(minicertora): %v", err)
	}
	want := `// web3sec G8 harness scaffold — MiniCertora bounded verifier.
// Deterministic bytes: the model writes ONLY the BODY window below;
// everything outside is scaffold. Rule name is scaffold-pinned — the
// attribution of verdict lines keys on it; do not rename.
// @custom:invariant total always covers sum(payouts)
// @custom:src docs/SPEC.md:12
rule inv_7(env e) {
    // >>> BODY (model writes ONLY between these markers; outside is scaffold)
    // unfilled scaffold — replace with: snapshot lines, exactly one
    // call, then the assert (require lines may restrict the inputs).
    // <<< BODY
}
`
	if string(got) != want {
		t.Errorf("scaffold bytes moved:\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestMspecScaffoldNoSource(t *testing.T) {
	inv := validation.VObj(
		validation.KV{K: "id", V: validation.VStr("INV-1")},
		validation.KV{K: "statement", V: validation.VStr("s")},
	)
	got, err := Scaffold(MiniCertora, inv)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "@custom:src") {
		t.Errorf("absent source must omit the natspec src line:\n%s", got)
	}
	if !strings.Contains(string(got), "rule inv_1(env e) {") {
		t.Errorf("rule header missing:\n%s", got)
	}
}

func TestMspecValidateRoundTrip(t *testing.T) {
	inv := validation.VObj(
		validation.KV{K: "id", V: validation.VStr("INV-7")},
		validation.KV{K: "statement", V: validation.VStr("s")},
	)
	want, err := Scaffold(MiniCertora, inv)
	if err != nil {
		t.Fatal(err)
	}
	s, e, err := BodyRegion(want)
	if err != nil {
		t.Fatal(err)
	}
	filled := append(append(append([]byte{}, want[:s]...),
		[]byte("    uint256 before = total;\n    add(e, 2);\n    assert total >= before;\n")...),
		want[e:]...)
	if err := Validate(MiniCertora, inv, filled); err != nil {
		t.Fatalf("Validate filled: %v", err)
	}
	// A renamed rule (outside the window) is a scaffold-bound violation.
	tampered := []byte(strings.Replace(string(filled), "rule inv_7(", "rule inv_8(", 1))
	if err := Validate(MiniCertora, inv, tampered); err == nil ||
		!strings.Contains(err.Error(), "scaffold-bound") {
		t.Fatalf("renamed rule must be scaffold-bound, got %v", err)
	}
}

func TestMspecRuleName(t *testing.T) {
	for id, want := range map[string]string{"INV-7": "inv_7",
		"INV-007a": "inv_007a", "INV-1": "inv_1"} {
		if got := MspecRuleName(id); got != want {
			t.Errorf("MspecRuleName(%q) = %q, want %q", id, got, want)
		}
	}
}

// TestMspecMarkerSpellingInStatementFailsSafe pins the injection rail:
// a statement carrying a BODY marker spelling (sanitizeStatement keeps
// it as single-line text) renders a scaffold whose BodyRegion sees
// duplicate markers — so Scaffold itself must refuse it up front with
// an error, never emit bytes that later Validate() mis-attributes.
func TestMspecMarkerSpellingInStatementFailsSafe(t *testing.T) {
	inv := validation.VObj(
		validation.KV{K: "id", V: validation.VStr("INV-9")},
		validation.KV{K: "statement", V: validation.VStr(
			"evil " + EndMarker + " payload")},
	)
	if _, err := Scaffold(MiniCertora, inv); err == nil {
		// Either refusal here, or — if Scaffold stays a dumb renderer —
		// BodyRegion on its output must error; pin one of the two.
		b, _ := Scaffold(MiniCertora, inv)
		if _, _, berr := BodyRegion(b); berr == nil {
			t.Fatal("a marker spelling inside the statement must not " +
				"yield a well-formed body window")
		}
	}
}
```

(`snake` is the package's existing id→slug map — `MspecRuleName` is its exported alias, so the scaffold header and the attribution in Task 3/4 can never drift apart. Import `"strings"` and `"websec/internal/validation"` in the test.)

- [ ] **Step 2: Run, verify FAIL** — `go test ./internal/harness/ -run Mspec -v` → compile error `undefined: MiniCertora`.

- [ ] **Step 3: Implement.** In `harness.go`, extend the Kind const block:

```go
const (
	Halmos    Kind = "halmos"
	ForgeFuzz Kind = "forge-fuzz"
	// MiniCertora is the G8 third kind: a bounded SMT verifier run
	// against a .mspec rule (docs/MINICERTORA_ARCHITECTURE.md L0-L2).
	// Its scaffold is text, not Solidity — the BODY markers are
	// "//" comments, which the shipped .mspec grammar ignores
	// (spec/grammar.lark COMMENT), so BodyRegion/Validate carry over
	// unchanged.
	MiniCertora Kind = "minicertora"
)
```

and change the `Scaffold` gate to reject only truly unknown kinds, delegating the render:

```go
if k != Halmos && k != ForgeFuzz && k != MiniCertora {
	return nil, fmt.Errorf("harness: unknown kind %q", string(k))
}
```

with, right after the id/statement/snake extraction (before the Solidity `var b strings.Builder` block), the branch:

```go
if k == MiniCertora {
	return scaffoldMspec(sn, stmt, inv), nil
}
```

Create `mspec.go` (package `harness`) holding the renderer (exact bytes as pinned in Step 1, built with a `strings.Builder` in fixed order, the source line present iff `invField(inv, "source")` is a non-empty string), `DummyMspec` (the two comment lines inside the window as a const), and:

```go
// MspecRuleName is the scaffold-pinned rule name for an invariant id:
// the snake slug the scaffold renders and the verdict attribution
// matches — one exported spelling so the two can never drift.
func MspecRuleName(id string) string { return snake(id) }
```

Note `Scaffold` already errors before reaching the branch when the statement is missing/empty or the id has no name characters — the minicertora branch runs AFTER those guards. Do not touch `BodyRegion`/`Validate` (kind-agnostic already).

- [ ] **Step 4: Run** `go test ./internal/harness/ -count=1` → all green (the existing `harness_test.go` "unknown kind is inconclusive" rows keep passing; `Kind("halmos2")` still refuses).
- [ ] **Step 5: vet + commit**

```bash
go vet ./internal/harness/ && git add internal/harness/ && git commit -m "feat(harness): MiniCertora scaffold kind — .mspec render under the BODY law (G8 third kind, 1/5)"
```

---

### Task 2: `MapMinicertora` — JSONL to rung + proof sidecar (pure)

**Files:**
- Create: `internal/harness/minicertora.go`
- Create: `internal/harness/minicertora_test.go`
- Modify: `internal/harness/outcome.go` (package comment kind list only)

**Interfaces:**
- Consumes: `validation.ParseOrdered` (`var ParseOrdered = jval.ParseOrdered`, preserves key order), `Rung*` consts, `maxExcerpt`/`truncateRunes` (outcome.go helpers).
- Produces (Task 4 consumes exactly):

```go
// MapMinicertora maps one MiniCertora run (raw stdout bytes, the exec
// record's exit_status, and the scaffold-pinned rule name) onto the
// existing rung vocabulary, plus the proof sidecar captured verbatim.
// proof is VNull() when no verdict line was attributed. boundedK is set
// only for proved-bounded.
func MapMinicertora(raw []byte, exitStatus int, ruleName string) (rung,
	summary string, proof validation.Value, boundedK *int)
```

Mapping law (fixture-pinned, no prose scraping): blank lines skipped; an unparseable JSON line → `inconclusive ("inconclusive (output is not JSONL)")`; a line WITHOUT a `rule` key is an **abort** → `inconclusive ("aborted: <reason>: <details≤120>")`; zero attributed lines → `inconclusive ("inconclusive (no verdict line for rule inv_1)")`; two attributed lines → `inconclusive ("inconclusive (duplicate verdict lines for rule)")`; verdict-vs-exit contradiction (PROVEN@≠0, VIOLATED@≠1, UNKNOWN@≠2) → `inconclusive ("inconclusive (report-contradiction: exit N with verdict V)")`. **Caller contract (Task 4 wires it): a timed-out / killed run (`harnessTimedOut(rec)` true, or `exit_status ∈ {-1,137,…}`) is mapped to `inconclusive` by the caller BEFORE `MapMinicertora` is invoked** — the timeout-wins law is unchanged; `MapMinicertora` treats a negative `exitStatus` defensively (skips the contradiction check, still maps the line verdict, and never returns a rung that contradicts "no clean exit") so a caller bug degrades to inconclusive, never to a false proof. `PROVEN`→`RungProvedBounded`, summary `"proved bounded (k=%d)"` from `bounds.loop_bound` (missing/non-int → `"proved bounded"`), `boundedK` = that int; `VIOLATED`→`RungCounterexample`, summary `"counterexample: <failed_assertion.expression≤120>"` (absent → `"counterexample: <reason or 'assertion-violated'>"`), with `" [unconfirmed: crosses a havoc'd call]"` appended when `confidence=="unconfirmed"`, `" [modeled]"` when `"modeled"`; `UNKNOWN`→`RungInconclusive`, summary `"inconclusive (<reason>: <details≤120>)"`. `proof` is captured whenever a line is attributed (UNKNOWN included): fixed key order `tool_version, solc_version, spec_version, evm_version, confidence, reason, bounds, assumptions, warnings, ghosts`, values verbatim (missing → `VNull()`/`VArr()` for the arrays; `bounds` = obj with `loop_bound, path_cap, solver_timeout_ms` kept as parsed ints; `assumptions/warnings/ghosts` arrays copied as-is). The full counterexample witness (params/calls/final_storage) deliberately does NOT ride into the sidecar — it stays in the EXEC stdout artifact (L4 plane: repro reads it from there).

- [ ] **Step 1: Write the failing tests.** Build fixtures as JSONL consts, e.g.:

```go
const mcProven = `{"schema_version":"1","tool_version":"0.4.2","spec_version":"v0.1","solc_version":"0.8.36","evm_version":"paris","optimizer_enabled":false,"contract":"V.sol","rule":"inv_1","verdict":"PROVEN","confidence":"modeled","reason":null,"details":"","assumptions":["msg.value-default-zero","entry-binding:wrapper"],"bounds":{"loop_bound":4,"loop_bound_exhaustive":true,"path_cap":64,"solver_timeout_ms":30000},"warnings":[]}
`
const mcViolated = `{"tool_version":"0.4.2","solc_version":"0.8.36","spec_version":"v0.1","evm_version":"paris","contract":"V.sol","rule":"inv_1","verdict":"VIOLATED","confidence":"unconfirmed","reason":"assertion-violated","details":"","assumptions":["external-call-abstraction"],"bounds":{"loop_bound":4,"path_cap":64,"solver_timeout_ms":30000},"failed_assertion":{"expression":"total >= before"},"params":{"x":"2"},"calls":[],"final_storage":{"total":"0"}}
`
const mcUnknown = `{"contract":"V.sol","rule":"inv_1","verdict":"UNKNOWN","confidence":"modeled","reason":"loop-bound-may-be-exceeded","details":"unrolling exhausted at k=4","assumptions":[],"bounds":{"loop_bound":4,"path_cap":64,"solver_timeout_ms":30000}}
`
const mcAbort = `{"verdict":"UNKNOWN","reason":"tool-error","details":"spec file unreadable"}
`
```

Test rows (table-driven like `outcome_test.go`): proven→proved-bounded k=4, exitStatus 0; violated→counterexample + ` [unconfirmed...]` + proof.confidence "unconfirmed"; unknown→inconclusive summary `inconclusive (loop-bound-may-be-exceeded: unrolling exhausted at k=4)`; abort→inconclusive `aborted: tool-error: spec file unreadable`, proof null; wrong rule name (`rule:"inv_2"`) → no-verdict-line inconclusive; contradiction (mcProven with exitStatus 1); malformed JSON; empty bytes; duplicate attributed lines. Assert the proof key ORDER with `for i, kv := range proof.O { kv.K }` — the determinism law is the point of the sidecar.

- [ ] **Step 2:** `go test ./internal/harness/ -run Minicertora -v` → FAIL (undefined).
- [ ] **Step 3:** Implement `minicertora.go` with a package doc mirroring `MapRun`'s fail-open law (a prover that disagrees with itself gets zero trust). Line scan: `strings.Split`, skip `strings.TrimSpace(line) == ""`. Ints: `v.Kind == validation.Int → int(v.I)` (guard `Big != ""`). Reuse `truncateRunes`, `maxExcerpt`.
- [ ] **Step 4:** `go test ./internal/harness/ -count=1` green; update `outcome.go` package comment line naming the kinds to include MiniCertora (comment-only).
- [ ] **Step 5:** `go vet ./internal/harness/ && git add internal/harness/ && git commit -m "feat(harness): MapMinicertora — JSONL verdict mapping with proof sidecar (G8 third kind, 2/5)"`

---

### Task 3: sandbox profile `minicertora` + toolchain probe (host-side, E3-capped)

**Files:**
- Modify: `internal/sandbox/profiles.go` (Profiles slice :26-27, profileNetwork, profileFilesystem, HostProfile :237-242, ProfileAvailable :247-256)
- Modify: `internal/sandbox/exec.go` (toolVersions probe list :566-568)
- Modify: `assets/schema/sandbox_execution.schema.json` (profile enum + its description line)
- Test: append to `internal/sandbox/exec_test.go` (harnessExec-style profile pins already live there)

**Interfaces:**
- Consumes: the existing deny-rule PolicyCheck machinery (no argv allowlist table exists for host profiles — halmos is policed by deny rules + host execution; match that bar exactly).
- Produces: `Profiles` contains `"minicertora"`; `HostProfile("minicertora") == true`; `ProfileAvailable("minicertora") == true`; `toolVersions()` probes a `minicertora --version` first line; schema enum accepts the profile.

- [ ] **Step 1: Write the failing tests** — append to `internal/sandbox/exec_test.go`:

```go
// TestMinicertoraProfilePolicy pins the profile's table entries:
// host-side, network none, readonly fs, E3-capped like halmos.
func TestMinicertoraProfilePolicy(t *testing.T) {
	v, err := PolicyCheck("minicertora target/src/V.sol artifacts/harness/INV-1/INV.mspec --solc-path /usr/local/bin/solc --loop-bound 4 --timeout-ms 30000", "minicertora")
	if err != nil {
		t.Fatalf("PolicyCheck: %v", err)
	}
	if !validation.PyTruthy(objAt(v, "allowed")) {
		t.Errorf("clean minicertora argv must pass: %s", validation.CanonCompact(v))
	}
	if _, err := PolicyCheck("minicertora x; rm -rf /", "minicertora"); err == nil {
		// PolicyCheck only errors on unknown profiles; the smuggling case
		// must come back not-allowed, mirroring TestHalmosProfileRejectsSmuggling.
	}
	if !HostProfile("minicertora") {
		t.Error("minicertora must be a host profile (E3 cap)")
	}
	if !ProfileAvailable("minicertora") {
		t.Error("minicertora availability is the host toolchain, like halmos")
	}
}

// TestToolVersionsProbesMinicertora mirrors TestToolVersionsProbesHalmos:
// a stub binary on PATH reports its --version first line; absent = omitted.
```

(Write the smuggling assertion properly: `v2, _ := PolicyCheck(...); if PyTruthy(objAt(v2,"allowed")) { t.Error }`. The second probe test copies `TestToolVersionsProbesHalmos` verbatim with the tool name swapped — same fake `runProc` pattern, `argv[0] == "minicertora" && argv[1] == "--version"`, expect `strAt(toolVersions(), "minicertora") == "minicertora 0.4.2"`.)

- [ ] **Step 2:** `go test ./internal/sandbox/ -run Minicertora -v` → FAIL `unknown profile 'minicertora'`.
- [ ] **Step 3:** Implement — add `"minicertora"` to `Profiles`; entries `"minicertora": "none"` (network) and `"minicertora": "readonly"` (filesystem); `case "host-readonly", "halmos", "forge-fuzz", "minicertora":` in BOTH `HostProfile` and `ProfileAvailable`; add `"minicertora"` to the toolVersions list after `"halmos"`. Update the Profiles doc comment to name it as the G8 third kind (host-readonly + halmos + forge-fuzz + minicertora — can never back E4+). Schema: extend the profile enum `"halmos", "forge-fuzz", "minicertora"` and amend the description line: `host-readonly, halmos, forge-fuzz and minicertora execute on the host and may only host evidence at or below E3; E4+ requires a container/VM profile`.
- [ ] **Step 4:** `python3 scripts/sync-asset-manifest.py` (schema bytes changed) → `go test ./internal/sandbox/ ./assets/... -count=1` green. NOTE: the shim binary `minicertora` on PATH is OPERATOR infrastructure (package-root + venv + absolute solc folded into one argv[0], per the architecture L0 plane); this task only pins that the host probes for it and omits it honestly when absent. Document one sentence saying so in the Profiles comment.
- [ ] **Step 5:** `go vet ./... && git add internal/sandbox/ assets/schema/sandbox_execution.schema.json assets/testdata/asset_manifest.json && git commit -m "feat(sandbox): minicertora host profile + version probe (G8 third kind, 3/5)"`

---

### Task 4: CLI wiring — choices, `INV.mspec` file, attribution, proof write

**Files:**
- Modify: `internal/cli/cmd_verify.go` (usage :34, help :53-57, choice checks :149-166, scaffold choice error :154-156/278, `verifyScaffold` fname switch :314-317)
- Modify: `internal/cli/cmd_verify_harness.go` (`harnessKindFor` suffix list + error texts :216-231, exit-status plumbing :68-91, `harnessField` proof kv, `harnessRecordedHashes` :404-421)
- Modify: `assets/schema/protocol_model.schema.json` (harness.kind description; add `proof` property)
- Create: `internal/cli/cmd_verify_minicertora_test.go`
- Test: modify pinned texts in `internal/cli/cmd_verify_test.go` (:191, :344 rows)

**Interfaces:**
- Consumes: `harness.MiniCertora`, `harness.MspecRuleName`, `harness.MapMinicertora` (Tasks 1-2), `harnessExec`/`harnessCamp`/`t15SeedInvariant` test helpers (`cmd_verify_harness_test.go`).
- Shape rule (reviewer note): `harnessMapBound` grows by threading `exitStatus`+`ruleName`, but each backend's *decision* lives in its own `map*`/`MapMinicertora` — the CLI wrapper stays a dispatcher, not a god function. Revisit with a mapper struct only when a 4th backend lands (YAGNI now).
- Produces: `verify --scaffold minicertora --invariant INV-n` writes `artifacts/harness/INV-n/INV.mspec` + `HARNESS-INV-n-minicertora` artifact/event; `verify --harness-result ... --kind minicertora` writes `verification.harness {kind, rung, exec, bounded_k, summary, proof}` and logs `harness_run` (same event shape).

- [ ] **Step 1: Write the failing tests** in `internal/cli/cmd_verify_minicertora_test.go`:

```go
// cmd_verify_minicertora_test.go: the G8 third kind end to end —
// scaffold bytes land as INV.mspec, a hand-written EXEC maps through
// MapMinicertora, and the proof sidecar rides verification.harness.

func TestVerifyScaffoldMinicertora(t *testing.T) {
	c, root := t15Campaign(t, "mc-scaffold")
	t15SeedInvariant(t, c, "INV-1", "total always covers sum(payouts)")
	code, out, errS := run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold", "minicertora", "--invariant", "INV-1")
	if code != 0 {
		t.Fatalf("exit %d out=%q err=%q", code, out, errS)
	}
	want := "HARNESS-INV-1-minicertora: scaffolded artifacts/harness/" +
		"INV-1/INV.mspec\n"
	if out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
	// Re-run: unchanged, no second event (the T17 law).
	code, out, _ = run(t, "--root", root, "verify", c.CampaignID,
		"--scaffold", "minicertora", "--invariant", "INV-1")
	if code != 0 || out != "HARNESS-INV-1-minicertora: unchanged\n" {
		t.Errorf("re-run = (%d,%q)", code, out)
	}
}
```

Plus `mcHarnessExec(t, c, execID, stdout string, exitStatus int64, hashes map[string]string)` — a copy of `harnessExec` with `profile` set to `"minicertora"` (keep the original untouched; both live in package `cli`). Then the mapping tests (model the record seeding on `TestHarnessResultProvedBounded`):
- `TestHarnessResultMinicertoraProven`: scaffold, exec with the Task-2 `mcProven` line, exit 0, `input_hashes` `{"artifacts/harness/INV-1/INV.mspec": <scaffold sha>}` → expect stdout `INV-1: proved-bounded (minicertora, k=4, EXEC-1)\n`, and the links entry `verification.harness.bounded_k == 4`, `.proof.confidence == "modeled"`, `.proof.assumptions` first element `"msg.value-default-zero"`.
- `TestHarnessResultMinicertoraViolated`: violated line, exit 1 → rung `counterexample`, summary carries `[unconfirmed: crosses a havoc'd call]`.
- `TestHarnessResultMinicertoraUnknown`: unknown line exit 2 → `inconclusive`, but the `proof` sidecar IS present (an UNKNOWN line is *attributed* — Task 2 captures the sidecar on every attributed line including UNKNOWN; only *unattributed* runs — abort / zero-line / duplicate-line / contradiction — store no `proof` key at all, key absent not `null`). Assert `.proof.reason == "loop-bound-may-be-exceeded"` and the `harness` rung `inconclusive`.
- `TestHarnessResultMinicertoraBoundViolation`: hashes entry names `INV.mspec` with a WRONG sha → rung inconclusive, summary `scaffold-bound violation: harness file hash differs from stored scaffold`.
- `TestVerifyKindMinicertoraChoice`: `--scaffold bogus` now errors `(choose from 'halmos', 'forge-fuzz', 'minicertora')`; update the two pinned rows in `cmd_verify_test.go` (:191 and the harnessCamp no-scaffold text) in this step and expect FAIL before the impl.

- [ ] **Step 2:** `go test ./internal/cli/ -run Minicertora -v` → FAIL (invalid choice).
- [ ] **Step 3:** Implement. `cmd_verify.go`: usage `--scaffold {halmos,forge-fuzz,minicertora}`; the two choice-guard lines gain `&& a.scaffold != string(harness.MiniCertora)` and the error becomes `(choose from 'halmos', 'forge-fuzz', 'minicertora')` (both `--scaffold` and `--kind` guards + help text); `verifyScaffold` fname switch: `case harness.MiniCertora: fname = "INV.mspec"`. `cmd_verify_harness.go`:
  - `harnessKindFor`: suffix accept gains `string(harness.MiniCertora)`; the two error texts become `{halmos|forge-fuzz|minicertora}` and the ambiguity message `verify: %s has multiple harness scaffolds; pass --kind {halmos|forge-fuzz|minicertora}\n`;
  - `verifyHarnessResult`: read `exitStatus` from the record (`objAt(rec, "exit_status")`, Int → `int(v.I)`; non-Int → `-2` meaning "unknown", which skips the contradiction check) and branch BEFORE `harnessMapBound`… actually keep ONE path: extend `harnessMapBound(kind, raw, rec, scaffold, timedOut, k)` → add `exitStatus int, ruleName string` params; inside, when `kind == harness.MiniCertora` and NOT timedOut, replace the `harnessMapped` call with `MapMinicertora(raw, exitStatus, ruleName)` + the same bound-suffix rules; halmos/forge ignore the two new params (pass `""`/0 at the single call site is wrong — compute `ruleName := harness.MspecRuleName(a.harnessResult)` in `verifyHarnessResult` and thread it; MapRun branches never use it).
  - `harnessField`: add `proof validation.Value` param — when `proof.Kind == validation.Obj`, append `KV{K: "proof", V: proof}` after `summary` (fixed key order preserved; absent for other kinds AND for unattributed minicertora → golden bytes for every existing campaign cannot move).
  - `harnessRecordedHashes`: harnessNamed detection gains `|| strings.HasSuffix(base, ".mspec")` (the T17 law is that a harness-named file with a foreign hash is a VIOLATION of the bind, never an "unbound" pass — `.mspec` must read as harness-named or the whole Decision-2b rail is paper for this backend).
  - Schema `protocol_model.schema.json`: `verification.harness` properties gain a `"proof"` object. Every key is NULLABLE so the Go builder can emit the full fixed key-set with `null` for absent fields (determinism over omission — a strict `additionalProperties:false` + typed-only schema plus an omit-missing builder is a byte-instability trap; this mirrors the existing `bounded_k: ["integer","null"]`). Write it explicitly (JSON Schema has no positional tuple types):
    ```json
    "proof": { "type": "object", "additionalProperties": false, "properties": {
      "tool_version": { "type": ["string","null"] },
      "solc_version": { "type": ["string","null"] },
      "spec_version": { "type": ["string","null"] },
      "evm_version":  { "type": ["string","null"] },
      "confidence":   { "type": ["string","null"] },
      "reason":       { "type": ["string","null"] },
      "bounds": { "type": ["object","null"], "additionalProperties": false, "properties": {
        "loop_bound": { "type": ["integer","null"] },
        "path_cap": { "type": ["integer","null"] },
        "solver_timeout_ms": { "type": ["integer","null"] } } },
      "assumptions": { "type": "array", "items": { "type": "string" } },
      "warnings":    { "type": "array", "items": { "type": "string" } },
      "ghosts":      { "type": "array" } } }
    ```
    `ghosts` carries objects (`{name, expression}`) — left unconstrained by design: it is copied verbatim from the parsed line (`v.V`), never reconstructed, so mixed/ordered content is preserved for free. `kind` description becomes `(halmos | forge-fuzz | minicertora)`. Then `python3 scripts/sync-asset-manifest.py`.
- [ ] **Step 4: Runbook honesty.** `assets/runbook/RUNBOOK.md:1402` → `--scaffold halmos|forge-fuzz|minicertora`; re-sync manifest; run the walkthrough `scripts/runbook-walkthrough.sh` (it must stay green — it pins documented commands, and the D7 registry↔docs check compares usage text).
- [ ] **Step 5:** `go test ./internal/cli/ ./internal/audit/... -count=1` green; `bash scripts/golden.sh` green (no proof bytes exist in the recipe → campaign bytes MUST be identical — that is this task's regression proof); commit:

```bash
git add -A && git commit -m "feat(cli): minicertora scaffold/kind wiring + proof sidecar on verification.harness (G8 third kind, 4/5)"
```

---

### Task 5: doctor/env honesty + close-out pins

**Files:**
- Modify: `internal/doctor/` (version line — locate via `rg "halmos" internal/doctor internal/envgo`)
- Modify: `docs/IMPROVEMENTS.md` (one cross-ref line under the Wave K header)
- Test: `go run ./cmd/webv2 selftest` + full suite

**Interfaces:**
- Consumes: `sandbox.toolVersions` (Task 3), `doctor`'s `e4_capable` filter (keys off `HostProfile` — must already classify minicertora right, this task PINS it).

- [ ] **Step 1:** Write a failing doctor pin test in the existing doctor test file: with a fake PATH binary set (the established stub-runProc pattern), the env report lists `minicertora` under host tools and `e4_capable` EXCLUDES the minicertora profile (host profile). Run → FAIL.
- [ ] **Step 2:** Implement whatever glue the probe list didn't already cover (expect: nothing in `HostProfile`-keyed code — only the explicit ordering of the env report; keep deltas minimal). `docs/IMPROVEMENTS.md` Wave K header gains: `*Update 2026-09-12: MiniCertora landed as the G8 third kind (docs/superpowers/plans/2026-09-12-minicertora-harness-backend.md; architecture docs/MINICERTORA_ARCHITECTURE.md). K1/K3/K4 re-scoped per that doc §0.*`
- [ ] **Step 3:** Full battery: `go vet ./... && go test ./... -count=1 && bash scripts/golden.sh && bash scripts/runbook-walkthrough.sh && go run ./cmd/webv2 selftest` — all green, golden bytes identical to the base commit's.
- [ ] **Step 4:** Commit `test+docs: minicertora profile in doctor surface; Wave K cross-ref (G8 third kind, 5/5)`.

---

## Out of scope (deliberate — the follow-on plans)

L3 escalation dispositions (`internal/harness/disposition.go` + re-run ladders), L5 sweep templates, L6 calibration fixtures, and the `calls[] → sequence_poc` repro bridge are plans 2–4 of `docs/MINICERTORA_ARCHITECTURE.md`'s §6 (tasks L-e→L-h). This plan is the honest minimum that makes `PROVEN-BOUNDED (minicertora, k=4, EXEC-n)` a real campaign byte.

## Self-Review (writer, 2026-09-12)

1. **Spec coverage:** architecture §2 L0→Task 3, L1→Task 1, L2→Tasks 2+4, §3 schema/data-contract→Task 4 (proof sidecar; `bounded_k` from `bounds.loop_bound`), §4 determinism→global constraints + Tasks 1/2 pure tests, §5 non-goals honored (no verbs, no auto-attribution, gate weight untouched, `PROVEN-UNBOUNDED` absent). L3–L6 explicitly parked above. 2. **Placeholders:** the `TestToolVersionsProbesMinicertora` body is specified as a verbatim copy-swap of the pinned halmos neighbor (file:line given) — acceptable because the source of the copy is exact, not invented. 3. **Type check:** `MapMinicertora(raw []byte, exitStatus int, ruleName string) (rung, summary string, proof validation.Value, boundedK *int)` — consumed in Task 4 step 3 with the same shape; `MspecRuleName` produced Task 1, consumed Task 4; profile string `"minicertora"` consistent across Tasks 3/4/5; rung constants reused, never redefined.


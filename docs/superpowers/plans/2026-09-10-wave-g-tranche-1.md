# Wave G Tranche 1 — Hybrid Evidence & Critic Outlook — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land Wave G tranche 1 of `docs/IMPROVEMENTS.md`: G7 (claim-intake methodology doc), G1 (Slither detector evidence as campaign findings + corroboration factor + tool-flags rendering), G6 (critic triager-outlook recorded and scored).

**Architecture:** Everything rides existing rails: the hypothesis-ingest path (`findings.IngestHypothesis`), the dedup `same`-resolution path (`dedup.ResolveCandidate`), the verdict transition (`findings.SetCriticVerdict` template), the deterministic A3 score (`internal/risk/acceptance.go`), and embedded asset packs (schema/prompts/runbook, SHA-256-pinned). New fields are presence-gated so no existing campaign's bytes move.

**Tech Stack:** Go 1.26.2, stdlib only (module `websec`; deps frozen in `go.mod`: go-toml, jsonschema/v6, x/text, yaml.v3). Tests: standard `testing` with table fixtures. Gates: `go test ./... -count=1`, `scripts/golden.sh`, `scripts/verify-full.sh`, `go run ./cmd/webv2 selftest`.

## Global Constraints

- **No new dependencies.** stdlib only for new code.
- **No new CLI verbs.** `ingest` and `verdict` gain optional flags; every other change is data/schema/pure code.
- **Deterministic:** no wall clock, no map iteration order in outputs — sort explicitly (the repo pattern); `WEBV2_NOW`/`WEBV2_UUID` are the pinned seams.
- **Byte discipline (principle 1):** a new score factor contributes 0 when its field is absent; `scripts/golden.sh` must stay green with zero fixture edits. If a golden byte moves, the task FAILS and is returned for redesign.
- **Asset packs:** any edit under `assets/` requires `python3 scripts/sync-asset-manifest.py` before committing, or `go test ./assets` fails.
- **argparse-shaped usage/help text:** new flags appear in the exact style of the existing `t14*Usage/Help` strings (flags list, positional order, `--flag=` and `--flag v` both accepted).
- **Commit per task** with the message given in that task's final step; do not batch tasks.
- **Language of report/brief renderings:** plain ASCII table text, matching existing sections.

## File Structure (what this tranche touches)

| file | action | responsibility |
|---|---|---|
| `docs/eval-methodology.md` | create | the nine-check claim-intake rubric (G7) |
| `assets/runbook/RUNBOOK.md` | modify | one hard-rule bullet pointing at the rubric (G7) |
| `internal/datasets/slither/slither.go` | create | Slither JSON → hypothesis payloads (G1) |
| `internal/datasets/slither/slither_test.go` | create | adapter unit tests + fixtures (G1) |
| `internal/datasets/slither/testdata/slither_sample.json` | create | golden Slither JSON input (G1) |
| `internal/cli/cmd_ingest.go` | modify | `--from slither` flag → IngestHypothesis loop (G1) |
| `internal/cli/cmd_ingest_test.go` | modify | CLI-level tests for `--from` (G1) |
| `internal/dedup/dedup.go` | modify | record `dedup_meta.corroborated_by` on `same` (G1) |
| `internal/dedup/dedup_test.go` | modify | corroboration tests (G1) |
| `internal/risk/acceptance.go` | modify | corroboration bonus + outlook factor (G1/G6) |
| `internal/risk/acceptance_test.go` | modify | pinned-weight tests for both factors (G1/G6) |
| `internal/briefing/briefing.go` | modify | "Tool flags vs critic verdicts" advisory block (G1) |
| `internal/findings/transitions.go` | modify | `SetTriagerOutlook` (G6) |
| `assets/schema/finding.schema.json` | modify | `verification.triager_outlook` (G6) |
| `internal/cli/cmd_verdict.go` | modify | `--outlook/--outlook-reason` flags (G6) |
| `internal/cli/testdata/p3_args_golden.json` | modify | new usage blocks land here (verify at task time) |
| `assets/prompts/48_critic_system.md` | modify | triager-outlook rubric section (G6) |
| `assets/testdata/asset_manifest.json` | regenerate | after every `assets/` edit |

---

### Task 1: G7 — the claim-intake checklist doc + runbook pointer

**Files:**
- Create: `docs/eval-methodology.md`
- Modify: `assets/runbook/RUNBOOK.md` (the `## Hard rules for the operator` section, append the next numbered rule)
- Regenerate: `assets/testdata/asset_manifest.json`

**Interfaces:**
- Consumes: nothing.
- Produces: a stable doc path `docs/eval-methodology.md` that later waves (G2 asset validator, G12) reference verbatim; runbook rule text "eval-methodology" (G7 validator items key their prose on it).

- [ ] **Step 1: Write `docs/eval-methodology.md`** with exactly this content:

```markdown
# Claim-intake methodology (Wave G, G7)

An external claim (tool accuracy, dataset score, benchmark result) may enter
framework DATA — assets, playbooks, prompts, weights — only after surviving
this rubric. Record the trial: every numeric external claim baked into an
asset carries a `provenance` row {claim, source_url, checked_date, verdict,
tier}. `verdict: uncorroborated` is legal but renders in reports. The gate:
numbers without a row enter only as `uncorroborated`.

## Hard kills (one is fatal for the claim as evidence)

1. **No leakage control.** Trained models: no temporal split by deployment
   date, no dedup of near-identical contracts across splits. For LLM claims
   the split must respect the model's PRETRAINING CUTOFF, not just the study's
   own split.
2. **Synthetic labels counted as real.** Injected-bug corpora (SmartBugs,
   SolidiFI style) are pattern labels, not exploitability labels — scores on
   them never mix with real-incident scores in one number.
3. **Contract-level F1 as the unit.** Flagging a whole file can game
   contract-level metrics; demand function/line-level or explicitly discount.
4. **No baseline, or a strawman baseline.** The baseline is the best detector
   FOR THAT CLASS (not "always Slither"), plus trivial floors
   (always-flag / never-flag).
5. **No significance test.** A 1-point F1 delta without a paired test or CI
   is noise.

## Soft failures (down-weight and say so)

6. **No run variance.** LLM detectors reporting one greedy decode are
   unmeasured; require pass@k or multi-seed spread.
7. **No cost accounting.** Token/compute overhead is part of the result
   (a 4x overhead changes the decision).
8. **Secondary-source numbers.** Blog mirrors of a standard (content farms)
   don't count; re-verify against the primary page and cite THAT.
9. **Edition/version drift.** Figures must cite the edition of the standard
   whose incident window they come from (e.g. OWASP SCTop10 2025-edition
   numbers describe 2024 incidents; the 2026 edition restates on 2025 data —
   never blend the two).

## Application points

- `assets/taxonomy/class_weights.json` rows (G2) — validator enforced.
- Playbook/prompt prose citing external numbers — manual check at authoring,
  `provenance` block in the asset where a numeric claim is baked.
- Reports: `uncorroborated` figures render with that word.

*Fixes applied while drafting Wave G (kept as worked examples): the
$953.2M access-control figure belongs to the 2025-edition analysis window;
the 2026 edition is 122 deduplicated 2025 incidents, ~$905M
(https://scs.owasp.org/sctop10/). GMX V1 (Jul 2025, $42M) is a refund-based
cross-contract reentrancy inflating GLP pricing — not flash-loan-mediated
(https://sherlock.xyz/post/gmx-exchange-hack-explained,
https://blocksec.com/blog/gmx-incident-cross-contract-reentrancy-bypasses-a-four-year-old-guard).*
```

- [ ] **Step 2: Append the runbook hard rule.** Read `assets/runbook/RUNBOOK.md`, find `## Hard rules for the operator`, and append as the next number: "External claims (tool metrics, benchmark numbers) enter assets, playbooks, and prompts only per `docs/eval-methodology.md`; a baked-in number without a provenance row renders as uncorroborated."

- [ ] **Step 3: Re-pin the asset pack and run the doc's consumers.**

```bash
python3 scripts/sync-asset-manifest.py
go run ./cmd/webv2 selftest
go test ./assets/ -count=1
go test ./internal/cli/ -run Runbook -count=1
```
Expected: manifest updated; selftest green; asset test green; the D7 runbook↔registry test green (the new bullet is prose, not a command — no registry change).

- [ ] **Step 4: Commit**

```bash
git add docs/eval-methodology.md assets/runbook/RUNBOOK.md assets/testdata/asset_manifest.json
git commit -m "docs(G7): claim-intake methodology checklist + runbook hard rule (Wave G tranche 1)"
```

---

### Task 2: G1 — Slither adapter package

**Files:**
- Create: `internal/datasets/slither/slither.go`
- Create: `internal/datasets/slither/slither_test.go`
- Create: `internal/datasets/slither/testdata/slither_sample.json`

**Interfaces:**
- Consumes: `validation.Value` (ordered-JSON value tree, `websec/internal/validation`), `taxonomy.KnownClasses()` (class validity check).
- Produces: `func ToPayloads(doc validation.Value) ([]validation.Value, error)` — one hypothesis-shaped payload per Slither check result, byte-deterministic order; the exact payload keys Task 3 feeds to `findings.IngestHypothesis`. Every payload carries `provenance.sast_tools = ["slither:<check>"]` and `provenance.discovered_by = "sast/slither"`.

- [ ] **Step 1: Create the fixture** `internal/datasets/slither/testdata/slither_sample.json` (a real-shape Slither `--json` document; `success` may be absent — tolerate both):

```json
{
  "success": true,
  "error": null,
  "results": [
    {"check": "reentrancy-eth", "impact": "High", "confidence": "Medium",
     "description": "Reentrancy in Vault.withdraw (src/Vault.sol#42-58):\n\tExternal calls:\n\t- token.transfer(msg.sender, amount) (src/Vault.sol#50)\n",
     "vertices": [
       {"type": "source", "filename": "src/Vault.sol", "line_no": 50},
       {"type": "source", "filename": "src/Vault.sol", "line_no": 44}
     ]},
    {"check": "unchecked-transfer", "impact": "Medium", "confidence": "Medium",
     "description": "Unused return value of token.transfer (src/Pay.sol#11) (src/Vault.sol#33)",
     "vertices": [{"type": "source", "filename": "src/Pay.sol", "line_no": 11}]},
    {"check": "solc-version", "impact": "Informational", "confidence": "High",
     "description": "Detected pragma not locked (src/Vault.sol#2)",
     "vertices": [{"type": "source", "filename": "src/Vault.sol", "line_no": 2}]},
    {"check": "assembly", "impact": "Informational", "confidence": "Low",
     "description": "Usage of assembly detected in Vault.risky (src/Vault.sol)",
     "vertices": [{"type": "source", "filename": "src/Vault.sol", "line_no": 77}]}
  ]
}
```

- [ ] **Step 2: Write the failing test** `internal/datasets/slither/slither_test.go`:

```go
package slither

import (
	"encoding/json"
	"os"
	"testing"

	"websec/internal/validation"
)

func loadFixture(t *testing.T) validation.Value {
	t.Helper()
	raw, err := os.ReadFile("testdata/slither_sample.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var anyv any
	if err := json.Unmarshal(raw, &anyv); err != nil {
		t.Fatalf("fixture json: %v", err)
	}
	return validation.FromAny(anyv)
}

func TestToPayloadsMappingAndOrder(t *testing.T) {
	ps, err := ToPayloads(loadFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	// Informational checks (solc-version, assembly) are DROPPED: two remain.
	if len(ps) != 2 {
		t.Fatalf("want 2 payloads, got %d", len(ps))
	}
	// Deterministic order: class-key path order is (src/Pay.sol:11) then
	// (src/Vault.sol:44/50) — sorted by (first path, first line, check).
	if got := objStr(objAt(ps[0], "root_cause"), "class"); got != "unchecked-external-call" {
		t.Fatalf("payload 0 class: %s", got)
	}
	if got := objStr(objAt(ps[1], "root_cause"), "class"); got != "reentrancy" {
		t.Fatalf("payload 1 class: %s", got)
	}
	pro := objAt(ps[1], "provenance")
	tools := valsOf(objAt(pro, "sast_tools"))
	if len(tools) != 1 || tools[0].S != "slither:reentrancy-eth" {
		t.Fatalf("sast_tools: %v", tools)
	}
	if objStr(pro, "discovered_by") != "sast/slither" {
		t.Fatal("discovered_by must name the SAST lane")
	}
	aff := valsOf(objAt(ps[1], "affected"))
	if len(aff) != 2 {
		t.Fatalf("reentrancy affected: %d (both vertices, sorted by line)", len(aff))
	}
	if lines := valsOf(objAt(aff[0], "lines")); lines[0].I != 44 {
		t.Fatal("affected must be sorted by line")
	}
}

func TestUnmappedCheckKeepsDefaultClass(t *testing.T) {
	doc := validation.FromAny(map[string]any{"results": []any{
		map[string]any{"check": "something-new", "description": "brand new finding text",
			"impact": "High", "confidence": "Medium",
			"vertices": []any{map[string]any{"filename": "a.sol", "line_no": 3}}},
	}})
	ps, err := ToPayloads(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || objStr(objAt(ps[0], "root_cause"), "class") != "logic-error" {
		t.Fatalf("unmapped checks must land logic-error, got %d payloads", len(ps))
	}
}

func TestNoResultsIsEmpty(t *testing.T) {
	ps, err := ToPayloads(validation.FromAny(map[string]any{"results": []any{}}))
	if err != nil || len(ps) != 0 {
		t.Fatalf("want empty, got %d %v", len(ps), err)
	}
}

func TestPayloadPassesHypothesisValidation(t *testing.T) {
	ps, err := ToPayloads(loadFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	// The payload is a hypothesis payload (the --example shape): no
	// finding_id/status yet, but the required non-system keys must be there.
	for _, p := range ps {
		for _, k := range []string{"title", "root_cause", "affected", "attacker", "evidence"} {
			if objAt(p, k).Kind == validation.Null {
				t.Fatalf("payload missing %s", k)
			}
		}
	}
}
```

Add the package-local helpers `objAt/objStr/valsOf` the test uses (same 10-line pattern as `dedup.go`'s local helpers — copy them, they must exist before the test compiles; run the test to see the compile failure first — that IS the red step).

- [ ] **Step 3: Run to verify it fails**

```bash
go test ./internal/datasets/slither/ -count=1
```
Expected: FAIL (undefined: ToPayloads / helpers).

- [ ] **Step 4: Write `slither.go`:**

```go
// Package slither is the Wave G G1 adapter: Slither JSON output becomes
// campaign hypothesis payloads that ride the existing ingest path — same
// dedup fingerprints, same gates, and an honest provenance tag. A tool flag
// is a HYPOTHESIS, never evidence: impact/confidence from Slither are
// rendered into the description, never into severity.
//
// Contract mirrors internal/datasets/defihacklabs: unmapped labels fall to
// the default class, ordering is explicit (no map iteration in output), and
// Informational/Low-signal checks are dropped because the framework's budget
// law says every finding costs reviewer time.
package slither

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"websec/internal/validation"
)

// Dataset names the adapter for messages.
const Dataset = "slither"

// minImpact admits Medium/High/Critical findings only.
var admittedImpacts = map[string]bool{"High": true, "Critical": true, "Medium": true}

// checkClasses maps Slither check ids to canonical taxonomy classes.
// Anything absent maps to logic-error (the taxonomy advisory on ingest is
// then the honest signal, not a silent invention).
var checkClasses = map[string]string{
	"reentrancy-eth":            "reentrancy",
	"reentrancy-no-eth":         "reentrancy",
	"reentrancy-unlimited-gas":  "reentrancy",
	"unchecked-transfer":        "unchecked-external-call",
	"unchecked-lowlevel":        "unchecked-external-call",
	"calls-loop":                "dos-griefing",
	"locked-ether":              "dos-griefing",
	"arbitrary-send-eth":        "access-control",
	"suicidal":                  "access-control",
	"tx-origin":                 "access-control",
	"weak-prng":                 "signature-replay",
	"uninitialized-state":       "upgrade-initializer",
	"uninitialized-public":      "upgrade-initializer",
	"incorrect-equality":        "logic-error",
	"shadowing-local":           "logic-error",
}

const defaultClass = "logic-error"

// ToPayloads renders every admitted Slither result as a hypothesis payload,
// in deterministic (path, line, check) order.
func ToPayloads(doc validation.Value) ([]validation.Value, error) {
	type row struct {
		path string
		line int64
		check string
		out  validation.Value
	}
	var rows []row
	for _, r := range valsOf(objAt(doc, "results")) {
		check := objStr(r, "check")
		if check == "" {
			return nil, fmt.Errorf("slither: result without 'check' id")
		}
		if !admittedImpacts[objStr(r, "impact")] {
			continue
		}
		desc := strings.TrimSpace(objStr(r, "description"))
		if desc == "" {
			continue
		}
		type site struct {
			path string
			line int64
		}
		var sites []site
		for _, v := range valsOf(objAt(r, "vertices")) {
			fn := objStr(v, "filename")
			ln := objAt(v, "line_no")
			if fn == "" || ln.Kind != validation.Int {
				continue
			}
			sites = append(sites, site{fn, ln.I})
		}
		if len(sites) == 0 {
			continue // a flag with no location cannot anchor; drop it
		}
		sort.Slice(sites, func(i, j int) bool {
			if sites[i].path != sites[j].path {
				return sites[i].path < sites[j].path
			}
			return sites[i].line < sites[j].line
		})
		affected := make([]validation.Value, 0, len(sites))
		for _, s := range sites {
			affected = append(affected, validation.VObj(
				kv("path", validation.VStr(s.path)),
				kv("lines", validation.VArr(
					validation.VInt(s.line), validation.VInt(s.line))),
				kv("entry_point", validation.VBool(false))))
		}
		cls, ok := checkClasses[check]
		if !ok {
			cls = defaultClass
		}
		title := "Slither " + check + ": " + firstLine(desc)
		if utf8.RuneCountInString(title) > 120 {
			title = string([]rune(title)[:117]) + "..."
		}
		out := validation.VObj(
			kv("title", validation.VStr(title)),
			kv("root_cause", validation.VObj(
				kv("class", validation.VStr(cls)),
				kv("description", validation.VStr(clip(desc, 900))),
				kv("mechanism", validation.VStr("static pattern: slither/"+check)))),
			kv("affected", validation.VArr(affected...)),
			kv("attacker", validation.VObj(
				kv("profile", validation.VStr("static analysis (Slither)")),
				kv("capabilities", validation.VArr()))),
			kv("evidence", validation.VArr()),
			kv("provenance", validation.VObj(
				kv("discovered_by", validation.VStr("sast/slither")),
				kv("sast_tools", validation.VArr(
					validation.VStr("slither:"+check))))),
		)
		rows = append(rows, row{sites[0].path, sites[0].line, check, out})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].path != rows[j].path {
			return rows[i].path < rows[j].path
		}
		if rows[i].line != rows[j].line {
			return rows[i].line < rows[j].line
		}
		return rows[i].check < rows[j].check
	})
	out := make([]validation.Value, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.out)
	}
	return out, nil
}

// firstLine is the text up to the first newline, trimmed.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// clip cuts to n RUNES (byte cuts split UTF-8 and Python never did).
func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-3]) + "..."
}

// ---- local ordered-object helpers (same pattern as internal/dedup) -------

func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, e := range v.O {
		if e.K == key {
			return e.V
		}
	}
	return validation.VNull()
}

func objStr(v validation.Value, key string) string { return objAt(v, key).S }

func valsOf(v validation.Value) []validation.Value {
	if v.Kind != validation.Arr {
		return nil
	}
	return v.A
}
```

- [ ] **Step 5: Run the tests**

```bash
go test ./internal/datasets/slither/ -count=1
go vet ./internal/datasets/slither/
```
Expected: PASS. Note the fixture's `assembly` check is Informational ⇒ dropped; `solc-version` also Informational ⇒ dropped; exactly two payloads survive.

- [ ] **Step 6: Commit**

```bash
git add internal/datasets/slither/
git commit -m "feat(G1): Slither JSON adapter — detector flags become hypothesis payloads with provenance"
```

---

### Task 3: G1 — `webv2 ingest --from slither` (campaign path)

**Files:**
- Modify: `internal/cli/cmd_ingest.go` (parser + runIngest + the two usage consts)
- Modify: `internal/cli/cmd_ingest_test.go`

**Interfaces:**
- Consumes: `slither.ToPayloads(doc validation.Value) ([]validation.Value, error)` (Task 2); `orchestrator.Ingest(payload, IngestOpts{Trajectory, Stage, AnswersPriority, PriorityOutcome})` (existing); `validation.ParseOrdered([]byte) (validation.Value, error)` (existing).
- Produces: CLI behavior `webv2 ingest <CID> --from slither --json-file out.json` — N hypotheses, one per admitted check result, each through the SAME orchestrator ingest path as a model payload (schema validation, dedup fingerprint, intake checks, taxonomy advisory, budget law included). No new fields on findings beyond what the payloads carry.

- [ ] **Step 1: Write the failing CLI test** (append to `cmd_ingest_test.go`, mirroring how the existing tests build a campaign + payload there — reuse their helpers; if the file's helpers differ, adapt names, NOT semantics):

```go
func TestIngestFromSlitherCreatesHypotheses(t *testing.T) {
	root := mkroot(t) // existing test helper
	cid := initOne(t, root)
	// existing helpers: write target + snapshot so intake passes; if the
	// file's ingest tests skip snapshotting, follow their pattern exactly.
	raw := `{"results":[{"check":"reentrancy-eth","impact":"High","confidence":"Medium",
	  "description":"Reentrancy in Vault.withdraw (src/Vault.sol#42-58)",
	  "vertices":[{"filename":"src/Vault.sol","line_no":50}]}]}`
	p := filepath.Join(t.TempDir(), "out.json")
	if err := os.WriteFile(p, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out := runCLI(t, root, "ingest", cid, "--from", "slither", "--json-file", p)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, "slither:reentrancy-eth") && !strings.Contains(out, "F-") {
		t.Fatalf("output must report the created finding: %s", out)
	}
	// provenance survived the round-trip into the stored finding:
	f := loadFirstFindingJSON(t, root, cid) // parse campaigns/<cid>/findings/*.json
	sast := pathString(f, "provenance", "sast_tools", "0")
	if sast != "slither:reentrancy-eth" {
		t.Fatalf("provenance.sast_tools lost in ingest: %q", sast)
	}
}

func TestIngestFromRejectsUnknownSource(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out := runCLI(t, root, "ingest", cid, "--from", "mytool", "--json-file", "/dev/null")
	if code != 2 {
		t.Fatalf("want usage error exit 2, got %d (%s)", code, out)
	}
	if !strings.Contains(out, "argument --from: invalid choice") {
		t.Fatalf("argparse-shaped error expected: %s", out)
	}
}

func TestIngestFromRequiresJsonFile(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out := runCLI(t, root, "ingest", cid, "--from", "slither")
	if code != 2 {
		t.Fatalf("want exit 2, got %d (%s)", code, out)
	}
	if !strings.Contains(out, "--json-file") {
		t.Fatalf("the message must name the missing flag: %s", out)
	}
}
```
(`runCLI`, `loadFirstFindingJSON`, `pathString` are the file's existing CLI-exec and JSON-path test helpers if present; if absent, write them once here as small helpers using the package's established pattern of invoking `cli.Run(root, argv, out)` and reading the finding file with `os.ReadFile` + `validation.ParseOrdered`.)

- [ ] **Step 2: Run to verify failure** — `go test ./internal/cli/ -run TestIngestFrom -count=1` → FAIL: `unrecognized arguments: --from`.

- [ ] **Step 3: Implement.**
  a. `ingestArgs`: add field `from string`.
  b. `parseIngest`: accept `--from` (value + `=` form, same case-pair style as existing flags), and the invalid-choice guard:

```go
		case a == "--from" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			a.from = args[i+1]
			i++
		case strings.HasPrefix(a, "--from="):
			a.from = strings.TrimPrefix(a, "--from=")
		case a == "--from":
			return nil, argErrf("ingest", "argument --from: expected one argument")
```
After the loop:
```go
	if a.from != "" && a.from != "slither" {
		return nil, argErrf("ingest",
			"argument --from: invalid choice: %s (choose from %s)",
			validation.PyReprStr(a.from), quotedList([]string{"slither"}))
	}
```
  c. `runIngest`: branch BEFORE the single-payload path but AFTER the campaign open:

```go
	if a.from == "slither" {
		return runIngestSast(root, c, a, r)
	}
```
with:
```go
// runIngestSast is the G1 lane: Slither JSON -> hypothesis payloads -> the
// SAME orchestrator ingest as a model payload. A rejected payload exits 2
// after reporting which check died — detector output is input, not verdict.
func runIngestSast(root string, c *state.Campaign, a ingestArgs, r *Runner) error {
	if a.jsonFile == "" {
		return t14ExitErr(2, "--from requires --json-file (the tool's JSON output)\n")
	}
	raw, err := readArgFile(a.jsonFile)
	if err != nil {
		return t14ExitErr(2, "%s\n", err)
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		return t14ExitErr(2, "slither JSON unparsable: %s\n", err)
	}
	payloads, err := slither.ToPayloads(doc)
	if err != nil {
		return t14ExitErr(2, "%s\n", err)
	}
	orch := orchestrator.New(c)
	var created []string
	for _, p := range payloads {
		f, err := orch.Ingest(p, orchestrator.IngestOpts{
			Trajectory: a.trajectory, Stage: orDefault(a.stage, "sast-slither")})
		if err != nil {
			printIngestFailure(r, err)
			return t14ExitErr(2, "")
		}
		created = append(created, objStr(f, "finding_id"))
	}
	fmt.Fprintf(r.Out, "slither ingest: %d hypotheses created\n", len(created))
	for _, id := range created {
		fmt.Fprintf(r.Out, "  %s\n", id)
	}
	return nil
}
```
(`readArgFile` = the existing `t14ReadPayload` reader minus its payload validation — reuse it reading the file and returning bytes; if it returns a parsed Value directly, add a tiny `os.ReadFile` local instead. `orDefault` exists in evalstore, not cli — write `if a.stage == "" { stage = "sast-slither" }` explicitly. Match reality at edit time; semantics fixed: stage defaults to `sast-slither`.)

  d. Usage/help: add to BOTH `t14IngestUsage` and `t14IngestHelp` the line `--from {slither}   tool-output ingest (G1); requires --json-file`, keeping argparse's exact layout (options block order = declaration order).

- [ ] **Step 4: Run tests green**

```bash
go test ./internal/cli/ -run 'TestIngest' -count=1
go run ./cmd/webv2 ingest --help | grep -- '--from'
```

- [ ] **Step 5: Commit**

```bash
git add internal/cli/cmd_ingest.go internal/cli/cmd_ingest_test.go
git commit -m "feat(G1): ingest --from slither — detector findings ride the hypothesis path"
```

---

### Task 4: G1 — corroboration link on `same` resolution + acceptance factor

**Files:**
- Modify: `internal/dedup/dedup.go` (`ResolveCandidate`, `verdict == "same"` region ~L591)
- Modify: `internal/dedup/dedup_test.go`
- Modify: `internal/risk/acceptance.go`
- Modify: `internal/risk/acceptance_test.go`

**Interfaces:**
- Consumes: `getDeep(f, "provenance", "sast_tools")` (dedup.go already has `getDeep`), `validation.SetOrAppend`, the sides loop in `ResolveCandidate`.
- Produces: `dedup_meta.corroborated_by = "<tool finding id>"` (string — legal under the dedup_meta `additionalProperties: string` schema) recorded on the non-tool side of a `same` pair when EXACTLY ONE side carries non-empty `provenance.sast_tools`; event `dedup.corroborated` {by, of}. New acceptance constant `acceptanceCorroborationBonus = 0.5`, applied iff `dedup_meta.corroborated_by` is a non-empty string. `AcceptanceEntry.Corroborated bool` (additive struct field; existing constructors leave it false).

- [ ] **Step 1: Failing dedup test** — follow the file's existing ResolveCandidate test setup (same campaign/finding helpers). First define the five tiny shared helpers the tests below use, once, at the top of the test additions: `idOf(v)` (returns `objStr(v, "finding_id")`), `reloadID(t, c, id)` (wraps `findings.LoadFinding`, `t.Fatal` on error), `attachTools(t, c, f, tool)` (loads the finding, `SetOrAppend`s `provenance.sast_tools = [tool]`, saves, returns the saved value), and `setupPair` / `setupPairUntooled` (same construction, the former with one SAST side, the latter with none — build two findings, run the dedup sweep or hand-set `dedup.possible_duplicate_of` on both via `findings.SaveFinding`). Then add:

```go
func TestResolveSameRecordsCorroboration(t *testing.T) {
	c, f, toolF := setupPair(t) // f model-flagged (no sast_tools), toolF has provenance.sast_tools
	if _, err := ResolveCandidate(c, objStr(f, "finding_id"), objStr(toolF, "finding_id"),
		"same", "", "operator"); err != nil {
		t.Fatal(err)
	}
	// `same` merges the younger side: reload BOTH ids; the corroboration
	// record must exist on whichever survives (the non-tool side).
	reloaded := reloadID(t, c, idOf(f))
	corr := getDeep(reloaded, "dedup_meta", "corroborated_by")
	if corr.Kind != validation.Str || corr.S != objStr(toolF, "finding_id") {
		t.Fatalf("corroborated_by not recorded on the model side: %s", corr)
	}
}

// setupPair mirrors this file's existing ResolveCandidate `same` test
// setup (sweep or hand-written possible_duplicate_of on both sides via
// findings.SaveFinding); the ONLY additions: the tool side carries
// provenance.sast_tools = ["slither:reentrancy-eth"], the model side has
// no provenance object at all.

func TestResolveToolVsToolRecordsNothing(t *testing.T) {
	c, a, b := setupPair(t)
	a = attachTools(t, c, a, "slither:reentrancy-eth") // both sides SAST
	b = attachTools(t, c, b, "slither:unchecked-transfer")
	if _, err := ResolveCandidate(c, idOf(a), idOf(b), "same", "", "operator"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []validation.Value{reloadID(t, c, idOf(a)), reloadID(t, c, idOf(b))} {
		if getDeep(f, "dedup_meta", "corroborated_by").Kind == validation.Str {
			t.Fatal("tool-vs-tool is not independent corroboration")
		}
	}
}

func TestResolveDistinctRecordsNothing(t *testing.T) {
	c, f, toolF := setupPair(t)
	if _, err := ResolveCandidate(c, idOf(f), idOf(toolF),
		"distinct", "", "operator"); err != nil {
		t.Fatal(err)
	}
	if getDeep(reloadID(t, c, idOf(f)), "dedup_meta", "corroborated_by").Kind ==
		validation.Str {
		t.Fatal("a distinct verdict records no corroboration")
	}
}

func TestResolveSameWithoutAnyToolsRecordsNothing(t *testing.T) {
	c, f, other := setupPairUntooled(t) // neither side has provenance.sast_tools
	if _, err := ResolveCandidate(c, idOf(f), idOf(other), "same", "", "operator"); err != nil {
		t.Fatal(err)
	}
	if getDeep(reloadID(t, c, idOf(f)), "dedup_meta", "corroborated_by").Kind ==
		validation.Str {
		t.Fatal("no tool side -> no corroboration")
	}
}
```

- [ ] **Step 2: Verify failure** — `go test ./internal/dedup/ -run Corroboration -count=1` → FAIL (no `corroborated_by`).

- [ ] **Step 3: Implement in `ResolveCandidate`, inside the `if verdict == "same"` block, BEFORE `mergeYounger`** (so the merge moves the record with the survivor):

```go
	if verdict == "same" {
		// G1 corroboration law: exactly one side SAST-flagged => the model
		// side is corroborated by the tool finding. Same-engine pairs never
		// corroborate; the operator resolved the SAME-ROOT-CAUSE link, we
		// only record what that resolution mechanically implies.
		sides := []struct{ self, other validation.Value }{
			{f, other}, {other, f},
		}
		for _, s := range sides {
			selfTools := valsOf(getDeep(s.self, "provenance", "sast_tools"))
			otherTools := valsOf(getDeep(s.other, "provenance", "sast_tools"))
			if len(selfTools) == 0 && len(otherTools) > 0 {
				corroborated := setDeep(s.self,
					validation.VStr(objStr(s.other, "finding_id")),
					"dedup_meta", "corroborated_by")
				if err := findings.SaveFinding(campaign, &corroborated); err != nil {
					return validation.VNull(), err
				}
				data := validation.VObj(
					kv("of", validation.VStr(objStr(s.other, "finding_id"))))
				fid := objStr(s.self, "finding_id")
				if _, err := campaign.Log("dedup.corroborated", &fid, &data); err != nil {
					return validation.VNull(), err
				}
			}
		}
		if err := mergeYounger(campaign, f, ofFindingID); err != nil {
			return validation.VNull(), err
		}
	}
```
`valsOf` may not exist in dedup.go — add the same 5-line local helper (pattern already duplicated across packages; this repo accepts the duplication). Note the return value: `f` was captured before re-save — return the latest side that holds the record: re-`LoadFinding` `findingID` just before `return f, nil`.

- [ ] **Step 4: Failing acceptance test** in `acceptance_test.go`:

```go
func TestCorroborationBonus(t *testing.T) {
	base := accFinding(func(f *validation.Value) {
		setCritic(f, "confirmed")
	})
	s0, _ := AcceptanceScore(base)
	withCorr := accFinding(func(f *validation.Value) {
		setCritic(f, "confirmed")
		*f = withKeyR(*f, "dedup_meta", validation.VObj(
			kvR("corroborated_by", validation.VStr("F-9"))))
	})
	s1, _ := AcceptanceScore(withCorr)
	if s1-s0 != 0.5 {
		t.Fatalf("corroboration must add exactly 0.5: %v -> %v", s0, s1)
	}
	// non-string garbage never fires (schema prevents it; the score is still
	// the last line of defense):
	junk := accFinding(func(f *validation.Value) {
		setCritic(f, "confirmed")
		*f = withKeyR(*f, "dedup_meta", validation.VObj(
			kvR("corroborated_by", validation.VBool(true))))
	})
	if s, _ := AcceptanceScore(junk); s != s0 {
		t.Fatal("only a string corroborated_by counts")
	}
}
```

- [ ] **Step 5: Implement in `acceptance.go`** — after the demotions block, before reversibility:

```go
	// corroboration (G1): operator-resolved same-root-cause pair where the
	// partner is SAST-flagged; recorded by dedup.ResolveCandidate, consumed
	// here. Absent => 0, so existing bytes never move.
	if cb := objAt(orObj(objAt(finding, "dedup_meta")), "corroborated_by"); cb.Kind ==
		validation.Str && cb.S != "" {
		score += acceptanceCorroborationBonus
		e.Corroborated = true
	}
```
plus `const acceptanceCorroborationBonus = 0.5`, `Corroborated bool` on `AcceptanceEntry`, and a new line in the file-header formula comment: `+ wCorroboration(dedup_meta.corroborated_by) = +0.5 (G1)`.

- [ ] **Step 6: Green + commit**

```bash
go test ./internal/dedup/ ./internal/risk/ -count=1
scripts/golden.sh   # byte discipline: no fixture carries sast_tools, so no move
git add -A && git commit -m "feat(G1): corroboration — resolved same pairs with one SAST side record corroborated_by (+0.5 acceptance)"
```

---

### Task 5: G6 — `verification.triager_outlook`: schema + transition + `verdict --outlook`

**Files:**
- Modify: `assets/schema/finding.schema.json` (`verification` properties)
- Modify: `internal/findings/transitions.go`
- Modify: `internal/findings/transitions_test.go` (or the file holding `SetCriticVerdict` tests)
- Modify: `internal/cli/cmd_verdict.go`
- Modify: `internal/cli/cmd_scope.go` (the registry `line:` for `verdict`)
- Modify: `assets/runbook/RUNBOOK.md` (cheat-sheet line, if it quotes the verdict line)
- Modify: `internal/cli/testdata/p3_args_golden.json` (usage-block pin)
- Regenerate: `assets/testdata/asset_manifest.json`

**Interfaces:**
- Consumes: `SetCriticVerdict` (transitions.go:538, the template).
- Produces: `func SetTriagerOutlook(campaign *state.Campaign, findingID, outcome, reason string) (validation.Value, error)` — enum `likely|uncertain|unlikely`, reason >= 15 runes post-strip (same law as shield adjudication); writes `verification.triager_outlook = {outcome, reason}`; event `finding.triager_outlook` {outcome}. CLI: `verdict ... [--outlook O --outlook-reason R]` (both-or-neither; never replaces the verdict call).

- [ ] **Step 1: Failing transitions test** (pattern-match the `SetCriticVerdict`/`SetShieldAdjudication` tests in the package):

```go
func TestSetTriagerOutlook(t *testing.T) {
	c, fid := fixtureWithFinding(t) // existing helper style
	f, err := SetTriagerOutlook(c, fid, "likely",
		"on-chain fork PoC with drain terminal; policy pays critical")
	if err != nil {
		t.Fatal(err)
	}
	o := objAt(objAt(f, "verification"), "triager_outlook")
	if objStr(o, "outcome") != "likely" {
		t.Fatal("outcome not recorded")
	}
	if _, err := SetTriagerOutlook(c, fid, "maybe", "short"); err == nil {
		t.Fatal("invalid enum must be rejected")
	}
	if _, err := SetTriagerOutlook(c, fid, "likely", "too short"); err == nil {
		t.Fatal("reason under 15 runes must be rejected")
	}
	// idempotent replace, not append:
	f2, err := SetTriagerOutlook(c, fid, "uncertain",
		"policy excludes the token's chain; acceptance unclear")
	if err != nil {
		t.Fatal(err)
	}
	if objStr(objAt(objAt(f2, "verification"), "triager_outlook"), "outcome") != "uncertain" {
		t.Fatal("second call must replace the first")
	}
}
```

- [ ] **Step 2: Verify failure** — `go test ./internal/findings/ -run TestSetTriagerOutlook -count=1` → undefined.

- [ ] **Step 3: Schema edit.** In `assets/schema/finding.schema.json`, `properties.verification.properties`, after `critic_verdict` (order in JSON files is cosmetic; keep it next to the critic field):

```json
"triager_outlook": {
  "type": "object",
  "additionalProperties": false,
  "required": ["outcome", "reason"],
  "properties": {
    "outcome": {"type": "string", "enum": ["likely", "uncertain", "unlikely"]},
    "reason": {"type": "string", "minLength": 15}
  },
  "description": "G6: the critic's payment-likelihood call under the campaign's live bounty policy — separate from truth (critic_verdict) and separate from policy (bounty.accepted_risk)"
}
```

- [ ] **Step 4: Transition.** In `transitions.go`, after `SetCriticVerdict`:

```go
// SetTriagerOutlook is the G6 companion of set_critic_verdict: record the
// critic's acceptance-likelihood call — WILL A TRIAGER ACCEPT AND PAY THIS —
// kept structurally separate from critic_verdict (truth) and
// bounty.accepted_risk (policy). Absent field = no call = no score effect.
func SetTriagerOutlook(campaign *state.Campaign, findingID, outcome,
	reason string) (validation.Value, error) {
	switch outcome {
	case "likely", "uncertain", "unlikely":
	default:
		return validation.VNull(), fmt.Errorf("invalid triager outlook %s "+
			"(choose: likely, uncertain, unlikely)", validation.PyReprStr(outcome))
	}
	stripped := strings.TrimSpace(reason)
	if len([]rune(stripped)) < 15 {
		return validation.VNull(), fmt.Errorf("triager outlook reasoning must " +
			"be substantive (>= 15 chars) — 'probably fine' is not a call")
	}
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	ver := asDict(objAt(finding, "verification"))
	ver.O = validation.SetOrAppend(ver.O, "triager_outlook", validation.VObj(
		validation.KV{K: "outcome", V: validation.VStr(outcome)},
		validation.KV{K: "reason", V: validation.VStr(stripped)},
	))
	finding.O = validation.SetOrAppend(finding.O, "verification", ver)
	if err := SaveFinding(campaign, &finding); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(validation.KV{K: "outcome", V: validation.VStr(outcome)})
	if _, err := campaign.Log("finding.triager_outlook", &findingID, &data); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}
```
(`strings` import if the file lacks it.)

- [ ] **Step 5: CLI.** In `cmd_verdict.go`: `var triagerOutlooks = []string{"likely", "uncertain", "unlikely"}`; parse `--outlook`/`--outlook-reason` (both forms, same case style as `--verdict`/`--reason`); XOR error:

```go
	if (outlook == "") != (outlookReason == "") {
		return r.fail(root, requiredErrf("verdict", "--outlook", "--outlook-reason"))
	}
```
Invalid choice mirrors the `--verdict` guard's message shape (`argument --outlook: invalid choice: '...' (choose from 'likely', 'uncertain', 'unlikely')`). After the existing `SetCriticVerdict` call:

```go
	if outlook != "" {
		if _, err := findings.SetTriagerOutlook(c, pos[1], outlook, outlookReason); err != nil {
			return r.withErr(root, func() error { return err })
		}
		fmt.Fprintf(r.Out, "  triager outlook: %s — %s\n", outlook, outlookReason)
	}
```
Update BOTH usage consts (`verdict`'s), the `line:` entry in `internal/cli/cmd_scope.go` to `verdict <campaign> <finding> --verdict V --reason R [--outlook O --outlook-reason R]`, and if `assets/runbook/RUNBOOK.md`'s cheat sheet quotes the old line, update it in the same edit.

- [ ] **Step 6: Re-pin + green**

```bash
python3 scripts/sync-asset-manifest.py
go test ./internal/findings/ ./internal/cli/ -run 'Triager|Verdict' -count=1
go test ./internal/cli/ -count=1   # P3 golden: if it fails on the verdict usage block, update internal/cli/testdata/p3_args_golden.json with the new block verbatim from --help output
```

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(G6): verdict --outlook records the critic's payment-likelihood call (schema + transition + CLI)"
```

---

### Task 6: G6 — outlook factor in the acceptance score

**Files:**
- Modify: `internal/risk/acceptance.go`
- Modify: `internal/risk/acceptance_test.go`

**Interfaces:**
- Consumes: `verification.triager_outlook` (Task 5).
- Produces: score nudge `likely +0.5 / uncertain 0 / unlikely -0.5`, presence-gated (absent field = 0 = existing bytes), never disqualifying (outlook is a likelihood call, not a refutation).

- [ ] **Step 1: Failing test:**

```go
func TestTriagerOutlookFactor(t *testing.T) {
	base := accFinding(func(f *validation.Value) { setCritic(f, "confirmed") })
	s0, _ := AcceptanceScore(base)
	setOutlook := func(f *validation.Value, outcome string) {
		*f = withKeyR(*f, "verification", validation.VObj(
			kvR("critic_verdict", validation.VStr("confirmed")),
			kvR("triager_outlook", validation.VObj(
				kvR("outcome", validation.VStr(outcome)),
				kvR("reason", validation.VStr("policy pays critical; fork PoC"))))))
	}
	likely := accFinding(func(f *validation.Value) { setOutlook(f, "likely") })
	unlikely := accFinding(func(f *validation.Value) { setOutlook(f, "unlikely") })
	uncertain := accFinding(func(f *validation.Value) { setOutlook(f, "uncertain") })
	if s, _ := AcceptanceScore(likely); s-s0 != 0.5 {
		t.Fatalf("likely: +%v", s-s0)
	}
	if s, _ := AcceptanceScore(unlikely); s0-s != 0.5 {
		t.Fatalf("unlikely: %v", s-s0)
	}
	if s, _ := AcceptanceScore(uncertain); s != s0 {
		t.Fatal("uncertain must be score-neutral")
	}
	// Outlook NEVER disqualifies:
	if _, d := AcceptanceScore(unlikely); d {
		t.Fatal("outlook is not a refutation")
	}
	// clamp at 0 still holds with unlikely on a bare hypothesis
	bare := accFinding(func(f *validation.Value) { setOutlook(f, "unlikely") })
	if s, _ := AcceptanceScore(bare); s != 0 {
		t.Fatalf("clamped: %v", s)
	}
}
```

- [ ] **Step 2: Verify failure** (`likely: +0`), then **implement** — after the critic block in `Acceptance`:

```go
	// triager outlook (G6): likelihood call under the live policy, bounded
	// and never disqualifying — only the critic disproves.
	if o := objAt(orObj(objAt(finding, "verification")), "triager_outlook"); o.Kind ==
		validation.Obj {
		if w, ok := wAcceptanceOutlook[orStr(objAt(o, "outcome"))]; ok {
			score += w
		}
	}
```
plus:
```go
// wAcceptanceOutlook is the G6 nudge table: bounded, symmetric, and absent
// outcomes contribute nothing (same posture as reversibility).
var wAcceptanceOutlook = map[string]float64{"likely": 0.5, "uncertain": 0.0, "unlikely": -0.5}
```
and extend the file-header formula comment: `+ outlook(verification.triager_outlook) = ±0.5 (G6)` next to the G1 line from Task 4.

- [ ] **Step 3: Green + golden + commit**

```bash
go test ./internal/risk/ -count=1 && scripts/golden.sh
git add -A && git commit -m "feat(G6): acceptance score consumes the triager outlook (±0.5, presence-gated)"
```

---

### Task 7: G1 — tool-flags advisory block in `brief` (computed, never stored)

**Files:**
- Modify: `internal/briefing/briefing.go` (+ `BuildBrief` wiring)
- Modify: `internal/briefing/briefing_test.go`

**Interfaces:**
- Consumes: campaign findings with `provenance.sast_tools` (Task 3) and `verification.critic_verdict` (existing).
- Produces: `func ChToolFlags(campaign *state.Campaign, problems *[]string) validation.Value` — mirrors the `ChAmplifiers` signature; renders NOTHING (absent key, zero byte move) when no finding carries `provenance.sast_tools`. When present: `{total, by_verdict: {confirmed, disproved, pending, possible, duplicate, out_of_scope, informational}, corroborated: [finding ids sorted]}` — the per-detector FP ledger computed at view time; no new store, sidecar law untouched.

- [ ] **Step 1: Failing test** (follow the package's existing Ch* test pattern — fixture campaign + findings):

```go
func TestChToolFlagsPresenceGated(t *testing.T) {
	c := fixtureCampaign(t) // existing briefing test helper
	mk := func(id string, tools []string, verdict string) validation.Value {
		f := validation.VObj(kvB("finding_id", validation.VStr(id)))
		if len(tools) > 0 {
			f.O = append(f.O, kvB("provenance", validation.VObj(kvB("sast_tools",
				validation.VArr(vstrs(tools)...)))))
		}
		if verdict != "" {
			f.O = append(f.O, kvB("verification", validation.VObj(kvB("critic_verdict",
				validation.VStr(verdict)))))
		}
		return f
	}
	// no tools -> Null (renders nothing):
	writeFindings(t, c, mk("F-a", nil, "confirmed"))
	if v := ChToolFlags(c, &[]string{}); v.Kind != validation.Null {
		t.Fatal("must be absent without tool findings")
	}
	writeFindings(t, c,
		mk("F-b", []string{"slither:reentrancy-eth"}, "confirmed"),
		mk("F-c", []string{"slither:unchecked-transfer"}, "disproved"),
		mk("F-d", []string{"slither:tx-origin"}, "pending"))
	v := ChToolFlags(c, &[]string{})
	if objAt(v, "total").I != 3 {
		t.Fatalf("total: %v", objAt(v, "total"))
	}
	bv := objAt(v, "by_verdict")
	if objAt(bv, "confirmed").I != 1 || objAt(bv, "disproved").I != 1 ||
		objAt(bv, "pending").I != 1 {
		t.Fatalf("verdict census: %v", bv)
	}
}
```
(`kvB/vstrs/writeFindings`: reuse the briefing tests' existing builders; if the package saves findings through `findings.SaveFinding`, use that — check `briefing_test.go` and copy its mechanism exactly.)

- [ ] **Step 2: Verify failure** — undefined: ChToolFlags.

- [ ] **Step 3: Implement** `ChToolFlags` (pure scan over `findings.LoadAllFindings(campaign)`; deterministic key order in `by_verdict` built by iterating the fixed verdict list, never a map; `corroborated` collected from `dedup_meta.corroborated_by` and sorted). Wire into `BuildBrief` exactly like `ChAmplifiers` is wired (same presence-gate idiom: attach the section only when non-null), and add the plain-text block to the brief formatter under a `TOOL FLAGS (SAST hypotheses)` heading listing the census + "flags: N, corroborated: M".

- [ ] **Step 4: Green — the whole package + golden**

```bash
go test ./internal/briefing/ -count=1
go test ./internal/cli/ -run Brief -count=1
scripts/golden.sh   # golden campaigns have no sast_tools findings -> zero move
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(G1): brief TOOL FLAGS block — detector census computed from findings, presence-gated"
```

---

### Task 8: G6 — critic prompt rubric (data-only) + full-gate close-out

**Files:**
- Modify: `assets/prompts/48_critic_system.md`
- Modify: `docs/IMPROVEMENTS.md` (Wave G statuses)
- Regenerate: `assets/testdata/asset_manifest.json`

**Interfaces:**
- Consumes: the `verdict --outlook` command surface (Task 5) — the prompt documents a mechanism that must already exist, so this task lands last.
- Produces: the critic role's standing instruction to record the outlook; no code.

- [ ] **Step 1: Append the rubric section** to `assets/prompts/48_critic_system.md`:

```markdown

## The payment question (G6): triager outlook

After you record your verdict, you MAY also record whether a bounty triager
would accept and PAY this finding under THIS campaign's policy. Read the live
policy first (`webv2 scope <campaign> --show` and the brief) — the rubric is
the program's own words, never your imagination:

- `likely` — matches policy scope AND a critical/high minimum payout clearly
  covers the demonstrated loss; no exclusion or accepted-risk pattern hits.
- `uncertain` — real, but payout hinges on a judgment the program has not
  pre-committed to (novel class, borderline TVL math, unpriced impact).
- `unlikely` — policy excludes or documents as accepted risk, below the
  minimum payout, duplicate of a known issue, or the "impact" needs a
  chain the program treats as out of scope.

Record it beside your verdict:

    webv2 verdict <campaign> <finding> --verdict V --reason R \
        --outlook {likely|uncertain|unlikely} --outlook-reason "policy cite"

Rules: the outlook NEVER changes your verdict and is not a refutation — it is
a prediction about a third party. Cite the policy line, not a vibe. If the
campaign has no bounty policy recorded, do not speculate: skip the outlook.
```

- [ ] **Step 2: Re-pin, verify prompt packs and the full Go surface**

```bash
python3 scripts/sync-asset-manifest.py
go test ./assets/ -count=1
go vet ./... && go test ./... -count=1
scripts/golden.sh
scripts/runbook-walkthrough.sh
scripts/verify-full.sh          # if the docker daemon is unavailable, note it
                                # in the commit message; do NOT skip the rest
go run ./cmd/webv2 selftest --full
```
Expected: all green. Any golden byte move is a REGRESSION of this tranche — stop and report, do not "fix" the golden.

- [ ] **Step 3: Update `docs/IMPROVEMENTS.md`** — in the Wave G TOC table, change G1, G6, G7 rows to `LANDED (tranche 1, 2026-09-10)`; under the header status line, replace the sentence to reflect tranche 1 landed, tranches 2–4 (G2/G3, G4, G5, G8–G12) still proposed. In G1's Design, mark the deferred sub-parts explicitly: dataset vocabulary additions, `--backtest`, and any automatic corroboration detection REMAIN deferred — corroboration is recorded only on operator-resolved pairs (per this tranche).

- [ ] **Step 4: Commit**

```bash
git add assets/prompts/48_critic_system.md assets/testdata/asset_manifest.json docs/IMPROVEMENTS.md
git commit -m "feat(G6): critic payment-rubric prompt section; Wave G tranche 1 closed (G1+G6+G7 landed)"
```

---

## Self-review notes (done at authoring)

- **Spec coverage:** G7 (Task 1 doc — the asset-side validator lands with G2's `class_weights.json`, by design in tranche 2); G1 (adapter T2, campaign path T3, corroboration T4, ledger-as-view T7; the dataset-registry vocabulary + `--backtest` explicitly DEFERRED — tool flags have no ground-truth `outcome`, so the eval-case lane stays empty until G3 exists); G6 (T5 schema/CLI, T6 score, T8 prompt).
- **Deferred by plan, not accident:** the policy-flag graduation from the Wave G design survives to G3's backtest — presence-gated writes are this tranche's whole default story.
- **Pins to keep an eye on:** `internal/cli/testdata/p3_args_golden.json` (usage-block pins for `ingest` and `verdict` — Tasks 3 and 5 both touch it); `assets/testdata/asset_manifest.json` (Tasks 1, 5, 8 each regenerate it — never hand-edit).
- **Type consistency:** `corroborated_by` is a string (matches `dedup_meta` `additionalProperties: string`); `triager_outlook.reason` minLength 15 matches the transition's rune check; the outlook enum is defined once in the schema and twice mirrored verbatim in Go (`triagerOutlooks` CLI list, `wAcceptanceOutlook` keys — add a test-asserted `triagerOutlookChoices()` accessor in transitions.go so all three read from one source if a fourth consumer appears).

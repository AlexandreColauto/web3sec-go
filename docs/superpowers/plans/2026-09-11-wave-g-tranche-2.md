# Wave G Tranche 2 — Measurement, Calibration, Defense Layers, Proof Rungs — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land Wave G tranche 2 of `docs/IMPROVEMENTS.md` in order: G4 (gold-eval expansion — make recall/precision claims measurable with Wilson CIs), G2 (per-class three-weight table as data), G3 (acceptance priors from adjudicated outcomes + `--backtest`), G5 (two-layer defense matcher: soundness `mitigation_present` vs policy `accepted_risk`), G8 (invariants → Halmos/forge harnesses with a `PROVEN-BOUNDED` rung).

**Architecture:** Everything rides existing rails: the eval-case store (`internal/evalstore`, schema `evaluation_case.schema.json`), the embedded-asset pack pattern (`assets/*.go` FS + `scripts/sync-asset-manifest.py` + `TestAssetPackManifest`), the corpus surface (`internal/corpus`), the A3 score (`internal/risk/acceptance.go`), the ackscan post-ingest hook (`internal/findings/ackscan.go` + `ingest.go:382`), the bounty gate check13 (`internal/bounty/bounty.go:1201`), the sandbox exec path (`internal/sandbox`, docker profiles), and the audit-section registry (`internal/audit/sections/register.go`). New score influence is policy-gated OFF by default; new report sections are presence-gated so campaigns without an eval link keep byte-identical output.

**Tech Stack:** Go 1.26.2, stdlib only. Pure-math Wilson interval in a new leaf package. Fixture data is JSON + tiny Solidity, embedded as asset packs and manifest-pinned. Tests: standard `testing`; docker-gated tests follow the existing skip-when-absent pattern (`internal/reproduction` docker e2e).

## Global Constraints

- No new dependencies; no new CLI verbs (flags on existing verbs only). Surface budget: G3's backtest attaches to `corpus-surface` (the existing eval-store reader).
- Determinism (principle 4): every number computed from stored data; no wall-clock, no map order in output. Floats printed with explicit formats; CI percentages one decimal, en-dash separator `–` (U+2013).
- Additive + presence-gated (principle 1): untouched campaigns render byte-identical; the ONLY sanctioned byte movers in this tranche are (a) G2's corpus weight-table swap, which ships with an equal-valued initial table so golden MUST NOT move, and (b) none other. If any golden fixture byte moves in any other task, that is a regression — stop and report BLOCKED; never edit a golden fixture to "fix" a red golden.
- Fail-open on judgment, fail-closed on money (principle 2): priors inform, never auto-dismiss; `wPrior` ships gated OFF by `bounty_policy.acceptance_priors` (default false); only a `--backtest` win on held-out data may flip the default (a later tranche decision, NOT this plan).
- Soundness and policy never mix (G5 law): `mitigscan` may write ONLY `dedup_meta.mitigation_present`; check13 may write ONLY `bounty.accepted_risk`; enforced by a non-interference test, and the report renders them under different bullets.
- Every claim baked into this tranche's data files carries G7 provenance rows `{source_url, checked_date, primary}`; secondary-source figures may seed NOTHING (validator-enforced).
- Every `assets/` edit requires `python3 scripts/sync-asset-manifest.py` before tests/commit; never hand-edit `assets/testdata/asset_manifest.json`.
- Schema enum edits MUST be pinned in `t14FindingLegend` (walk order) — `TestIngestExampleLegendMatchesSchema` fails the cli suite otherwise. (Eval-section additions with NO new finding-schema enum do not touch the legend; tasks say which apply.)
- Sandbox: run every go command with `GOCACHE=$PWD/.gocache` (default `~/.cache/go-build` is read-only here). Search with the `rg` shell command, never `grep`. The repo owner may commit to `main` concurrently: never `git add -A`; stage only task files; `git status` before each commit.
- Gates per task: focused tests, then package suite, then `scripts/golden.sh` untouched-green, before commit. Task 19 re-runs the full close-out (`go vet ./...`, `go test ./... -count=1`, `scripts/golden.sh`, `scripts/runbook-walkthrough.sh`, `scripts/verify-full.sh`, `go run ./cmd/webv2 selftest --full`).

## File Structure (tranche-wide map)

- Create: `internal/wilson/wilson.go` (+ test) — pure Wilson score interval, leaf package, consumed by evalscore, calibration, backtest.
- Create: `assets/evalsuite/cases.json`, `assets/evalsuite/src/*.sol` — G4 fixture pack (embedded, manifest-pinned); `assets/evalsuite.go` — pack FS.
- Create: `internal/evalscore/evalscore.go` (+ test) — Score(campaign findings, suite cases): hits/misses/FP + Wilson renderers.
- Create: `internal/audit/sections/eval.go` (+ test) — presence-gated `eval` audit section.
- Create: `assets/taxonomy/class_weights.json` + `assets/schema/class_weights.schema.json` + `assets/taxonomy.go` — G2 data table (embedded pack).
- Modify: `internal/corpus/corpus.go` (read `search` column), `internal/floors/floors.go` + `internal/risk` (refuse `severity_default` as input), `internal/taxonomy` (drift test consumer).
- Create: `internal/datasets/c4audit/`, `internal/datasets/sherlock/`, `internal/datasets/immunefi/` — G3 loaders (defihacklabs template).
- Create: `internal/risk/calibration.go` (+ test) — `AcceptancePrior(class)` with Wilson CI + n<10 global fallback that says so.
- Modify: `assets/schema/bounty_policy.schema.json` (`acceptance_priors` bool, `reference_url` on accepted_risks), `internal/risk/acceptance.go` (gated `wPrior`), `internal/cli/cmd_corpus_surface.go` (`--backtest`).
- Create: `internal/findings/mitigscan.go` (+ test) — G5 soundness scanner (ackscan sibling).
- Modify: `internal/findings/ingest.go` (hook), `assets/schema/finding.schema.json` (`dedup_meta.mitigation_present` object property, `verification.harness`), `internal/report/report.go` (mitigation bullet beside ack, under the CORRECTNESS bullet group; never the accepted-risk bullet), `internal/risk/acceptance.go` (mitigation demotion).
- Create: `internal/harness/harness.go` (+ test) — G8 deterministic scaffold generator + body-region validator.
- Modify: `internal/sandbox/profiles.go` + `exec.go` (halmos/forge-fuzz recipes + tool probe), `internal/cli/cmd_verify.go` (`--scaffold`), `internal/audit` ladder rendering (harness rungs, presence-gated), `internal/learning` (falsified-claim negative memory reuse).

## Task Index

| # | Area | Deliverable |
|---|---|---|
| 1 | G4 | `internal/wilson` leaf package (pinned CI math) |
| 2 | G4 | evalsuite asset pack: 16 gold cases (≥8 classes) + clean control + validator |
| 3 | G4 | `internal/evalscore`: hits/misses/FP join + CI renderer (2/2 pinned) |
| 4 | G4 | presence-gated `eval` audit section + zero-drift proof on golden |
| 5 | G2 | `class_weights.json` + schema + embed + drift & provenance validators |
| 6 | G2 | corpus consumes `search` column (byte-identical swap); floors/risk refuse `severity_default` |
| 7 | G3 | `internal/risk/calibration.go`: `AcceptancePrior` + fallback-says-so + pinned Wilson table |
| 8 | G3 | c4audit loader + fixtures |
| 9 | G3 | sherlock loader + fixtures |
| 10 | G3 | immunefi-resolved loader + registry vocabulary |
| 11 | G3 | `wPrior` beside outlook, policy-gated OFF; byte check; brief/report per-class prior (gated) |
| 12 | G3 | `corpus-surface --backtest`: top-K precision vs outcomes, deterministic |
| 13 | G5 | `mitigscan.go` scanner + hook + per-pattern fixtures |
| 14 | G5 | mitigation demotion (−1.0) + absent-field byte check |
| 15 | G5 | non-interference test + report subsection separation + `reference_url` policy add |
| 16 | G8 | scaffold generator (halmos/fuzz templates, body-region validator, compile fixture) |
| 17 | G8 | sandbox recipes + `verify --scaffold` + toolchain probe |
| 18 | G8 | outcome mapping → `verification.harness` rung field + timeout→inconclusive + negative memory |
| 19 | close | runbook + IMPROVEMENTS statuses + full gates |

---

### Task 1: `internal/wilson` — the CI leaf package (G4 foundation)

**Files:**
- Create: `internal/wilson/wilson.go`
- Test: `internal/wilson/wilson_test.go`

**Interfaces:**
- Consumes: nothing (leaf package, stdlib `math` only).
- Produces: `func Interval(k, n int) (lo, hi float64)` — Wilson score interval at z=1.959963984540054 (95%); `n<=0` returns `(0,0)` with `NaN`-free guarantee documented; `func Format(k, n int, noun string) string` — renders `"<noun>: k/n (95% CI L–H%)"` with one-decimal percents and en-dash U+2013. Consumed verbatim by Tasks 3, 7, 12.

- [ ] **Step 1: Failing test** — `internal/wilson/wilson_test.go`. Pinned table values below were computed independently (python `math`, same z); do not "re-derive" them:

```go
package wilson

import "testing"

func TestIntervalPinnedTable(t *testing.T) {
	cases := []struct {
		k, n   int
		lo, hi float64
	}{
		{2, 2, 0.342380, 1.0},        // the 2-gold case: NOT 20% — the
		{2, 3, 0.207660, 0.938508},   // doc's illustrative "20–100" belongs
		{15, 16, 0.716713, 0.988881}, // to 2/3, not 2/2 (G7 erratum, Task 19)
		{0, 1, 0.0, 0.793451},
		{8, 10, 0.490162, 0.943318},
	}
	for _, c := range cases {
		lo, hi := Interval(c.k, c.n)
		if d := lo - c.lo; d > 1e-5 || d < -1e-5 {
			t.Fatalf("Interval(%d,%d) lo = %v, want %v", c.k, c.n, lo, c.lo)
		}
		if d := hi - c.hi; d > 1e-5 || d < -1e-5 {
			t.Fatalf("Interval(%d,%d) hi = %v, want %v", c.k, c.n, hi, c.hi)
		}
	}
}

func TestIntervalEdges(t *testing.T) {
	if lo, hi := Interval(0, 0); lo != 0 || hi != 0 {
		t.Fatalf("n=0 must be (0,0), got (%v,%v)", lo, hi)
	}
	if lo, hi := Interval(-1, 5); lo != 0 || hi != 0 {
		t.Fatal("k<0 must be (0,0)")
	}
	if lo, hi := Interval(6, 5); lo != 0 || hi != 0 {
		t.Fatal("k>n must be (0,0) — nonsense input, refuse loudly-by-zero")
	}
}

func TestFormat(t *testing.T) {
	got := Format(2, 2, "recall")
	want := "recall: 2/2 (95% CI 34.2–100.0%)" // en-dash, one decimal
	if got != want {
		t.Fatalf("Format = %q, want %q", got, want)
	}
	if got := Format(0, 0, "precision"); got != "precision: 0/0 (95% CI n/a)" {
		t.Fatalf("empty n must render n/a, got %q", got)
	}
}
```

- [ ] **Step 2: Verify failure** — `GOCACHE=$PWD/.gocache go test ./internal/wilson/ -count=1` → build fails, `undefined: Interval`.

- [ ] **Step 3: Implement** — `internal/wilson/wilson.go`:

```go
// Package wilson computes Wilson score intervals — the ONLY interval the
// framework may print for "X of Y" evidence counts (G4 discipline: a raw
// ratio without an interval is a claim the suite cannot support). Pure
// math, no storage, no model. z is fixed at 1.959963984540054 (two-sided
// 95%); a second confidence level is a future flag, not a second constant.
package wilson

import (
	"fmt"
	"math"
)

const z95 = 1.959963984540054

// Interval returns the Wilson score interval for k successes in n trials.
// Degenerate inputs (n<=0, k<0, k>n) return (0, 0) — callers must check
// n>0 before rendering; Format does exactly that.
func Interval(k, n int) (float64, float64) {
	if n <= 0 || k < 0 || k > n {
		return 0, 0
	}
	p := float64(k) / float64(n)
	z2 := z95 * z95
	den := 1 + z2/float64(n)
	center := p + z2/(2*float64(n))
	spread := z95 * math.Sqrt(p*(1-p)/float64(n)+z2/(4*float64(n)*float64(n)))
	lo, hi := (center-spread)/den, (center+spread)/den
	if lo < 0 {
		lo = 0
	}
	if hi > 1 {
		hi = 1
	}
	return lo, hi
}

// Format renders the framework's canonical interval line, e.g.
// "recall: 2/2 (95% CI 34.2–100.0%)". noun is the metric name.
func Format(k, n int, noun string) string {
	if n <= 0 || k < 0 || k > n {
		return fmt.Sprintf("%s: %d/%d (95%% CI n/a)", noun, k, n)
	}
	lo, hi := Interval(k, n)
	return fmt.Sprintf("%s: %d/%d (95%% CI %.1f–%.1f%%)", noun, k, n,
		math.Round(lo*1000)/10, math.Round(hi*1000)/10)
}
```

- [ ] **Step 4: Green** — `GOCACHE=$PWD/.gocache go test ./internal/wilson/ -count=1 && GOCACHE=$PWD/.gocache go vet ./internal/wilson/` PASS. `scripts/golden.sh` untouched (leaf package, nothing imports it yet).

- [ ] **Step 5: Commit**

```bash
git add internal/wilson/
git commit -m "feat(G4): Wilson interval leaf package — the CI primitive every metric must use"
```

---

### Task 2: G4 evalsuite pack — 16 gold cases, 8+ classes, clean control (data + validator)

**Files:**
- Create: `assets/evalsuite.go` (pack FS), `assets/evalsuite/cases.json`, `assets/evalsuite/src/*.sol` (17 files: 16 bug cases + the control protocol's source)
- Modify: `assets/manifest_test.go` (pack list), `scripts/sync-asset-manifest.py` (PACKS), `assets/evalsuite_test.go` (new: validator)
- Test: `assets/evalsuite_test.go`

**Interfaces:**
- Consumes: `evaluation_case.schema.json` (existing), `taxonomy.CanonicalClasses()`, `internal/validation` (`ParseOrdered`, schema validation entry used by `evalstore.Validate` — reuse the same call path), `assets.AssetFS` pattern from `assets/archetypes.go:10`.
- Produces: `assets.LoadEvalCases() ([]validation.Value, error)` — parsed, schema-validated suite in file order (Task 3 consumes; Task 4 renders through it). Case ids: `EVC-<slug>`; every case pins `code.repo: "internal://evalsuite"`, `code.commit: "tranche2-v1"`.

- [ ] **Step 1: Failing validator** — `assets/evalsuite_test.go`:

```go
package assets

import (
	"strings"
	"testing"

	"websec/internal/taxonomy"
	"websec/internal/validation"
)

func TestEvalSuiteSchemaAndCoverage(t *testing.T) {
	cases, err := LoadEvalCases()
	if err != nil {
		t.Fatalf("LoadEvalCases: %v", err)
	}
	if len(cases) < 16 {
		t.Fatalf("G4 requires >=16 cases, got %d", len(cases))
	}
	known := taxonomy.CanonicalClasses()
	classes := map[string]int{}
	control := 0
	for i := range cases {
		c := &cases[i]
		// schema contract
		if errs := validation.ValidateCase(c); len(errs) != 0 { // existing evalstore path — see note
			t.Fatalf("case %d invalid: %v", i, errs)
		}
		part := objAtS(*c, "partition").S
		if part != "dev" && part != "held-out" {
			t.Fatalf("partition must be dev|held-out, got %q", part)
		}
		cls := objAtS(*c, "gold").O // bug_class lives under gold
		bc := ""
		for _, kv := range cls {
			if kv.K == "bug_class" {
				bc = kv.V.S
			}
			if kv.K == "outcome" && kv.V.S == "confirmed-not-exploitable" {
				control++ // the clean control protocol
			}
		}
		if bc == "" {
			t.Fatal("every gold needs bug_class")
		}
		classes[bc]++
		// G7 provenance discipline on every row
		src := objAtS(*c, "source")
		url := ""
		for _, kv := range src {
			if kv.K == "url" {
				url = kv.V.S
			}
		}
		if !strings.HasPrefix(url, "https://") && url != "internal://evalsuite" {
			t.Fatalf("source.url must be primary-or-internal, got %q", url)
		}
	}
	if len(classes) < 8 {
		t.Fatalf("G4 requires >=8 classes, got %d: %v", len(classes), classes)
	}
	if control != 2 { // ES17 clean control + ES16 ack decoy share the
		t.Fatalf("exactly two confirmed-not-exploitable rows required, got %d", control)
	}
	for _, must := range []string{"access-control", "reentrancy", "oracle-manipulation",
		"share-price-inflation", "precision-rounding", "upgrade-initializer",
		"cross-chain-replay", "dos-griefing"} {
		if classes[must] == 0 {
			t.Fatalf("required class %s missing", must)
		}
	}
}
```

NOTE (do not skip): `validation.ValidateCase` above stands for the eval-case validator evalstore already uses — read `internal/evalstore/evalstore.go` `AddCase` (L108) to find the real validation entry point and call THAT (exported wrapper if present; if the validator is unexported inside evalstore, call `evalstore.VerifyEvalStore` on a temp dir seeded with the suite rows via `AddCase` — mirror what `scripts/golden/p4` does). `objAtS` = the package's existing dict helper or a 4-line local in the test.

- [ ] **Step 2: Verify failure** (`undefined: LoadEvalCases`).

- [ ] **Step 3: Solidity fixtures** — 16 planted mini-protocols + 1 clean control. All tiny (≤30 lines), pragma ` solidity ^0.8.24`; the variant axes are EXPLICIT in the ids. Each file under `assets/evalsuite/src/`:

| file | bug_class | outcome | variant axis |
|---|---|---|---|
| `ES01VaultMissingAuth.sol` | access-control | confirmed-exploitable | baseline |
| `ES02GovernanceOwnable.sol` | authorization | confirmed-exploitable | baseline |
| `ES03BankReentrancy.sol` | reentrancy | confirmed-exploitable | tool-corroborable (slither reentrancy-eth fires — exercises G1 flag on next real run) |
| `ES04LenderUnderflow.sol` | unchecked-external-call | confirmed-exploitable | baseline |
| `ES05LPOracleSpot.sol` | oracle-manipulation | confirmed-exploitable | spot-price, no TWAP |
| `ES06VTokenDonation.sol` | share-price-inflation | confirmed-exploitable | donation-inflation |
| `ES07FeeMathFloor.sol` | precision-rounding | confirmed-exploitable | non-default solc pin `0.8.19` comment header |
| `ES08ImplNoInitializer.sol` | upgrade-initializer | confirmed-exploitable | transparent proxy |
| `ES09BridgeNoChainId.sol` | cross-chain-replay | confirmed-exploitable | missing chainId in digest |
| `ES10GovernanceQueueDoS.sol` | dos-griefing | confirmed-exploitable | liveness (revert bricks proposals) |
| `ES11MintInflation.sol` | donation | confirmed-exploitable | obfuscated comments axis |
| `ES12SignatureReplay.sol` | signature-replay | confirmed-exploitable | missing nonce binding |
| `ES13FlashLoanSpot.sol` | flash-loan | confirmed-exploitable | economic-invariant companion |
| `ES14LiquidationTWAP.sol` | liquidation-logic | confirmed-exploitable | documented-assumption decoy (see ES17) |
| `ES15BridgeMsgReplay.sol` | bridge-message | confirmed-exploitable | tool-corroborable #2 |
| `ES16AckDecoyVault.sol` | reentrancy | confirmed-not-exploitable | IN-CODE-ACK DECOY: body is guarded; the `// acknowledged: known issue, accepted by design` comment line makes ackscan record `in_code_ack` — feeds G5/A2 tests |
| `ES17CleanControl.sol` | (none — see case) | confirmed-not-exploitable | documented-assumption protocol, zero bugs: CEI-clean, checks-effects, auth'd |

Representative sources (write ALL seventeen in this exact style — constructor-free where possible, `msg.sender` flows, one obvious flaw each):

```solidity
// ES03BankReentrancy.sol — planted reentrancy (CEI violation)
pragma solidity ^0.8.24;
contract Bank {
    mapping(address => uint256) public bal;
    function deposit() external payable { bal[msg.sender] += msg.sender.balance == 0 ? 0 : msg.value; }
    function withdraw() external {
        uint256 a = bal[msg.sender];
        (bool ok, ) = msg.sender.call{value: a}("");   // effects AFTER interaction
        require(ok, "send");
        bal[msg.sender] = 0;                            // violation: CEI broken
    }
    receive() external payable {}
}
```

```solidity
// ES17CleanControl.sol — the protocol that must yield ZERO findings
pragma solidity ^0.8.24;
contract Escrow {
    mapping(address => uint256) public deposits;
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "auth"); _; }
    function deposit() external payable { deposits[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 a = deposits[msg.sender];
        require(a > 0, "zero");
        deposits[msg.sender] = 0;                       // effects first
        (bool ok, ) = msg.sender.call{value: a}("");    // interaction last
        require(ok, "send");
    }
    function sweep(address payable to) external onlyOwner { to.transfer(address(this).balance); }
}
```

`ES16AckDecoyVault.sol`: a withdraw function that IS CEI-correct but carries the line `// acknowledged: known issue, accepted by design` above it (ackscan phrase) — its gold outcome is confirmed-not-exploitable. The other 14 follow the same ≤30-line pattern with the named flaw present; the implementer writes them from the table (each must be a REAL instance of the class — a reviewer will read every file against its class).

- [ ] **Step 4: `assets/evalsuite/cases.json`** — 17 rows (16 bug cases + control; the decoy ES16 and control ES17 are the two `confirmed-not-exploitable` rows; control requirement = the ZERO-findings protocol ES17, and ES16 counts as its own decoy axis), ordered ES01→ES17, each in this exact shape (row 1 verbatim, then the row-by-row substitution list):

```json
{
 "case_id": "EVC-es01-vault-missing-auth",
 "source": {"dataset": "manual", "record_id": "evalsuite-ES01", "url": "internal://evalsuite"},
 "partition": "dev",
 "program": {"program": "ES01VaultMissingAuth", "platform": null, "chains": []},
 "gold": {"outcome": "confirmed-exploitable", "bug_class": "access-control",
   "severity": "high",
   "root_cause": "withdraw() moves funds to msg.sender with no ownership or allowance check",
   "locations": [{"file": "assets/evalsuite/src/ES01VaultMissingAuth.sol"}]},
 "code": {"repo": "internal://evalsuite", "commit": "tranche2-v1",
   "files": ["assets/evalsuite/src/ES01VaultMissingAuth.sol"], "snapshot_note": "planted fixture"},
 "created_at": "2026-09-11T00:00:00Z",
 "schema_version": "1",
 "notes": "G4 planted-bug fixture; gold anchor is the finding shape a real run must produce"
}
```

Partition split: ES01–ES11 `dev`; ES12–ES17 `held-out` (the backtest set). Substitutions per row: `case_id`/`program`/`file` from the table; `bug_class`/`outcome` from the table; `root_cause` one clause naming the planted flaw; ES16/ES17 `outcome: "confirmed-not-exploitable"` with `bug_class` kept (their class labels what was DECOYED/expected-absent: ES16 `reentrancy`, ES17 `access-control` — the scorer treats confirmed-not-exploitable as "zero live findings for this program is the hit"). `severity`: any of the four enum values, real-world judgment, `null` allowed.

- [ ] **Step 5: Embed + manifest wiring.** `assets/evalsuite.go` mirrors `assets/archetypes.go` exactly (FS field `EvalSuiteFS`, `go:embed evalsuite` subtree — copy its shape incl. the `init()` helper if it has one):

```go
package assets

import "embed"

// EvalSuiteFS is the G4 gold-eval pack: cases.json (evaluation_case
// instances) + src/*.sol planted fixtures. Manifest-pinned; presence is
// asserted by assets/evalsuite_test.go, consumers go through
// LoadEvalCases — nobody fs.Walks this at score time.
//
//go:embed evalsuite/cases.json evalsuite/src
var EvalSuiteFS embed.FS
```

`scripts/sync-asset-manifest.py` PACKS gains `"evalsuite"` the same way `archetypes` is listed; `assets/manifest_test.go` pack list gains it identically. Then `LoadEvalCases`:

```go
// LoadEvalCases parses cases.json (ordered) and returns the case objects.
// Schema validation is the CALLER'S gate (assets/evalsuite_test.go runs it);
// this function only guarantees parse + shape (array, non-empty).
func LoadEvalCases() ([]validation.Value, error) {
	raw, err := evalsuiteFS.ReadFile("evalsuite/cases.json")
	if err != nil {
		return nil, err
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		return nil, err
	}
	if doc.Kind != validation.Arr {
		return nil, fmt.Errorf("evalsuite cases.json must be an array")
	}
	return doc.A, nil
}
```

(If `archetypes.go` embeds via an inner named FS var, copy that indirection verbatim — the path prefix inside `ReadFile` must match how the embed directive is written.)

- [ ] **Step 6: Green.** `python3 scripts/sync-asset-manifest.py` → then `GOCACHE=$PWD/.gocache go test ./assets/ -count=1` PASS (17 cases validate against `evaluation_case.schema.json` via the real validator path; coverage assertions pass). `scripts/golden.sh` untouched.

- [ ] **Step 7: Commit**

```bash
git add assets/evalsuite.go assets/evalsuite assets/evalsuite_test.go assets/testdata/asset_manifest.json scripts/sync-asset-manifest.py assets/manifest_test.go
git commit -m "feat(G4): 17-case gold-eval suite (8+ classes, control + decoys) as a manifest-pinned asset pack"
```

---

### Task 3: `internal/evalscore` — the scorer join (G4)

**Files:**
- Create: `internal/evalscore/evalscore.go`
- Test: `internal/evalscore/evalscore_test.go`

**Interfaces:**
- Consumes: `findings.LoadAllFindings`/`LoadLiveFindings` (campaign live set), `assets.LoadEvalCases()` (Task 2), `wilson.Format` (Task 1), `state.Campaign` target metadata (the program name the campaign pinned — read `campaign.json`'s target/program naming via `internal/state` — the join key is `program.program` matched case-insensitively against the campaign's target NAME; state exposes target name — Task 3's implementer finds the exact accessor in `internal/state` and records it in the report).
- Produces:

```go
type Report struct {
	GoldTotal, Hits, Misses, FP int // FP: live findings in suite-matched programs that match no gold anchor
	RecallLine, PrecisionLine string
	HeldOut  bool
}
func Score(c *state.Campaign, cases []validation.Value) (Report, bool) // ok=false when no case matches the campaign's program
func ScoreSuite(programs []string, liveByProgram map[string][]validation.Value, cases []validation.Value) Report // suite-level roll-up for selftest/report
```

Hit rule (verbatim law, encode exactly): a gold case is HIT iff, among the campaign's live findings for its program, some finding has `root_cause.class == gold.bug_class` AND (gold has no `locations` OR finding `affected[0].path` suffix-matches a gold `locations[i].file` basename). `outcome == "confirmed-not-exploitable"` inverts: the case is HIT iff ZERO live findings exist for that program (clean control + decoy law — ES16/ES17). FP = live findings in a suite-matched program that anchored no gold case.

- [ ] **Step 1: Failing tests** (table; write with synthetic `validation.Value` finding builders — package-local `kvE/objE` helpers as the repo's per-package convention):

```go
func TestHitMissAndControl(t *testing.T) {
	// two golds (access-control + reentrancy) + one control program;
	// findings: both classes found for P1 (file basename match), none for CTRL
	// => recall 2/2, hits on control = its zero-findings rule.
	r := mustScore(t, suite, map[string][]validation.Value{
		"p1": {finding("access-control", "src/Vault.sol"), finding("reentrancy", "src/Bank.sol")},
		"ctrl": {},
	})
	if r.GoldTotal != 3 || r.Hits != 3 || r.Misses != 0 || r.FP != 0 {
		t.Fatalf("%+v", r)
	}
	if r.RecallLine != "recall: 3/3 (95% CI 43.9–100.0%)" {
		t.Fatalf("recall line: %q", r.RecallLine)
	}
}

func TestMissAndFalsePositive(t *testing.T) {
	r := mustScore(t, suite, map[string][]validation.Value{
		"p1": {finding("oracle-manipulation", "src/Vault.sol")}, // wrong class => FP
		"ctrl": {finding("reentrancy", "src/Bank.sol")},          // control polluted => miss+FP
	})
	// gold: 2 p1 cases (miss,miss) + ctrl (miss) => recall 0/3
	if r.RecallLine != "recall: 0/3 (95% CI 0.0–56.1%)" {
		t.Fatalf("recall: %q", r.RecallLine)
	}
	if r.FP != 2 {
		t.Fatalf("FP: %d", r.FP)
	}
}

func TestPrecisionDenominator(t *testing.T) {
	// precision = hits-with-anchor / live-findings in matched programs;
	// 2 hits + 1 FP => "precision: 2/3 (95% CI 20.8–93.9%)"
}

func TestNoMatchReturnsFalse(t *testing.T) {
	_, ok := Score(campaignFor(t, "unrelated-program"), suite)
	if ok {
		t.Fatal("no suite case matches the campaign's program — Score must refuse")
	}
}
```

(Exact CI endpoints above were computed with the Task 1 formula — Wilson 3/3 = 43.9–100.0, 0/3 = 0.0–56.1, 2/3 = 20.8–93.9; recompute once with `go run` if in doubt, never tune a test to green.)

- [ ] **Step 2: Red** → [ ] **Step 3: Implement** `evalscore.go` per the join rules (single pass over cases, findings grouped by program lowercased; sort ids before any iteration; no time). `Score` = `ScoreSuite` on one program.
- [ ] **Step 4: Green** + `scripts/golden.sh` untouched (nothing wired into the CLI yet).
- [ ] **Step 5: Commit** — `git add internal/evalscore/`; `git commit -m "feat(G4): evalscore joins live findings to gold anchors — recall/precision with Wilson CIs"`.

---

### Task 4: G4 audit section — presence-gated `eval` (zero-drift proof)

**Files:**
- Modify: `internal/audit/sections/register.go`, create `internal/audit/sections/eval.go` (+ test)
- Modify: `internal/cli/cmd_selftest.go` — `--full` gains the `evalsuite-selfcheck` step (deterministic scorer proof over embedded fixtures WITHOUT docker: build in-memory findings straight from each case's gold, expect recall 17/17 + FP 0; a scorer that can score the suite against itself proves the data, not the detector — say exactly that in the step's output line)

**Interfaces:**
- Consumes: `evalscore.Score` (Task 3), `assets.LoadEvalCases` (Task 2), the section registry pattern from `internal/audit/sections/register.go:23` + presence-gate example `stagecompletions.go:37`.
- Produces: audit/report section named exactly `eval` rendering:

```
## eval
- suite: 3 gold cases matched (2 dev, 1 held-out)
- recall: 2/2 (95% CI 34.2–100.0%)
- precision: 2/3 (95% CI 20.8–93.9%)
- false positives (unanchored live findings): 1
```

GATE (byte law): the section renders ONLY when at least one `assets/evalsuite` case matches the campaign's pinned program name. The golden campaigns pin synthetic programs (`toy-protocol` etc.) that match nothing → the section NEVER appears in golden → `check-golden.py` EXPECTED_SECTIONS stays 14, zero fixture edits. A test asserts this explicitly (Task 4 step 2).

- [ ] **Step 1: Failing test** in `internal/audit/sections/eval_test.go`: synthetic campaign named `ES03BankReentrancy` (matching two suite cases) with crafted live findings → section renders with the pinned lines above; a campaign named `nothing-here` → registry output contains NO `## eval` section AND `check-golden.py`'s pinned list still passes (`python3 scripts/check-golden.py` — run via golden.sh in step 4).
- [ ] **Step 2: Implement** section + register. Follow `stagecompletions.go`'s shape exactly (returns skip when nothing matched). Do NOT add any new finding-schema enum (no legend touch).
- [ ] **Step 3: selftest step** — `internal/cli/cmd_selftest.go` plan-full list gains `evalsuite-selfcheck` (fast plan unchanged): constructs findings from gold data in memory (helper local to cmd_selftest), calls `evalscore.ScoreSuite`, fails unless `Hits == GoldTotal && FP == 0`; prints `ok: gold suite self-scores 17/17 (95% CI …)`. Pin `pinSelftestClock` as neighboring steps do.
- [ ] **Step 4: Green** — `GOCACHE=$PWD/.gocache go test ./internal/audit/... -count=1 && GOCACHE=$PWD/.gocache go run ./cmd/webv2 selftest --full && scripts/golden.sh` all PASS/GREEN.
- [ ] **Step 5: Commit** — `git add internal/audit internal/cli/cmd_selftest.go`; `git commit -m "feat(G4): presence-gated eval audit section + selftest self-score proof (golden untouched by construction)"`.

---
---

### Task 5: G2 `class_weights.json` — three-weight table as a validated, embedded asset

**Files:**
- Create: `assets/taxonomy/class_weights.json`, `assets/schema/class_weights.schema.json`, `assets/taxonomy.go` (pack FS), `internal/classweights/classweights.go` (+ test)
- Modify: `scripts/sync-asset-manifest.py` (PACKS += `taxonomy`), `assets/manifest_test.go` (pack list)

**Interfaces:**
- Consumes: `taxonomy.CanonicalClasses()` (drift test), the assets embed pattern (`assets/archetypes.go:10`, Task 2's `assets/evalsuite.go`), `internal/validation`.
- Produces:
  - `classweights.Load() (validation.Value, error)` — parsed embedded table, validated once (sync.Once, sticky error).
  - `classweights.SearchFactor(class string) float64` — `classes[cls].search`; missing class → 1.0 (unknown must never be silenced).
  - `classweights.Row(class string) (validation.Value, bool)`.
  - `classweights.ClassesWithNonNeutralWeights() []string` — used by tests + the G3 graduation gate.
- `internal/classweights` is a LEAF for consumers (imports `assets` + `taxonomy` + `validation`); nothing under `assets/` or `taxonomy` may import it.

**The table's meaning (bootstrap honesty — reviewer context):** `search`/`acceptance` ship NEUTRAL (1.0) on purpose: principle 1 forbids this tranche's data from moving golden bytes, and G3's backtest (Tasks 7–12) is the ONLY venue allowed to promote a class off 1.0 — later a data-only JSON edit, never a code change. The `provenance[]` rows carry the real loss figures NOW with G7 hygiene: the table is the SEAM between research and score, not research baked into score. `severity_default` is DISPLAY data — floors/risk refuse it (Task 6). Do NOT seed non-neutral weights "from the OWASP numbers"; the drift test pins all-1.0 for THIS tranche.

- [ ] **Step 1: Failing tests** — `internal/classweights/classweights_test.go`:

```go
package classweights

import (
	"testing"

	"websec/internal/taxonomy"
	"websec/internal/validation"
)

func TestEveryCanonicalClassPresentOnce(t *testing.T) {
	doc, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	classes := objAt(doc, "classes")
	known := taxonomy.CanonicalClasses()
	for cls := range known {
		if objAt(classes, cls).Kind == validation.Null {
			t.Fatalf("canonical class %s missing from class_weights.json", cls)
		}
	}
	if objAt(classes, "unmapped").Kind == validation.Null {
		t.Fatal("unmapped bucket missing")
	}
	if len(classes.O) != len(known)+1 {
		t.Fatalf("table carries %d rows, want %d (+unmapped)", len(classes.O), len(known))
	}
}

func TestBootstrapNeutralAndProvenanceHygiene(t *testing.T) {
	doc, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	classes := objAt(doc, "classes")
	for _, kv := range classes.O {
		if f := objAt(kv.V, "search").F; f != 1.0 {
			t.Fatalf("%s: search=%v — tranche-2 law: all 1.0 until a backtest wins", kv.K, f)
		}
		if f := objAt(kv.V, "acceptance").F; f != 1.0 {
			t.Fatalf("%s: acceptance=%v — must stay 1.0 (G3 gate)", kv.K, f)
		}
		prov := objAt(kv.V, "provenance").A
		if len(prov) == 0 {
			t.Fatalf("%s: provenance rows required (G7)", kv.K)
		}
		for _, pr := range prov {
			if objAt(pr, "checked_date").S == "" || objAt(pr, "source_url").S == "" {
				t.Fatalf("%s: provenance row incomplete", kv.K)
			}
		}
	}
	if got := ClassesWithNonNeutralWeights(); len(got) != 0 {
		t.Fatalf("non-neutral weights before graduation: %v", got)
	}
}

func TestSearchFactorMissingClassIsNeutral(t *testing.T) {
	if SearchFactor("no-such-class") != 1.0 {
		t.Fatal("unknown class must be 1.0, never 0/silence")
	}
}
```

(`objAt` = the 4-line local helper, per-package convention.)

- [ ] **Step 2: Red.**

- [ ] **Step 3: `assets/schema/class_weights.schema.json`:**

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "class_weights",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "classes"],
  "properties": {
    "schema_version": {"type": "string", "enum": ["1"]},
    "classes": {
      "type": "object",
      "additionalProperties": {
        "type": "object",
        "additionalProperties": false,
        "required": ["search", "acceptance", "severity_default", "provenance"],
        "properties": {
          "search": {"type": "number", "minimum": 0.25, "maximum": 4.0},
          "acceptance": {"type": "number", "minimum": 0.25, "maximum": 4.0},
          "severity_default": {"type": ["string", "null"],
            "enum": ["critical", "high", "medium", "low", null]},
          "provenance": {
            "type": "array", "minItems": 1,
            "items": {
              "type": "object",
              "additionalProperties": false,
              "required": ["source_url", "checked_date", "primary"],
              "properties": {
                "source_url": {"type": "string", "minLength": 8},
                "checked_date": {"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"},
                "primary": {"type": "boolean"},
                "figure": {"type": "string"},
                "note": {"type": "string"}
              }
            }
          }
        }
      }
    }
  }
}
```

- [ ] **Step 4: Enumerate classes PROGRAMMATICALLY.** One-shot in `.scratch/` (delete after): a 10-line `main.go` printing `taxonomy.CanonicalClasses()` sorted; copy the exact output into `assets/taxonomy/class_weights.json` rows (+ `"unmapped"`). Never hand-type the vocabulary — the drift test is the authority. Row shape (per-class, values as stated in the bootstrap law):

```json
"reentrancy": {
  "search": 1.0, "acceptance": 1.0, "severity_default": "high",
  "provenance": [
    {"source_url": "https://owasp.org/www-project-smart-contract-top-10/",
     "checked_date": "2026-09-11", "primary": true,
     "figure": "recurring exploit-loss class; dollar share varies by edition — quote docs/IMPROVEMENTS.md G2, not this row",
     "note": "weights neutral until the G3 backtest graduates them; severity_default is DISPLAY-only (floors refuse it)"}
  ]
}
```

severity_default bands: access-control/reentrancy/oracle-manipulation/share-price-inflation/flash-loan/cross-chain-replay/bridge-message → `"high"`; everything else → `"medium"`; `unmapped` → `null`. Provenance `source_url` may differ per row (primary sources only); every row needs ≥1 `"primary": true`.

- [ ] **Step 5: embed + reader.** `assets/taxonomy.go`:

```go
package assets

import "embed"

// TaxonomyFS is the G2 data pack: class_weights.json (schema-validated by
// internal/classweights; drift-tested against taxonomy.CanonicalClasses()).
//
//go:embed taxonomy
var TaxonomyFS embed.FS
```

`internal/classweights/classweights.go` (shape; fill per the tests):

```go
// Package classweights loads the G2 per-class three-weight table. It is the
// ONLY door through which historical-loss data may reach ranking, and the
// door ships LOCKED: every weight starts 1.0 (neutral) and only a G3
// backtest win on held-out data may move a number — in the JSON, never in
// code. severity_default is DISPLAY-only: internal/floors and internal/risk
// refuse it at their boundaries (Task 6 pins that).
package classweights

import (
	"fmt"
	"sync"

	"websec/internal/assets"
	"websec/internal/validation"
)

var (
	once  sync.Once
	docV  validation.Value
	docEr error
)

func Load() (validation.Value, error) {
	once.Do(func() {
		raw, err := assets.TaxonomyFS.ReadFile("taxonomy/class_weights.json")
		if err != nil {
			docEr = err
			return
		}
		doc, err := validation.ParseOrdered(raw)
		if err != nil {
			docEr = fmt.Errorf("class_weights.json: %w", err)
			return
		}
		if errs := validation.ValidateAssetDoc("class_weights", doc); len(errs) != 0 {
			docEr = fmt.Errorf("class_weights.json invalid: %v", errs)
			return
		}
		docV = doc
	})
	return docV, docEr
}
// + classes()/SearchFactor()/Row()/ClassesWithNonNeutralWeights() per the
// Interfaces block: table lookups on objAt(doc, "classes"), 1.0 defaults.
```

NOTE: `validation.ValidateAssetDoc(name, doc)` stands for the existing "validate doc against `assets/schema/<name>.schema.json`" entry. READ `internal/validation` first (bounty_policy/campaign asset validation is the sibling pattern; evalstore's case validator closest). If no exported wrapper exists, add a thin `ValidateAssetDoc` to `internal/validation/asset.go` reusing the SAME registry the other loaders use — record the choice in the report.

- [ ] **Step 6: manifest** — PACKS += `"taxonomy"` in `scripts/sync-asset-manifest.py` + `assets/manifest_test.go`; `python3 scripts/sync-asset-manifest.py`; `GOCACHE=$PWD/.gocache go test ./assets/ ./internal/classweights/ -count=1` GREEN.
- [ ] **Step 7: Commit**

```bash
git add assets/taxonomy assets/taxonomy.go assets/schema/class_weights.schema.json internal/classweights scripts/sync-asset-manifest.py assets/manifest_test.go assets/testdata/asset_manifest.json
git commit -m "feat(G2): per-class three-weight table as a schema-validated embedded asset (bootstrap-neutral, provenance-gated)"
```

---

### Task 6: G2 consumers — corpus reads `search`; floors/risk REFUSE `severity_default`

**Files:**
- Modify: `internal/corpus/corpus.go` (score line ~276 + package var), `internal/corpus/corpus_test.go`
- Modify: `internal/floors/floors.go` (policy-validation boundary near `SetFloorPolicy:118`), `internal/floors/floors_test.go`
- Modify: `internal/risk` (same refusal at its caller-input boundary) + test

**Interfaces:**
- Consumes: `classweights.SearchFactor` (Task 5).
- Produces: no new exported API; behavior inside existing funcs.

**Byte law:** `x*1.0 == x` is bit-exact in IEEE754 — multiply the class factor in LAST, LEFT-ASSOCIATIVE: `float64(len(hits)) * math.Log2(1+float64(weight)) * ConfidenceFactor[...] * searchFactor(cls)`. Do NOT reassociate anything else. `scripts/golden.sh` must pass with ZERO fixture edits; if corpus bytes move, the multiplication was reordered — fix the code, never the golden.

- [ ] **Step 1: Failing corpus test** — append to `corpus_test.go` (reuse the file's existing ExposureRows fixture builder; the hook is a package-level var so the DEFAULT path stays byte-identical while the test path can inject):

```go
func TestExposureRowsSearchFactorApplied(t *testing.T) {
	old := searchFactor
	defer func() { searchFactor = old }()
	searchFactor = func(cls string) float64 {
		if cls == "reentrancy" {
			return 2.0
		}
		return 1.0
	}
	// build the file's standard inventory+probed inputs containing a
	// reentrancy row with N hits, neutral weight w:
	rows := ExposureRows(inv, probed)
	// find the reentrancy row; baseline score from the 1.0 run computed
	// once with the original factor (call BEFORE the swap in a subtest or
	// recompute by hand): doubled.
	base, doubled := scoreOf(rows, "reentrancy")
	if doubled != validation.PythonRound(base*2, 6) {
		t.Fatalf("factor 2.0 must double the score: %v vs %v", doubled, base*2)
	}
}
```

(`scoreOf` = 5-line local reading `objAt(row,"score").F` after locating by `bug_class`; if the file's builder makes "before" scores awkward, pin TWO ExposureRows calls — one with default factor, one swapped — and compare.)

- [ ] **Step 2: Implement corpus** — `var searchFactor = classweights.SearchFactor` (package level, comment: test seam + the ONLY graduation door); score line per the byte law. Green + package suite.
- [ ] **Step 3: Floors refusal** — first READ where floor_policy payloads are validated (`SetFloorPolicy` and its schema check — legitimate keys per `assets/schema/floor_policy.schema.json`... verify the real file name at edit time). Add a boundary walk BEFORE other validation: any key named `severity_default`, `class_weights`, or a top-level `classes` map → error naming the refused key. Test:

```go
func TestFloorPolicyRefusesClassWeightSmuggling(t *testing.T) {
	c := mkFloorCampaign(t) // existing helper in this file
	pol := validation.VObj(kvF("classes", validation.VObj(kvF("reentrancy",
		validation.VObj(kvF("severity_default", validation.VStr("critical")))))))
	err := SetFloorPolicy(c, pol)
	if err == nil || !strings.Contains(err.Error(), "severity_default") {
		t.Fatalf("floors must refuse class-weights-shaped input naming the key, got %v", err)
	}
}
```

(`kvF` = local KV helper following the file's pattern.)
- [ ] **Step 4: Risk boundary** — same refusal walk where `internal/risk` accepts caller-supplied Value inputs from the CLI (find the Set*/Build* entry taking raw Values; add the walk + one test, same shape).
- [ ] **Step 5: Golden untouched** — `scripts/golden.sh` GREEN, zero edits; `GOCACHE=$PWD/.gocache go test ./internal/corpus/ ./internal/floors/ ./internal/risk/ ./internal/classweights/ -count=1`.
- [ ] **Step 6: Commit**

```bash
git add internal/corpus internal/floors internal/risk
git commit -m "feat(G2): corpus search column wired (neutral, byte-identical); floors/risk refuse severity_default at their boundaries"
```

---
---

### Task 7: G3 `internal/risk/calibration.go` — AcceptancePrior over the eval store

**Files:**
- Create: `internal/risk/calibration.go`, `internal/risk/calibration_test.go`

**Interfaces:**
- Consumes: `evalstore.LoadCases()`, `wilson.Interval/Format` (Task 1), taxonomy classes.
- Produces:

```go
// Prior is one class's acceptance prior. Adjudicated outcomes only:
// accepted := gold.outcome == "confirmed-exploitable" (the `paid` field,
// where a case carries one, is reserved for the immunefi loader's
// mapping — it never invents acceptance). Every OTHER adjudicated
// outcome (disproved, out-of-scope, duplicate, economic-no-go,
// confirmed-not-exploitable) counts AGAINST — they are triage outcomes,
// not absolution; `prior.Fallback` says when the class was too thin to
// carry its own number.
type Prior struct {
	Class                string
	Rate, CILo, CIHi     float64
	N                    int      // adjudicated rows for this class
	Fallback             bool     // true => global prior used, class n < minN
	GlobalN              int
}
const DefaultMinN = 10
func AcceptancePriors(minN int) (map[string]Prior, Prior, error) // per-class + global; global always exact
func (p Prior) Render() string // "oracle-manipulation: 0.50 (n=12, 95% CI 26.7–72.5%)" | fallback appends " (fallback: global, n=3)"
```

`internal/risk` already imports `internal/evalstore`? VERIFY at edit time (acceptance reads the finding, not the store); if not, adding it must not create a cycle (evalstore imports validation + schema only). If a cycle appears, the prior lives in a new leaf `internal/calibration` imported by risk — same API names.

- [ ] **Step 1: Failing tests** — seed a temp eval store via `WEBV2_EVAL_DIR` (the file's existing override at `evalstore.go:41`) with synthetic cases (helper writes rows with `evalstore.AddCase`; construct minimal valid case docs the way p4's cases.json does):

```go
func TestPriorWilsonAndFallback(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WEBV2_EVAL_DIR", dir)
	// 12 oracle-manipulation: 6 accepted + 6 other-adjudicated
	//  3 reentrancy: 2 accepted  (below DefaultMinN => fallback)
	//  1 unadjudicated case: outcome null/"unknown" => EXCLUDED from n
	//  ...build cases compactly, then:
	priors, global, err := AcceptancePriors(DefaultMinN)
	if err != nil { t.Fatal(err) }
	o := priors["oracle-manipulation"]
	if o.N != 12 || o.Fallback { t.Fatalf("oracle prior: %+v", o) }
	lo, hi := wilson.Interval(6, 12)
	if o.CILo != lo || o.CIHi != hi { t.Fatalf("CI must BE the wilson package's number: %+v", o) }
	if math.Abs(o.Rate-0.5) > 1e-12 { t.Fatalf("rate: %v", o.Rate) }
	r := priors["reentrancy"]
	if !r.Fallback || r.N != 3 { t.Fatalf("n=3 must fall back: %+v", r) }
	if r.Rate != global.Rate || r.CILo != global.CILo { t.Fatal("fallback carries global numbers") }
	if !strings.Contains(r.Render(), "(fallback: global, n=3)") {
		t.Fatalf("fallback must SAY SO: %q", r.Render())
	}
}

func TestUnadjudicatedExcluded(t *testing.T) { /* every outcome outside the
	Outcomes vocabulary ("" / null / "unknown") contributes to NO n */ }
```

- [ ] **Step 2: Red → implement → green.** Implementation rules: iterate `evalstore.LoadCases()` in stored order; group by `gold.bug_class`; `accepted := outcome == "confirmed-exploitable"`; `n := accepted + negatives`; skip rows where `gold.outcome` is not one of the seven `ingest.Outcomes` values (report as `Skipped` count in error-free stats line of Render? NO — keep Prior pure; the CLI backtest prints the skipped count, Task 12). Global prior = same over ALL classes. Wilson via `wilson.Interval`. No time, no I/O beyond LoadCases.
- [ ] **Step 3: Commit**

```bash
git add internal/risk/calibration.go internal/risk/calibration_test.go
git commit -m "feat(G3): AcceptancePrior over adjudicated eval cases — Wilson CI, n<10 fallback that says so"
```

---

### Task 8: G3 `c4audit` loader (defihacklabs template)

**Files:**
- Create: `internal/datasets/c4audit/c4audit.go` (+ test), `internal/datasets/c4audit/testdata/normalized_sample.jsonl`

**Input contract (deterministic, documented):** JSONL, one row:

```json
{"id":"c4-2025-07-swap-zeroX-H-01","class":"access-control","severity":"High",
 "judge":"High","known":false,"duplicate_of":"","title":"Owner-only mint missing",
 "url":"https://github.com/code-423n4/data/tree/main/...","program":"swap-0x-2025-07"}
```

`judge` ∈ `High|Medium|QA|Invalid|Informational|Gas|Duplicate`; mapping table (verbatim, in code as a named map so the drift test can read it):

| judge (+flags) | Outcomes |
|---|---|
| High/Medium, known=false | `confirmed-exploitable` |
| High/Medium, known=true | `out-of-scope` (previously known = not a paid acceptance) |
| QA | `confirmed-not-exploitable`? NO — QA is informational-valid: `out-of-scope` |
| Invalid | `disproved` |
| Informational/Gas | `out-of-scope` |
| Duplicate, duplicate_of non-empty | `duplicate` |

Partition: every loaded row lands `held-out` unless the caller passes a different partition (loader option), because adjudicated public data is ground truth, never training fuel for self-test. `dataset` field: `c4audit` (already in the registry, `ingest.go:47` ✓).

- [ ] **Step 1: failing test** (fixture = 6-row jsonl covering every judge mapping + one bad row):

```go
func TestC4JudgeMapping(t *testing.T) {
	rows, err := LoadRecords("testdata/normalized_sample.jsonl")
	if err != nil { t.Fatal(err) }
	if len(rows) != 6 { t.Fatalf("%d rows", len(rows)) }
	// per-row outcome assertions exactly per the table; the 7th
	// (judge:"Banana") row in the fixture must FAIL LoadRecords with
	// "unknown judge" — keep it in a _bad.jsonl sibling + its own test.
}
```

- [ ] **Step 2: Red → implement `LoadRecords(path) ([]validation.Value, error)` + `Ingest(store, rows, opts)` writing eval cases through `evalstore.AddCase` (mirror `defihacklabs.go:1002/942` call shape: same store-entry, `source.dataset:"c4audit"`, `source.record_id: row.id`, `source.url: row.url`, `program:{program, platform:null}`, `gold:{outcome:<mapped>, bug_class:<class>, severity:<mapped High|Medium->high/medium, others null>, root_cause:<title>, locations:[]}`.)
- [ ] **Step 3: green + commit** `git add internal/datasets/c4audit && git commit -m "feat(G3): c4audit loader — judge verdicts to the Outcomes vocabulary"`.

---

### Task 9: G3 `sherlock` loader

Same shape as Task 8, differences only (implementer: build on the Task 8 file's skeleton; a shared tiny helper is NOT warranted until a third loader proves it — duplicate the ~40 lines, this repo accepts that at this size):

- `judge` ∈ `High|Medium|Low|QA|Invalid|Duplicate|Griefing`; mapping: High/Medium/Low (not known, not dupe) → `confirmed-exploitable`; Low + `griefing:true` → `economic-no-go`; QA → `out-of-scope`; Invalid → `disproved`; Duplicate → `duplicate`; `known=true` → `out-of-scope`.
- `dataset: "sherlock"` (registry ✓); severity map High→critical? NO — sherlock's High == "high": pass through lowercased; the loader never inflates bands.
- Fixture: 7 rows covering every mapping + `_bad` unknown-judge row.
- Commit: `feat(G3): sherlock loader — verdict mapping beside c4audit (template duplication accepted at this size)`.

---

### Task 10: G3 `immunefi-resolved` loader + registry vocabulary

**Files:** Create `internal/datasets/immunefi/` (loader + fixtures); modify `internal/ingest/ingest.go:47` (dataset vocabulary += `"immunefi-resolved"`), eval-case `platform` enum check first:

- [ ] **Step 0 (schema truth):** read `assets/schema/evaluation_case.schema.json` `program.properties.platform`: scout says platform is an OPTIONAL string (immunefi/cantina/sherlock live in values, not an enum — CONFIRM no enum; if there IS one, adding "immunefi" needs the legend-pin dance — it does NOT for eval-case (legend walks the FINDING schema only — see cmd_ingest_test pin source `SchemaEnumLegend("finding")`).
- Input row: `{"id":"imm-...","status":"accepted|rejected|downgraded|split","paid":true|false,"paid_usd":"120000","class":"access-control","severity":"critical","root_cause":"...","program":"...","url":"https://immunefi.com/bug-bounty/.../validation/..."}`.
- Mapping: accepted+paid → `confirmed-exploitable` AND case carries `gold.severity` verbatim + `notes: "paid_usd=<amount>"` (the paid fact rides the notes string until the schema grows a paid field — do NOT hand-add a gold.paid key: `additionalProperties` will reject it at AddCase; record that in the report); accepted+!paid → `confirmed-exploitable`; rejected → `disproved`; downgraded → `confirmed-not-exploitable`? NO — a downgrade is still an acceptance, `confirmed-exploitable` with notes "downgraded from X"; split → `confirmed-exploitable` (one row per report).
- Registry: `ingest.go:47` vocabulary append `"immunefi-resolved"` + the dataset test that asserts registry stability (find the existing test asserting that list and update it — it exists because the list is consumed by `IngestRecord` validation).
- Tests: mapping table, AddCase round-trip, unknown-status rejection.
- Commit: `feat(G3): immunefi-resolved loader + registry vocabulary (paid rides notes, never smuggled keys)`.

---

### Task 11: G3 `wPrior` — policy-gated OFF beside the outlook nudge

**Files:**
- Modify: `assets/schema/bounty_policy.schema.json` (`acceptance_priors` boolean, default false — presence of the KEY only, never legend-relevant), `internal/risk/acceptance.go` (+ test), `internal/bounty` (policy accessor if the schema file is read elsewhere — find the existing reader of `patch_clause` at `acceptance.go:34`'s path and mirror)

**Formula (verbatim law):** when priors are ON for the campaign (policy `acceptance_priors: true`) AND the finding's class prior is known with `!Fallback AND n >= DefaultMinN`:

```
wPrior = clamp( 2*(rate - global.rate) * min(1, n/30), -0.5, +0.5 )
```

Zero when OFF (default), or class fell back, or n too thin — presence-gated in BOTH score and Factors:

- `AcceptanceEntry` gains `PriorFactor float64` (json `prior_factor,omitempty`) and `Prior string` (`prior,omitempty`, the `Render()` line) — additive, omitempty ⇒ absent when zero ⇒ **existing JSON bytes do not move** (verify `encoding/json` on the struct's current fields tolerates omitempty ordering: keys append AFTER existing; golden acceptance JSON must be byte-identical with the flag off — golden.sh proves it).
- `risk.SetPriorsEnabled(bool)` package var-free API: the CALLER (report/rank/brief cmd layer + orchestrator paths that hold the campaign) resolves the policy and calls `AcceptanceWithPriors(f, priors map[string]Prior, global Prior)` — new exported function; `Acceptance(f)` keeps its exact signature and behavior (byte law: the default path must not change one float).

- [ ] **Step 1: failing test** in `acceptance_test.go`: same finding, priors map {oracle-manipulation: rate .8 n 20} + global .5 ⇒ `likely` case: `AcceptanceWithPriors` score == `Acceptance` score + clamp(2*(.8-.5)*min(1,20/30),±.5) = +0.3 exactly; `Acceptance` untouched; Fallback prior ⇒ delta 0; policy-off ⇒ caller never passes priors ⇒ structurally zero (test the function, not a hidden global).
- [ ] **Step 2: wire the resolution point** — `internal/risk`'s existing campaign-aware entry (find where report/rank construct scores with campaign context — `AcceptanceRanking` is the hub: add a variant `AcceptanceRankingWithPriors(...)`; keep `AcceptanceRanking` delegating with priors=nil so NO current caller changes). The bounty_policy read mirrors how `patch_clause` is reached (`acceptance.go:34` reads the FINDING's bounty key — the campaign policy object is a different store: locate `bounty_policy.json` loader (`internal/campaign` or state) — call it once inside the new WithPriors entry's CALLER (cli layer), not inside risk; the cmd resolves `priorsEnabled` + calls `calibration.AcceptancePriors` — keeps risk pure.
- [ ] **Step 3: byte check** — golden untouched (flag never set in golden campaigns) + `TestCombinedFactors` (tranche 1) still exact.
- [ ] **Step 4: brief/report per-class rendering (GATED)** — `internal/briefing` finding rows + `internal/report` submission table: when the WithPriors path ran, append ` [prior: 0.50 (n=12, 95% CI …)]` to the class column; absent ⇒ no change. Tests in each package, mirroring the outlook presence pattern; the CLI wires WithPriors only when policy enables (default OFF everywhere ⇒ selftest/golden surfaces unchanged).
- [ ] **Step 5: Commit**

```bash
git add assets/schema/bounty_policy.schema.json internal/risk internal/briefing internal/report internal/cli
git commit -m "feat(G3): wPrior acceptance term, policy-gated OFF — calibrated rank ships dark"
```

---

### Task 12: G3 `corpus-surface --backtest` — the ONLY place "improved" may be said

**Files:**
- Modify: `internal/cli/cmd_corpus_surface.go` (new `--backtest` + `--top N`, default 10), `internal/cli/cmd_corpus_surface_test.go`

**Contract (deterministic, honest):** over the eval store's adjudicated rows ONLY (partition `held-out` for the scorecard; `dev` for the per-class table, labeled): build ONE pseudo-finding per case (class + severity + no evidence, no critic — the backtest measures the RANKING SIGNALS THE STORE ACTUALLY CARRIES, say this verbatim in the help text), rank by (a) `severity-only` baseline and (b) `AcceptanceWithPriors` computed over the SAME priors minus the class's own held-out rows (leave-one-class-out shrinkage: prior from dev only ⇒ no self-confirmation; state it in the output header), report for each: `top-<K> precision: A/B (95% CI …)` + `selected accepted: X` + `accepted available: Y` rows (exact labels) + Wilson CI over hits∩accepted/K, and a final `verdict:` line — one of `improves` / `regresses` / `indistinguishable` decided ONLY by interval overlap (if both CIs' lower bounds are equal-or-lower and the point estimate is not higher ⇒ indistinguishable; spell the rule in code comments; it is the doc's "two 14-finding reports with 13 overlapping findings are the same experiment" law).

- [ ] **Step 1: failing tests**: (a) seeded store (Task 7 helper) with synthetic classes where the prior is engineered to reorder the top-K ⇒ `improves` line deterministic; (b) flat store (all one class) ⇒ `indistinguishable`; (c) empty store ⇒ exit 2 with "eval store: no adjudicated rows — the backtest certifies nothing without ground truth" (fail-open on judgment = refuse the claim); (d) `--top 0` ⇒ exit 2 argparse-shaped; (e) run twice ⇒ byte-identical (captured).
- [ ] **Step 2: implement** (pure join code, no new deps; reuse calibration + wilson); help text updates (`t14CorpusSurfaceUsage` — legend/golden: `p3_args_golden.json` pin may move for the usage block ONLY if that file pins corpus-surface usage — check `internal/cli/testdata/p3_args_golden.json`; if it does, update via the golden record command and verify ONLY that entry changed; anything else = BLOCKED).
- [ ] **Step 3: commit** `feat(G3): corpus-surface --backtest — top-K precision vs outcomes, leave-one-out priors, indistinguishable-by-default`.

---
---

### Task 13: G5 `internal/findings/mitigscan.go` — the soundness scanner (ackscan sibling)

**Files:**
- Create: `internal/findings/mitigscan.go`, `internal/findings/mitigscan_test.go`
- Modify: `internal/findings/ingest.go` (post-ingest hook beside the `RecordAckScan` call ~:382)
- Modify: `assets/schema/finding.schema.json` — `dedup_meta.properties` gains `mitigation_present`:

```json
"mitigation_present": {
  "type": "string",
  "description": "G5 soundness layer: a structural defense (guard modifier, CEI order, EIP-712 binding, pull pattern) covers the flagged code. Written ONLY by mitigscan; JSON-encoded string (all values string — dedup_meta additionalProperties is string-only). NEVER auto-dismisses: demotes in risk (Task 14). The POLICY layer (bounty.accepted_risk / check13) never reads or writes this; enforced by non-interference test (Task 15)."
}
```

(STRING holding JSON, not an object — dodges the `additionalProperties: string` wall entirely; same discipline as `corroborated_by` strings. Decode with the local helper at consumption.)

**Patterns (deterministic, regex-over-source; NO AST, NO inference):** scan the finding's affected-file function region (file + region from `affected[0]`, region = function whose name the mechanism text mentions, else whole file). Four patterns, first match wins (ordered list, stable id strings):

1. `"guard-modifier"` — flagged function signature contains `nonReentrant|nonReentrantBefore|nonReentrantAfter|lockRequired|onlyWhenUnlocked` or body opens with `if \(locked\) revert|assert\(!locked\)` and the same file declares a lock boolean written true/false around calls.
2. `"cei-order"` — in the function body, the LAST storage write (`\w+(\[[^\]]*\])?\s*(=|\+=|-=)` on a state var, i.e. any line not inside a `local` decl) occurs BEFORE the first external interaction (`.call\{|\.call\(|\.send\(|\.transfer\(|delegatecall|staticcall`).
3. `"eip712-binding"` — file contains `DOMAIN_SEPARATOR|_hashTypedDataV4|typehash|0x1901` (case-insensitive for the hex).
4. `"pull-pattern"` — file declares a function matching `function\s+(claim|withdraw|redeem|sweep)\w*\(` AND the flagged flow writes a user-scoped balance (`balances?[...\w*]?\s*([-+]?=)` or `owed[...]`) rather than pushing funds.

A match stores `mitigation_present = {"pattern":"cei-order","file":"src/Escrow.sol","line":"23","evidence":"last write at L23 precedes call at L26"}` (JSON with string values; `line` decimal string). NEVER writes `bounty.*`, NEVER changes status, NEVER touches `in_code_ack`.

- [ ] **Step 1: failing tests** — reuse Task 2's evalsuite sources as the fixture oracle (import path `assets.LoadEvalCases` not needed; the files live under `assets/evalsuite/src/` — the test reads them via `assets.EvalSuiteFS.ReadFile`):
  - `ES17CleanControl.sol` `withdraw` → `cei-order` present ✓ (and on `sweep`? no external call — no match on that function, file-scope EIP712 absent, pull: file has `withdraw(` + balance write → pull-pattern would hit — ORDER the patterns so cei-order is checked on the flagged function first; document the exact precedence).
  - `ES03BankReentrancy.sol` withdraw → NO pattern hits (call precedes write; no modifiers) → field absent.
  - `ES16AckDecoyVault.sol` → ackscan hits (phrase) AND mitigscan MAY hit (its body is CEI-correct) — assert both fields coexist independently (this is the tranche's one-two-punch proof).
  - `ES12SignatureReplay.sol` → `eip712-binding` absent (that's the bug — no binding); a sibling `ES12bSignatureOK.sol`? NO new fixture: use the digest-bound portion if ES12 declares a separator for the non-replayed path — if not, assert absent-only + craft a 6-line inline-source test (like ackscan tests) for a positive EIP-712 + a positive pull-pattern + a positive guard-modifier case.
- [ ] **Step 2: implement** `ScanMitigations(c *state.Campaign, f *validation.Value) bool` + `RecordMitigationScan(f, hit)`; hook: after `RecordAckScan` in the ingest path — SAME gate class (only when the finding has a resolvable pinned source file; fail-open silently on any IO error, exactly as ackscan does).
- [ ] **Step 3: golden** — existing golden findings have no scanned source files? golden campaigns DO ingest with code refs in places (h-campaigns use file paths like `src/Vault.sol` not present in snapshots → mitigscan finds no file → no-op → zero bytes). PROVE: golden.sh untouched.
- [ ] **Step 4: Commit** `git add internal/findings assets/schema/finding.schema.json && git commit -m "feat(G5): mitigscan — structural-defense scanner writing dedup_meta.mitigation_present (never bounty fields)"`.

---

### Task 14: G5 mitigation demotion — score-only, field-absent byte law

**Files:** Modify `internal/risk/acceptance.go` (+ test)

- `acceptanceMitigationDemotion = 1.0` const beside `acceptanceAckDemotion`; block AFTER the ack block (same guard shape):

```go
// G5 soundness layer: a structural defense covers the flagged code. A
// guard proves the ONE risk it guards; it never proves the whole payment
// path (the ack law, widened: mitigation demotes, dismissal needs the
// proof). Policy accepted-risk (−2) is a DIFFERENT layer and stays with
// bounty.check13 — this block must never read bounty keys.
if s := objAt(objAt(f, "dedup_meta"), "mitigation_present").S; s != "" {
	var m map[string]string
	if json.Unmarshal([]byte(s), &m) == nil && m["pattern"] != "" {
		score -= acceptanceMitigationDemotion
		entry.Factors["mitigation_present"] = m["pattern"]
	}
}
if score < 0 { score = 0 }
```

- [ ] **Step 1: failing test** — finding with `dedup_meta.mitigation_present` valid JSON ⇒ score exactly `acceptance*0.9 − 1.0` (reuse existing table-driven test rows; pin BOTH demotions stacking: ack + mitigation ⇒ −2; with accepted_risk too ⇒ −4 clamps to 0 and Factors show all three).
- [ ] **Step 2: green + byte law**: absent-field ⇒ `TestCombinedFactors` unchanged; golden untouched.
- [ ] **Step 3: report bullets** — `internal/report/report.go`: the in_code_ack bullet group (~:1572) gains a sibling line for `mitigation_present` under the **correctness/dismissal** bullet: `"why the soundness layer demoted it: <pattern> (<file>:<line>)"`. The accepted-risk bullet (~:1601) must NOT gain it (Task 15 proves the separation). Test in `internal/report` following the ack-bullet test's shape.
- [ ] **Step 4: Commit** `git add internal/risk internal/report && git commit -m "feat(G5): mitigation demotion (score-only) + dismissal-subsection rendering; policy subsection untouched"` — plus legend check: schema added a dedup_meta PROPERTY (not an enum) ⇒ legend file untouched (tranche-1 precedent).

---

### Task 15: G5 separation law — non-interference test + policy `reference_url`

**Files:**
- Modify: `assets/schema/bounty_policy.schema.json` — `accepted_risks` items gain optional `"reference_url": {"type":"string","minLength":8}` (+ description: the program page / scope clause the exclusion cites — G7 hygiene: a policy claim without a reference is still valid but the report stamps it `(no reference cited)`).
- Modify: `internal/bounty/bounty.go` — check13's record builder (~:1231 copy list): pass `reference_url` through when present.
- Modify: `internal/report` accepted-risk bullet: append ` — cites <reference_url>` when present, else ` — no reference cited`.
- Test: `internal/bounty/bounty_test.go` + the non-interference suite below.

**Non-interference law (the task's spine, encode as tests):**

```go
func TestMitigationAndPolicyNeverTouchSameField(t *testing.T) {
	// (a) a finding with BOTH dedup_meta.mitigation_present AND
	//     bounty.accepted_risk: acceptance shows BOTH factors, score −3,
	//     and the record's mitigation entry has no `excluded_by` key while
	//     the accepted-risk entry has no `pattern` key (field-level mix-up
	//     fails at the JSON level).
	// (b) mitigscan's writer surface: RecordMitigationScan given a finding
	//     carrying bounty.accepted_risk MUST NOT modify the bounty object
	//     (deep-compare bounty before/after).
	// (c) check13 given a finding carrying mitigation_present: the
	//     accepted-risk match is byte-identical to without it (deep-compare
	//     the produced record list).
}
```

- [ ] Step order: failing tests (a/b/c) → schema + pass-through + bullets → green → golden untouched (no golden finding carries either field) → commit `test+feat(G5): soundness-vs-policy separation is a law, not a convention — non-interference enforced, reference_url rides`.

---
---

### Task 16: G8 `internal/harness` — deterministic scaffold generator + body-region law

**Files:**
- Create: `internal/harness/harness.go`, `internal/harness/harness_test.go`

**Interfaces:**
- Consumes: the campaign's invariant records (read `internal/invariants`' exported Load — the objects carry `id`, `statement`, `source file/line`, `status`; implementer reads that package first and adapts field names), pinned campaign target source (`internal/state` snapshot paths — same accessor the ackscan/mitigscan source reads use, so the scaffold's `@custom:src` header cites the identical pinned path).
- Produces:

```go
type Kind string
const (Halmos Kind = "halmos"; ForgeFuzz Kind = "forge-fuzz")
// Scaffold renders the harness skeleton for one invariant. Byte-deterministic:
// the ONLY variable content is the invariant data itself; no timestamps, no
// map iteration (emit order: invariant fields in the fixed order below).
func Scaffold(k Kind, inv validation.Value) ([]byte, error)
// BodyRegion locates the model-writable window. Everything OUTSIDE it is
// scaffold bytes and must stay byte-identical when a filled harness is
// validated; Validate rejects edits outside the markers outright.
func BodyRegion(src []byte) (start, end int, err error)
func Validate(k Kind, inv validation.Value, filled []byte) error
```

Markers (exact, on their own lines):

```
// >>> BODY (model writes ONLY between these markers; outside is scaffold)
// <<< BODY
```

Templates (both start with a `pragma solidity >=0.8.0;` header line and the invariant text as a `@custom:invariant` natspec line — the FULL skeleton per kind; keep every line, the tests byte-pin them):

Halmos (`H.t.sol` style, unit-test driven):

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.0;

import "forge-std/Test.sol";
import "halmos-cheatcodes/SymTest.sol";
// @custom:invariant <statement verbatim>
// @custom:src <pinned file>:<line>

contract <CamlName>InvariantHalmos is SymTest, Test {
    // symbol address + symbolic calldata are the model's job INSIDE the body
    function check_<snake(inv.id)>() external {
        // >>> BODY (model writes ONLY between these markers; outside is scaffold)
        // <<< BODY
        assert(<boolExprFrom(inv.predicate)>); // predicate slot: model replaces via body + sets PRED here ONLY if body defines it
    }
}
```

(Simplify honestly: the scaffold's assert line is `revert("unfilled scaffold — the assert slot is the contract");` OUTSIDE the body; the body must end with a concrete `require`/`assert` of its own and the scaffold contains a compile-valid dummy. Write the exact template in code and let the test pin it — the two lines above are the SHAPE law, the code IS the spec.)

forge-fuzz (`fuzz.invariant.t.sol` style): same spine minus SymTest, `function fuzz_<snake>(uint256 seed) external` with the body writing symbolic-ish values from `seed`.

`CamlName`/`snake` = deterministic case helpers local to the package (test them). `Validate` = re-render scaffold, split at markers, byte-compare outside regions, AND require exactly one start + one end marker (duplicate/missing ⇒ error).

- [ ] **Step 1: failing tests**: determinism (Scaffold twice ⇒ equal bytes; two invariants differing only in statement ⇒ only the natspec line differs); Validate accepts an untouched scaffold and a body-filled variant, REJECTS a header-line edit, an added import, a swapped marker, a marker inside a string; snake/caml edge cases (`INV-007a` → `inv_007a`, non-alnum → `_`).
- [ ] **Step 2: implement → green.**
- [ ] **Step 3: compile proof (docker-gated)** — `harness_compile_test.go`: write both templates (with the dummy assert) to `t.TempDir()`, `docker run --rm -v ... ` compile via the repo's existing image (`grep DockerImage() internal/sandbox` for the pinned image), forge-std available from the campaign pattern's `lib/` — reuse whatever the existing docker e2e mounts; SKIP (`t.Skip("docker absent")`) when docker is missing, same as `internal/reproduction`'s pattern. `GOCACHE=$PWD/.gocache go test ./internal/harness/ -count=1` green either way; when docker present: both templates COMPILE clean (zero warnings tolerated = error).
- [ ] **Step 4: Commit** `git add internal/harness && git commit -m "feat(G8): deterministic harness scaffolds — model writes the predicate body, nothing else"`

---

### Task 17: G8 recipes + `verify --scaffold` (no new verb — a flag)

**Files:**
- Modify: `internal/sandbox/profiles.go` (recipe for `halmos` + `forge` fuzz mode), `internal/sandbox/exec.go` (allowlist + `toolVersions` probe list ~:566), `internal/sandbox/exec_test.go`
- Modify: `internal/cli/cmd_verify.go` (`--scaffold {halmos|forge-fuzz} --invariant INV-id`), `internal/cli/cmd_verify_test.go`

- [ ] **Step 0 (presence-gate preflight, REQUIRED before coding):** `which halmos` — installed at `~/.local/bin/halmos` on this box (verified); inside the pinned docker image it may NOT be — the recipe runs on the HOST binary path like slither/aderyn already do (confirm by reading how the `slither` recipe invokes it: host argv vs container exec — mirror EXACTLY that mechanism for halmos; if slither runs inside docker, halmos gets a recipe that runs only when the image ships it, and the probe reports `halmos: absent` honestly in `webv2 verify --probe`-style output if such exists, else in selftest).
- [ ] **Step 1: failing tests**: allowlist accepts `halmos check --root . ...` argv and REJECTS `halmos; rm -rf` shaped argv (same guard style as existing exec tests); `verify --scaffold halmos --invariant INV-1` on a synthetic campaign with one invariant writes `artifacts/harness/INV-1/H.t.sol` (path from the invariant id + kind) and appends an audit event `harness_scaffold {kind, invariant, artifact, scaffold_sha256}` — everything else in the event byte-stable; second run with unchanged invariant ⇒ same bytes + event `harness_scaffold_unchanged` (idempotent); `--invariant INV-missing` ⇒ exit 2 naming the id; `--scaffold bogus` ⇒ usage error listing the two kinds.
- [ ] **Step 2: implement** — profiles: a `halmos` tool profile cloning the slither recipe's fields (network none, read-only mount + writable `out/`); exec.go allowlist += the token(s) the recipe's argv uses; toolVersions probe gains halmos (version string parse fail-open → "unknown"). cmd_verify: flag parse + `harness.Scaffold` write through the campaign's artifact writer (find `writeArtifactFile`-equivalent used by exec findings; reuse, no new store).
- [ ] **Step 3: green; golden untouched** (golden campaigns carry no invariants ⇒ flag never fires; verify that the verify-step count in golden-run doesn't auto-run the new flag — it won't, flags are opt-in).
- [ ] **Step 4: Commit** `git add internal/sandbox internal/cli && git commit -m "feat(G8): halmos/fuzz recipes + verify --scaffold — generation is a flag, not a verb"`

---

### Task 18: G8 outcome mapping → `verification.harness` (the rung rides the FIELD, not the ladder)

**Files:**
- Modify: `assets/schema/invariant.schema.json` (or the real file — find it: the audit section `invariant_verification` has a store object; read `internal/invariants`' schema name at edit time) — add OPTIONAL `verification.harness`: `{"type":"object","additionalProperties":false,"required":["kind","rung","exec"],"properties":{"kind":{"type":"string"},"rung":{"type":"string","enum":["counterexample","proved-bounded","inconclusive"]},"exec":{"type":"string"},"bounded_k":{"type":["integer","null"]},"summary":{"type":"string"}}}`. NOTE the legend law: this is the INVARIANT schema, not `finding` — `t14FindingLegend` walks `SchemaEnumLegend("finding")` ONLY ⇒ no pin dance needed (verify with `GOCACHE=$PWD/.gocache go test ./internal/cli/ -run Legend -count=1`).
- Create: `internal/harness/outcome.go` (+ test) — `MapRun(out []byte, timedOut bool, k int) Rung`:
  - halmos: `Status: fail` (+ counterexample block present) ⇒ `counterexample` with the model values excerpted (first `HalmosCheatCode`/`getSymbolicAddress`/input model line, ≤120 chars); `Successfully proved` + bounded flag ⇒ `proved-bounded` (+bounded_k); timeout ⇒ `inconclusive` (summary "timeout after <k>s" — k passed in, NOT read from the wall); unknown/empty ⇒ `inconclusive` (fail-OPEN-to-inconclusive: a run that proves nothing must never promote OR demote).
  - forge-fuzz: `fail:.` counterexample ⇒ counterexample with fuzz seed line; `Tests: 1 passed` ⇒ proved-bounded (bounded_k = fuzz runs from argv); interrupted ⇒ inconclusive.
- Modify: `internal/cli/cmd_verify.go` or the exec-result hook — wherever `exec` records terminalize (find `execs/EXEC-*/exec_record.json` writer): when an EXEC's command matches a harness profile AND its artifact is a scaffold-carrying invariant, run `MapRun` + write `verification.harness` onto the invariant + audit event `harness_run {rung, exec, invariant}`; counterexample additionally: linked finding (via `--finding` if exec carried one) gains an evidence entry (EXEC link) through the EXISTING evidence path — no status change (promotion rides triage, principle 2); `Validate` (Task 16) runs FIRST on the artifact — a model that edited outside the body ⇒ rung `inconclusive` + summary "scaffold-bound violation: <detail>" and the run's output is NOT used to promote anything.
- Modify: `internal/audit/sections` invariant_verification renderer: presence-gated line per invariant that has `verification.harness`: `INV-3: PROVEN-BOUNDED (halmos, k=100, EXEC-7)` / `counterexample (EXEC-9)` / `inconclusive (EXEC-11)` — absent field ⇒ section bytes unchanged.
- Modify: `internal/learning` negative memory: find the existing "disproved hypothesis" sink (learning records on triage disproval); call the SAME function when a harness run yields `counterexample` for an `intent-claim`-type invariant (the claim is dead: record it); `proved-bounded` on an intent-claim records the POSITIVE twin if such a path exists, else nothing (say which in the report).
- [ ] Tests: MapRun table (each rung × both kinds, including the scaffold-bound rejection path); schema AddCase-style round trip; audit section render pinned for a synthetic invariant with harness (one golden-campaign proof that WITHOUT the field the section is byte-identical — golden.sh); learning call (counterexample on intent claim ⇒ negative record exists).
- [ ] Commit `git add ... && git commit -m "feat(G8): counterexample / PROVEN-BOUNDED / inconclusive — bounded proof is a rung, scaffold edits outside the body are bound-violations"`

---

### Task 19: tranche close-out — docs, erratum, full gates

**Files:** `assets/runbook/RUNBOOK.md` (modify), `docs/IMPROVEMENTS.md` (modify), full gates.

- [ ] **Step 1: Runbook** — after the G1/G6 paragraph added in tranche 1 (`assets/runbook/RUNBOOK.md:321-322` block), append one terse block covering: `corpus-surface --backtest` (what it certifies and its indistinguishable-by-default verdict law); the evalsuite (17 gold cases, `## eval` appears only when the campaign's program matches); mitigscan (`dedup_meta.mitigation_present` — soundness demotion, NOT dismissal; policy layer separate); `verify --scaffold` + harness rungs (PROVEN-BOUNDED = bounded, never unbounded proof; body-region law). Sync manifest + `scripts/runbook-walkthrough.sh` green (the walkthrough greps the runbook for commands that must exist — every command added must RUN: use ones already proven by tasks).
- [ ] **Step 2: IMPROVEMENTS statuses** — G2/G3/G4/G5/G8 → LANDED (this tranche) with the same status-line format tranche 1 used (`docs/IMPROVEMENTS.md`, G-section anchors ~L1918+; grep the exact LANDED line style from G1/G6/G7). Add the **G4 erratum** beside the `recall: 2/2 (95% CI 20–100%)` example: `(erratum 2026-09-11: Wilson 95% for 2/2 is 34.2–100.0 — 20–100 is the 2/3 interval; the framework renders the exact computed value, see internal/wilson pinned table)`. G2: note that weights ship neutral BY DESIGN and graduation requires Task 12's `improves` verdict on real data.
- [ ] **Step 3: Full gates, in order** — `GOCACHE=$PWD/.gocache go vet ./...` ; `GOCACHE=$PWD/.gocache go test ./... -count=1` ; `scripts/golden.sh` ; `scripts/runbook-walkthrough.sh` ; `scripts/verify-full.sh` (13 steps — step 5's double-run determinism: commit EVERYTHING first so no edit lands between run1/run2, tranche-1 lesson) ; `go run ./cmd/webv2 selftest --full`.
- [ ] **Step 4: Commit** `git add assets/runbook docs/IMPROVEMENTS.md && git commit -m "docs(G): tranche 2 close-out — runbook blocks, IMPROVEMENTS statuses, Wilson erratum"`.

---

## Plan Self-Review (done by the plan author; implementers re-verify against code)

1. **Spec coverage:** G4→T1–4, G2→T5–6, G3→T7–12, G5→T13–15, G8→T16–18, close→T19. Every G-doc clause maps: three-weights-as-data T5; refusal-at-boundary T6; priors+Wilson+fallback T7; loaders T8–10; policy-gated wPrior T11; backtest T12; suite≥15/≥8 classes+control+variants T2; CI rendering T1/T3; soundness-vs-policy separation T13–15; scaffold+bounded rungs T16–18. No task references "later plan" except G3 graduation of defaults (explicitly OUT of tranche scope — policy flip needs real backtest data).
2. **Known doc-vs-math conflict:** G4's illustrative `2/2 (95% CI 20–100%)` is wrong (20.8–93.9 is 2/3; 2/2 is 34.2–100.0). Plan renders EXACT Wilson and files the erratum in T19 — never tune math to a doc sentence (G7 discipline).
3. **Byte-risk register:** T2/T5 (new embedded packs: manifest-only additions — allowed, golden compares CAMPAIGN outputs not asset bytes… VERIFY the asset manifest itself is not pinned inside campaign goldens: it isn't — check-golden sections are campaign state). T6 neutral-factor identity. T13 new schema property without enum ⇒ legend safe; mitigscan no-op on golden paths. T11/T14/T15/T18 all presence-gated additions. T12 usage-block risk on `p3_args_golden.json` flagged inline. Any move elsewhere ⇒ BLOCKED, report, never edit fixtures.
4. **Placeholder audit:** the three `NOTE: …real name` indirections (eval-case validator entry, ValidateAssetDoc, invariants schema name) are SEARCH-AND-MIRROR instructions with the sibling to copy named — acceptable for a competent Go dev because the sibling is given; everything else has real code or a pinned table.
5. **Type consistency:** `wilson.Interval(k,n)(lo,hi)` used by evalscore/calibration/backtest; `Prior` struct fields identical across T7/T11/T12; `validation.Value` helpers (`objAt/intAt/…`) per-package convention restated in each task header that uses them; section name `eval` used identically in T4/T19.

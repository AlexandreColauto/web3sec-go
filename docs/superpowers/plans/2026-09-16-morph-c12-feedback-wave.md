# Morph C-12f17fd555 Feedback Wave — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the feedback items from the Morph campaign review (C-12f17fd555) that measurably change detection or scoring outcomes; refuse the rest.

**Architecture:** Eight small, independently testable fixes in the Go framework (`webv2`) plus one data fix in the held-out gold pack. Three of them target the *measured* campaign outcome: the custody probe's true-positive row existed but was quota-cut behind symmetry noise (verified by re-running the surface with `--total 200` — rows `4dc010af55`, `a047e6509f`, `3ec92e56da` appear and name the exact bug), so the fix is noise removal, not extractor changes. Two target the eval join, whose class leg is an exact string compare on both sides (`internal/evalscore/evalscore.go:122-166`). One restores the eval spec's CONFIRMED-only FP budget, one stops synthesized economic equations from being reported as operator model gaps, two are 1-2 LOC hygiene fixes.

**Tech Stack:** Go 1.x stdlib only; no new dependencies. Existing test harness (`go test ./...`), existing scratch-campaign repro flow.

## Global Constraints

- No new dependencies; stdlib only.
- No new asset files, no asset-manifest churn (`assets/testdata/asset_manifest.json` pins sha256s; this wave touches zero embedded assets).
- Golden-pinned outputs (byte-law tests, `scorecard` section order) may change only where a task says the change is intended; every other test must keep passing.
- Repro convention: build with `GOCACHE=/tmp/gocache-webv2 go build -o .scratch/bin/webv2 ./cmd/webv2` (home cache is read-only here); run against a *copy* of the campaign at `.scratch/repro-c/campaigns/C-12f17fd555` (copied from `../morph/campaigns/`), never the original — `probes run` and `report` write.
- Commit style: conventional commits (`fix:`, `test:`, `docs:`), one commit per task.
- Python twin (`web3sec-final`) is deprecated; fixes are intentional Go-side decisions, no divergence ledger row needed (ledger is archived at `docs/archive/`).

---

### Task 1: Reconcile gate must accept cites for `members` it demands

**Files:**
- Modify: `internal/planner/disposition.go:377-380` (`rowSymbolKeys`)
- Test: `internal/planner/disposition_members_test.go` (create)

**Interfaces:**
- Consumes: `RowSymbols(row validation.Value) []string` (existing, `internal/planner/disposition.go`).
- Produces: `rowSymbolKeys` now includes `"members"`, so a cite naming a family member that the reconcile gate requires (`internal/planner/reconcile.go:338-354`) passes the cite validator instead of being refused (`reconcile.go:352-353`).

This is the L-04 blocker from the review §8a: the required-member set lists 34 members the cite validator then refuses, because `members` is absent from `rowSymbolKeys`. One line.

- [ ] **Step 1: Write the failing test**

```go
// disposition_members_test.go — the reconcile gate demands cites for the
// members it lists; RowSymbols (the cite validator's vocabulary) must
// therefore read the row's members field too. C-12f17fd555 §8a: row
// b6c0484194 demanded 34 members and refused every one of them.
package planner

import (
	"testing"

	"websec/internal/validation"
)

func TestRowSymbolsIncludeMembers(t *testing.T) {
	row := validation.VObj(
		validation.KV{K: "contract", V: validation.VStr("L1ReverseCustomGateway")},
		validation.KV{K: "members", V: validation.VArr(
			validation.VStr("IL1ERC20Gateway"),
			validation.VStr("L1ERC721Gateway"),
		)},
	)
	got := RowSymbols(row)
	for _, want := range []string{"L1ReverseCustomGateway", "IL1ERC20Gateway", "L1ERC721Gateway"} {
		found := false
		for _, s := range got {
			if s == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("RowSymbols missing member %q; got %v", want, got)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/planner/ -run TestRowSymbolsIncludeMembers -v`
Expected: FAIL — `RowSymbols missing member "IL1ERC20Gateway"`.

- [ ] **Step 3: Implement (one line)**

In `internal/planner/disposition.go`, extend the var (keep the listed order; `members` is the least specific, so it goes last):

```go
var rowSymbolKeys = []string{
	"contract", "consumer", "base", "asserter", "custody",
	"concept_keys", "forward", "siblings", "members",
}
```

- [ ] **Step 4: Run the planner test suite**

Run: `go test ./internal/planner/`
Expected: PASS. If a pinned refusal-message golden includes the offered-symbol list, update that golden — the list growing is the intended change.

- [ ] **Step 5: Commit**

```bash
git add internal/planner/disposition.go internal/planner/disposition_members_test.go
git commit -m "fix(planner): reconcile cites may name row members (C-12f17fd555 8a)"
```

---

### Task 2: Class synonyms — canonicalize on BOTH sides of the eval join + say so at ingest

**Files:**
- Modify: `internal/taxonomy/taxonomy.go` (add `classSynonyms` + `CanonicalClass`, and a synonym branch in `ClassAdvisory`)
- Modify: `internal/evalscore/evalscore.go:122-166` (`anchor`, `goldAcceptsClass`)
- Test: `internal/evalscore/synonym_test.go` (create), `internal/taxonomy/classsynonyms_test.go` (create)

**Interfaces:**
- Consumes: `anchor(f, gold)` (package-private, evalscore); `ClassAdvisory(bugClass *string, campaign *state.Campaign) string` (taxonomy, wired via `findings.SetClassAdvisory`).
- Produces: `taxonomy.CanonicalClass(class string) string` — identity for unlisted labels, canonical class for listed synonyms, never `"unmapped"`. The join uses it on the finding side AND the gold side (`bug_class` + every `bug_class_accept` entry).

Evidence: the review's §8b/§10. `denial-of-service` is not one of the 23 canonical classes; `closeMatches("denial-of-service", …, 0.6)` returns nothing (measured: difflib ratio 0.21 vs `dos-griefing`), so the existing ingest advisory printed no suggestion; `anchor()` compares exact strings, so the finding anchored nothing. A fuzzy matcher cannot bridge a synonym — an explicit map can. G-02's miss (canonical `bridge-message` refused by accept list `{logic-error, token-integration}`) is pack data, fixed in Task 9, not here.

- [ ] **Step 1: Write the failing tests**

`internal/taxonomy/classsynonyms_test.go`:

```go
package taxonomy

import "testing"

func TestCanonicalClass(t *testing.T) {
	cases := []struct{ in, want string }{
		{"denial-of-service", "dos-griefing"},
		{"Denial-of-Service", "dos-griefing"}, // case-insensitive key, canonical value
		{"dos-griefing", "dos-griefing"},      // canonical passes through
		{"bridge-message", "bridge-message"},
		{"totally-unknown", "totally-unknown"}, // identity: unknown stays unknown
		{"", ""},
	}
	for _, tc := range cases {
		if got := CanonicalClass(tc.in); got != tc.want {
			t.Errorf("CanonicalClass(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if CanonicalClass("weird") == "unmapped" {
		t.Fatal("CanonicalClass must never invent the unmapped verdict")
	}
}
```

`internal/evalscore/synonym_test.go`:

```go
package evalscore

import "testing"

// The C-12f17fd555 miss: the finding's class is a synonym of the gold
// bug_class; the location and mechanism legs pass, the class leg alone
// decided the miss.
func TestAnchorCanonicalizesSynonymClass(t *testing.T) {
	f := finding("denial-of-service", "src/Rollup.sol")
	g := goldCase("CASE-SYN", "p1", "confirmed-exploitable", "dos-griefing", "gold/Rollup.sol")
	if !anchor(f, obj(g, "gold")) {
		t.Fatal("synonym class must anchor its canonical gold bug_class")
	}
	// Gold side too: a pack that files the synonym must accept the canonical
	// finding class (the review's counter-case direction).
	f2 := finding("dos-griefing", "src/Rollup.sol")
	g2 := goldCase("CASE-SYN2", "p1", "confirmed-exploitable", "denial-of-service", "gold/Rollup.sol")
	if !anchor(f2, obj(g2, "gold")) {
		t.Fatal("canonical class must anchor a gold row filed under its synonym")
	}
	// Unknown labels still anchor nothing — fail-closed is unchanged.
	f3 := finding("totally-unknown", "src/Rollup.sol")
	if anchor(f3, obj(g, "gold")) {
		t.Fatal("unknown class must not anchor")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/taxonomy/ -run TestCanonicalClass -v && go test ./internal/evalscore/ -run TestAnchorCanonicalizesSynonymClass -v`
Expected: FAIL — `CanonicalClass` undefined; anchor returns false for the synonym pair.

- [ ] **Step 3: Implement**

In `internal/taxonomy/taxonomy.go`, near `ClassReport` (line ~174), add:

```go
// classSynonyms maps labels auditors file in practice (the standards
// vocabulary and informal kebab-case) to the canonical class. Applied by
// CanonicalClass on BOTH sides of the eval join and by the ingest advisory.
// Identity for any label not listed — an unlisted label keeps anchoring
// nothing. ponytail: three entries where the campaign measured misses; add
// entries as measured misses arrive, not speculatively.
var classSynonyms = map[string]string{
	"denial-of-service": "dos-griefing",
}

// CanonicalClass is the synonym layer over the taxonomy: a listed label
// becomes its canonical class (keyed case-insensitively, the canonical form
// is returned lowercase); everything else is returned unchanged and stays
// non-canonical. It never returns "unmapped" — only explicit entries move a
// label, so the eval join's fail-closed behavior is untouched.
func CanonicalClass(class string) string {
	if c, ok := classSynonyms[strings.ToLower(strings.TrimSpace(class))]; ok {
		return c
	}
	return class
}
```

In `internal/evalscore/evalscore.go`, change the two class-leg call sites (`anchor` line 123, `goldAcceptsClass` lines 157-165):

```go
func anchor(f, gold validation.Value) bool {
	if !goldAcceptsClass(gold, taxonomy.CanonicalClass(field(obj(f, "root_cause"), "class"))) {
		return false
	}
	// ... mechanism leg unchanged ...
```

```go
func goldAcceptsClass(gold validation.Value, class string) bool {
	if class == "" {
		return false
	}
	if class == taxonomy.CanonicalClass(field(gold, "bug_class")) {
		return true
	}
	for _, v := range obj(gold, "bug_class_accept").A {
		if v.Kind == validation.Str && taxonomy.CanonicalClass(v.S) == class {
			return true
		}
	}
	return false
}
```

Add `"websec/internal/taxonomy"` to evalscore's imports. If `go build ./...` reports an import cycle (taxonomy must not import evalscore — it doesn't today), move `CanonicalClass`/`classSynonyms` into `internal/classweights` instead and import from both sides; do not add a cycle.

Still in `internal/taxonomy/taxonomy.go`, in `ClassAdvisory` (line ~225), insert the synonym branch first — the operator must hear that the class is scoring-load-bearing *at ingest*, which is the review's actual complaint:

```go
	if bugClass != nil {
		if canon := CanonicalClass(*bugClass); canon != *bugClass {
			return fmt.Sprintf("class %s is a synonym of canonical %s — use %s "+
				"(it decides the CONFIRMED floor AND whether the finding can "+
				"anchor a gold case).",
				validation.PyReprStr(*bugClass), validation.PyReprStr(canon), canon)
		}
	}
```

- [ ] **Step 4: Run both package suites**

Run: `go test ./internal/taxonomy/ ./internal/evalscore/`
Expected: PASS. `go build ./...` clean (no import cycle).

- [ ] **Step 5: Verify against the real campaign (the measured outcome)**

```bash
GOCACHE=/tmp/gocache-webv2 go build -o .scratch/bin/webv2 ./cmd/webv2
.scratch/bin/webv2 --root .scratch/repro-c scorecard C-12f17fd555 --gold ../targets/morph-gold-cases.json 2>&1 | sed -n '/eval/,/adjusted/p'
```
Expected: G-01 (`denial-of-service` finding, `dos-griefing` gold) now anchors — recall moves 0/2 → 1/2. G-02 stays a miss until Task 9. Record the numbers in the commit message body.

- [ ] **Step 6: Commit**

```bash
git add internal/taxonomy/taxonomy.go internal/taxonomy/classsynonyms_test.go internal/evalscore/evalscore.go internal/evalscore/synonym_test.go
git commit -m "fix(eval): canonicalize class synonyms on both join sides + advisory"
```

---

### Task 3: Custody/symmetry probes must ignore test-double members

**Files:**
- Modify: `internal/probes/symmetry.go:377-395` (`PrimitiveMatrix` member loop)
- Test: `internal/probes/symmetry_testdouble_test.go` (create)

**Interfaces:**
- Consumes: `IsTestDoublePath(path string) bool` (existing, `internal/probes/collapse.go:18` → `srcclass.IsTestDouble`); `contractNodes(index)` nodes carry a `"path"` field.
- Produces: family cells no longer include cells contributed by test-double contracts, so all-test-double divergences (8 of the 12 quota-filling rows in the measured campaign: `d030096914`, `dd688b424a`, `a283479dbb`, `6476df1a6d`, `5c2f2bd715`, `83797a7db6`, `d47a01a479`, `994b7e202f`) disappear from the surface.

- [ ] **Step 1: Write the failing test**

```go
// symmetry_testdouble_test.go — a test harness is not a custody member: its
// mint/burn cells are fixture noise that outranks real pairings in the
// per-axis quota (C-12f17fd555: 8 of 12 custody slots were MockTree/test_*
// rows, and the true-positive onDropMessage rows sat in the cut tail).
package probes

import (
	"testing"

	"websec/internal/validation"
)

func TestSymMemberIsTestDouble(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"contracts/contracts/test/MorphTokenTest.sol", true},
		{"contracts/contracts/mocks/MockRollup.sol", true},
		{"contracts/contracts/l1/gateways/L1ERC20Gateway.sol", false},
		{"contracts/contracts/l2/Staking.sol", false},
	}
	for _, tc := range cases {
		node := validation.VObj(validation.KV{K: "path", V: validation.VStr(tc.path)})
		if got := symMemberIsTestDouble(node); got != tc.want {
			t.Errorf("symMemberIsTestDouble(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/probes/ -run TestSymMemberIsTestDouble -v`
Expected: FAIL — `symMemberIsTestDouble` undefined.

- [ ] **Step 3: Implement**

In `internal/probes/symmetry.go`, add the guard (next to `symmetryCells`):

```go
// symMemberIsTestDouble reports whether a family member contract node is a
// test double (its declaring file classifies as one). Test harnesses are not
// custody members: their mint/burn cells are fixture noise that fills the
// per-axis emit quota ahead of real pairings. Reuses srcclass via
// IsTestDoublePath — the same rule collapse.go already applies when folding.
func symMemberIsTestDouble(cnode validation.Value) bool {
	return IsTestDoublePath(vStr(cnode, "path"))
}
```

and in `PrimitiveMatrix`'s member loop, skip test-double members:

```go
		for _, cnode := range contractNodes(index) {
			cname := vStr(cnode, "name")
			if _, ok := memberSet[cname]; !ok {
				continue
			}
			if symMemberIsTestDouble(cnode) {
				continue
			}
```

- [ ] **Step 4: Run the probes suite**

Run: `go test ./internal/probes/`
Expected: PASS. Where an existing golden pins the count of test-double rows, that count dropping is the intended change — update the golden, not the rule.

- [ ] **Step 5: Verify against the real campaign**

```bash
GOCACHE=/tmp/gocache-webv2 go build -o .scratch/bin/webv2 ./cmd/webv2
.scratch/bin/webv2 --root .scratch/repro-c probes C-12f17fd555 run --per-axis 12 --total 40 >/dev/null
python3 - <<'PY'
import json
s = json.load(open('.scratch/repro-c/campaigns/C-12f17fd555/artifacts/probe_surface.json'))
cr = [r for r in s['rows'] if r['probe'] == 'custody-primitive']
test_rows = [r['row_id'] for r in cr if 'test_' in r.get('consumer', '') or 'Mock' in json.dumps(r.get('siblings', []))]
print('custody rows:', len(cr), 'test-double rows:', len(test_rows))
PY
```
Expected: `test-double rows: 0`.

- [ ] **Step 6: Commit**

```bash
git add internal/probes/symmetry.go internal/probes/symmetry_testdouble_test.go
git commit -m "fix(probes): test doubles are not custody/symmetry members"
```

---

### Task 4: Sibling disagreement must not pair across token standards

**Files:**
- Modify: `internal/probes/symmetry.go:78-111` (`symmetryCells`) + one helper
- Test: `internal/probes/symmetry_asset_test.go` (create)

**Interfaces:**
- Consumes: the external-call receiver embedded in the indexed call string (`"IERC1155Upgradeable.safeTransferFrom"`, `"IERC20Upgradeable.safeTransfer"` — verified in the campaign's `structural_index.json`).
- Produces: cells carry asset `erc1155`/`erc721` instead of `erc20` when the receiver names that standard, so `symmetryDivergencesOf` (which groups by `Direction+"\x00"+Asset`, `symmetry.go:277-279`) stops pairing ERC-20 gateways against ERC-1155/721 gateways (campaign rows `b6c0484194`, `be5532323d`, `135acfc612`, `4badf2ba8a`, `a836f14fd6` — the review's "top-ranked noise").

- [ ] **Step 1: Write the failing test**

```go
// symmetry_asset_test.go — the verb table collapses every token call to
// "erc20", so an ERC-1155/721 gateway "disagrees" with an ERC-20 gateway over
// the same verb. A member-disagreement across token standards is noise.
package probes

import (
	"testing"

	"websec/internal/validation"
)

func nodeWith(calls ...string) validation.Value {
	arr := make([]validation.Value, 0, len(calls))
	for _, c := range calls {
		arr = append(arr, validation.VStr(c))
	}
	return validation.VObj(validation.KV{K: "calls_external", V: validation.VArr(arr...)})
}

func TestSymmetryCellsAssetStandard(t *testing.T) {
	cases := []struct {
		call string
		want string
	}{
		{"IERC20Upgradeable.safeTransfer", "erc20"},
		{"IMorphERC20Upgradeable.burn", "erc20"},
		{"IERC1155Upgradeable.safeTransferFrom", "erc1155"},
		{"IERC721Upgradeable.safeTransferFrom", "erc721"},
	}
	for _, tc := range cases {
		cells := symmetryCells("C", "deposit", 1, nodeWith(tc.call))
		if len(cells) != 1 {
			t.Fatalf("%s: expected 1 cell, got %d", tc.call, len(cells))
		}
		if cells[0].Asset != tc.want {
			t.Errorf("%s: asset = %q, want %q", tc.call, cells[0].Asset, tc.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/probes/ -run TestSymmetryCellsAssetStandard -v`
Expected: FAIL — 1155/721 cells report asset `"erc20"`.

- [ ] **Step 3: Implement**

In `internal/probes/symmetry.go`, add above `symmetryCells`:

```go
// symAssetOf refines the asset label from a call's receiver: the verb table
// above collapses every token call to "erc20", which made an ERC-1155/721
// gateway disagree with an ERC-20 gateway over the same verb. Receiver-name
// matching is deliberately shallow — the indexed call string already carries
// the interface name.
// ponytail: receiver substring (1155/721); a per-interface kind table only if
// a mislabeled receiver ever shows up in a campaign.
func symAssetOf(call, def string) string {
	recv := call
	if i := lastIndexByte(recv, '.'); i >= 0 {
		recv = recv[:i]
	}
	rl := lower(recv)
	switch {
	case strings.Contains(rl, "1155"):
		return "erc1155"
	case strings.Contains(rl, "721"):
		return "erc721"
	}
	return def
}
```

and in `symmetryCells`' external-calls switch, replace the four `"erc20"` literals with `symAssetOf(low, "erc20")`:

```go
		switch {
		case inSet(mintCalls, method):
			hits = append(hits, hit{"mint", symAssetOf(low, "erc20")})
		case inSet(burnCalls, method):
			hits = append(hits, hit{"burn", symAssetOf(low, "erc20")})
		case hasPrefix(low, "low-level."), method == "sendvalue", method == "transfereth":
			hits = append(hits, hit{"send-native", "native"})
		case inSet(payCalls, method):
			hits = append(hits, hit{"transfer-out", symAssetOf(low, "erc20")})
		case inSet(inCalls, method):
			hits = append(hits, hit{"transfer-in", symAssetOf(low, "erc20")})
		}
```

Internal mint/burn stay `"share"`; native stays `"native"`.

- [ ] **Step 4: Run the probes suite**

Run: `go test ./internal/probes/`
Expected: PASS, goldens for cross-standard disagreement rows updated where pinned (intended change).

- [ ] **Step 5: Verify against the real campaign (the measured outcome)**

Repeat Task 3 Step 5's run, then:

```bash
python3 - <<'PY'
import json
s = json.load(open('.scratch/repro-c/campaigns/C-12f17fd555/artifacts/probe_surface.json'))
cr = [r for r in s['rows'] if r['probe'] == 'custody-primitive']
cross = [r['row_id'] for r in cr if '1155' in r.get('why', '') or '721' in r.get('why', '')]
drop = [r for r in s['rows'] if 'onDrop' in r.get('consumer', '')]
print('custody rows:', len(cr), 'cross-standard rows:', len(cross))
print('onDropMessage rows emitted at default quota:', [r['row_id'] for r in drop])
PY
```
Expected: cross-standard rows 0; at default quota (`--per-axis 12 --total 40`) the `onDropMessage` rows (`4dc010af55`, `a047e6509f`, `3ec92e56da`) are now **emitted**, not tail-cut — the flagship row the operator had to find by reading.

- [ ] **Step 6: Commit**

```bash
git add internal/probes/symmetry.go internal/probes/symmetry_asset_test.go
git commit -m "fix(probes): gate sibling disagreement on token standard"
```

---

### Task 5: FP budget — split the precision denominator by CONFIRMED status

**Files:**
- Modify: `internal/evalscore/evalscore.go` (`Report` struct ~line 55, `ScoreSuiteWith` precision loop ~line 469)
- Modify: `internal/cli/cmd_scorecard.go:617-634` (text render) and `:773-781` (JSON render)
- Test: `internal/evalscore/confirmed_split_test.go` (create)

**Interfaces:**
- Consumes: `finding(class, path)` and `goldCase(...)` fixtures from `internal/evalscore/evalscore_test.go`; `validation.SetOrAppend`.
- Produces: `Report.ConfirmedLive`, `Report.ConfirmedAnchored` (ints), `Report.ConfirmedPrecisionLine` (string; `""` when the program has no CONFIRMED live findings). Raw `FP` semantics unchanged.

The review's §10a, measured: the scorer's FP denominator counted 6 live findings (5 CONFIRMED + 1 POSSIBLE) while the eval spec says "count all other CONFIRMED findings" (4). Under the raw rule, an honestly-labelled unproven hypothesis is priced exactly like a fabrication.

- [ ] **Step 1: Write the failing test**

```go
// confirmed_split_test.go — the eval spec's false-positive budget counts
// "all other CONFIRMED findings"; the raw FP count includes live POSSIBLE
// rows. Both numbers stay visible; the incentive to file honest hypotheses
// is restored by printing the split (C-12f17fd555 §10a).
package evalscore

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

func withStatus(class, path, status string) validation.Value {
	f := finding(class, path)
	f.O = validation.SetOrAppend(f.O, "status", validation.VStr(status))
	return f
}

func TestConfirmedPrecisionSplit(t *testing.T) {
	r := mustScore(t, testSuite(), map[string][]validation.Value{
		"p1": {
			withStatus("access-control", "src/Vault.sol", "CONFIRMED"),      // anchors CASE-A
			withStatus("oracle-manipulation", "src/Other.sol", "CONFIRMED"), // raw FP
			withStatus("unmatched-class", "src/Hyp.sol", "POSSIBLE"),        // raw FP, not a claim
		},
		"ctrl": {},
	})
	if r.FP != 2 {
		t.Fatalf("raw FP = %d, want 2 (raw semantics unchanged)", r.FP)
	}
	if r.ConfirmedLive != 2 || r.ConfirmedAnchored != 1 {
		t.Fatalf("confirmed split = %d/%d, want 2 live / 1 anchored", r.ConfirmedLive, r.ConfirmedAnchored)
	}
	if !strings.Contains(r.ConfirmedPrecisionLine, "1/2") {
		t.Fatalf("ConfirmedPrecisionLine = %q, want the 1/2 wilson line", r.ConfirmedPrecisionLine)
	}
}

func TestConfirmedPrecisionEmptyProgram(t *testing.T) {
	r := mustScore(t, testSuite(), map[string][]validation.Value{
		"p1":   {withStatus("unmatched-class", "src/Hyp.sol", "POSSIBLE")},
		"ctrl": {},
	})
	if r.ConfirmedPrecisionLine != "" {
		t.Fatalf("no CONFIRMED findings: line = %q, want empty", r.ConfirmedPrecisionLine)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/evalscore/ -run 'TestConfirmedPrecision' -v`
Expected: FAIL — `r.ConfirmedLive` undefined (compile error).

- [ ] **Step 3: Implement**

In `Report` (after `AdjustedPrecisionLine`, keep the comment style):

```go
	// ConfirmedLive/ConfirmedAnchored split the precision scope by status:
	// the eval spec's FP budget counts "all other CONFIRMED findings", while
	// the raw FP counts every live finding — an honest POSSIBLE hypothesis
	// must not be priced like a fabrication. Both numbers print; the raw
	// number stays the harsh one.
	ConfirmedLive, ConfirmedAnchored int
	ConfirmedPrecisionLine           string
```

In `ScoreSuiteWith`, in the precision-scope loop:

```go
	confirmedLive, confirmedAnchored := 0, 0
	for _, p := range scopedPrograms(matched) {
		fs := live[p]
		liveTotal += len(fs)
		for i := range fs {
			confirmed := field(fs[i], "status") == "CONFIRMED"
			if confirmed {
				confirmedLive++
			}
			if anchorsAny(fs[i], byProg[p]) {
				anchored++
				if confirmed {
					confirmedAnchored++
				}
				continue
			}
			// ... existing adjudication switch unchanged ...
		}
	}
```

after `r.AdjustedPrecisionLine = ...` add:

```go
	r.ConfirmedLive = confirmedLive
	r.ConfirmedAnchored = confirmedAnchored
	if confirmedLive > 0 {
		r.ConfirmedPrecisionLine = wilson.Format(confirmedAnchored, confirmedLive, "precision")
	}
```

In `internal/cli/cmd_scorecard.go`, text render — insert one row after the raw-FP row (line ~620):

```go
		if r.ConfirmedPrecisionLine != "" {
			scRow(w, "false positives (CONFIRMED-only, the eval-spec budget): %d",
				r.ConfirmedLive-r.ConfirmedAnchored)
			scRow(w, "%s (CONFIRMED claims only)", r.ConfirmedPrecisionLine)
		}
```

and the JSON block (line ~773), after `scKV("adjusted_precision", ...)`:

```go
	if r.ConfirmedPrecisionLine != "" {
		scKV("confirmed_live", validation.VInt(int64(r.ConfirmedLive)))
		scKV("confirmed_precision", validation.VStr(r.ConfirmedPrecisionLine))
	}
```

- [ ] **Step 4: Run the evalscore + cli suites**

Run: `go test ./internal/evalscore/ ./internal/cli/`
Expected: PASS. Scorecard section goldens gain two rows only when `--gold` is loaded with CONFIRMED findings — update pinned goldens where the section is pinned (intended).

- [ ] **Step 5: Commit**

```bash
git add internal/evalscore/evalscore.go internal/evalscore/confirmed_split_test.go internal/cli/cmd_scorecard.go
git commit -m "feat(eval): CONFIRMED-only precision split beside the raw FP count"
```

---

### Task 6: Synthesized economic equations are templates, not operator gaps

**Files:**
- Modify: `internal/economics/economics.go` (`add()` ~line 155, `EquationGaps` ~line 214)
- Test: `internal/economics/synthesized_test.go` (create)

**Interfaces:**
- Consumes: `BuildEquations(model)` — `add()` appends "universal" template equations with `kv("enforced_by", validation.VArr())` (empty by construction), which `EquationGaps` then reports as unfinished model.
- Produces: synthesized rows carry `synthesized: true`; `EquationGaps` skips them. Recorded relations are unaffected. The report stops accusing the operator of a gap no operator input can clear (`internal/economics/economics.go:159-170`, review §2).

- [ ] **Step 1: Write the failing test**

```go
// synthesized_test.go — the universal template equations carry empty
// enforced_by BY CONSTRUCTION; reporting them as equation gaps accuses the
// operator of a gap that no operator input can clear without guessing an
// internal literal (C-12f17fd555: "sum(user_claims) + protocol_liabilities
// <= total_assets" flagged with 3 recorded relations, all enforced).
package economics

import (
	"testing"

	"websec/internal/validation"
)

func accountingModel() validation.Value {
	// One accounting variable is enough to trigger the universal
	// sum(user_claims) template (AccountingVars non-empty).
	return validation.VObj(
		validation.KV{K: "state_variables", V: validation.VArr(
			validation.VObj(
				validation.KV{K: "name", V: validation.VStr("totalAssets")},
				validation.KV{K: "kind", V: validation.VStr("accounting")},
			),
		)},
	)
}

func TestEquationGapsSkipSynthesized(t *testing.T) {
	gaps := EquationGaps(accountingModel())
	for _, g := range gaps {
		eq := objStr(g, "equation")
		if eq == "sum(user_claims) + protocol_liabilities <= total_assets" {
			t.Fatalf("synthesized template reported as a gap: %+v", g)
		}
	}
	// The template still exists in the equation list — adoptable, not hidden.
	found := false
	for _, eq := range BuildEquations(accountingModel()) {
		if objStr(eq, "equation") == "sum(user_claims) + protocol_liabilities <= total_assets" {
			found = true
			if !validation.PyTruthy(objAt(eq, "synthesized")) {
				t.Fatal("template equation must carry synthesized: true")
			}
		}
	}
	if !found {
		t.Fatal("template equation missing from BuildEquations")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/economics/ -run TestEquationGapsSkipSynthesized -v`
Expected: FAIL — either the gap is reported, or `synthesized` is absent. (If `accountingModel()` fails to trigger the template, check `protocolgraph.AccountingVars`'s expected field shape in `internal/protocolgraph/` and adjust the fixture — the assertion stays.)

- [ ] **Step 3: Implement**

In `add()`, tag the row:

```go
		eqs = append(eqs, validation.VObj(
			kv("id", validation.VStr(fmt.Sprintf("EQ-%03d", len(eqs)+1))),
			kv("equation", validation.VStr(eq)),
			kv("meaning", validation.VStr(meaning)),
			kv("variables", strArr(variables...)),
			kv("enforced_by", validation.VArr()),
			kv("breakable_by", strArr(breakable...)),
			kv("synthesized", validation.VBool(true)),
		))
```

In `EquationGaps`, skip templates:

```go
	for _, eq := range BuildEquations(model) {
		if validation.PyTruthy(objAt(eq, "synthesized")) {
			continue // a template ships with empty enforced_by by construction
		}
```

- [ ] **Step 4: Run the economics + report suites**

Run: `go test ./internal/economics/ ./internal/report/`
Expected: PASS. `economics_test.go:280` (dup_eq_model gaps) is unaffected — its gaps come from recorded rows. Where a report golden pins the `## Protocol economics` warning line, its disappearance is the intended change.

- [ ] **Step 5: Commit**

```bash
git add internal/economics/economics.go internal/economics/synthesized_test.go
git commit -m "fix(economics): synthesized template equations are not equation gaps"
```

---

### Task 7: Two hygiene fixes — model error flood + build-output drag

**Files:**
- Modify: `internal/protocolgraph/protocolgraph.go:196` and `:220` (`maxErrors` 1 → 25)
- Modify: `internal/snapshot/ladder.go:19-31` (`BulkSourceExcludes` += `forge-artifacts`, `broadcast`)
- Test: `go test ./internal/protocolgraph/ ./internal/snapshot/`

**Interfaces:**
- Consumes: `validation.Validate(doc, name, maxErrors)` — with maxErrors > 1 the renderer (`internal/validation/schema_render.go:310-331`) already prints the "also at" path list; only the call-site cap changes.
- Produces: a malformed protocol model reports up to 25 exact paths in one round trip (the review's 119-error `+118 more`); `forge build` output dirs are excluded from pins by default (review §3 — the 281-file `forge-artifacts` drag).

- [ ] **Step 1: Change the two call sites**

Both lines read `validation.Validate(model, "protocol_model", 1)`; change to:

```go
		if err := validation.Validate(model, "protocol_model", 25); err != nil {
```

- [ ] **Step 2: Change the exclude map**

```go
var BulkSourceExcludes = map[string]struct{}{
	"data":            {},
	"datasets":        {},
	"data-raw":        {},
	".scratch":        {},
	"webv2-workspace": {},
	".pytest_cache":   {},
	".mypy_cache":     {},
	".ruff_cache":     {},
	".tox":            {},
	"build":           {},
	"dist":            {},
	"forge-artifacts": {}, // forge build output; in-tree builds must not enter the audit surface
	"broadcast":       {}, // forge script broadcast artifacts
}
```

- [ ] **Step 3: Run the suites**

Run: `go test ./internal/protocolgraph/ ./internal/snapshot/`
Expected: PASS. Any golden pinning an exclude-list rendering gains the two entries (intended).

- [ ] **Step 4: Verify the model-error flood is gone**

```bash
GOCACHE=/tmp/gocache-webv2 go build -o .scratch/bin/webv2 ./cmd/webv2
.scratch/bin/webv2 --root .scratch/repro-c model C-12f17fd555 load --json <(python3 -c "
import json,sys
d=json.load(open('.scratch/repro-c/campaigns/C-12f17fd555/artifacts/protocol_model.json'))
d['contracts'][0]['state_variables'][0]={'committedBatches':'oops'}
print(json.dumps(d))") 2>&1 | head -4
```
Expected: multiple exact `contracts/0/...` paths listed in one message, no `(+N more errors)` truncation for ≤25 errors.

- [ ] **Step 5: Commit**

```bash
git add internal/protocolgraph/protocolgraph.go internal/snapshot/ladder.go
git commit -m "fix(cli): report 25 model errors at once; exclude forge build output from pins"
```

---

### Task 8: Make the disposition + grading contracts discoverable

**Files:**
- Modify: `internal/cli/cmd_answered.go` (help block ~lines 69-108: print the per-probe anchor table)
- Modify: `internal/cli/cmd_plan.go` (summary block: scorecard pointer line)
- Modify: `assets/runbook/RUNBOOK.md` (operator contract block near the ingest advisory, ~line 522)
- Test: `go test ./internal/cli/`

**Interfaces:**
- Consumes: `anchorFields` (`internal/probes/registry.go:127-140`) — the per-probe anchor enum already exists; the help currently prints only the union (`cmd_answered.go:69-77`).
- Produces: `answered --help` names each probe's anchor/ref/passes shapes; `plan` output points at `scorecard --gold`; the runbook states the three machine-read fields. No new flag, no new verb (per-row `--explain` is deliberately deferred — see the cut list).

- [ ] **Step 1: Print the per-probe anchor table in `answered --help`**

In `cmd_answered.go`, extend the help text after the union-enum block with lines rendered from `anchorFields` (import `"websec/internal/probes"`; render deterministically in sorted probe order):

```go
// t29AnchorHelp renders the per-probe anchor contract (anchorFields) into the
// answered help text: dispositioning cost one failure per row type because
// the required anchor/ref shapes lived in the registry, not the help
// (C-12f17fd555 §8c).
```

Render loop (build the string once, keep it a pure function so a table test can pin it):

```go
func anchorHelp() string {
	probes := make([]string, 0, len(anchorFields))
	for p := range anchorFields {
		probes = append(probes, p)
	}
	sort.Strings(probes)
	var b strings.Builder
	b.WriteString("  per-probe anchors (the anchor must be one the probe produced):\n")
	for _, p := range probes {
		names := make([]string, 0, len(anchorFields[p]))
		for a := range anchorFields[p] {
			names = append(names, a)
		}
		sort.Strings(names)
		fmt.Fprintf(&b, "    %s: --anchor %s\n", p, strings.Join(names, "|"))
	}
	return b.String()
}
```

and append `anchorHelp()` to the answered usage text (`cmd_answered.go:69-77`) where the union enum is printed. Row-type ref conventions (assertion-strength → consumer `file#L`; trust-assumption → actor name; custody-primitive → primitive verb or `--anchor base` with `file#L`; short-circuitable-guard → the guard expression; `--passes` takes a literal, not prose) go into the same help block as one line each — copy the wording from §8c of the review, which the failure messages already imply.

- [ ] **Step 2: Add the scorecard pointer to plan output**

In `cmd_plan.go`, in the block that prints the plan summary (the same block that prints the E5/E6-unreachable lines, `cmd_plan.go:176-186`), add one line:

```go
	fmt.Fprintln(out, "grading: webv2 scorecard <campaign> --gold <pack.json> — run a dry join before closing (read-only)")
```

- [ ] **Step 3: Runbook — the operator contract for the machine-read fields**

In `assets/runbook/RUNBOOK.md`, immediately after the ingest-advisory paragraph (the block at lines 522-528), insert:

```markdown
Three finding fields are machine-read by the eval join (`scorecard --gold`)
and by dedup — write them like identifiers, not prose:

- `root_cause.class`: one of the 23 canonical classes in
  `assets/taxonomy/class_weights.json` (kebab-case, exact). A class outside
  the list cannot anchor any gold case; ingest warns, and a synonym
  (`denial-of-service` → `dos-griefing`) is canonicalized on both sides of
  the join. If ingest names a canonical class, use it.
- `affected[0].path`: the **defining** contract's file (where the flawed
  function is declared), not an inheritor — the join reads `affected[0]`
  only, basename-suffix matched against the gold case's locations.
- `root_cause.mechanism`: one sentence carrying the code identifiers and the
  wrong/right primitive pair ("`_deposit` burns the user's token while the
  inherited `onDropMessage` pays the refund out of the gateway's own
  balance"), because packs may match mechanism phrases by containment.

Before closing a graded campaign: `webv2 scorecard <C> --gold <pack.json>`
is read-only — run it as a dry join while every finding is still editable.
```

- [ ] **Step 4: Run the cli suite + check the runbook renders**

Run: `go test ./internal/cli/ && sed -n '520,560p' assets/runbook/RUNBOOK.md`
Expected: PASS; the runbook block reads correctly in place. Note: `assets/runbook/*` is embedded (`assets/runbook.go`) and hash-pinned — after editing, run `python3 scripts/sync-asset-manifest.py` and include the manifest diff in the commit.

- [ ] **Step 5: Commit**

```bash
git add internal/cli/cmd_answered.go internal/cli/cmd_plan.go assets/runbook/RUNBOOK.md assets/testdata/asset_manifest.json
git commit -m "docs(cli): surface the per-probe anchor contract and the grading path"
```

---

### Task 9 (data, outside this repo): G-02 accept list must cover the framework's own vocabulary

**Files:**
- Modify: `../targets/morph-gold-cases.json` — `CASE-2024a0923002` (`bug_class_accept`: `["logic-error", "token-integration"]` → `["logic-error", "token-integration", "bridge-message"]`)
- Modify: `../targets/morph-gold-cases.sha256` (regenerate)

**Interfaces:**
- Consumes: nothing in this repo. `bridge-message` is a canonical class (`class_weights.json` gives it `severity_default: high`); the framework's own vocabulary for "wrong primitive across a message boundary" must be acceptable for the gateway-defect case, or every correct filing of that mechanism scores as a miss (review §8b counter-case, §10b).
- Produces: with Task 2 landed, `scorecard --gold` moves to recall 2/2 and raw FP 4 (5 CONFIRMED, 2 anchored, 3 unanchored; the POSSIBLE row leaves the CONFIRMED-only budget).

- [ ] **Step 1: Edit the pack**

```bash
cd /home/xand/Projects/dsh-plugins/websec2
python3 - <<'PY'
import json
p = 'targets/morph-gold-cases.json'
d = json.load(open(p))
for c in d['cases']:
    if c['case_id'] == 'CASE-2024a0923002':
        acc = c.setdefault('bug_class_accept', [])
        if 'bridge-message' not in acc:
            acc.append('bridge-message')
            acc.sort()
json.dump(d, open(p, 'w'), indent=2)
PY
```

- [ ] **Step 2: Regenerate the sidecar (same format: `<hex>  targets/morph-gold-cases.json`)**

```bash
cd /home/xand/Projects/dsh-plugins/websec2
sha256sum targets/morph-gold-cases.json > targets/morph-gold-cases.sha256
cat targets/morph-gold-cases.sha256
```

- [ ] **Step 3: Verify the full measured outcome**

```bash
cd /home/xand/Projects/dsh-plugins/websec2/web3sec-go
.scratch/bin/webv2 --root .scratch/repro-c scorecard C-12f17fd555 --gold ../targets/morph-gold-cases.json 2>&1 | sed -n '/eval/,/containment/p'
```
Expected: recall 2/2; raw FP 4; CONFIRMED-only FP 3 with precision line present; the record itself untouched (no class/path/mechanism was retro-fitted — the review's §10b counterfactual, now run for real through data + code instead of by editing the campaign).

- [ ] **Step 4: Commit (in the targets repo, not web3sec-go)**

```bash
cd /home/xand/Projects/dsh-plugins/websec2
git add targets/morph-gold-cases.json targets/morph-gold-cases.sha256
git commit -m "fix(targets): G-02 accept list covers the canonical bridge-message class"
```

---

## Cut list (refused, with the reason)

| ask | why not now |
|---|---|
| `model --scaffold` (80-120 LOC skeleton writer) | Task 7 removes 90% of the pain (25 exact paths in one round trip); the rest is a one-time schema read. Build it when a second operator hits it. |
| Per-row `answered --explain` | Task 8's help block carries the same table for zero flag parsing; add the flag only if operators still miss it. |
| `evidence_ceiling` scope field (25-40 LOC + schema) | Real, but it silences a cosmetic warning; `floors set` already caps the campaign. Batch with the next schema-touching wave. |
| `examined-unproven` closure status | Honest-record nicety; the reason prose already carries it and Task 5 stops it from being *priced* as a fabrication. Revisit with the statuses vocabulary decision (see triage doc's Task-4 residual — two terminal-status vocabularies already disagree). |
| Probe-row `--subsumed-by` bulk disposition | With Tasks 3+4 the custody surface shrinks from 39 open rows to ~5; the noise that made bulk closure urgent is gone. |
| `complete` scope-capped vs unfinished grouping | Cosmetic; `deferred` already lists flags with reasons. |
| Full OWASP/SWC crosswalk file | `aliases.json` already cross-references for display; a second vocabulary axis is a standardization project, not a bug fix. |
| `poc_requirements.require_control_arm` switch | Not machine-checkable cheaply; the runbook operator-contract block (Task 8) is where the convention belongs, and memory patterns already capture it. |
| Contamination-check extension (fixtures, `targets/`, pinned tree) | Eval-harness ops decision, spans outside this repo; the review's own disclosure records the discipline gap. Worth its own plan. |
| `grep` pipeline guard | Host-side (DSH), not this repo. |
| Mechanism-phrase stemming / description matching | Inert for this pack (no `match_mechanisms` rows); revisit when a pack carries phrases. |

## Self-review

- **Spec coverage:** every review item marked "implement" above traces to a task; everything else is in the cut list with a reason. The review's three suggested custody fixes are replaced by the verified root cause (quota + noise), with the re-run as evidence.
- **Placeholders:** none — every code step carries the actual code; Task 9 is exact data surgery.
- **Type consistency:** `CanonicalClass` (taxonomy) consumed by evalscore and ClassAdvisory; `symMemberIsTestDouble`/`symAssetOf` consumed inside `PrimitiveMatrix`/`symmetryCells`; `Report.ConfirmedLive/ConfirmedAnchored/ConfirmedPrecisionLine` defined in Task 5 and rendered in the same task.


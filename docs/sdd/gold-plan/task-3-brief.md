### Task 3: brief renders evidence-reachability per bug class (class floor vs box ceiling)

Defect 5, re-derived against current code: the eval claimed "G-01's accepted classes floor at E6 (economic-invariant)" — but `internal/findings/levels.go` `CLASS_CONFIRM_FLOOR` pins `dos-griefing: E4` and `logic-error: E4`, and the eval box reached E4. So CONFIRMED for G-01's accepted classes was **locally reachable**; the cockpit simply never said so. This task makes reachability visible so the ceiling is a planning input, not a post-hoc discovery. No new status is added (rejected: the benchmark's own pass bar already accepts `HYPOTHESIS + correct root cause + working PoC draft`, and `CONFIRMED@E4` is legal for the accepted classes — a new status would be a cross-gate state-machine change for no scoring gain).

**Files:**
- Modify: `internal/findings/levels.go` (export accessors; no map changes)
- Modify: the brief builder — `rg -n "func NextActions" internal/briefing/briefing.go` (the mint Task 7/fix1 converted)
- Test: `internal/findings/levels_reachability_test.go` (new)
- Test: `internal/briefing/task14_reachability_test.go` (new)

**Interfaces:**
- Consumes: `findings.STATUS_FLOOR`, `findings.CLASS_CONFIRM_FLOOR`, `findings.EVIDENCE_ORDER` (all package-level in `internal/findings/levels.go:30-60`); the box's E-cap recorded by the environment ceiling (`rg -n "E4|e4_capable" internal/envgo/env.go` for the accessor name).
- Produces (all three are part of the contract, pinned by tests):
  - `findings.ClassConfirmFloor(class string) string` — the class's floor id from `CLASS_CONFIRM_FLOOR`, or `"E5"` (the `STATUS_FLOOR["CONFIRMED"]` default) for unknown classes.
  - `findings.ReachableLocally(class, cap string) bool` — true when the class floor's evidence level ≤ cap in `EVIDENCE_ORDER`.
  - `briefing.ReachabilityLine(classes []string, cap string) string` (in package `briefing`) — rendering rules: reachable classes first, fork-required classes second, each group alphabetized; reachable clause `evidence reachability: CONFIRMED locally reachable for <c1> (floor <F1>); fork required for <c2> (floor <F2> > <cap>)` — **one class per clause with its own floor value** (this exact form is what the test pins; the earlier prose with comma-joined classes and `floor ≤ E4` was inconsistent and is superseded). Edge cases: all classes reachable → omit the fork clause entirely; all classes fork-required → omit the reachable clause and start the line with `evidence reachability: fork required for ...`. Empty class list → empty string (no line rendered).

- [ ] **Step 0: Pre-flight — floor-map facts**

Read `internal/findings/levels.go` `CLASS_CONFIRM_FLOOR` and record: does a key with floor `E6` exist (the comment names `share-price-inflation`)? Copy the REAL key and value into the test below — if no E6 key exists, pin the default-`E5` path with an unknown class instead and say so in the report. Never pin an assumed key.

- [ ] **Step 1: Write the failing tests**

```go
func TestClassConfirmFloor(t *testing.T) {
	if got := ClassConfirmFloor("dos-griefing"); got != "E4" {
		t.Fatalf("dos-griefing floor = %q, want E4", got)
	}
	// share-price-inflation's real value comes from Step 0's read of levels.go
	if got := ClassConfirmFloor("share-price-inflation"); got != "E6" {
		t.Fatalf("share-price-inflation floor = %q, want the map's real value", got)
	}
	if got := ClassConfirmFloor("nonexistent-class"); got != "E5" {
		t.Fatalf("unknown class floor = %q, want E5 (CONFIRMED default)", got)
	}
}

func TestReachabilityLine(t *testing.T) {
	got := ReachabilityLine([]string{"economic-invariant", "dos-griefing"}, "E4")
	want := "evidence reachability: CONFIRMED locally reachable for dos-griefing " +
		"(floor E4); fork required for economic-invariant (floor E6 > E4)"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if all := ReachabilityLine([]string{"dos-griefing", "logic-error"}, "E4"); strings.Contains(all, "fork required") {
		t.Fatalf("all-reachable line must omit the fork clause: %q", all)
	}
	if forkOnly := ReachabilityLine([]string{"economic-invariant"}, "E4"); strings.Contains(forkOnly, "locally reachable") {
		t.Fatalf("all-fork line must omit the reachable clause: %q", forkOnly)
	}
}
```

(The `share-price-inflation` expected value above is a placeholder for whatever Step 0 found — the committed test pins the map's real value.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/findings ./internal/briefing -run "Reachab|ClassConfirmFloor" -count=1`
Expected: FAIL — accessors undefined.

- [ ] **Step 3: Implement the accessors and the brief line**

Accessors in `levels.go` are pure map reads (no behavior change to any gate). `ReachabilityLine` lives in package `briefing` (it is a rendering concern; `findings` stays data-only). The brief renders the line once per brief when the campaign's findings carry at least one open finding class, **positioned immediately after the cold-probe warning line (Task 11) — pin that ordering in the briefing test by asserting the reachability line's index is exactly one greater than the cold-probe warning's index** in a fixture that has both. Advisory only: no gate, proof, or phase transition reads it. If any minted line embeds a command it must lead with `webv2 ` per the Task 7 law; this line is pure prose so no command is embedded.

- [ ] **Step 4: Tests green, then gates**

Run: `go test ./internal/findings ./internal/briefing -count=1`; `go test ./... -count=1`; `go vet ./...`; `scripts/golden.sh`; `scripts/runbook-walkthrough.sh`.
Expected: green; brief-shape pins move only if a pinned fixture has open findings with classes (deliberate re-pin with `(golden: <file>)` in the subject if so).

- [ ] **Step 5: Commit**

```bash
git add internal/findings/levels.go internal/findings/levels_reachability_test.go internal/briefing/briefing.go internal/briefing/task14_reachability_test.go
git commit -m "feat(briefing): evidence reachability line (class confirm floor vs box cap) (defect 5)"
```

---


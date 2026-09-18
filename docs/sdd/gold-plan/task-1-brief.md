### Task 1: invariant-verify refuses execs that did not target an applies_to contract

Defect 6 (wish 4): "I closed INV-003 (staking liveness) citing a generic full-suite exec (EXEC-5ca6c7aac3). The framework recorded `CHECKED_AGAINST_CODE` without checking any relation between the cited exec and the invariant's `applies_to`". A foundry full-suite run names every contract in its output, so output text-matching cannot enforce this — the gate must inspect what the exec *ran*, not what it printed.

**Files:**
- Modify: `internal/invariants/invariants.go` (verify path; near `VerifyInvariantStatement` and the Task 4 artifact-reference helpers)
- Modify: `internal/cli/cmd_invariant_verify.go:82-97` (`resolveExecArtifact` already resolves the cited exec)
- Test: `internal/invariants/invariants_exec_relevance_test.go` (new)
- Test: `internal/cli/cmd_invariant_verify_exec_relevance_test.go` (new)

**Interfaces:**
- Consumes: `invariants.VerifyInvariantStatement(c *state.Campaign, invID string, artifact string) (validation.Value, error)` (unchanged signature); `state.Campaign` exec record access used by `resolveExecArtifact` (`internal/cli/cmd_invariant_verify.go:116`); the Task 4 `referenceTokens` matcher family in `internal/invariants/invariants.go:832`.
- Produces: exported `invariants.ExecTouchesInvariant(c *state.Campaign, invID string, execID string) (bool, string)` — `(true, "")` when the exec's recorded command targeted one of the invariant's `applies_to` tokens under the **binding matcher semantics** below; `(false, reason)` otherwise, where `reason` is one of `"no-exec-record"`, `"no-command-record"`, `"no-target-match"`. All existing callers keep compiling (additive).
- **Matcher semantics (binding, decided after three independent plan reviews):** case-insensitive **left-boundary token match** — the lowered command contains the lowered token at a position whose preceding character is NOT `[0-9a-z_]` (start-of-string counts as a boundary); there is **no trailing boundary**. Explicitly rejected alternatives: (a) regex `\b` on both sides — `\bStaking\b` fails on `StakingTest` (no boundary between `g` and `T`), under-accepting exactly the commands the gate must accept, since Foundry's `--match-contract` is a regex/prefix filter; (b) plain case-insensitive substring — over-accepts (`Staking` would match `Unstaking`). Left-boundary accepts `--match-contract Staking`, `--match-contract StakingTest`, `--match-path src/Staking.t.sol` (`/` is a boundary) and rejects `Unstaking` (`n` precedes) — both rejections are pinned as adversarial tests, not incidental. Strip surrounding shell quotes from the recorded command before matching.
- **Matcher provenance:** before implementing, read what the Task 4 `referenceTokens` matcher (`invariants.go:832`) actually does. If it already implements left-boundary matching, reuse it; if it implements full `\b...\b`, implement the left-boundary matcher as a NEW named helper (e.g. `tokenOccursLeftBound(command, token string) bool`) — do NOT change the Task 4 matcher's behavior (that would silently move Task 4's pinned refusal semantics), and document in the new helper's comment that the two intentionally differ and why.

- [ ] **Step 0: Pre-flight — fixture blast radius**

Run: `rg -n "forge test\b" internal/ --glob '*_test.go' --glob '!*_exec_relevance_test.go' | rg -v "match-contract|match-path" | wc -l`
Expected: a count. Record it in the report: it is the number of existing test fixtures that close an invariant with an untargeted suite exec and will need targeted-exec updates in Step 4 (5-minute fix if small, a deliberate fixture-migration commit if large — if the count exceeds ~20, STOP and report before proceeding; the operator decides whether to split the task). Never a weakened gate.

- [ ] **Step 1: Write the failing tests**

In `internal/invariants/invariants_exec_relevance_test.go`, build a campaign via the existing `invCamp` helper family (see `internal/invariants/invariants_test.go:1167` for the Task 4A fixtures). Invariant with `applies_to: ["Staking"]`. Exec records written with the same helper the Task 4 tests use to register exec artifacts:

```go
func TestExecTouchesInvariant(t *testing.T) {
	c := invCamp(t)
	registerInv(t, c, "INV-3", "staking liveness", []string{"Staking"})
	// command naming the contract directly
	direct := registerExec(t, c, "forge test --match-contract Staking")
	// CamelCase test-contract glob — Foundry prefix-filter form, must match
	camel := registerExec(t, c, "forge test --match-contract StakingTest")
	// path-scoped form — token preceded by '/', must match
	path := registerExec(t, c, "forge test --match-path src/Staking.t.sol")
	for _, ex := range []state.Exec{direct, camel, path} {
		if ok, reason := ExecTouchesInvariant(c, "INV-3", ex.ID); !ok || reason != "" {
			t.Fatalf("targeted exec %s: ok=%v reason=%q, want true/\"\"", ex.ID, ok, reason)
		}
	}
	// adversarial near-miss: token present as substring but inside another word
	un := registerExec(t, c, "forge test --match-contract Unstaking")
	// disjoint contract
	other := registerExec(t, c, "forge test --match-contract OracleTest")
	// whole-suite run: no token anywhere in the command
	suite := registerExec(t, c, "forge test")
	for _, ex := range []state.Exec{un, other, suite} {
		if ok, reason := ExecTouchesInvariant(c, "INV-3", ex.ID); ok || reason != "no-target-match" {
			t.Fatalf("untargeted exec %s: ok=%v reason=%q, want false/no-target-match", ex.ID, ok, reason)
		}
	}
	if ok, reason := ExecTouchesInvariant(c, "INV-3", "EXEC-missing"); ok || reason != "no-exec-record" {
		t.Fatalf("missing exec: ok=%v reason=%q", ok, reason)
	}
}

func TestExecTouchesInvariantEmptyAppliesTo(t *testing.T) {
	c := invCamp(t)
	registerInv(t, c, "INV-9", "unbound invariant", nil) // applies_to: []
	ex := registerExec(t, c, "forge test --match-contract Staking")
	if ok, reason := ExecTouchesInvariant(c, "INV-9", ex.ID); ok || reason != "no-target-match" {
		t.Fatalf("empty applies_to: ok=%v reason=%q, want false/no-target-match", ok, reason)
	}
}
```

Adapt the exact constructor names to the real helpers (`registerExec` above stands for however Task 4's tests materialize an EXEC record with a command line — read them first; if the exec record has no command field, the field name discovered there governs, and this test pins it).

Ruling on empty `applies_to` (deliberate, matches the hardening branch): Task 4's pinned rule is that an empty `applies_to` does NOT bypass the artifact-reference refusal — empty means **unbound → unverifiable**, never wildcard. This task is consistent with that: an invariant bound to nothing cannot be exec-verified.

In `internal/cli/cmd_invariant_verify_exec_relevance_test.go`: happy path (targeted exec) still verifies; refusal path prints the exact new refusal text and leaves the registry untouched — assert ALL of: exit 2, stderr text, status stays `UNVERIFIED`, **zero new `invariant.verified` events** (explicit event-absence loop over the event list, not just the status), no attestation label:

```go
func TestInvariantVerifyRefusesUntargetedExec(t *testing.T) {
	// fixture: INV-3 applies_to [Staking]; cite the `forge test` suite exec
	code, out, errOut := runInvariantVerify(t, "INV-3", suiteExecID)
	if code != 2 { t.Fatalf("exit = %d, want 2", code) }
	if !strings.Contains(errOut, "does not target any applies_to contract of INV-3") {
		t.Fatalf("stderr missing refusal text: %q", errOut)
	}
	if got := objStr(invEntry(t, c, "INV-3"), "status"); got != "UNVERIFIED" {
		t.Fatalf("status = %q, want UNVERIFIED", got)
	}
	for _, ev := range events(t, c) {
		if objStr(ev, "type") == "invariant.verified" {
			t.Fatal("refusal must emit no invariant.verified event")
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `GOCACHE=$PWD/.scratch/gocache GOFLAGS=-mod=mod GOPATH=$PWD/.scratch/gomod GOMODCACHE=$PWD/.scratch/gomod/pkg/mod go test ./internal/invariants ./internal/cli -run ExecTouches -count=1` (and the CLI test)
Expected: FAIL — `ExecTouchesInvariant undefined`, CLI test fails because verify currently accepts the suite exec.

- [ ] **Step 3: Implement the gate**

In `internal/invariants/invariants.go`, next to the Task 4 helpers: `ExecTouchesInvariant` reads the exec record the same way `resolveExecArtifact` does, extracts the recorded command, strips surrounding quotes, and applies the binding left-boundary matcher against the invariant's `applies_to` tokens. Empty `applies_to` → refuse with `"no-target-match"`. In `cmd_invariant_verify.go` after artifact resolution, call the gate; on refusal print `invariant verify failed: cited exec <ID> does not target any applies_to contract of <invID> (<reason>)` and return 2. The check runs *before* `VerifyInvariantStatement` writes anything.

- [ ] **Step 4: Run the tests to verify they pass, then the package gates**

Run: focused tests (expect PASS), then `go test ./internal/invariants ./internal/cli -count=1`.
Expected: PASS. If existing fixtures close invariants with suite execs and now fail, that is the law working — update those fixtures to targeted execs (deliberate, reason in commit body, count from Step 0), never weaken the gate.

- [ ] **Step 5: Full gates and commit**

Run: `go test ./... -count=1`; `go vet ./...`; `scripts/golden.sh`.
Expected: all exit 0 (golden pins should not move — no stdout change on the happy path; if a pin does move, re-pin in THIS commit with `(golden: <file>)` in the subject and the reason in the body).

```bash
git add internal/invariants/invariants.go internal/invariants/invariants_exec_relevance_test.go internal/cli/cmd_invariant_verify.go internal/cli/cmd_invariant_verify_exec_relevance_test.go
git commit -m "fix(invariants): exec-relevance gate for invariant-verify (defect 6)"
```

---


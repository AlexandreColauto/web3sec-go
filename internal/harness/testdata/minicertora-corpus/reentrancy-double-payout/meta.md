# reentrancy-double-payout

- bug_class: reentrancy
- source: the classic single-function reentrancy (DAO-hack / DV `Reentrancy` family),
  distilled so that the double payout is visible in *state* rather than in a balance the
  tool cannot see: `payouts` is a public counter, both frames increment it, and the
  balance write is idempotent (`= 0`) so the second frame cannot underflow.
- lineage: `reentrancy-withdraw`'s honest 2-call rule (`withdraw; withdraw`) is the
  *sequential* shape of the same bug.  This target is the *re-entrant* shape: the honest
  rule writes the attacker's callback position explicitly, as Task 5's `reenter { ... }`
  block requires, because re-entry inside an unmodelled callee is not modelled in v0.2
  (v0.2 design §3, reentry policy).
- distillation decision: the rule is `withdraw(e, x); reenter { withdraw(e, x); }` with
  `assert payouts <= 1`.  Without the `reenter` block the second `withdraw` is a *sequence*
  (a second transaction's worth of calls, where the balance is already zero and the guard
  reverts), which is exactly the distinction Task 5's gate is about.
- status: **unwritable**.  The Task-5 prototype *did* express the attack (the splice is
  built, see measured: below), but the tool cannot translate the contract's full-gas
  external call, so no reentrancy verdict is claimable for it.  Recorded as a ruling, not
  weakened silently (v0.2 design §3: "the criterion is re-scoped by ruling").
- assumptions posture: n/a (unwritable).  For the record, the *spliced* program carried
  `multi-call-sequential` (sequential) / `reentrancy-single-level-explicit` +
  `reentrancy-inner-revert-excluded` (reentrant) before translation refused — visible in the
  `probe` measurement below.

## Measured (2026-09-11, solc 0.8.36, `--loop-bound 4 --timeout-ms 30000`)

`python -m cli Vault.sol reentrancy.mspec --multi-call=<mode>`

| mode | result | evidence |
|---|---|---|
| `off` | UNKNOWN, `unsupported-feature`, details `multi-call-sequence: rule no_double_payout has a reenter block; …`, exit 2 | the default never guesses: a rule that needs the sequence machinery is refused |
| `sequential` | UNKNOWN, `rejected-feature`, details ``, exit 2 | the splice is built (2 steps), then translation refuses |
| `reentrant` | UNKNOWN, `rejected-feature`, details ``, exit 2 | the splice is built (outer `__pre` → inner → `__post`), then translation refuses |

The bare reason code is unhelpful here on purpose-of-the-old-code, so the *instruction that
refuses* was measured directly with a `_PathAbort` trace (scratch probe, not shipped):

```
VCABORT rejected-feature: non-word-aligned memory offset mem_0[LShR(64, 5)]
```

That expression is the **free-memory pointer**: `memPtr := mload(0x40)`, then
`mstore(memPtr, length)` while decoding the discarded `bytes` component solc emits for
`(bool ok, ) = msg.sender.call{value: amount}("")`.  The offset is symbolic, and
`vcgen.translate._word_index` refuses symbolic offsets by design (design Stage 2d lists
"symbolic memory offset" as an adversarial gate that must reject loudly).

**Second refusal, measured by temporarily relaxing that one check in a scratch experiment
(the relaxation was deliberately NOT shipped):** the next refusal is
`external-call-abstraction` — `symbolic returndata copy bounds`
(`RETURNDATACOPY data+32, 0, returndatasize()`) from the same ABI decoder.  So this target
is blocked on **Stage 2d (`ABI-decoded memory`: free-memory region model + the
`extract_returndata` class)**, not on the multi-call/reentrancy machinery.

## The splice machinery is not the blocker (measured end to end)

`reentrant` mode ran end to end through the CLI on a contract the tool *can* translate
(`unchecked-callback`'s `transfer`-based Vault, with the same rule + `reenter` block):

| mode | verdict | assumptions added | report |
|---|---|---|---|
| `off` | UNKNOWN `unsupported-feature` | — | reenter block refused |
| `sequential` | VIOLATED | `multi-call-sequential` | calls `[step 0 reentrant=false, step 1 reentrant=true]` |
| `reentrant` | VIOLATED | `reentrancy-single-level-explicit`, `reentrancy-inner-revert-excluded` | same two steps, inner program spliced at the call site |

No reentrancy *claim* is attached to that measurement: `transfer` forwards 2300 gas, so a
re-entering callee cannot execute — which is precisely why the shipped flagship uses a
full-gas `call` and why `unchecked-callback` is not a reentrancy witness.  The *machinery*
(grammar → parser → plan → splice → report plumbing) is demonstrated; the *claim* is not.

Also measured (existing targets, untouched, under the new flag only — no expectation
flipped; the Stage 2 flip is Task 6's job): `privilege-escalation` → VIOLATED exit 1 with
`multi-call-sequential`, `flashloan-price-oracle` → VIOLATED exit 1 with
`multi-call-sequential`, `reentrancy-withdraw` → UNKNOWN (`external-call-abstraction`, its
`msg.sender.call("")` decoder).

## The exploit is real (replay.sh, live anvil, 2026-09-11)

```
$ anvil --port 8613 & ANVIL_URL=http://127.0.0.1:8613 bash replay.sh
replay ok: reentrancy double payout — payouts=2 after ONE logical withdrawal   (exit 0)
```

The vault is seeded with a victim deposit first (5 ether of real balance against a 1 ether
accounting claim) — without it the *second* `call{value: x}` cannot be paid, `require(ok)`
reverts the re-entrant frame, and the honest outer `require(ok)` reverts everything: no
bug, `payouts == 0`.  That is a property of the *bug*, not of the model, and the brief's
one-line replay omitted it.

## Deviations from the task brief

- `Vault.deposit` is `payable`.  The brief's snippet spells it non-payable while its own
  `Attacker.attack` does `vault.deposit{value: a}(a)` — value sent to a non-payable
  function reverts, so the replay could not run at all.  One added keyword; `withdraw`
  (the modelled function) is untouched.
- The brief's `splice_sequential` sketch redirected *every* exit to the next step, `Revert`
  included ("call 1 reverted, then call 2 ran" — an execution the EVM cannot produce).
  Shipped semantics redirect only *clean* exits (`Return`/`Stop`); reverting exits stay
  reverting and the existing `reverted_observed` machinery drops those paths.  Tested in
  `tests/test_sequence_splice.py::test_splice_sequential_leaves_a_reverting_exit_reverting`.

## Rulings

<!-- date | task | field | old | new | reason | evidence -->
| 2026-09-11 | task-5 | status / blocked_on / expected_error_code | (new target) | `unwritable` / `abi-decoded-memory` / `rejected-feature` | The Stage 2 reentrancy exit criterion is *conditional* on the Task-5 prototype (v0.2 design §3). The `reenter` grammar, the planner and both splices work and are measured end to end (see above), but the distilled target's full-gas call cannot be translated: solc's ABI decoder for `(bool ok, ) = addr.call{value: x}("")` needs the free-memory region model (symbolic `mload(0x40)` offset) and a bounded symbolic `returndatacopy`, i.e. design Stage 2d. Per the design's own instruction the criterion is re-scoped by ruling, never silently weakened: Stage 2 reentrancy stays open, blocked_on `abi-decoded-memory`. | three-mode table above; `_PathAbort` trace `non-word-aligned memory offset mem_0[LShR(64, 5)]`; relaxation experiment → `external-call-abstraction`; `replay.sh` exit 0 with `payouts=2`; `python -m corpus.matrix` row refuses with `rejected-feature`, exit 2 |
| 2026-09-12 | task-6x.1 | expected_details_include | `null` | `non-word-aligned memory offset` | 6x.1 landed the details channel: `TranslationResult.unknown_details` carries the failing `VCAbort`'s own instruction through all three conversion sites (`translate_rule`'s fast path, `_build_path_query`, `_guard_true_formula` via `_PathAbort.details`) and the CLI prints it. Task 5 could pin only the reason code and left the instruction in §14 of the mini-spec; the row now pins the evidence itself. Status / `blocked_on` / `expected_error_code` / exit code unchanged — but the expectation is *stricter*: a rejection that lost its details now fails the corpus. | `python -m cli Vault.sol reentrancy.mspec --multi-call=reentrant --loop-bound 4 --timeout-ms 30000` → `{"verdict": "UNKNOWN", "reason": "rejected-feature", "details": "non-word-aligned memory offset mem_0[LShR(64, 5)]"}`, exit 2; `pytest tests/test_unknown_details.py -q` → 5 passed (one test per conversion site + the negative space + this line end to end) |
| 2026-09-12 | task-9 | blocked_on + expected_error_code + expected_details_include | `abi-decoded-memory` / `rejected-feature` / `non-word-aligned memory offset` | `returndata-copy-bounds` / `external-call-abstraction` / `symbolic returndata copy bounds` | 9a modelled the free-memory region (a word map for word-aligned concrete offsets, seeded with the dispatcher's `memoryguard(128)`, declared as `concrete-free-memory-model` when used), so the decoder's `memPtr` offsets are no longer the blocker and the row's pinned details would be a lie. The refusal is now the *next* instruction: `returndatacopy(<symbolic dest>, 0, returndatasize())` bounds the copy by a symbolic size, which the model cannot enumerate — refused, not flattened. Design class unchanged (Stage 2d external-call summaries), status/exit unchanged (unwritable / 2). The tally must say so: `abi-decoded-memory` now has 0 unwritable targets, `returndata-copy-bounds` has 2. | `python -m cli Vault.sol reentrancy.mspec --multi-call=reentrant --loop-bound 4 --timeout-ms 30000` → `{"verdict": "UNKNOWN", "reason": "external-call-abstraction", "details": "symbolic returndata copy bounds"}`, exit 2; the memory gate's own evidence is `corpus/targets/memory-abi-encode` (PROVEN + VIOLATED on the same model) |

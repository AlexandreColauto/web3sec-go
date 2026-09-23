# v16 (the only prompt file)

Self-contained. A fresh session reads this and works. **There is no other prompt file.**

**Maintain it as you go:** when you finish a §5 item, move it into §3 (with its commit sha), and
commit this file alongside your work. Do not create sibling prompt files.

---

## 1. The project

`web3sec-go` (`https://github.com/AlexandreColauto/web3sec-go.git`), closing the gap between the
shipped `webv2` Go control plane and the v1.6 spec, in spec build order.

**Standing laws (in force for every code change):**

- Go floor `go 1.26.2`, module `websec`, **stdlib only**.
- **TDD.** Plain Go tests, same package, `t.TempDir()`, no Docker, no network, no model.
- **Gates:** `go test ./... -count=1 -p 2`, then `scripts/verify-full.sh`, plus gofmt /
  `go vet` / golangci-lint.
- **Byte-pinned CLI surfaces.** Help/usage/error text asserted verbatim; `--flag` names must
  appear quoted in `internal/cli/*.go`.
- **Ledger law.** One hash-chained event per mutation; projection unwind on log-write failure.
- **Determinism pins.** `WEBV2_NOW` / `WEBV2_UUID` / `WEBV2_FINDING_IDS`; never `time.Now()` or a
  raw UUID in a new record.
- **Schema discipline.** `additionalProperties: false`; a new key ⇒ schema edit +
  `validation.Validate(v, name, 1)` on the write path.
- **Asset manifest.** Any edit under `assets/` needs `python3 scripts/sync-asset-manifest.py`.
- **D9 freeze.** Spec changes only on measurement.
- **§2.4 replayability.** *demonstrated* vs *computed* vs *reported* are three distinct
  quantities, never conflated. **A reported loss is never laundered into `extractable_usd`.**
- **Refusal is a valid outcome.** *Measured, or refused with a recorded reason.* An unmeasured
  spike is refused rather than estimated; the refusal is itself evidence.

**Model routing** (lesson `20260922-0h6m`): **implementation → `deepseek-v4.1-flash`**,
**review → `mimo-v2.6-flash`**. Do not invert. Run an adversarial review on anything that changes
code or a record's claims — it has earned its keep every time (refuted a central claim; found
tests passing for the wrong reason).

**Known environment hazard:** `rg` output has rendered identifiers incorrectly (e.g.
`fork_block` → `n`). Verify anything load-bearing with Python or by reading the file.

**Working style:** make judgement calls and log them. Do not stop to ask. If an item's spec is
ambiguous, **write a scoping document instead of guessing**, then move on. **Commit after every
item** so partial progress survives interruption.

---

## 2. Control-target facts (Exactly Protocol) — settled, do not re-derive

| fact                     | value                                                                                 |
| ------------------------ | ------------------------------------------------------------------------------------- |
| proxy (attacked address) | `0x675d410dcf6f343219aae8d1dde0bfab46f52106`                                          |
| impl A (vulnerable)      | `0x16748cb753a68329ca2117a7647aa590317ebf41`, 24,087 B                                |
| impl B (fixed)           | `0x910e91d24a948c3e36b71b505fb45fe80e95adb3`, 24,356 B (+269)                         |
| proxy code               | 1,648 B, invariant at every height — **it is an EIP-1967 proxy**                      |
| attack block             | 108,375,558 = 2023-08-18 09:11:33 UTC                                                 |
| impl B created           | 108,401,937 = 2023-08-18 23:50:51 UTC                                                 |
| **repoint**              | **108,445,162 = 2023-08-19 23:51:41 UTC** (~24h after impl B; **not** "next morning") |
| repoint tx               | `0x2474d2a50b4439434cefa63c42278f3530c2d494510b6e56d51f8fcc23321ad2`                  |

**Encoding rule (learned the hard way):** always name the canonical encoding. `a6b12297…` was
sha256 of the `0x`-prefixed hex *string*; `c71f1646…` is sha256 of the bytecode *bytes*. An
unlabelled canonical encoding is not evidence.

**`tx.to` is never the contract that matters.** Attack tx `to` = `0x6dd61c69…` (attacker's
contract); repoint tx `to` = `0xc0d6bc5d…` (Gnosis Safe, selector `0x6a761202`). No transaction
at 108,445,162 has `to` = proxy. Two instances — it is a rule, not a coincidence.

**Scope limit (§3.2, as rewritten):** proxy-resolving detectors *can* be certified on this target;
detectors keyed on the attacked address's own code are **provably false-negative at every
height**. This makes it a proxy-resolution test case.

**Other corrections already applied:** RPC blocker is **overstated** — one public endpoint does
serve archive state; the real hazard is **silent pruning**. Reported loss is not one number ($7.3M
/ $7.6M / ~$12.04M, 65% spread). The attack is **three** transactions, so any single-tx
`extractable_usd` is one of three.

---

## 3. Done

| item                        | commit                 | key result                                                                      |
| --------------------------- | ---------------------- | ------------------------------------------------------------------------------- |
| B2 re-verification          | `cbc9387`              | pair exists at impl level; three numeric/label errors corrected                 |
| campaign floor override     | `2a89ecd`              | `input-validation → E4`; measured, attributed, audit-reconciled, reversible     |
| route 2 implemented + fixed | `a8fc132f`, `1684e640` | `expected_outcome` / `expected_failure`; review refuted the signature rule      |
| exec-record anchor          | anchor commits         | `exec_record_sha256` + mandatory alg; fail-open absent / fail-closed present    |
| **CONFIRMED**               | confirm-run commits    | `F-cfff3ebc0250` CONFIRMED, E4, full history with reasons                       |
| provenance limitation       | `e4b683e6`             | anchor proves contemporaneity with its own run, **not operator blindness**      |
| docker count                | `7e0eac87`             | proved by enumeration: 19 registered − 3 skipping = 16                          |
| `failure_class` archival    | `95cedeb5`             | six keys on `sandbox.exec`, seven on `.registered`                              |
| P0 Task 3 steps 1–6         | `414b4a0c`             | **two spec defects found — see §5.3**                                           |
| 10b fork spike              | `c5ba1048`             | `fork_block_used` 108375557 from observed output; **`extractable_usd` refused** |
| P5 scoped, handoff refused  | `9ba6bb12`             | scope written, not built; handoff refusal is the sharper result (§5.1)          |
| **handoff unpriceable escape** | `911be0a9`         | `priceable:false` + ceiling + reason + actor; audit now schema-validates **and** reconciles with the ledger |

### 3.1 The gate mechanics that took the most work to establish

- `RequiredLevelFor("CONFIRMED", "input-validation")` misses `CLASS_CONFIRM_FLOOR` ⇒ falls to
  `STATUS_FLOOR["CONFIRMED"] = E5`. `bug_class` is **free-form** (`^[a-z0-9-]{3,64}$`, no enum),
  so E5 was the conservative default for an *unknown string*, not a judgment about absent-guard
  bugs. Fixed with the **campaign floor override** — not a spec change.
- The E5 floor was what demanded fork evidence. At E4, **this target needs no fork** to reach
  CONFIRMED. 10b is therefore *off the CONFIRMED path*, not blocked on it.
- **No ladder-adjacency rule exists.** "Monotonic, no skipping" is a comment only; `AddEvidence`
  performs no skip check. E0 → E4 on one item is legal.
- **Rise guardrail is real and wired** (`cmd/webv2/main.go:93`), fail-closed — but vacuously
  satisfied here (campaign invariants N=0).
- The `HYPOTHESIS → POSSIBLE` refusal was **downstream of zero evidence**, not a separate bug: one
  E4 item clears both E2 and E4.

### 3.2 Route 2's final shape

- `expected_outcome`: `pass | fail`; **absent means `pass`** — every pre-existing record keeps
  exact bytes (this was re-measured against pre-commit messages, byte-for-byte).
- `expected_failure`: **required** under `fail`, **forbidden** under `pass`.
- Signature rule (`1684e640`): **8-character floor**, **ban the literal `FAIL`**, and for
  forge-like commands the line must carry **`[FAIL`** — bracket then `FAIL`, separator unpinned.
  (My original "any line containing `FAIL`" was refuted: forge's `Suite result: FAILED` summary
  satisfied it, as did `a` and `test`.)
- Both keys live on the **exec record**, never the evidence item — declaring at mint time is
  writing the expectation after seeing the result.

---

## 4. Do not

- Touch `CLASS_CONFIRM_FLOOR` or `STATUS_FLOOR`.
- Disturb `F-cfff3ebc0250` (CONFIRMED, E4) — not its status, evidence, or history.
- Reopen the anchor, `sha256-canon-spaced`, or the floor override.
- Fabricate `extractable_usd`; upgrade "reasoned" to "verified"; or re-run 10b expecting a
  different answer.
- Mint evidence from an **old** exec. The expectation must be declared **before** the run, so a
  fresh exec is required — the anchor proves the record wasn't edited after the digest, but cannot
  make a pre-existing run's expectation contemporaneous.

---

## 5. Work queue — in order

### 5.1 ~~Fix the handoff schema fabrication trap~~ — DONE, `911be0a9`

See §3. The escape exists; the queue continues at §5.2.

### 5.2 Resolve the `codebase_id` gap — blocks Step 7 and Task 4

Step 7's extractor joins `project_id`; the correction table demands `codebase_id`; the row schema
has no such key.

**Do:** determine which id is **canonical from the codebase** — count the usages, follow the
majority, record the count in the commit. This is a fact, not a judgement. Only if it is genuinely
50/50, pick `codebase_id` (a correction table keys on code identity) and say so. Then give the row
schema the needed key per schema discipline.

### 5.3 P0 Task 3 — disposition the review defects, fix `containsWord`, **re-measure**

Two spec defects found in `414b4a0c`: (a) the spec's own `containsWord` closes **both** word
boundaries, making every stem phrase in its own table unmatchable — **its own test fails under
it**; (b) the `project_id` / `codebase_id` split (→ §5.2). The review also found **9 defects, 2
HIGH — both tests passing for the wrong reason.**

**Do, in order:** (1) fix `containsWord` so the spec's own table is matchable by its own matcher;
(2) **re-run Steps 1–6 and report whether any result changes** — `414b4a0c` shipped against a
self-contradictory spec, so its outputs are suspect until re-measured; (3) confirm all 9 defects
are dispositioned. Do not leave the 2 HIGH open silently.

### 5.4 P0 Task 3 Step 7, then P0 Task 4 (weighted set-cover)

Once §5.2 is resolved. **P0 stays on the critical path** — the control target supplies the true
side only; the false side needs P0's fresh targets.

### 5.5 Build P5 — runner-level fork pin

Scope exists at `9ba6bb12`. **Justification is silent pruning** (a pruned node returns `0x` for a
contract that exists, indistinguishable from "not deployed yet") — **not** "no archive endpoint
works." That overstatement was corrected and must not reappear.

---

## 6. Report — under 500 words

Per item: **done / scoped / refused**, commit sha, gate results, judgement calls. Then:

1. **Did re-running Steps 1–6 after the `containsWord` fix change any result?** Yes/no, and what —
   this is the first thing I read.
2. Which id won in §5.2, on what count.
3. The handoff escape's exact shape, and how it prevents an unattributed omission.
4. Judgement calls, especially any I might have made differently.
5. What remains open, and next, in order.

**Remember to update §3 and commit this file as you complete items.** When finished: stop, tree
clean, report.

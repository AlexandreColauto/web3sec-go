# Task 4 review — offline gold scorer (`scripts/eval-gold.py`)

Commits reviewed: `280e348d..8b2886ec` (one commit, `8b2886ec`). Review method: read the full diff,
cross-checked the scorer against the real benchmark file (`web3sec-final/targets/gold-findings.json`),
`assets/schema/finding.schema.json`, `internal/findings/levels.go` (`EVIDENCE_ORDER`), and the legacy
fixture; re-ran the suites and the real-run reproduction myself.

## Verdicts

- **Spec compliance: YES**
- **Task quality: APPROVED** — with the findings below (one MEDIUM test gap, three LOW/INFO notes). None
  block the commit; the MEDIUM one is a missing test assertion, not a code defect.

## Evidence I verified first-hand (not taken from the report)

- `python3 scripts/eval_gold_test.py` → 25/25 OK; `python3 -m unittest scripts.eval_gold_test` → 25/25 OK.
- Real run reproduced: real benchmark × real Morph campaign `C-7f1005ecd5` → 0/2, `verdict FAIL`, exit 0;
  with `--confirm G-01` still FAIL, `operator_confirmed {"G-01": true}` — advisory-only holds live.
- `scoring.pass` in the real benchmark reads verbatim: *"G-01 found at CONFIRMED with E4+ evidence (or
  HYPOTHESIS/INVESTIGATING with the correct root cause named and a working PoC draft)"*; budget prose is
  *"…buries it under 10+ FPs is a partial result"* — the `BUDGET_RE` parse and `MIN_EVIDENCE_INDEX=4` are
  grounded in the real file, not the report's paraphrase.
- `FINDING_REQUIRED_KEYS` matches the schema's 14 `required` keys exactly; `attempts[].outcome` enum
  contains `"reproduced"`; `evidence[].level` enum is `E0–E7` (the scorer's `E[0-7]` fullmatch mirrors it);
  `affected[].function` is optional-per-item — all as the scorer assumes.
- Diff touches only the two scripts + the plan-doc correction (same commit, as the brief requires);
  `verify-full.sh` untouched (no CI wiring); historical fixtures untouched; stdlib-only imports in both files;
  no write path in the scorer (plus the tree-hash non-mutation test).

## Rulings on the implementer's flagged concerns

1. **Accepted-state breadth — faithful, no over-accept.** The benchmark's own `scoring.pass` string names
   both branches verbatim, so accepting HYPOTHESIS/INVESTIGATING is the benchmark text, not scope creep.
   Encoding "the correct root cause named" as the criteria match itself and "a working PoC draft" as
   `attempts[].outcome == "reproduced"` is if anything *stricter* than the prose (a draft that never
   reproduced is under-accepted — the conservative direction). The CONFIRMED branch (E4+ = ladder index of
   E4 in `EVIDENCE_ORDER`) matches the benchmark's literal "E4+". See LOW-2 for the one dead branch.
2. **MIN_KEYWORD_HITS=3 — synthetic-only calibration, disclosed.** No real finding exists to calibrate
   against (the Morph campaign produced none), and the report says so explicitly (concern 3) with a
   `ponytail:` note in the code. 3-of-many distinct tokens + 1 function over `title` + `root_cause.description`
   + `mechanism` is a sane floor for the real G-01/G-02 criteria prose. Accepted as an honest heuristic with
   the FP budget and `--confirm` as the human layer; first real finding is the calibration datum.
3. **Missing `findings/` dir exits 2 — correct for a measurement tool.** The brief's exit contract lists
   "either pinned file absent" → exit 2, and a scorer that silently scored a broken record as 0/2 would
   launder a data-collection failure into a benchmark miss — exactly the mis-scoring the schema-drift guard
   exists to prevent. The Go store's `ListPrefixedOptional` leniency is mid-campaign store behavior, not a
   scoring contract. The empty-but-present dir still scores empty (the real Morph path; verified live).
4. **`operator_confirmed` keeping a confirmed-but-missed gold — acceptable superset.** The brief specifies
   "default false for every found gold" but does not forbid keys for `--confirm`ed missed golds; keeping the
   operator's judgment visible without letting it touch `pass`/`bonus`/`verdict` serves the stated purpose
   (no silent laundering). Verified live on a FAIL run: verdict unchanged, `{"G-01": true}` reported.

## Decision-table row-by-row pinning audit

Pinned by tests: `found`/`missed` (empty, G-01 only, both, benchmark order); `false_positives` (0 on empty,
matched-not-FP, only-CONFIRMED-count, criteria-matching-but-not-accepted is neither found nor FP);
`pass`/`bonus` independence (from confirmation and from FPs); `verdict` FAIL/PASS/PARTIAL_RESULT/
PASS_WITH_BONUS; `verdict_note` (PARTIAL text + FP count, pending-confirmation text, `""` on confirmed
PASS / bonus / FAIL, `"; "` join implied); `operator_confirmed` (default false, `--confirm` true,
advisory-only, `{}` on empty); exact stdout key set + types; all exit-2 paths (gold absent, campaign
absent, `events.jsonl` absent, `findings/` absent, unparseable finding JSON, unparseable events line,
findings drift, gold drift, unreadable budget, unknown `--confirm`) each with clean-stderr assertions;
line-by-line events parsing; non-mutation via tree hashes.

**Not pinned:** the exact `false_positives == budget` boundary — see MEDIUM-1.

## Findings

- **MEDIUM-1** — `scripts/eval_gold_test.py` (the two boundary tests): the `>=` semantics of the
  PARTIAL_RESULT row are not actually pinned. `9 FPs → PASS` and `11 FPs → PARTIAL_RESULT` (budget 10), and
  `4 → PASS` / `6 → PARTIAL` (budget 5), are satisfied equally by `>= budget` and by a strictly-greater
  comparison — an off-by-one at exactly the budget value would pass all 25 tests. The brief's own test
  snippet uses 9/11, so the implementer followed the brief, but the brief's stated intent is
  "verdict-affecting at that boundary" (`false_positives >= 10`). Fix: add a fixture with exactly 10 FPs
  (and/or budget 5 with exactly 5) asserting `PARTIAL_RESULT`; the code itself is correct.
- **LOW-2** — `scripts/eval-gold.py:159` (`POC_STATUSES = ("HYPOTHESIS", "INVESTIGATING")`):
  `INVESTIGATING` is not in `assets/schema/finding.schema.json`'s `status` enum (real statuses:
  HYPOTHESIS, NEEDS_RESEARCH, PROVISIONALLY_VALID, POSSIBLE, CONFIRMED, …), so that branch is dead —
  no schema-validated finding can ever carry it. Harmless (no over-accept in practice) and the literal
  comes from the benchmark's prose, but the contract comment should say the store cannot emit that status,
  so a future reader does not treat it as a live accept path.
- **LOW-3** — `scripts/eval-gold.py` (verdict chain): the interplay "bonus short-circuits the FP budget"
  (`PASS_WITH_BONUS` even when `false_positives >= budget`, per the brief's unconditional first row) is
  implemented but unpinned — the bonus fixture has 0 FPs. One test (both golds found + ≥budget FPs →
  `PASS_WITH_BONUS`) would close it.
- **INFO-4** — `scripts/eval-gold.py:154-155` (`PASS_GOLD_ID`/`BONUS_GOLD_ID`): the two gold ids are
  hardcoded in the scorer rather than parsed out of `scoring.pass`/`scoring.bonus`. The brief's decision
  table itself hardcodes G-01/G-02, and the docstring discloses the exception, so this is compliant —
  noting it only because a future benchmark edit that renumbers golds would need a scorer edit.

## Cannot verify

- **No positive control on real prose.** No campaign record containing a real matched finding exists
  (the Morph campaign produced none), so the keyword quorum's adequacy against real finding prose is
  unverifiable until the first fresh re-run produces one — the report discloses this; nothing more can be
  done offline.
- **`go test ./...` not re-run by the reviewer.** The commit contains zero Go files, so the Go gate is not
  a compliance criterion for this task; I relied on the report's logs (71 packages ok) plus `go vet` claims.
- **Sandbox read-only caches claim** (report concern 6): I did not reproduce the host-cache failure mode;
  immaterial to the verdict since no Go code changed.

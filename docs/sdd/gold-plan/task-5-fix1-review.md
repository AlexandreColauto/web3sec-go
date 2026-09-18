# Task 5 fix-round-1 review — `e28efeed..bc80d151` (`docs/eval/morph-rerun-protocol.md` only)

Independent read-only re-review. Inputs: task-5-review.md (F-1 major, F-2 minor, F-3 note),
task-5-report.md fix appendix, the diff. Everything below was re-verified mechanically in this
session, not taken from the implementer's report: the two ```json blocks were extracted from the
committed doc text at `bc80d151` (`git show`, working tree clean for the file), `json.loads`-parsed,
checked against `assets/schema/protocol_model.schema.json` by hand, and fed to the leftover
`webv2` binary (`.scratch/task5-fix1/webv2`, built from this HEAD; source is untouched by the
doc-only commit) in fresh scratch campaigns under `.scratch/t5rev/` (untracked; no tracked changes).

## Verdicts on the open findings

- **F-1 (major, schema-invalid minimal shape): ADDRESSED.** §3.1 now presents a skeleton with the
  six schema-required keys (`protocol_id`, `name`, `contracts`, `actors`, `assets`, `relations`)
  plus `state_machines`; verified against the schema (`name` ≥2 chars — "Morph L2" OK;
  `additionalProperties: false` satisfied; machine entries carry the required
  name/states/transitions). Reproduced: extracted block → `webv2 model` in a fresh campaign →
  **exit 0**, and the doc's quoted output block is **byte-equal** to the captured
  stdout+stderr (WARNING line included, and the doc correctly says it rides stderr). The bare
  fragment is retained only as a negative example; re-running it reproduced the quoted six-line
  schema error **byte-for-byte** (exit 2). "Verified loadable" confirmed empirically.
- **F-2 (minor, zero- vs partial-coverage): ADDRESSED.** §3.1 now states the zero-coverage
  synthesis path (loads, exit 0, `liveness-template` minted) vs the partial-coverage refusal,
  matching `internal/invariants/invariants.go:493-505` (`len(uncovered) < len(machines)`).
  §3.2-1 carries a complete, pasteable partial-coverage variant (schema-valid: `INV-1` matches the
  `^INV-[0-9]{1,4}$` pattern, `kind: liveness` and `severity_if_broken: critical` are enum-valid,
  statement is 51 chars ≥ the 15-char minimum), and its quoted refusal is **byte-equal** to a real
  fresh-campaign run (exit 2, `…state machine(s) rollup_finalization have no liveness invariant…`).
  One trap remains, introduced by the fix itself — see N-1.
- **F-3 (note, 25 vs 26 tests): ADDRESSED.** §4 now says 26 tests; re-ran
  `python3 -m unittest scripts.eval_gold_test` from the repo root at HEAD: `Ran 26 tests … OK`.

## New findings (in the fix diff only)

- **N-1 (important, fix in doc): the §3.2-1 verbatim refusal is reproducible only in a *fresh*
  campaign; an operator who follows the doc's own §3.1→§3.2-1 sequence in the same campaign sees a
  different machine named.** §3.1's skeleton load takes the zero-coverage synthesis path, which
  mints a `liveness-template` invariant — numbered `INV-1` — covering `rollup_finalization`.
  Loading the §3.2-1 variant into that same campaign, `SeedFromModel` appends the model's `INV-1`
  *before* the gate, but `hasKey(reg, "INV-1")` is already true, so the entry is only
  `refreshSource`d — its `applies_to: ["message_queue"]` never lands. Coverage is therefore
  {rollup_finalization} (from the template), the uncovered set is {message_queue}, and the
  refusal reads `…state machine(s) message_queue have no liveness invariant…` — reproduced
  (exit 2), twice. Note the quoted `rollup_finalization` refusal is then **unreachable** in that
  campaign at any invariant id: the synthesized template already covers `rollup_finalization`
  (with `INV-2` in the variant both machines are covered → exit 0, also reproduced by
  construction). The doc's G-01 payoff line ("If the uncovered machine is
  `rollup_finalization`, the gate has just named the G-01 gap") fails in the natural in-sequence
  flow. Fix: one clarifying line — the §3.2-1 variant must be loaded in a **fresh** campaign (or
  the doc must show the `message_queue` refusal as the expected output of the in-sequence run).
  The gate fires and exit 2 either way; no claim in §1/§2/§4/§5/§6 is affected.

## Scope check

- The diff (`e28efeed..bc80d151`) touches exactly `docs/eval/morph-rerun-protocol.md`
  (73 insertions, 12 deletions, three hunks: §3.1, §3.2-1, §4 test count). No source, test,
  fixture, or CI change; the working tree is clean for the file at `bc80d151`.
- Untouched regions were not re-verified (per the fix appendix and consistent with a scoped
  re-review); the three quoted gate-firing strings were re-checked where the diff touches them:
  the refusal sentence in §3.2-1 remains verbatim against
  `internal/invariants/invariants.go:498-502`.

**Bottom line: F-1, F-2, F-3 all ADDRESSED; one new Important finding (N-1) joins the closure
list.**

# packed-storage-rejected

- bug_class: unsupported-layout
- source: seed target (Task 1); two `uint128`s sharing slot 1 — the packed-slot
  case v0.1 excludes by design (`ir/yul_lower.py` "packed-slot case v0.1
  excludes on purpose"; `analysis/passes.py` `_validate_packing`).
- lineage: `Packed` packs `a` (offset 0) and `b` (offset 16) into slot 1
  (solc storageLayout confirms `b.offset = 16`). The rule would be PROVEN if
  the packing gate did not fire, so this target proves the gate is
  load-bearing.
- measured (Task 1): 2026-09-11, solc 0.8.36, `python -m cli Packed.sol
  touch.mspec --loop-bound 4 --timeout-ms 30000` → exit 2, abort report (no
  `rule` key): `{"verdict": "UNKNOWN", "reason": "tool-error", "details":
  "rejected-feature: packed-storage:Packed.b"}`.
- measured (Task 4, after 4g): `{"verdict": "UNKNOWN", "reason":
  "rejected-feature", "details": "packed-storage:Packed.b"}` — the deliberate
  rejection now carries its own taxonomy instead of the crash label.
- expectation shape: `status: "unwritable"` with `blocked_on` /
  `expected_error_code` (the runner's dedicated loud-rejection contract).
  The Task 1 brief wrote `status: "expected"` with a per-rule
  `expected_verdict: "UNKNOWN"`; that shape can never pass the runner: a CLI
  abort line carries no `rule` key, so the expected-status path reports
  `no report line` and never consults the abort. The unwritable branch exists
  precisely for this case (reject the whole target loudly), so the seed was
  converted — a structural deviation from the brief, see task-1-report.md.

## Rulings

<!-- date | task | field | old | new | reason | evidence -->
- date: 2026-09-11
  task: 1
  field: expected.json status + rule block
  old: status "expected", rules [{expected_verdict: UNKNOWN,
    expected_reason_code: "unsupported-storage-layout",
    expected_details_include: "packed storage"}]
  new: status "unwritable", blocked_on "packed-storage",
    expected_error_code "tool-error",
    expected_details_include "packed-storage:Packed.b"
  reason: (1) the packing gate fires at the M2a artifacts gate
    (validate_artifacts -> LoaderError "packed-storage:<name>.<label>",
    reason "rejected-feature") BEFORE any rule report exists, so no per-rule
    line is ever printed — "expected" status can only mismatch ("no report
    line"); the runner's unwritable branch is the mechanism designed for
    whole-target loud rejections. (2) The CLI has no LoaderError clause, so
    the generic handler reports reason "tool-error" with details
    "rejected-feature: packed-storage:Packed.b"; the brief's
    "unsupported-storage-layout"/"packed storage" strings describe the
    analysis-layer gate (AnalysisError ... reason "unsupported-storage-layout")
    that this contract never reaches. The loud-rejection property the seed
    exists to prove (UNKNOWN, exit 2, gate fires) holds — only the taxonomy
    strings and the expectation shape differed.
  evidence: raw CLI JSON above; pytest output in task-1-report.md
  status: proposed (Gate 1) — expectation updated to observed truth, not
    weakened (the target still measures the gate firing loudly).

| 2026-09-12 | task-4 | expected_error_code + expected_details_include | `"tool-error"` / `"packed-storage:Packed.b"` | `"rejected-feature"` / `"packed-storage:"` | 4g RESOLUTION of the Task 1 finding above: the CLI taxonomy-carrying clause listed only `(LoweringError, AnalysisError)` and never imported `LoaderError`, so a deliberate loader refusal fell into the generic `except Exception` and was reported as a tool malfunction. `LoaderError` is now in that clause and `details` is the exception precise `feature` (`_abort_details`), which is what the corpus matches on. Status, `blocked_on` and exit code unchanged; nothing was weakened — the gate still fires loudly. | `python -m cli Packed.sol touch.mspec` → `{"verdict": "UNKNOWN", "reason": "rejected-feature", "details": "packed-storage:Packed.b"}`, exit 2; `tests/test_loader_error_taxonomy.py` |

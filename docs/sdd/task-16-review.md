# Task 16 review: reject duplicate YAML mapping keys (b00532ca vs 32ce5578)

Scope: `internal/validation/yaml.go` + `internal/validation/yaml_test.go` only. Read-only review;
inputs: task-16-brief.md, task-16-report.md, task-16-review-package.md, stored logs under
`.scratch/sdd/task-16-logs/`, plus two bounded in-package probe runs (`-run` on temporary probe
files, deleted immediately; `git status` confirmed clean afterwards).

## Review-package fidelity

- +/- content lines of the review package are byte-identical to `git diff 32ce5578 b00532ca --
  internal/validation/` (only hunk context widths differ: package used a larger `-U` context).
- Commit stat confirms exactly the two owned paths (+11/-1 and +115); message matches the brief.
- Worktree at HEAD matches the commit for owned files; `gofmt -l` clean on both.

## Spec compliance — YES

- **Duplicate rendered keys refused per-object, before appending.** One `seen map[string]struct{}`
  allocated inside the `MappingNode` case; check occurs immediately after `yamlKeyText(k)` and
  *before* the value is converted or appended — matches the brief's ordering requirement verbatim.
  Error text is exactly `fmt.Errorf("yaml: duplicate mapping key %q", key)`; failure returns
  `VNull()`. No new exported API, no dependency, `ParseYaml` signature untouched.
- **Nested/sibling scope.** `seen` is per call on a per-mapping basis, so recursion gives nested
  mappings fresh guards: nested duplicate `outer:\n a: 1\n a: 2` refused (tested), while sibling
  mappings, sequence items, and alias-expanded mappings reusing `a` stay accepted (all tested;
  independently re-confirmed by probe: `seq: [*a, *a]` → `[{"k": 1}, {"k": 1}]`, no false positive).
- **Valid order preserved.** Append loop unchanged (`out = append(out, KV{K: key, V: v})`);
  `VObj`/`DumpsOrdered` verified to be insertion-order (no sort, no dedupe), so the
  `{"z": 1, "a": 2, "m": {"z": 3}}` expectation is a meaningful order assertion.
- **Plain error + Null.** Plain `fmt.Errorf` (no custom type), `Value` is `Null` on every refused
  path; tests assert `got.Kind != Null || DumpsOrdered(...) != "null"`.
- **Acceptance cases truly assert values.** Sequence test checks `Kind`/length/key/int values
  *and* the full dump; siblings/alias/merge/order cases pin exact `DumpsOrdered` output. Nothing
  asserts only `err == nil`.
- **No historical fixtures or unrelated semantics altered.** Diff touches nothing else; alias and
  merge-key handling untouched; `1` vs `"1"` rendered collision refused as required (flow-style
  mappings covered for free — probes: `{a: 1, a: 2}` and `1`/`"1"` both rejected).
- **yamlKeyText identity is the sanctioned guard basis** (downstream object keys are strings);
  probe confirms null key vs `"None"` and `true` key vs `"true"` collide too — consistent with the
  stated rationale, documented in report concern 1.

## Evidence integrity

`red.exit=1` (5 reject subtests fail showing the old duplicated parses, e.g. `{"a": 1, "a": 2}`,
at the cited Fatalf line), `green-focused.exit=0` with all 10 subtests listed PASS,
`focused-4pkg.exit=0`, `full-test.exit=0` (zero FAIL lines), `vet.exit=0` (empty output).
Report's quoted excerpts match the stored logs.

## Quality — APPROVED (non-blocking findings)

- **[Low] Rendered-identity strictness beyond PyYAML is intended but only half-pinned.** Tests pin
  the required `1`/`"1"` collision; the null-vs-`"None"` case (probe-confirmed refused) rests only
  on report prose. Optional: one extra table row (`{null: x, "None": y}`) to pin it.
- **[Low] Double merge key edge wording.** `<<: *x` + `<<: *y` in one mapping is now refused as a
  duplicate rendered `"<<"` (probe-confirmed). Coherent under the new law (merge is never expanded
  here anyway, so the base kept two colliding literal keys), but "merge semantics untouched" in the
  report is slightly imprecise for this edge; PyYAML would flatten both merges. Consider a one-line
  comment or test pinning the chosen behavior.
- **[Low] Exactness style.** Duplicate assertions use `strings.Contains` against the exact message;
  the returned error is unwrapped here so equality would hold — Contains is acceptable (tolerates
  the `ParseYamlFileError` phrasing elsewhere) but slightly looser than "exact text."
- **[Info] No sentinel/`%w`.** Callers cannot `errors.Is` a duplicate-key failure; consistent with
  the package's existing "return the error as-is" contract, not required by the brief.

## Adjacent issues (pre-existing, NOT introduced by this commit)

- **Recursive alias:** parse-level probe (no expansion, safe): `a: &x { b: *x }` parses with nil
  error at the `yaml.Node` layer while forward references error as `unknown anchor`, so report
  concern 3 is real: `yamlNodeValue`'s `AliasNode` recursion has no visited/depth bound and such a
  document could crash the process. Existed at 32ce5578; correctly out of scope, correctly not
  exercised per the brief. Recommend a follow-up task (visited set or depth cap).
- **Multi-document:** `ParseYaml` (unchanged) decodes only the first document; a duplicate in a
  second document passes silently. Pre-existing loader semantics, unrelated to this diff.

## Limitations

- Full test suite not rerun per instructions; green status taken from stored logs (which are
  internally consistent) plus two bounded `-run` probe executions (each ~0.003s) that never
  expanded recursive structures; all temp probe files deleted, tracked tree unmodified.
- No resource-exhaustion payloads constructed or executed, per brief.

## Verdicts

- Spec compliance: **YES**
- Code quality: **APPROVED** (findings above are Low/Info polish, none blocking)
- Suggested follow-up (separate task): bounded alias recursion + document merge-key edge.

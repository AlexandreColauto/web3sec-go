# Task 16 report: reject duplicate YAML mapping keys

- Worktree: `/home/xand/Projects/dsh-plugins/websec2/web3sec-go/.worktrees/production-readiness` (branch `production-readiness`)
- BASE: `32ce55787da67ec29b8749757f76b0b670eaf03f`
- HEAD: `b00532ca` — `fix(validation): reject duplicate YAML mapping keys`
- Files (only these two committed): `internal/validation/yaml.go` (+11/-1), `internal/validation/yaml_test.go` (new, 115 lines)
- Shared signature `ParseYaml(raw []byte) (Value, error)` unchanged. No new API, dependency, canonicalization or refactor. No fixture or reviewer file touched; `.scratch` is gitignored so logs/report stay out of the commit.

## Change

`yamlNodeValue` `MappingNode` case now allocates one `seen map[string]struct{}` per mapping, renders the key once via the existing `yamlKeyText`, and immediately after key conversion (before converting/appending the value) refuses a repeat:

```go
key := yamlKeyText(k)
if _, dup := seen[key]; dup {
    return VNull(), fmt.Errorf("yaml: duplicate mapping key %q", key)
}
seen[key] = struct{}{}
```

The map is per mapping, so repeated keys in distinct mappings (sequence items, nested siblings, aliased mappings) stay legal. `yamlKeyText` is computed once per entry and reused for the appended `KV`.

## Red → green (exact evidence)

Logs: `.scratch/sdd/task-16-logs/` (`.exit` files hold the exit status; no pipelines, so statuses are real).

RED — `GOCACHE=$PWD/.scratch/gocache go test ./internal/validation/ -run 'TestParseYaml' -count=1` → **EXIT=1** (`red.txt`, `red.exit`)

```
--- FAIL: TestParseYamlRejectsDuplicateMappingKeys (0.00s)
    --- FAIL: .../flat: ParseYaml("a: 1\na: 2\n") = {"a": 1, "a": 2}, want duplicate-key error
    --- FAIL: .../nested: ParseYaml("outer:\n  a: 1\n  a: 2\n") = {"outer": {"a": 1, "a": 2}}, want duplicate-key error
    --- FAIL: .../unquoted_then_quoted: ... = {"a": 1, "a": 2}, want duplicate-key error
    --- FAIL: .../quoted_then_unquoted: ... = {"a": 1, "a": 2}, want duplicate-key error
    --- FAIL: .../rendered_numeric/string_collision: ParseYaml("1: x\n\"1\": y\n") = {"1": "x", "1": "y"}, want duplicate-key error
FAIL websec/internal/validation 0.005s
```

The 5 acceptance subtests already passed at red (the law's other half), so red is confined to the new guard.

GREEN — same command with `-v` → **EXIT=0** (`green-focused-verbose.txt`, `green-focused.exit`)

```
--- PASS: TestParseYamlRejectsDuplicateMappingKeys (0.00s)  [flat, nested, unquoted_then_quoted, quoted_then_unquoted, rendered_numeric/string_collision]
--- PASS: TestParseYamlAcceptsRepeatedKeysAcrossMappings (0.00s)  [sequence_items, nested_siblings, alias_to_previously_defined_mapping, merge_key_beside_explicit_key, key_order_preserved]
PASS
ok  websec/internal/validation  0.004s
```

Duplicate cases assert non-nil error containing the exact `yaml: duplicate mapping key "a"` / `"1"` text **and** `Value` == `Null` (`null` via `DumpsOrdered`). Acceptance cases assert real values/order, not just `err == nil`: `[{"a": 1}, {"a": 2}]` for `- a: 1\n- a: 2\n`; `{"first": {"a": 1}, "second": {"a": 2}}`; alias `{"base": {"a": 1}, "use": {"a": 1}}`; merge-key case `{"base": {"a": 1}, "derived": {"<<": {"a": 1}, "a": 2}}`; order `{"z": 1, "a": 2, "m": {"z": 3}}`.

## Compatibility / validation

| Command (GOCACHE=$PWD/.scratch/gocache) | Exit | Log |
| --- | --- | --- |
| `go test ./internal/validation ./internal/playbooks ./internal/archetypes ./internal/taxonomy -count=1` | 0 | `focused-4pkg.txt` |
| `go test ./... -count=1` | 0 | `full-test.txt` |
| `go vet ./...` | 0 (empty output) | `vet.txt` |

Full suite: 71 packages `ok`, zero `FAIL` lines. No compatibility failure, so no historical fixture was altered or sanitized (confirmed by `git status`: only the two owned paths). `gofmt -l` on both owned files is clean.

## Concerns

1. **Rendered-key strictness (intended, but stricter than PyYAML).** The guard keys on `yamlKeyText`, so keys that are semantically distinct but render identically are refused: `1: x` + `"1": y` (both key `"1"`) and, by the same rule, a null key vs the string `"None"`. PyYAML would keep `1` and `"1"` as two distinct dict keys. This is required by the brief ("rendered numeric/string key collision") and is correct for the string-keyed `Value` model, but it is a deliberate strictness beyond Python parity.
2. **Alias/merge semantics deliberately untouched.** `<<` is not expanded (pre-existing): the merge case loads as `{"<<": {...}, "a": 2}` and is accepted. PyYAML would merge and collapse to one key. Out of scope per brief; reported only.
3. **Adjacent risk, not reproduced.** `yamlNodeValue` has no visited set for `AliasNode` (`return yamlNodeValue(n.Alias)`), so a self-referential/recursive anchor could recurse without bound. The brief forbids reproducing resource-exhaustion payloads, so this was not exercised — flagging it as candidate hardening for a future task.
4. **Error type/shape.** The failure is a plain `fmt.Errorf`, not a `yaml.TypeError`, so callers that wrap through `ParseYamlFileError` phrase it as `"<what> is not valid YAML: yaml: duplicate mapping key \"a\""`. The exact inner text matches the brief; the wrapper prefix is pre-existing behavior.

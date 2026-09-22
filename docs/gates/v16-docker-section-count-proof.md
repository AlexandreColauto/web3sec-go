# The `p2-docker-e2e.sh` section count — proof by enumeration

`scripts/p2-docker-e2e.sh:331` asserts `len(rep["sections"]) == 16`. That number was raised from
15 when the exec-record anchor landed. The script has **not** been executed on this machine — no
Docker — so the assertion is reasoned, not verified by execution. This note is the reasoning, and
it is the only claim made for it.

## The enumeration

The registry holds **19** sections (`internal/audit/sections/register.go`, counted: 19; the audit
test pins the same number at `internal/audit/audit_test.go:85`). They decompose as:

| section | presence gate | renders here? | why |
|---|---|---|---|
| the 14 ported sections | **none** — no `ErrSkip` in any of the fourteen files | **14** | unconditional |
| `v16_coverage` | **none** | **1** | registered unconditionally (its own comment says so) |
| `eval` | `ErrSkip` unless the campaign's pinned program matches a suite case | **0** | not an eval-suite campaign |
| `price_table` | `ErrSkip` when `!fileFound && len(priceEvents) == 0` (`pricetable.go:33-35`) | **0** | the script contains **0** price invocations and writes no `prices.json` |
| `regression_suite` | `ErrSkip` without a regression target record | **0** | the script contains **0** references to regression |
| `exec_record_anchor` | `ErrSkip` without a carrier event | **1** | the script runs **2** real execs — `exec-pass` (`:235`) and `exec-fail` (`:240`) — so `sandbox.exec` carrier events exist |

**14 + 1 + 0 + 0 + 0 + 1 = 16.**

The "no `ErrSkip` in any of the fourteen" row is the load-bearing one and it is mechanical: each
of the fourteen files was searched for the token and returned zero hits, so none of them can
decline to render.

## The independent cross-check

The strongest evidence is not the enumeration above but the assertion that was there before.
The pre-anchor script asserted **15**, and its comment named exactly two gated sections (`eval`
and `price_table`) against an 18-section registry:

```
- # 4. the audit: ok + all 15 rendered sections (17 registered; `eval` and
- #    `price_table` are presence-gated, `v16_coverage` is unconditional and
- if len(secs) != 15:
```

18 registered − 3 skipping (`eval`, `price_table`, `regression_suite`) = **15**. That value
passed whenever the docker tier last ran, so it is an *executed* fact that those three gates were
closed for this campaign. The anchor adds exactly one registered section, it renders (the two
execs above), and it closes no gate that was open. **15 + 1 = 16.**

Two things follow that are worth recording:

- The old comment's "17 registered" was **already wrong** — the registry held 18. The new
  comment's "19" is correct.
- `eval` is the one gate this note cannot close from the script's text alone; it is closed by the
  pre-anchor 15, which could not have been 15 if `eval` had rendered.

## What is still not established

The new value has **not** been observed. This is a derivation from the registry, the section
gates, the script's own contents, and one previously-executed assertion — not a run. If the
docker tier is executed and reports a different count, the derivation is what is wrong, and the
right response is to fix the reasoning rather than the number.

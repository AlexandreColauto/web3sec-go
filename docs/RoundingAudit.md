# Rounding audit (risk R3) — round-half-to-even

> Scope: every `round(x, n)` call site in the Python reference
> (`web3sec-final/src/webv2/`, ported test assertions noted). P0 owns the
> mechanism; each phase re-runs this grep as its modules land and adds rows.

## Verified CPython semantics (the target)

`round(x, n)` = **decimal round-half-even on the EXACT binary value of x**,
then correctly rounded back to `float64`. It is *not* `round(x*10**n)/10**n`
in binary: scaling introduces a second rounding that can flip an exact `.5`
boundary (e.g. a value whose binary value is exactly `62.5·10⁻ⁿ` must round
to even, and a binary value `ε` above a decimal half must round up even
though `x*10**n` in float lands below it).

Evidence (CPython 3.14.7):

- 1,557,310-case probe: CPython `round` vs an exact `Fraction`-based
  round-half-even reference — **0 real mismatches**; the only difference is
  the sign convention (rounding a tiny negative to zero yields `-0.0`).
- Go implementation `internal/validation/pyround.go` reproduces the exact
  algorithm (exact binary value → big.Int decimal round-half-even →
  correctly-rounded `float64` via a 128-bit `big.Float` intermediate, which
  clears the double-rounding danger bound for 53-bit results, `P ≥ p+2`).
- `internal/validation/pyround_test.go`: 31 CPython-captured table vectors
  (bit-exact, including the `-0.0` sign cases) plus a 20,000-case
  differential oracle test (structured tie-habitat values + random
  full-range floats, `n ∈ {1,2,3,4,6}`).

## Call-site classification

Rule: a site is **ties-possible** unless the input is provably never a
binary rational whose scaled value lands exactly on `.5`. Count ratios
(`len(a)/len(b)`) and weighted sums of small rationals *can* be such values
(e.g. `1/16 = 0.0625` is an exact tie at `n=3`), so **no site below is
certified ties-impossible — every ported site uses `pythonRound`**.
That is the minimal safe policy: the helper is the same cost as the naive
scale.

| Site | n | input shape | ties-possible | port uses |
|---|---|---|---|---|
| forkdiff.py:81 | 4 | weighted Jaccard sum | yes | pythonRound |
| forkdiff.py:89-90 (×4) | 4 | Jaccard ratios (int/int) | yes | pythonRound |
| history_mining.py:132 | 3 | verified/len(contracts) | yes | pythonRound |
| history_mining.py:224 | 4 | weight × decay fraction | yes | pythonRound |
| risk.py:66 | 3 | min(score, 1.0), weighted sum | yes | pythonRound |
| risk.py:83 | 2 | min(0.5·len(hit), 1.0) — 0.5·k is a binary rational; k/2 at n=2 lands on .05-grid, ties possible | yes | pythonRound |
| risk.py:116 | 2 | weighted score | yes | pythonRound |
| risk.py:123 | 3 | usd ratio (float(float)) | yes | pythonRound |
| risk.py:142 | 2 | weighted score | yes | pythonRound |
| risk.py:239 | 2 | sum of band weights (small rationals) | yes | pythonRound |
| sft_dataset.py:657 | 1 | 100·held/total | yes | pythonRound |
| sft_dataset.py:675 | 1 | 100·count/n_curated | yes | pythonRound |
| sft_dataset.py:678 | 1 | target − pct | yes | pythonRound |
| sft_dataset.py:682 | 1 | 100·with_pivot/n_curated | yes | pythonRound |
| shared_memory.py:596 | 3 | len(overlap)/len(union) | yes | pythonRound |
| corpus_surface.py:401 | 6 | surface score | yes | pythonRound |
| corpus_surface.py:612 | 4 | best score | yes | pythonRound |
| relations.py:384 | 3 | len(overlap)/len(union) | yes | pythonRound |
| coverage.py:108 | 3 | reviewed/total | yes | pythonRound |
| invariants.py:271 | 3 | tested/total | yes | pythonRound |
| briefing.py:401 | 1 | seconds/3600 | yes | pythonRound |

No `round(x)` (one-arg) or `round(x, n)` with `n ≤ 0` exists in the port
surface; `pythonRound` panics on `n < 0` and non-finite input (no call site
can produce those).

## Ported test assertions that call `round()`

These Python tests re-derive expectations with `round()` in the assertion;
the Go ports compare against `pythonRound` of the same inputs (or a
captured literal) so the banker's-rounding semantics stay pinned:

- tests/test_risk_amplifiers.py:47 — `boosted == round(min(10.0, base+0.5), 2)`
- tests/test_corpus_surface_scoring.py:24 — `rows[0]["score"] == round(expected, 6)`
- tests/test_severity_split.py:51 — `iv["score"] == round(9.0, 2)` (weights sum)

## P0 modules

`validation.py`, `state.py`, `snapshot.py`, `audit.py` contain **no**
`round()` calls — P0 ports nothing; the helper is shared infrastructure
landed early per the design (§6.2).

# Leanness review — polish wave F

Date: 2026-09-10 · Status: PROPOSAL (review only; no code changed).
Method: full-tree audit (git ls-files, `go list -deps`, helper hashing, script
tracing) against the doctrine in `docs/IMPROVEMENTS.md` principle 6 (surface
budget) and the 2026-09-09 twin-retirement banner in `KNOWN_DIVERGENCES.md`.

**Question asked:** what costs us maintenance and reader entropy but no longer
buys bug-finding power?

## Verdict

The hunting loop is in good shape: 76/76 CLI verbs are exercised and asserted
by `assets/runbook/RUNBOOK.md` (D7's registry↔runbook test holds), `go vet`
is clean across all 62 packages, the hash-chained state core is wired end to
end, and waves A–D closed the campaign-exposed defects. The entropy is **not**
in the bug-finding machinery — it is in three things left over from the port
itself:

1. a **parity tax** on a retired Python twin (~350 KB committed + a hard gate
   that needs the sibling checkout to pass at all),
2. **ported-but-never-wired modules** (~4.4k LOC of dead Go, kept alive by
   the 1:1 accounting),
3. **docs that describe a different repo** (README doctrine, stale counts,
   a dangling spec reference, a settled item still listed as deferred).

Each is removable without touching a single byte the campaign state depends
on. Total identified saving: ~4.4k dead LOC + ~1.5k duplicated-helper LOC +
~400 KB committed artifacts + 6 scripts whose only caller chain ends in the
retired twin + one hard gate dependency on `../web3sec-final`.

---

## F1. Retire the parity tax (the twin is dead — stop feeding it)

Verified dependencies on the sibling checkout (`../web3sec-final`, present on
this machine, absent for anyone who clones the repo per README §Quick start):

| item | evidence | today's behavior without the twin |
|---|---|---|
| `verify-full.sh` step 6 | `sync-assets.sh:23` diffs `assets/schema` byte-identical vs `<pyroot>/schema` | FAILS (`sync-assets.sh:33`) |
| `verify-full.sh` step 8 | `sync-testmap.py --check` + `check-testmap.py` vs `count-python-tests.py` | FAILS |
| `runbook-walkthrough.sh:107` | seeds a fixture from `$PY_ROOT/sft/examples.json` | FAILS |
| byte-identity tests | `archetypes_test.go:401`, `playbooks_test.go:417`, `adapter_test.go:224` | silently SKIP (false comfort) |
| `cmd/oq3check` + `scripts/oq3-check.py` | differential vs Python `jsonschema`; only referenced by `docs/gates/P0-gate.md` | dead one-off tool |
| `scripts/cap-analysis.py` | "D27 chain-cap **parity evidence**" — a completed investigation | dead one-off |
| `scripts/canon-oracle.py`, `invariants-vectors.py` | regenerate vectors by running the twin | unrunnable one-offs |

**Actions:**

- **F1a — make `verify-full.sh` stand alone.** Drop steps 6 and 8's twin
  legs. Replace sync-assets' byte-diff with a committed SHA-256 manifest of
  `assets/schema/` (the invariants it actually still protects: nobody edits
  a schema by hand unnoticed). Move `testmap.json` to
  `docs/archive/testmap-2026-09.json` (or delete; git remembers) and retire
  `check-testmap.py`, `count-python-tests.py`, `sync-testmap.py`.
  *This is the difference between "verified repo" and "verified repo on one
  laptop."*
- **F1b — replace the three skip-when-absent byte-identity tests** with
  a checksum manifest test over the embedded asset packs (they keep guarding
  "the binary contains what git says it contains" with zero external deps).
- **F1c — archive the one-off parity probes** (`oq3check`, `oq3-check.py`,
  `cap-analysis.py`, `canon-oracle.py`, `invariants-vectors.py`,
  `sync-assets.sh`, `sync-testmap.py`, `count-python-tests.py`,
  `check-testmap.py`) under `scripts/archive/` with a one-line README.
  `scripts/golden/` and `golden-run.py` stay (Go-only and load-bearing).
- **F1d — keep the formatters, kill the framing.** `PythonFloat`,
  `pythonRound`, `PyRepr`, `Canon`, ordered-parsing are now **Go-native
  stability contracts** — they pin artifact hashes and the event-chain
  content hashes, so "byte-exact with itself" is what pays. Do NOT touch the
  code or committed vector goldens; only retitle comments/docs from
  "matches CPython" to "canonical format v1" and stop regenerating vectors
  from the twin (F1c covers the generators). The committed vectors become
  plain regression goldens — same value, no fiction.
- **F1e — `KNOWN_DIVERGENCES.md` → `docs/archive/`.** The banner itself says
  the rows are historical and the normalization hooks are dormant; nothing
  reads it at runtime (only comments in `golden-run.py`). 60 KB at repo root
  with IDs (`D1`…`D36`) that **collide with the improvement waves' D1–D8** is
  actively confusing; `docs/python-twin-issues.md` joins it in archive.

## F2. Delete the never-wired modules (git is the archive)

`go list -deps ./cmd/...` proves these are unreachable from any shipped
binary — zero non-test importers anywhere:

| package | prod LOC | test LOC | note |
|---|---|---|---|
| `internal/routing` | 918 | 792 | ports Python's assumption router; only its own tests + `config/assumption_routing.example.json` reference it |
| `internal/datasets/forge` | 850 | 535 | enum strings `"forge"` in `ingest.go` are data, not code deps |
| `internal/datasets/scabench` | 427 | 390 | same |
| `internal/datasets` (parent) | 62 | 162 | registry used only by the two dead children |

≈ 2.6k prod + 1.9k test LOC. `datasets/defihacklabs` **stays** — it is wired
via `cmd_t34_wire.go` into corpus POC attribution (D26), which is in the
loop. Deleting these is exactly what the surface-budget principle says when
"an existing capability is demonstrably unreachable from any command" —
inverted: unreachable from any caller. If `routing` ever earns its keep it
comes back as a *designed* feature, not a faithful port. Remove the example
config alongside; note the retirement in the (post-F1a) Go-native test
inventory.

## F3. Consolidate the helper clones

`grep '^func setOrAppend'` finds **17 copies** in 17 packages (state,
snapshot, cli, findings, invariants, risk, pricing, dedup, floors, bounty,
planner, coverage, orchestrator, immunize, chainengine, maximization,
learning); hashing shows 5 byte-identical variants and the rest identical in
behavior modulo local aliases (`kv(...)`, `pair(...)`, inline literal).
Same story: `setDefault` ×5 (with **two different signatures** — `*Value` vs
value-replacing), `scalarStr` ×2 (cli/adapter, subtly different fallbacks),
`writeU4` ×3, `sortStrings` ×3, `pyReprTuple` ×2 (learning re-implements
`validation.pyReprTuple`), plus three parallel JSON writer stacks
(`validation.writeIndented` / `chainengine.writeDump` / `cli.writePretty`).

**Action:** export `validation.SetOrAppend` / `validation.SetDefault` (KV
form) + a `Value.SetDefault` method (the pointer form), one `SortStrings`,
one `ScalarStr` (keep the caller's fallback as a param), and collapse
`chainengine.writeDump` onto `validation` — **only after proving byte
equivalence** on a fixture diff (these feed artifact content hashes; the
emitters *look* similar but the divergence may be load-bearing; the F3
emitter merge is the one medium-risk item — do the KV helpers first, measure
the emitters separately, merge only what hashes equal). ~250 LOC saved
directly, 60+ symbol clones removed from search results forever.

## F4. Fix docs that describe a different repo

Verified stale against the tree:

- `README.md:5-11` — "Python wins … the Python tree remains the reference
  implementation": contradicts the 2026-09-09 retirement; also points at
  **`docs/GO_REWRITE_SPEC.md`, which does not exist** (never committed; the
  real doc is `docs/superpowers/specs/2026-09-07-go-rewrite-design.md`).
- `README.md:39,93,100,109` — counts already rotted: "1,963 test functions"
  (actual `^func (Test|Benchmark|Fuzz)`: **2,182**), "79.6k non-test lines"
  (actual: **86.4k**). "62 packages" ✓, "1,378 testmap rows" ✓ (until F1a).
- `README.md:87,110` + verification table — still advertises `python3
  scripts/check-testmap.py` and "cross-twin golden, both twins byte-diffed"
  as core gates after golden went Go-only.
- `docs/IMPROVEMENTS.md:32,1673` — "179 steps × 2 twins, 68 files
  byte-match" parity framing in principle 1; the "Wave E — Remaining asks
  (DEFERRED)" heading still lists **E5**, which landed 2026-09-10
  (commit `92104cf`, `risk.go:52` reversibility weights, G-02 regression
  pinning 7.0 high). E6 says "E5 is the fix" — both should be marked
  **LANDED**.
- `docs/runbook-go-notes.md` header and README's twin table rows keep the
  "with the Python-side equivalents" framing — fine as history, wrong as
  current contract; retitle as "historical port notes".

**Action + prevention (F4b):** delete hard numbers from README — they are
self-rotting contracts. D7 already proved "the runbook is a test"; the same
trick applies: `webv2 selftest` prints the live counts and the README says
"see selftest". One line of code kills a whole class of doc drift.

## F5. Committed cruft & history hygiene

- `.scratch-all-tests.json` (54 KB test-run dump, repo root, committed) —
  delete, and `sft/` at root is NOT cruft (it is the live SFT store by
  design, `internal/sft/sft.go:6` "VCS is the integrity layer") — leave it,
  but the root listing then needs README to say so, since it reads as a
  stray output dir.
- `.git` = 170 MB for an 86k-LOC Go repo; the top blob-sum paths are
  `testmap.json` (5 MB cumulative — dies with F1a), planner/orchestrator
  `oracles.json` (~2 MB each × 3–6 historical rewrites, ~700 KB on disk),
  `docs/IMPROVEMENTS.md` (1.2 MB cumulative). Nothing to rewrite history
  for; the **policy** is the fix: oracle/vector files get *appended* rows,
  not regenerated blobs — and any new 500 KB+ generated file must be
  regenerable or compressed.

## F6. Open decisions (not entropy — just decide)

- **D8 (patch clause follows the target program)** is PROPOSED and well
  specified; recommend landing it: it is the same "policy is data" posture
  as A1/B4 and removes a per-finding waiver tax on every submission to a
  program that doesn't want patches.
- **Wave E (E1–E4)** stays correctly deferred under principle 6 — nothing
  to do except the E5 relabel in F4.
- **C2/D-wave probe-surface golden blind spot** (plan-review item 8: the
  golden recipe emits 0 rows for some probe axes) — the one *capability*
  gap worth a slot, since every future probe field inherits the blind spot.

## Recommended landing order

Each step lands green (`go build ./... && go test ./... &&
scripts/golden.sh` + `scripts/runbook-walkthrough.sh` where touched), same
discipline as the A–E waves:

| # | step | est | risk | why this order |
|---|---|---|---|---|
| 1 | F4 docs fixes (README rewrite, E5 relabel, selftest prints counts) | S | none | zero code, kills the loudest confusion |
| 2 | F2 delete `routing` + `datasets/{forge,scabench}` + example config | S | low | nothing links them; `go build` is the proof |
| 3 | F1a verify-full twins-free + F1c scripts archive + F1e ledger move | M | low | one PR, one theme: "the gate passes on a fresh clone" — validate in a `git worktree` copy with no sibling dir |
| 4 | F1b checksum-manifest tests replace skip-when-absent | S | low | net stays, twin dep goes |
| 5 | F3 KV-helper consolidation (SetOrAppend/SetDefault/SortStrings/ScalarStr) | M | low | mechanical; green = hashes unchanged (living-artifacts tests already pin chains) |
| 6 | F3 emitter merge (chainengine/validation) | M | med | fixture byte-diff gate; keep separate if any hash moves |
| 7 | F5 root cruft delete + README note on the live `sft/` store | S | none | |
| 8 | D8 landing (separate decision, tracked in IMPROVEMENTS) | M | med | it is a capability change, not leanness |

## What this review deliberately does NOT propose

- **No output-format changes.** Canon ordering, `PythonFloat`, `pythonRound`,
  `PyRepr` stay byte-frozen forever — they are now self-stability anchors for
  content hashes and the event chain, not Python worship. The goldens that
  pin them stay (as Go-native regression vectors, per F1d).
- **No verb removals.** All 76 verbs are runbook-covered; the surface budget
  did its job. Merging, say, `chains`→`chain --list` or
  `artifact-list/register/reconcile`→`artifacts <sub>` is cosmetic churn with
  real contract-breaking cost — wrong trade at this stage.
- **No test-count trimming for its own sake.** 2,182 test functions are the
  regression net for a tool whose whole product *is* determinism; only the
  twin-dependent skip cases (F1b) and dead-module tests (F2) go.
- **No wave-E revival** — principle 6 already triaged those; this review
  agrees with the deferrals.

One-line summary: the bug-finding engine is lean and honest; the **port
scaffolding around it is what's left to strike.** F1–F5 remove it, F6 is a
decision, and nothing here weakens a single check the campaign loop runs.

## Landing record (2026-09-10)

What actually landed, in the order it landed, with the proof each step carried.
Three commits: `8c2864d` (F1+F2+F3+F4+F5), `dd08da5` (F7, found while gating
F1), and the D8 commit that follows.

| step | status | proof it did not move a byte |
|---|---|---|
| F4 docs (README truth, E5 relabel, doctrine sweep) | landed | no code touched; `selftest` still reports 76 commands |
| F2 dead modules (routing, datasets/{forge,scabench}, parent, config) | landed | `go build ./...` + `go test ./...` green; `go list -deps` had shown no importer |
| F1 twin-free gates (verify-full 12 steps, manifest test, legacy fixture, archives) | landed | `verify-full` step 6 manifest equality, step 9 legacy cross-audit PASS |
| F3 helper consolidation (SetOrAppend ×17, SetDefault ×5, WriteU4 ×3, sortStrings) | landed | full suite green; content hashes unchanged (golden: 179 commands, chain intact) |
| F3 emitter merge (chainengine + cli dump stacks) | landed | **permanent equivalence tests**: 190,476 and 126,987 sampled values encode byte-identically to the deleted implementations |
| F5 cruft (`.scratch-all-tests.json`, sft note) | landed | — |
| F7 walkthrough rot | landed | walkthrough went 131/9 → 140/0 and became **verify-full step 13** |

### F7. The walkthrough was red at HEAD, and nothing said so *(found 2026-09-10)*

The review's premise was "find what does not buy value". The inverse showed up
instead: a gate that bought value and had rotted because **it was not in the
gate**. `scripts/runbook-walkthrough.sh` was red at HEAD (9 failing rows) —
three of them caused by the twin retirement itself (the SFT fixture), six
stale in ways unrelated to wave F:

- three rows asserted behaviours Go had *deliberately corrected* (`ladder
  explore` without a rung, `resolve-candidate --note`, and raw-JSON `prove`
  markers) — the runbook documented the fixed behaviour, the walkthrough still
  asserted the reference's.
- three rows failed on a fixture bug: `snap` pins through git and walks up, so
  the toy target pinned **this repository** (472 nodes) instead of the 15-node
  toy; the probe surface was then emitted against one tree and re-derived from
  another, and the final audit correctly called it stale. The fixture now inits
  its own repo, and the runbook documents the walk-up.

Neither the README nor any gate caught it, because `verify-full` simply did not
run the walkthrough. Step 13 fixes the class, not the instance.

### F8. Lesson for the next wave

Leanness work needs the *anti*-gate as much as the gate: a check that is not in
the one command people run is a check that describes the past. `verify-full` is
now 13 steps and the runbook walkthrough — the only gate that reads the operator
contract end to end — is one of them.

### D8 landed (capability, not leanness) — and the advisory channel it exposed

`poc_requirements.patch_clause` (`verification` | `prose` | `none`) now drives
`check12`, so the gate asks for what the program actually wants: a tested patch,
a written recommendation, or nothing. The absent key is `verification`, so the
golden fixture, the pinned gate vectors and every existing campaign gate
byte-identically; unknown values are refused at policy load and again in the
gate. No new verb, no new flag.

Landing it surfaced a small piece of dead data: `bounty.advisories` — the
channel A2 introduced for in-code acknowledgements — was **written by the gate
and read by nobody**. An advisory nobody can see is not an advisory. The report
now renders it next to the gate verdict (`  - advisory: …`), emitted only when
the list is non-empty so no existing output moves, with tests pinning both
directions.

### Second pass (2026-09-10, after D8): dormant checks and dead scaffolding

Sweeping for the *inverse* of entropy — checks that cost nothing but buy
nothing because nothing runs them — turned up four more classes:

**F2b. Two inert twin-parity harnesses deleted.** `internal/audit/p1_parity_dump_test.go`
(`TestT15GoParityDump`, gated on `T15_OUT`) and
`internal/maximization/parity_dump_test.go` (`TestParityDump`, gated on
`MAX_PARITY_OUT`) could only ever run when a scratch Python driver pushed a
campaign through the *live* reference. The reference retired, the drivers are
untracked scratch, and both tests skipped silently in every gate — coverage
that reports green by never executing. Deleted (the golden suite and the
legacy cross-audit cover the same ground against committed fixtures).

**F2c. Two stale POSIX placeholders deleted from `findings`.**
`TestFreshContextGuidanceUnported` still claimed `reproduction.record_attempt`
was unported (it is ported, and `TestRecordAttemptGuidance` covers the
fresh-context ladder), and `TestAnsweredSliceHasNoFindingFacingAssertions`
asserted nothing at all — its only statement was a skip. Both were port-era
bookkeeping, both invisible in a green run.

**F9. A whole docker tier was invisible.** Four packages carry real
end-to-end tests behind `WEBV2_DOCKER_TESTS=1` — cli exec, forkpoc, immunize,
reproduction — and *no gate set the variable*: they had been skipping since
the day they were written. All four pass (35 s with the daemon up), and they
now run in `scripts/p2-docker-e2e.sh`, the one gate where docker is already a
precondition. This is F8's lesson in its general form: **a skip that nothing
un-skips is a lie told in green.**

**F10. The comments still described the deleted harness.** Live files
explained their behaviour in terms of a cross-twin golden harness that no
longer exists (`scripts/golden.sh`'s header promised "op-sequence through both
twins", `cmd/webv2/main.go` described patching the reference's minter,
`findings/storage.go` justified its id stream as "so both twins mint the same
finding ids"). The mechanisms are live and load-bearing — only the rationale
was obsolete. Rewritten in Go-only terms across 13 files, and
`docs/runbook-go-notes.md` is now explicitly titled *port notes (historical)*
so its "both twins" rows read as the record they are.

**The probe-surface golden blind spot (F6, C2) — closed in the next commit.**
This pass found it (some probe axes emitted 0 rows, so a regression there moved
no pinned expectation) and left it open rather than half-fixing it; see the
"F6 closed" section below for what it turned out to be and how both halves are
now pinned.

### F6 closed (2026-09-10): the probe-surface golden blind spot

The one capability gap this review left open. It was recorded as "the golden
recipe emits 0 rows for some probe axes"; measuring it first narrowed the claim
sharply, and the narrow version is what got fixed.

**What was already covered.** All six detectors are pinned byte-for-byte:
`internal/probes/testdata/golden/` holds `raw_<tree>_<probe>.json` for 15
fixture trees × 6 probes (90 vectors), so a regression *inside* a probe already
failed the default suite. What nothing pinned was the end-to-end path —
fixture present → index → surface assembly → quota → rows — and the flagships
of that path were empty: the recipe shipped `accumulator/blind` and
`assertion_strength/clean` but never their `buggy` siblings, so
`accumulator-skew` and `enforcement-timing` reported **0 sites** in the one run
the gate validates. A dead fixture copy, a broken index step or a surface
assembly that dropped an axis would have moved no expectation at all.

**The fix is a contract, not a bigger fixture set.** Every registered axis is
now pinned to the state it must reach, in `scripts/check-golden.py`:

| axis | state | why |
|---|---|---|
| `accumulator-skew` | **blind** | the `blind` fixture must stay silent and publish the BLIND key `probes blank` cites |
| `enforcement-timing` | **blind** | same, for `assertion_strength/clean` |
| `primitive-symmetry`, `liveness`, `guard-short-circuit`, `incentive-inversion` | **rows** | their fixtures must keep firing |

Either state requires `sites >= 1`; `no-sites` is refused outright, because
that is the exact signature of the blind spot. The complementary half lives in
`internal/probes/axis_coverage_test.go`, which drives the **production**
pipeline (`BuildSurfaceOpts` with `ProdProbeOpts`) over the buggy corpus and
requires ≥ 1 row on **every** registered axis — the strict floor the golden
cannot assert, since the golden needs its blind axes for the `probes blank`
step — plus "clean fixtures stay silent", so the floor cannot be met by a
detector that fires on anything. A third test parses the checker's table and
compares it to `RegisteredAxes()`, so a new probe cannot land without widening
the gate.

**Both directions were proven to bite**, not assumed:

* checker branches (against the real captures): declared-blind axis that
  stopped emitting, declared-rows axis that went silent, blind axis with no key
  to cite, unknown axis in the table, axis dropped from the table, `sites=0`;
* end to end: dropping `custody/buggy` from the recipe turns the golden RED
  with `axis primitive-symmetry reports sites=0 (status='no-sites') — the
  detector saw no code at all, so nothing downstream can catch a regression on
  it`, then green again on restore.

Green run: `6 probe axes alive, states as declared (accumulator-skew=blind,
enforcement-timing=blind, guard-short-circuit=rows, incentive-inversion=rows,
liveness=rows, primitive-symmetry=rows; rows=5)`.

## Open item found while proving D1: the walkthrough's `L###` labels are rotten

Not a gap in bug-finding power — a gate that MISREPORTS. `scripts/
runbook-walkthrough.sh` labels every `check` with the RUNBOOK line that
documents the command, and the label is printed in every PASS/FAIL row
(`[FAIL] L710 probes-run …`). Those numbers have not been true for a while:
`RUNBOOK.md` was restructured around them and nothing validates a label, so
`L710` currently points at "carry the campaign forward until you know what
changed" while the command it labels is documented elsewhere. Adding the D1
paragraphs shifted the labels by the block size (so their error is unchanged),
which is the moment the rot became impossible to ignore.

Two candidate remedies, both small:

1. **Make the label an anchor**: replace `L710` with the runbook SECTION
   (`§5`, `cheat`), and add one assertion that every label names a real heading.
   Stable under every future edit, and cheap to verify — but the label becomes
   coarser (a section covers many commands).
2. **Keep line numbers, verify them**: a Go test resolves each citation the way
   the walkthrough does and asserts the cited line mentions the command's verb,
   so a restructure that moves a line fails the suite instead of silently
   mislabelling a failure. More precise, more maintenance.

Recommendation: (1) for the labels plus (2) for the cheat-sheet block only
(where commands appear verbatim, so an exact check is possible). Left open
because it is a documentation-contract decision, not a bug.

# MiniProver × web3sec-go — host integration guide

MiniProver (`/home/xand/Projects/miniprover`, Python) is the **auto-prover**:
LLM agents analyse a contract, author `.mspec` properties, and drive
**MiniCertora** (the verifier, see `MINICERTORA_INTEGRATION.md`) in a
verify/revise loop until the spec publishes. web3sec-go is the **control
plane**: it decides what counts as evidence and keeps the ledger.

> **The tool's own operator guide is `python -m miniprover.guide`** (env
> contract: `python -m miniprover.guide --env`). It ships inside the
> package and is pinned against the real `--help` and the real report
> schema by `tests/test_agent_guide.py`, so it cannot drift the way prose
> can. This file is the webv2-side half — what the host may assume and what
> it must refuse; the guide is the tool-side half. Where they disagree, the
> guide is right about the tool and this file is right about the bind.
> **Refreshed 2026-09-17** against the prover tree at HEAD `9c997b3`: the
> report is now `report_revision: 3` (§5), the run writes artifacts this
> guide had never named (§5.2), and the ledger mode that closes the
> webv2→prover gap has shipped (§5.1).

Three services, three contracts between them — no repo merging, no shared
state beyond files each service OWNS:

```
 webv2 (Go)                    miniprover (Python)          minicertora (Python)
 ──────────                    ───────────────────          ────────────────────
 INV ledger + DESIGN text ──▶  autoprove run dir      ──drives──▶  verdict lines
 (scaffold or design doc)       reports/report.json                  (per rule)
                               reach.json, final .mspec
 verify --autoprove ◀───────   parsed ONLY from the JSON
 EXEC record + report.json     (exit code = tripwire,
 → rung / counterexample /         never a verdict)
   recorded gap, E3 cap
```

| File | Owner | Consumers | Frozen by |
|---|---|---|---|
| verdict JSON lines | minicertora | miniprover (`verifier/parse.py`), webv2 (`internal/harness`) | §1 of each guide; `rules` field is the v0.4 contract |
| `reports/report.json` | miniprover | webv2 (`verify --autoprove`) | prover honesty rules below |
| scaffolded `INV.mspec` | webv2 | minicertora, (later) miniprover | rule name `inv_<n>` is scaffold-owned |

## 1. Installing the prover CLI

Same rail as minicertora: editable install so the live source is what
runs, then ONE stable PATH shim.

```bash
uv tool install --editable /home/xand/Projects/miniprover
# or the venv shim:
ln -sf /home/xand/Projects/miniprover/.venv/bin/miniprover ~/.local/bin/miniprover
```

✅ Verified from a clean environment:

```bash
env -i PATH=$HOME/.local/bin:/usr/bin:/bin HOME=$HOME miniprover --version
#  miniprover, version 0.1.0
```

The `--version` flag exists **because of web3sec's probe** (same reason
minicertora got `fc0316d`): every EXEC record pins
`environment.tool_versions`, `miniprover` joined the probe list, and the
probe reads the FIRST line of `--version`. Running from an uninstalled
checkout prints `0+source` instead of lying about a version.

Presence is visible in three places, all honest:
- `webv2 env doctor` prints `prover minicertora: …` / `prover miniprover: …`
  rows on **stderr** (stdout is the twin-pinned docker surface; the JSON
  report carries `host_provers` for machines);
- every EXEC record's `tool_versions` (absent binary = key omitted);
- `exec` failing with `command not found`, which is now the LAST resort,
  not the first discovery.

## 2. Endpoint configuration (what a run needs)

MiniProver speaks OpenAI wire format with NO baked-in vendor (README):

```bash
export MINIPROVER_BASE_URL="http://127.0.0.1:1234/v1"   # e.g. LM Studio
export MINIPROVER_MODEL_EXTRACTION=<id> MINIPROVER_MODEL_AUTHORING=<id>
export MINIPROVER_MODEL_REVIEW=<a DIFFERENT id>         # independence is the point
export MINIPROVER_API_KEY=...   # omit for local servers
```

Two more variables are printed by `python -m miniprover.guide --env`
(measured 2026-09-17):

```
MINIPROVER_TIMEOUT_S=<seconds per request>
MINIPROVER_HEADERS=<NAME:VALUE, comma- or newline-separated; --header replaces it>
```

and two more are documented by the guide's invocation rules and `--help`
(they are NOT in the `--env` output, so read them from the guide):

```
MINIPROVER_MAX_TOKENS=<ceiling on the whole run; 0/unset = none>
MINIPROVER_MAX_TOKENS_PER_PROPERTY=<ceiling on one authoring agent; 0/unset = none>
```

Two of these are host-relevant and new since this guide was written:

- **`MINIPROVER_HEADERS` / `--header NAME:VALUE`** is how a gateway that
  wants more than a Bearer token is reached (a routing key, a session id, a
  tenant). Pairs split on the FIRST colon; `--header` REPLACES the
  environment's list and the CLI says so on stderr when both are set;
  `Authorization` is refused from either surface, because the credential
  comes from `MINIPROVER_API_KEY` and a header that could clobber it would
  send the request under a key nobody gave. A header value is a credential:
  the transport redacts it from every error string, and the report records
  NAMES only (`transport.extra_headers`, `[]` when none was configured).
- **`--max-tokens` / `--max-tokens-per-property`** bound the money. Both are
  off by default and both are recorded, so a run that stopped for money is
  distinguishable from one that stopped for difficulty: read
  `cost.budget_stopped`, and the property's own `token-budget` status. A
  property the ceiling stopped before an agent ran is a named
  `budget-gap`-routed gap, never a failure.

A run with no endpoint configured fails fast naming the variables —
that failure is an honest `INCONCLUSIVE(tool-error)` rollup, not a verdict.

## 3. The trust rails webv2 relies on (prover-side, by contract)

The prover's own honesty rules (§ README) are exactly the rails this
control plane enforces elsewhere:

1. **Exit codes never decide a verdict.** `0` = published, `2` = not
   published, `1` = usage error — run-level tripwires only. Per-property
   truth is `reports/report.json`. Revision 3 sharpens what `0` means:
   **every property was accounted for AND at least one property
   DELIVERED** (a decided, non-vacuous, declared rule) — never that
   anything was verified. A run that decided nothing about the contract
   (every property skipped, or every declared rule undecided or vacuous)
   publishes `false` and exits `2`, however honest its skips were.
   `VIOLATED` publishes; so does a property whose rules were all decided.
2. **A rule with no verifier line is never PROVEN** — it is `REFUSED` or
   `UNATTRIBUTED`. webv2 maps only `rule`-keyed outcomes.
3. `OUT_OF_FRAGMENT` / `INCONCLUSIVE` are **gaps, not passes**: mapped to
   the inconclusive rung shape, recorded, and they gate nothing silently.
   The same is true of the two outcomes revision 3 added:
   `PROVEN_VACUOUS` (the rule held because it exercised nothing — it is
   reported and it does not publish) and `PROVEN_CONDITIONAL`. webv2's
   mapper blesses a literal `PROVEN`/`VIOLATED` rollup and nothing else.
4. **A gate that did not run says `unavailable`.** Capability probes
   (`--parse-only`, `--check-only`, `--project-root`, the `rules` field —
   the R11–R14 v0.4 contract) degrade runs, they do not fake them. The
   report carries two lists that mean different things:
   `capabilities_missing` (the installed verifier lacks the flag — an
   honest degradation) and `capabilities_unmeasured` (the probe could not
   ask — not a failure and not a pass).
5. `review_independent: false` is recorded when the budget could not buy a
   DIFFERENT model for review — one model's opinion is never presented twice.
6. **PROVEN next to a SUSPECT review finding is the most expensive state
   there is** — webv2's mapper refuses to bless it (§4), FAIL-CLOSED on
   shape (r21: padded/case-folded verdicts, non-object findings, and
   unattributed suspect flags all refuse). The prover's own summary
   shout compared the LLM string verbatim — FIXED upstream in the same
   sweep (prover commit canonicalizing verdicts at storage:
   `.strip().lower()` in `review._finding`), so both rails now agree;
   webv2 stays fail-CLOSED on shapes regardless (defense in depth
   means the host gate never assumes the tool behaves).

## 4. Compiler provenance: recorded, and NOW enforced

The old open edge (`MINICERTORA_INTEGRATION.md` §6.2): the result mapper
COPIED each line's `solc_version` into the stored proof but nothing
compared it — a mismatched-compiler run bound its rung. Shipped (r18):

- `solc` joined the EXEC probe list; its record row stores the PARSED
  version (`0.8.36`), not solc's banner first line;
- `verify --harness-result` resolves the run's compiler pin — the
  `--solc-path` binary named by the exec's own command (probed at verify
  time), else `tool_versions.solc` — and REFUSES exit 2 with
  `toolchain-mismatch` naming BOTH versions when any attributed line
  disagrees;
- FOUR states, never a lie: pin + the ATTRIBUTED line's own
  `solc_version` → `checked against pinned solc X`; pin + other lines
  carry versions but the attributed line does not → `checked at run
  level ... (the attributed line carries no solc_version of its own)`
  (r20 F4 — a foreign rule's version checked the RUN, not this proof);
  pin but zero lines carrying any version → `unchecked (pin X ...
  nothing was verified)` (r19); no pin at all → `unchecked (no
  compiler pin visible...)`. An unmade comparison is never reported
  as made;
- a run that NAMES `--solc-path` in a form the check cannot resolve
  (relative path — the exec's cwd is not reconstructible here) is
  REFUSED exit 2 when a record row could silently stand in for it —
  a named compiler is never downgraded to `tool_versions.solc`
  (r19/r20 F8); with NO resolvable pin anywhere (no record row either)
  the bind takes the honest state-2 lane and the proof carries the
  `[note: ...]` naming the unresolved mention;
- minicertora v0.4 SHIPPED `--require-solc-version` (R13), so that flag is
  the belt and this webv2 check remains the braces. MiniProver refuses the
  run before any phase starts when the probed binary cannot enforce the
  pin, so a pinned run that reaches us really did pin. The two sides are
  INDEPENDENT, and webv2 reads the report's `flags` block for exactly one
  thing: `flags.loop_bound`, to get k (`DecideReport` → `BoundFromFlags`,
  the typed read that refuses a degenerate or foreign `loop_bound`). It
  does NOT read `flags.require_solc_version` — the compiler pin is
  resolved from the exec record's own command or `tool_versions.solc`
  (above). So a run may carry a pin in `report.json` while the exec record
  says nothing, and that is a proof `unchecked`, not a proof pinned.

## 5. The `verify --autoprove` mapper (SHIPPED)

Machine input to the BIND is ONE file: the run's `reports/report.json`
(schema versioned; unknown versions refuse). Mapping law, per invariant —
note the mapper checks per-rule VALUES, not just the rollup, and refuses
any report carrying non-empty `publish_problems` even if `published` is
set:

| prover state | webv2 rung |
|---|---|
| published, every attributed rule PROVEN | PROVEN-BOUNDED (k from flags) |
| any VIOLATED attributed to the property | counterexample (params + failed assertion carried) |
| OUT_OF_FRAGMENT / INCONCLUSIVE / REFUSED / UNATTRIBUTED | inconclusive — recorded, never passed |
| `PROVEN_VACUOUS` / `PROVEN_CONDITIONAL` (rev 3) | inconclusive — the mapper's default arm blesses a literal `PROVEN`/`VIOLATED` rollup only |
| published=false, or PROVEN + SUSPECT review finding | **not blessed** — mapper exits 2 like the compiler check |

**The report is `report_revision: 3` (measured 2026-09-17).** Its top-level
`schema_version` is still `"1.0"`, which is what the bind gates on
(`harness.ReportSchemaMajor` speaks the whole `1.x` family), and the two
keys the mapper reads per property — `property_outcomes[name].outcome` and
`.per_rule` — are unchanged, so the bind did not move. What rev 3 added is
the operator's context: `properties[]` (one row per property with
`outcome`, `rules_declared`, `rules_stale`, `rules_observed`, and
`routing` when there is no outcome), a `rules` block carrying each rule's
`reason` and the `requirement` a refusal routes to, `coverage`
(`properties` / `delivered` / `skipped` — the one-line answer to "how much
of the contract did this run decide something about"), `cost`, `fragment`,
`attribution`, `transport`, and `declined_by_probe`. webv2 reads none of
those for a rung; they are what the operator acts on.

Usage (attribution is exact-match; `--property` names the prover's
agent-authored title verbatim):

```bash
webv2 verify <C> --autoprove INV-1 --property total_monotonic_after_add        --report <run>/reports/report.json
# INV-1: proved-bounded — autoproved bounded (k=4, 1 rules)
```

That gap line is CONDITIONAL and is absent against the installed verifier
(R1–R24, §7): the bind prints it only when the report's
`capabilities_missing` is non-empty (`cmd_verify_autoprove.go`), and §7
records that the probe is fully green — so a clean bind prints exactly the
one line above. A run against a verifier that was missing rows adds
`  verifier gaps at run time: N capabilities missing (degraded run;
see tools/minicertora_conformance.py)`: a shorter stdout, never a
different verdict. **The bind does not read `capabilities_unmeasured` at
all** (measured 2026-09-17: the key appears nowhere in
`cmd_verify_autoprove.go`), so a run whose probe could not ask still binds
silently — "unmeasured" is not a gap the host reports. Read that key from
the artifact if you need it; it is an honest omission on the bind's side,
recorded here rather than papered over.

Live-verified against the prover's committed counter evidence (all three
arms): a genuine PROVEN rollup bound `proved-bounded` with the run's
loop bound; VIOLATED rollups named their refuted rules as
`counterexample`; the SUSPECT-flagged property was REFUSED exit 2 quoting
the reviewer's reasoning — the "PROVEN next to suspect" state cannot
bind. `report.json` registers as a `harness` artifact (the unwind-safe
`RegisterOrRefresh`), the binding logs `harness_run` with the report's
sha256, and `audit` stays PASS over the whole flow. Reports carry
`schema_version` (prover side, r18): major "1." speaks; anything else
refuses rather than best-efforts a contract change.

`stale_outcomes` (rules written, verified, then edited out) are display
context only: the deliverable is what SURVIVED in the final spec, and the
runbook for a real campaign should read rule count and decision count as
different numbers on purpose.

**Report contract as of v0.4 (re-verified 2026-09-16; still true at
`report_revision: 3`, re-checked 2026-09-17).** The prover-side
`schema_version` is still `"1.0"`, so this section's gate (major "1."
speaks) is untouched by either landing. `report.json` adds ONE block we do
not read: `verifier`, carrying the schema/tool/spec/solc versions the
verifier stamped on its own output lines (the committed v0.4 run:
`0.2.0 / 0.1.0 / v0.3 / 0.8.36`; the round-2 run carries the same block
under `report_revision: 3`). Verified rather than assumed:
`cmd_verify_autoprove.go` and `harness/reportmap.go` never key on it, so a
report carrying the block binds exactly as before. It is the prover
recording its own provenance, NOT a claim webv2 checks — the compiler
comparison that does gate a bind is §4's, resolved from the exec record.
Keys are omitted rather than defaulted when no line carried them, so a run
that observed nothing carries `{}` instead of invented versions.

### 5.1 Ledger mode: the host's INV ledger, consumed directly (SHIPPED)

`--invariants PATH` replaces P1's guesswork with the host's own list, and
the shape it accepts is **the shape `webv2 model` already writes**:
`{"invariants": [...]}` at top level (a wrapped `{"protocol_model": {...}}`
is accepted too, and hand-written files are usually bare). Verified rather
than assumed on 2026-09-17 by feeding this repo's `protocol_model.json`
shape to the prover's own loader (`miniprover.pipeline.extraction.load_invariants`)
— the field mapping is:

| `protocol_model.json` | prover property |
|---|---|
| `invariants[].id` | the property TITLE, verbatim (and so the name the bind's exact-match `--property` takes) |
| `invariants[].statement` | `description`; a missing/blank one is REFUSED by name — the tool does not invent the claim |
| `invariants[].applies_to` | the entry points the property names |
| `invariants[].severity_if_broken` | `rationale` / `risk` |

```bash
webv2 model $CID model.json        # LOADS the operator's protocol_model.json
                                   # → campaigns/$CID/artifacts/protocol_model.json
miniprover path/to/Contract.sol:ContractName --project-root . \
  --invariants campaigns/$CID/artifacts/protocol_model.json --run-dir runs/INV-1
# report.json: attribution.mode == "ledger", properties[].title == "INV-1"
webv2 verify $CID --autoprove INV-1 --property INV-1 \
  --report runs/INV-1/reports/report.json
```

In ledger mode `--max-properties` is ignored with a printed note (the
ledger IS the list of record), `attribution.mode` is `ledger` rather than
`extracted`, and `denominator_source` says which total the gap count
subtracted from (`ledger`, `p1-guess`, or `none`) — read `not_attempted`
directly, because no P1 guess happened. This is what closed §7's old
"DESIGN.md by hand" edge: the properties no longer have to be guessed, and
the id the ledger minted is the title the bind names.

### 5.2 The run's artifacts (what to read, in order)

The bind needs one file; an OPERATOR needs to know what the rest mean,
because "the run exited 0" is not "the contract was verified":

1. **`reports/feasibility.json` FIRST** — `feasible` / `infeasible` /
   `not_checked`, with the refusal's own `reason`, `details` and (when it
   maps) a `requirement`. An infeasible target stops the run before any
   model is called; `not_checked` means the tool could not ask the
   question, which is NOT a statement about the target.
2. **`reports/report.json`** — `published` / `publish_problems`, `coverage`
   (0/n means not a deliverable whatever the rule count says), then
   `properties[]` and `rules`.
3. **`reports/reach.md` + `reach.json`** — the gap/finding inventory grouped
   by reason, cost and requirement, plus the `## Fragment probe` table: one
   row per entry point measured BEFORE any author was paid. A row whose
   requirement column says "requirement unmapped" is a fact nobody has
   routed yet — fix the mapping table, not the contract.
4. **`reports/fragment.json`** — the verbatim per-entry-point refusals
   behind that table.
5. **`specs/final.mspec`** — the deliverable, and `transcripts/` — the
   measured record the cost decision is recomputable from.

Two artifacts are new since this guide was written and both matter:
`feasibility.json` (step 1) and `fragment.json` (step 4). `reach.json`
carries `denominator_source` and the same `capabilities_*` lists as the
report, so a gap count can always be traced to the total it subtracted
from.

## 6. Troubleshooting matrix

| symptom | cause | fix |
|---|---|---|
| `prover miniprover: ABSENT` in env doctor | no shim (§1) | `uv tool install --editable …` |
| run exits 1 at construction | no `MINIPROVER_BASE_URL` | §2 — the fail-fast names the variables |
| every property `INCONCLUSIVE(tool-error)` | verifier shim dangling or endpoint dead | check `minicertora --version` and curl the base URL |
| `review_independent: false` in report.json | review model == authoring model | set `MINIPROVER_MODEL_REVIEW` to a DIFFERENT id |
| a capability row says unavailable | the installed minicertora does not provide it — a fact the probe ANSWERS, so never assume it in either direction | run `tools/minicertora_conformance.py`; a MISSING row degrades runs honestly (§3 law 4), and an UNMEAS row says only that the probe could not ask, which is not a failure and not a pass |
| `toolchain-mismatch` on a harness result | the run's solc ≠ the pin | re-exec with `--solc-path` pointing at the reported version, or fix PATH solc |
| doctor row says `probe TIMED OUT after 5s` | a PATH binary hangs on `--version` | the row IS the diagnosis — fix the shim; EVERY host probe is now bounded (doctor 5s+WaitDelay, EXEC probes group-kill+grace, docker 20s+group-kill, compiler-pin 10s): a probe reports a hang, it never joins it |
| autoprove says `report-contradiction` | rollup claims PROVEN while per_rule values disagree | per-rule lines are the authority (law 3); file a prover bug if the rollup really disagreed |
| a property's `status` is `token-budget`, `notes` says it stopped on the ceiling | the run's token ceiling stopped it before an agent ran | read `cost.budget_stopped`; raise `--max-tokens`/`--max-tokens-per-property` if the property is worth the money |
| every property `NOT_ATTEMPTED`, `declined_by_probe` names them | each named entry point was MEASURED unwritable (out of fragment) | the work item is the `requirement` id in the skip reason, not the contract — the probe already answered "can we even write this" |
| `published: false` with `coverage` 0/n and honest skips | the run decided nothing about the contract | that is the gate working: nothing binds (exit 2). A skip is not a result — re-plan, do not re-bind |
| a gateway 401s naming neither the header nor the key | `Authorization` was attempted as a header (refused by design) | put the credential in `MINIPROVER_API_KEY` and use `--header`/`MINIPROVER_HEADERS` for routing keys only |

## 7. What is NOT integrated (open edges, honest list)

- **Phase C profile**: an `autoprove` exec profile needs WRITE (run dir)
  + network to the LLM endpoint (loopback for LM Studio) + env passthrough
  of `MINIPROVER_*` — strictly wider than the read-only `minicertora`
  profile. Until it exists, miniprover runs are launched by the operator
  and only their artifacts are consumed; the E3 host cap is unaffected.
- ~~DESIGN.md generation FROM the INV ledger (webv2 → prover input) is not
  wired; today the operator passes `--design` by hand.~~ The PROPERTIES side
  CLOSED 2026-09-17: `--invariants` ledger mode eats `protocol_model.json`
  directly (§5.1, verified against the prover's own loader). DESIGN.md (the
  prose design document, `--design`) is still passed by hand — the ledger
  replaced P1's property guessing, not the human's design notes.
- **`--cache-dir`: the verifier side is wired, MiniProver's own cache is
  not.** The operator's `--cache-dir` now reaches minicertora as
  `<cache-dir>/minicertora` (R15), for both the run and the commit gate, and
  is dropped with one warning when the binary has no such flag. What remains
  unwired is MiniProver's OWN content-addressed store (`ArtifactStore.put`/
  `get`): no phase result is reused, so no webv2-side assumption may depend
  on caching either way. Re-measured 2026-09-17 by call-site search: the
  store is constructed in the run context and used for `write_json` /
  `write_text`, but nothing in the package calls `put`/`get`.
- **minicertora R1–R24 are INSTALLED and verified green** — this bullet
  said "v0.4 (R1–R15) unshipped" until 2026-09-16 and "R1–R15 installed"
  until 2026-09-17, when the verifier's tree was measured at HEAD
  `be14d3a`: R16–R24 landed on 2026-09-16/17 (`MINICERTORA_INTEGRATION.md`
  §2.1, §7). The conformance table below remains the source of truth for
  what the installed verifier can do; re-run it rather than trusting this
  snapshot.

### Installed verifier, re-verified 2026-09-17

`tools/minicertora_conformance.py` (in the MiniProver repo) prints two
tables, both fully green against the installed binary — quoted verbatim
from this box:

```
minicertora capability probe (flag names + the rules field)
-----------------------------------------------------------
PASS    R2 --project-root
PASS    R14 --parse-only
PASS    R12 --check-only
PASS    R13 --list-rules
PASS    R15 --cache-dir
PASS    R16 --solc-path
PASS    R13 --require-solc-version
PASS    R11 rules field

minicertora behavioural probe (§1 semantics, not flag names)
------------------------------------------------------------
PASS  R14  --parse-only
PASS  R2   project-root compile of an import
PASS  R12  clean document is silent
PASS  R14  parse-only == the full parser
PASS  R12  check-only accepts nothing the full run refuses
PASS  R14  parse-only is silent only on refusals it cannot reach
PASS  R13  --list-rules shape
PASS  R11  rules names the rule
PASS  R12  no verdict line under --check-only
PASS  R13  --require-solc-version pin

every requirement present and every behavioural check passed
```

Two rows are new since the previous snapshot: `R16 --solc-path` (the
compiler pin §4 enforces) and the two parity rows R12/R14, which the probe
now asks only what each cheap gate can actually reach (prover commit
`9c997b3`). Both parity rows PASS here — MiniProver's own guide still lists
the R14 accept-drift row as failing, but its "Known limits" section is
dated 2026-09-16; the probe is the authority.

The two tables answer different questions and both are needed: a flag
existing does not mean it MEANS what the contract says. The `rules` row
establishes only that the KEY appears on every elicited line, not per-rule
attribution — attribution is the behavioural table's "rules names the rule"
row.

Consequences webv2-side: `capabilities_missing` is EMPTY in the committed
v0.4 run, so the write gates compile instead of answering `unavailable` and
attribution goes through R11's `rules` field instead of text matching.
Sentences elsewhere in this guide that describe a "degraded run" (the old
"7 capabilities missing") describe the v0.3 runs the MiniProver repo still
keeps under its `docs/evidence/`; §5's example output has been corrected to
match.

## 8. Binding law between the paths (r20)

Both mappers write the SAME `verification.harness` slot, last-wins — by
design the rung is display of the latest claim; the EVENT ledger is the
truth (every bind appends `harness_run`, and the F3 law means a bind
without its event cannot happen). Two consumption rails make overwrite
costly: one (report, property) pair can hold exactly ONE invariant
(a second bind refuses, naming the holder — a proof is not reusable
across ledger rows), and re-binding an invariant over a DIFFERENT
report digest warns on stderr and names both shas in the artifact
refresh reason (a substituted report file cannot ride a quiet refresh —
r24 made that literal twice: at bind time the registry's own hash votes
(register FIRST, compare, prune-and-refuse on any mismatch, so no event
can ever name bytes the store does not hold), and at audit time
`recheckRegistryEvidence` demands the event's `report_sha256` exist as a
registry row — a post-bind overwrite + reconcile burns §11).
Deliberately NOT added: rung stickiness (an operator who invalidates a
counterexample with a fixed spec must be able to bind the newer proof
without a --force flag ceremony; the sticky-rung alternative invents
an "invalidation" verb with more states than the event ledger already
records). The audit surface cross-checks claims against events; the
display slot is where "latest" belongs.

## 9. The audit backstop is real now (r21 F7)

§8's promise that "the audit surface cross-checks claims against
events" now LITERALLY holds for harness rungs: `audit` section
`invariant_verification` compares each stored `verification.harness`
slot against the LAST `harness_run` event for that invariant (kind,
rung, exec, summary — the summary being the mapper's full rendering,
so no stronger claim survives a drift). A slot written without an
event — hand edit, or the `UNWIND ALSO FAILED` state linksThenLog
names — burns audit instead of printing as a legitimate verification
line. `linksThenLog` additionally holds the campaign process lock
across snapshot→save→log→restore: a whole-file restore can no longer
silently revert a sibling writer's concurrent bind (r21 F9).

And the pipe-hold class is dead at all four sites (r21 F1/F5/F6):
process-GROUP kills reach wrapper children (uv shims are `#!/bin/sh`
scripts; killing the shell leaves the child holding the pipe — which
is what made "bounded" probes unbounded), the timeout arms return
EMPTY rather than racing the output Builders, and `go test -race` now
ships a pin for it.

## 10. Re-derivation: the evidence, not just the paperwork (r24)

Slot-vs-event rails bind the display to the LEDGER — a chain-valid
forger edits the ledger too. The audit therefore RE-DERIVES, at read
time, from the artifacts the event names:

* `EXEC-*` provenance + a blessing rung (proved-bounded /
  counterexample): the exec's stored stdout bytes are re-run through
  the SAME decision entry point the bind used — `harness.DecideBound`
  (r28: the whole decision, not just its last step. Before r28 section 11
  called the kind mappers directly and so reproduced only the mapping: a
  blessing whose CLAIM had drifted, or whose exec record pinned a foreign
  hash, audited green while a re-bind over the identical record refused
  `scaffold-degraded` / `scaffold-bound violation`. The recorded-hash
  arm, the `harness.Validate` re-render, the unbound suffix and the
  invocation-level floor now live in one function that both sides call
  with the same inputs — the cli keeps only the IO around it, so its
  stdout stays byte-identical)
  for minicertora (rung, proof-subtree digest with the mapper-added
  `compiler_pin` stripped both sides, `bounded_k`), and since r25
  `harness.MapRun`/`BoundK` for halmos and forge-fuzz (the kind-skip
  was an open door: a chain-valid forged pair rendered `halmos, k=100`
  over a stdout whose own marker said `k = 7`, and even
  `counterexample` over a PASS output, audit-green). The lie now needs
  the stdout bytes (or the ledger row) to match too, not just two
  mutually-consistent JSON files.
* `REPORT-*` provenance (autoprove): the pinned `report_sha256` must
  exist as a registry digest **and** those bytes are re-decided through
  `harness.DecideReport` (which calls `harness.BoundFromFlags` and
`harness.MapReport`, so the report rung's gates are re-derived too: the
schema version, `published`, `publish_problems`, the review-error flag,
the `review_findings` shape and SUSPECT attribution — r33: the schema
gate was the one gate still living only in the cli, so a pin this build
refuses to read could still bless). Section 11 also re-derives the
PROVENANCE rail the bind enforces: the rung's exec must name a record the
exec ledger actually holds, and a report rung's printed label must name
the digest it pins (r33: a forged row could print `REPORT-000000000000`
over a different pin, or cite an exec that never existed), and the
one-proof-one-row law is re-derived per property — the first event naming
a given proof keeps its rung, and a later row claiming the same proof
burns naming the collision (r33). An EMPTY property title is not "no
claim" but a title no bind can write, so it burns rather than switching
the collision rail off (r34: two rows claiming one proof under an empty
title both displayed a blessing). And the registry's one-row-per-path
law is enforced by the verb the RUNBOOK names as the sanctioned mutation
path: re-registering a registered path refreshes it in place, or
migrates it when the kind changes, recording `kind_migrated` (r34: the
verb appended a second row for the same path while the RUNBOOK told
operators a path holds one row). That law stops at a CITED row (r35):
the ghost prune asks the same one cite predicate the bind's guard and
the prune verb ask — both halves of it, by content AND by row id, since
a scaffold event's `ref` names a row outright where byte equality cannot
look — and a cited ghost is KEPT and disclosed on stderr instead of
being retired, because the id it names is the evidence section 11
re-derives and no re-registration can mint it again — the very functions
  `verify --autoprove` now calls at bind time (r25 F2: ownership was
  paperwork; a forged pair over honest registry bytes still has to
  reproduce rung, summary and bound). The bind stores a
  content-addressed COPY under `<campaign>/artifacts/reports/`, so the
  evidence is immutable and a later act cannot refresh-overwrite it:
  rung/summary/k are all re-checked against bytes that cannot move under
  them. The COPY survives a hand `artifact-prune <id> --reason R` (that
  verb removes a row, never a file), but the ROW can still be retired by
  name — the verb warns when a live bind cites it, and §11 then reports
  that rung ` (UNBACKED)`; the bytes stay, the blessing does not.
* Inconclusive rungs are outside the blessing law — but not outside
  fabrication: a conspiring (slot, event) pair with invented `| next:`
  advice feeds the disposition tally. When the witness still exists the
  summary is re-derived and compared BY DISPOSITION CLASS (`Disposition`
  is the classifier the tally itself reads) — a pair claiming
  escalate-flag advice over bytes whose reason re-derives escalate-bound
  burns, while the mapper's legitimate decorations (" (unbound: …)", its
  own "no clean completion" timeout wording) are transport, not a
  different class, and never burn. When the witness has genuinely aged
  out, absence stays silent: an inconclusive rung blesses nothing, and
  noise there only punishes honest age.

The rung's KIND is a rail of its own (r29): only the spellings the
mappers implement are canonical, and a blessing whose stored kind names
no mapper — 'mythril', a case variant, anything the bind could not have
written — burns with the kind as the reason instead of skipping the
evidence check. (The display used to render a line for ANY non-empty
kind while the re-derivation ran only for minicertora, so editing one
string in the slot and the event, with the chain recomputed, audited
green over a fabricated bound.)

Both sides also read the SAME bytes: the bind's stdout reader (the
record's own stdout path first, the run's size cap applied) is the one
the audit uses, so a run whose output exceeds the cap can no longer
bless under one reader and burn under the other. The harness-FILE
predicate is likewise single: the recorded hashes that count as scaffold
evidence are the scaffold files themselves, so an unrelated workdir file
with 'harness' in its name maps normally, and a genuine harness file with
a foreign sha still refuses. When a record carries a harness-file hash
but the scaffold bytes are gone, the burn says exactly that — it no
longer claims the record's stdout/stderr digests were 'bound to' the
scaffold.

Both sides read a record the same way (r33): the audit's re-derivation
takes the same kind-aware invocation reader the bind uses, so a record
whose command names a different tool than its kind cannot be blessed by
one side and burned by the other with a sentence that a re-bind
contradicts.

The invocation parse is PER-TOOL since r32: a bound flag is read with the
semantics of the CLI that would have received it, because the three tools
are three different command-line parsers. forge is Rust/clap — ASCII
digits only, no underscores, no sign, must fit u32, and its flag may not
repeat — while minicertora and halmos are Python. A value the tool would
reject cannot be read as a number, and a bound flag belonging to another
tool's family floors the run, because the tool has no such option (the
r30 round's Python-int reading let `forge test --fuzz-runs 4_000` record
k=4000 for an invocation forge refuses outright, and let a lone
`--loop 3` bind a forge run).

The invocation parse is shell-then-click faithful since r29. The
recorded command is lexed the way a shell would split it: quotes (single
quotes literal end to end; in double quotes a backslash escapes only
`$`, `` ` ``, `"` and `\`), a `#` comment at a word boundary, a backslash
escape, the `--` end-of-options terminator, and `$` forms — an expansion
only before a name start, `{`, `(`, a digit or a special parameter, and a
LITERAL `$` before anything else, so `$;` still separates commands, `$ `
still separates words and `$'` still opens a quote (r31: the old arm
swallowed the character after every `$`, so a hidden `;` let the second
command of `forge test --match-path $; --fuzz-runs 500` bind k=500 while
the first command never saw the flag at all, and the mirror read a stated
`--loop-bound 7` as unstated). The value is read the way Python's int()
reads it, its RANGE included: the whole int64 range is exact, and a stated
bound wider than int64 records the saturating 9223372036854775807 with a
`k>=…` summary instead of the `bound UNSTATED` the earlier 2^62 guard
produced (r31). So a flag inside a quoted argument is an argument and a
comment is not a flag.

What FLOORS the run as invocation-unreadable instead of guessing a
number, for EVERY kind through one shared predicate: an unmatched quote, a
trailing backslash, an unterminated expansion, a command list (a newline,
`;` or `&` with a command after it), a pipeline or subshell, a redirection,
a brace expression, an expansion where an option could be or in a bound
value, and — since r31 — an ambiguous option ARITY: an option-looking
token immediately followed by another one, as in
`--timeout-ms --loop-bound 4`, `--contract --loop-bound 4` or
`--loop-bound 4 -- --loop-bound 0`, where only the owning tool's table says
whether the first eats the second and the two readings disagree about the
bound itself. That floor's direction of risk is a REFUSED run whose option
really is a boolean flag (`halmos check -v --loop 100`). Two residuals
stay unmodelled, and their risk runs the other way: the POSITIONAL arity
of the tool (the twin's click takes one positional and refuses
`--loop-bound 4 -- x y`, while halmos and forge take many, so a positional
tail can still bless a bound for an invocation the twin would refuse), and
a BOUND flag's own value arity, which click settles by taking the next
element whatever it looks like (`--loop-bound --loop-bound 4` is still
named as the degenerate statement click refuses, never as an ambiguity).
The one shared predicate is why the kind that exists because of the
degenerate-flag rule cannot be the one that skips it (r30: the
minicertora arm tested only the stated-degenerate sentinel while the
other two floored on both). Only space, tab and newline separate words,
because that is what a shell does (r30: VT/FF/CR were split, inventing a
flag the tool never received), and the digit table is the twin's own
Unicode data rather than a walk over Go's (r30: four adjacent
mathematical Nd blocks decoded 0..8 as 9 — a blessing for a stated zero,
a ledger lie for a stated one). The LAST
occurrence wins and the value may be signed, so
`--loop-bound 4 --loop-bound 0` floors exactly as the twin would refuse
it, and `--loop-bound -1` is a stated degenerate bound rather than an
unparsable "unstated". An exec record whose `exit_status` is absent or
null feeds `-2` on BOTH sides (absence is inconclusive); before r28 one
section-11 site defaulted that to `0`, so a forged pair audited green
over a record the bind itself had refused.

A bound below 1 is a bound no tool would have run under — the twin's
own `VerifierFlags.__post_init__` raises for `loop_bound < 1` — so since
r27 the floor covers the THIRD kind as well: a minicertora line whose
`bounds.loop_bound` is 0, -1 or -2 floors the whole run (no rung, no
proof sidecar, no `bounded_k`), and an exec record whose own invocation
says `--loop-bound 0` floors on the flag alone, whatever its stdout
claims. A campaign that bound such a rung BEFORE the floor existed is
not grandfathered: its slot/event pair no longer reproduces from the
bytes, and section 11 burns it — the campaign really did bless a proof
about nothing, and the burn is the honest record of that.

The store refuses to hold anything that is not a regular file it owns,
in a directory it owns:
a symlink or directory at the `artifacts/reports` directory, at the
`report-<sha>.json` name or at its scratch name is a named refusal (r27 measured the alternative: a symlink
at the scratch name was renamed into place and the following read-only
chmod FOLLOWED it, silently rewriting the mode of a file outside the
campaign). Scratch names are unique per call, so two concurrent binds of
one digest no longer share a tmp and race to ENOENT — and where a race
still loses, the writer re-reads the published copy, verifies its bytes
and succeeds; the store is idempotent by digest, so both binds exit 0.
Durability covers the name as well as the bytes: the tmp is fsynced
before the rename, the store directory is fsynced after it, and the
0444 mode is flushed, because a copy the disk lost is evidence the audit
must burn.

A binding the section cannot back is QUALIFIED in the display: when
this section's own backing check burns an invariant's rung (pruned
registry row, deleted witness), its `harness_runs` line ends with
` (UNBACKED)` — a consumer that reads only that array can no longer see
an unbacked blessing unqualified. The qualifier rides the same two
checks that produced the problem, and the happy path is byte-identical.

The store is append-only and its growth is knowingly unbounded. Every
re-bind whose report bytes CHANGED mints one immutable copy
(`artifacts/reports/report-<full sha256>.json`, written read-only 0444),
one new registry row and one `artifact.registered` event — five
changed-bytes re-binds of the same path leave five files, five rows and
five events, and audits stay green throughout. A re-bind of the SAME
digest adds no new copy and no new row — the content-addressed copy already
stands, so the registry finds that same row — but it is NOT ledger-silent:
the campaign records the re-bind as it records any bind, one `harness_run`
event plus an `artifact.refreshed` on that row (`refresh_count` 0 → 1). No
verb garbage-collects the immutable copies, and every audit re-hashes every
registered row, so that cost is paid again on every audit. The operator's
tool is `artifact-prune <id> --reason R` (a single token, and the reason is
REQUIRED — it lands on the `artifact.pruned` event): the verb WARNS on
stderr when the row it retires is still cited by a live bind — a
`harness_run` event naming its sha, or an exec record the ledger holds
whose recorded `input_hashes`/`artifact_hashes` pin it (r28: the warning
used to see only the event form, so pruning a scaffold row a live EXEC
rung pinned was silent) — names every invariant whose blessing cites it and says audit §11 will
now report that rung ` (UNBACKED)`, and prunes anyway — retiring evidence is
an explicit operator act whose burn is the honest cost, not a bug. (The
bind's own cite-guard is narrower: a refused bind prunes only an orphan
row.) Collisions are a non-event by construction: the file NAME is the
full digest, so two different byte strings cannot name one file, and an
existing copy is verified rather than overwritten.

A slot that stored LESS proof than its bytes support is
under-reporting — richer evidence than displayed — and skipped: rails
burn lies, not modesty.

Two more write-time laws landed with the same sweep: `flags.loop_bound`
below 1 REFUSES (the twin's own `VerifierFlags.__post_init__` raises
for degenerate flags and its CLI default is 4, so a report stating 0 is
not a twin output at all — honoring it would bless a proof-about-
nothing), and the bind REGISTERS FIRST so the registry's hash votes on
the bind: a mismatch prunes the fresh row and refuses before any event
exists, while a refused bind never prunes a row another live event
cites.

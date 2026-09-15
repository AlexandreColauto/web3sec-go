# MiniProver × web3sec-go — host integration guide

MiniProver (`/home/xand/Projects/miniprover`, Python) is the **auto-prover**:
LLM agents analyse a contract, author `.mspec` properties, and drive
**MiniCertora** (the verifier, see `MINICERTORA_INTEGRATION.md`) in a
verify/revise loop until the spec publishes. web3sec-go is the **control
plane**: it decides what counts as evidence and keeps the ledger.

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

A run with no endpoint configured fails fast naming the variables —
that failure is an honest `INCONCLUSIVE(tool-error)` rollup, not a verdict.

## 3. The trust rails webv2 relies on (prover-side, by contract)

The prover's own honesty rules (§ README) are exactly the rails this
control plane enforces elsewhere:

1. **Exit codes never decide a verdict.** `0` = published, `2` = not
   published, `1` = usage error — run-level tripwires only. Per-property
   truth is `reports/report.json`.
2. **A rule with no verifier line is never PROVEN** — it is `REFUSED` or
   `UNATTRIBUTED`. webv2 maps only `rule`-keyed outcomes.
3. `OUT_OF_FRAGMENT` / `INCONCLUSIVE` are **gaps, not passes**: mapped to
   the inconclusive rung shape, recorded, and they gate nothing silently.
4. **A gate that did not run says `unavailable`.** Capability probes
   (`--parse-only`, `--check-only`, `--project-root`, the `rules` field —
   the R11–R14 v0.4 contract) degrade runs, they do not fake them.
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
- when minicertora v0.4 ships `--require-solc-version` (R13), that flag
  becomes the belt; this webv2 check remains the braces.

## 5. The `verify --autoprove` mapper (SHIPPED)

Machine input is ONE file: the run's `reports/report.json` (schema
versioned; unknown versions refuse). Mapping law, per invariant — note
the mapper checks per-rule VALUES, not just the rollup, and refuses any
report carrying non-empty `publish_problems` even if `published` is set:

| prover state | webv2 rung |
|---|---|
| published, every attributed rule PROVEN | PROVEN-BOUNDED (k from flags) |
| any VIOLATED attributed to the property | counterexample (params + failed assertion carried) |
| OUT_OF_FRAGMENT / INCONCLUSIVE / REFUSED / UNATTRIBUTED | inconclusive — recorded, never passed |
| published=false, or PROVEN + SUSPECT review finding | **not blessed** — mapper exits 2 like the compiler check |

Usage (attribution is exact-match; `--property` names the prover's
agent-authored title verbatim):

```bash
webv2 verify <C> --autoprove INV-1 --property total_monotonic_after_add        --report <run>/reports/report.json
# INV-1: proved-bounded — autoproved bounded (k=4, 1 rules)
#   verifier gaps at run time: 7 capabilities missing (degraded run; ...)
```

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

## 6. Troubleshooting matrix

| symptom | cause | fix |
|---|---|---|
| `prover miniprover: ABSENT` in env doctor | no shim (§1) | `uv tool install --editable …` |
| run exits 1 at construction | no `MINIPROVER_BASE_URL` | §2 — the fail-fast names the variables |
| every property `INCONCLUSIVE(tool-error)` | verifier shim dangling or endpoint dead | check `minicertora --version` and curl the base URL |
| `review_independent: false` in report.json | review model == authoring model | set `MINIPROVER_MODEL_REVIEW` to a DIFFERENT id |
| `--parse-only`/`--check-only` rows say unavailable | minicertora is pre-v0.4 (R12/R14 unshipped) | expected degradation; run `tools/minicertora_conformance.py` to see the full gap |
| `toolchain-mismatch` on a harness result | the run's solc ≠ the pin | re-exec with `--solc-path` pointing at the reported version, or fix PATH solc |
| doctor row says `probe TIMED OUT after 5s` | a PATH binary hangs on `--version` | the row IS the diagnosis — fix the shim; EVERY host probe is now bounded (doctor 5s+WaitDelay, EXEC probes group-kill+grace, docker 20s+group-kill, compiler-pin 10s): a probe reports a hang, it never joins it |
| autoprove says `report-contradiction` | rollup claims PROVEN while per_rule values disagree | per-rule lines are the authority (law 3); file a prover bug if the rollup really disagreed |

## 7. What is NOT integrated (open edges, honest list)

- **Phase C profile**: an `autoprove` exec profile needs WRITE (run dir)
  + network to the LLM endpoint (loopback for LM Studio) + env passthrough
  of `MINIPROVER_*` — strictly wider than the read-only `minicertora`
  profile. Until it exists, miniprover runs are launched by the operator
  and only their artifacts are consumed; the E3 host cap is unaffected.
- DESIGN.md generation FROM the INV ledger (webv2 → prover input) is not
  wired; today the operator passes `--design` by hand.
- The prover's `--cache-dir` is built-but-unwired upstream (their Known
  Gaps): no webv2-side assumption may depend on caching.
- minicertora v0.4 (R1–R15 contract) is unshipped; the conformance table
  is the source of truth for what the installed verifier can do today.

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
  `harness.BoundFromFlags` + `harness.MapReport` — the very functions
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

The invocation parse is shell-then-click faithful since r29: the
recorded command is lexed the way a shell would split it (quotes, a '#'
comment at a word boundary, the '--' end-of-options terminator, tab
separators) and the value is read the way Python's int() reads it — so a
flag inside a quoted argument is an argument, a comment is not a flag,
and a construct the parser cannot model faithfully FLOORS the run
(invocation-unreadable) instead of guessing a number — for EVERY kind,
through one shared predicate, so the kind that exists because of the
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

# Triage: webv2 framework feedback — Morph round 2 (C-f4e27261f7)

**Inputs**

- `../morph/REVIEW-webv2-morph-round1.md` — operator's use-review + eval
  round 1 (supersedes `../morph/NOTES-webv2-review.md`; both read).
- Eval gold: `../web3sec-final/targets/gold-findings.json`, morph-l2 @ 22ca805e.

**Method.** Every claim was re-verified against Go source at HEAD `0b626d75`
(8× parallel fact-check + adversarial re-check of every "absent" verdict),
and where cheap, against the installed binary (`~/.local/bin/webv2`, stamped
`0b626d75011d (2026-09-18) +dirty` by `--version`) with a throwaway campaign.
The review was written against a pre-19:38-Sep-18 binary, so several claims
that are TRUE about the review session are already closed at HEAD — the
verdicts below say which is which, because "fix or not" depends on it.

---

## TL;DR disposition

| review item | §ref | verdict at HEAD | disposition |
|---|---|---|---|
| 1. `webv2 schema <name>` | 4.1 | REAL GAP (confirmed twice, incl. alias/hidden-verb refutation pass) | build (P0) |
| 2. artifact-register `--kind`, sanity, dedupe | 4.2 | `--kind` EXISTS (un-advertised); enum enforced but late/ugly; empty file accepted; content-dedupe is a documented non-feature | partial build (P0: hygiene; NO: dedupe) |
| 3. error path hint + machine dump | 4.3 | REAL GAP — `assemble()` names the schema, never a path; `--json` on model/ingest is success-only; golden pins the truncation text itself | build additive (P1) |
| 4. generic oracle kind | 4.4 | REAL GAP — enum is 7 price-shaped values; **zero code branches on any of them** (repo-wide grep), so the fix is schema-only | build (P0) |
| 5. probes flood + summary mode | 4.5 | MISDIAGNOSED half: `probes run --emit` prints only aggregates (one line per axis) — never per-row. REAL half: `probes list` floods (cap 40 + "use --json"); quota warnings land on STDOUT mid-stream, easy to miss; no --quiet/--summary anywhere | build (P1) |
| 6. run halt exit 3 vs 0 | 4.6 | NOT REPRODUCIBLE — needs_model → exit 3 is pinned by `TestRunHaltsHonestlyAtTheFirstModelStage` (green re-run); scheduler halt → exit 2 (stderr HALTED block); the review's exit-0 sighting predates the binary's last rebuild | doc line only (P2) |
| 7. invariant-verify batch | 4.7 | REAL GAP (single positional inv_id; `--invariants` hits "unrecognized arguments"); the "unknown artifact" error names no heal | build (P1) |
| 8. probe ↔ plan anchor cross-link | 4.8 | REAL GAP, refined: a provenance join exists (`priority["probe"]["row_id"]`), but no code-anchor join; plan priorities carry no file/line fields today — the join needs `components`-level matching or new anchor stamps | build (P0-class, biggest) |
| eval-design asks (decoy taxonomy, PoC-draft bar, POSSIBLE-in-FP-budget) | 5.2 | eval artifacts, not CLI | belong to `targets/gold-findings.json` + scorer, separate deliverable |

## What the review did NOT ask for but the eval did (our own findings)

The round-1 miss diagnosis ("the framework HAD the right lead") is the most
important input here, so two items target it directly:

- **A9. `webv2 anchors <campaign> <target> [file[:line]]`** — an
  ask-the-ledger-about-this-code command. The operator read Rollup.sol:209
  while their own gold G-01 was two stores away (LC-008 + L-03 row
  34589e8588, both anchored at 204/496). A8 links stores at render time; A9
  makes it queryable at WORK time — "what does the surface, the plan, the
  findings, and the invariant-links ledger say about this file/function?"
  Data seams: `probes.RowAnchorPairs` (internal/probes/shape.go:95),
  priority `components` (internal/planner/queue.go:104),
  findings `affected` file/lines, invariant-links ledger
  (artifacts/invariant_links.json, the r42 links door).
- **A10. discovery hygiene — surface before narrative.** Campaign state at
  handoff: **40 probe rows / 0 dispositioned** while 14 hypotheses were
  ingested. Nothing in the ingest/gate path says "your own mechanical
  surface names this finding's anchors and you haven't dispositioned it".
  Proposal: `ingest` and `mint` print a presence-gated stderr note when the
  payload's affected file/functions match undispositioned surface rows or
  OPEN LC-* priorities (the note names them and the `answered`/`answered
  --disposition` commands; it never blocks — blocking would fight the FP
  budget's HYPOTHESIS-cheapness the eval §5.2 flags). The custody probe
  (`probeCustodyPrimitive`, internal/probes/probe_custody.go — its
  `recoveryFnRe` matches `^ondrop` and its testdata is literally a buggy
  `L1ERC20Gateway.sol`) already detects the G-02 shape mechanically:
  mint/burn/transfer-in/out primitives per recovery entry point. G-02
  was on the surface's radar all along; hygiene would have force-multiplied
  it. Same for `symmetry` (family custody-primitive matrix) — its report
  lives outside the brief; A10 gives it a trigger inside it.
- **A11. bootstrap version discipline.** Phase 0 verifies the binary is an
  ELF (assets/runbook/AGENT_BOOTSTRAP.md:39) but never asks WHICH build.
  `--version` exists (cli.go:178, r43b) and snapshots record
  `framework_build` (state/campaign_snapshot.go:183), yet neither is
  surfaced. Fix: one Phase 0 line — `webv2 --version` before work, report
  the stamp — and a brief warning when `framework_build` changes
  mid-campaign. Cheap insurance against reviews graded against stale
  binaries (this review contains two such items: #2's `--kind` claim, #6).

---

## Build spec (where each change lands, and what it must not break)

The cross-cutting constraint: **stdout bytes are golden-pinned** all over
this CLI (`cmd_plan.go:197` — "stdout is twin-pinned, so no line may be
added there; disclosures go to stderr"; `validation/schema_golden_test.go`
is generated and pins the `(+N more errors)` strings verbatim; every
artifact-register success line is pinned by `cmd_artifact_register_test.go`).
So the shape of nearly every fix below is the same: **new additive surface,
existing bytes untouched** — stderr disclosures, presence-gated blocks,
new flags, new verbs. Python parity: the reference is deprecated
(docs/gates/P4-gate.md §9.1 via feedback-triage.md); intentional divergences
take a `docs/archive/KNOWN_DIVERGENCES.md` row (D-series), and any
`assets/` edit must be followed by `python3 scripts/sync-asset-manifest.py`
or `assets/manifest_test.go` fails the gate.

### P0 — small, high-frequency-ergonomics, near-zero ripple

**B1. `webv2 schema <name>` (+ `<name> --list`, `--definitions`).**
New `internal/cli/cmd_schema.go`, registered like cmd_prompts.go. Body:
`validation.ReadSchemaFile(name)` (internal/validation/schema_enum.go:45)
→ write raw bytes to stdout; unknown name → exit 2 printing the
`knownSchemas` list (the exact list `schema.go:51` already renders, so the
error text stays consistent). Also: `model --example` (model has NO example
flag today — cmd_model.go has zero "example" references, while scope and
ingest both have one) and `scope --example` gains a stderr pointer line
("schema: bounty_policy — `webv2 schema bounty_policy`"). The
`invariant-verify`/`--artifact` errors and the gate's remediation lines get
the same pointer via B6's heal-text (below). New verb = additive; no pinned
text touched.

**B2. artifact-register hygiene.** Three sub-fixes, one file:
- `--kind` validation EARLY: today a wrong kind passes the CLI parser
  (cmd_artifact_register.go:52-91 free string) and dies late as a raw
  `campaign_state` schema wall (empirically: exit 1 with the whole 31-value
  enum dumped at `artifacts/1/kind`). Validate against the enum and exit 2
  with `invalid kind 'x'; one of: recon, protocol-model, ...` (reuse
  `validation.SchemaEnumLegend`/the walk in schema_enum.go).
- reject empty content: the AUTHORITATIVE check is the CLI verb, right after
  the `os.Stat` at cmd_artifact_register.go:153 — size-0 refuses exit 2
  (`artifact register failed: empty artifact: <path>`); `/dev/null` must not
  mint a row. The two state-layer twins (artifacts.go:50,
  artifacts_register.go:84) stay existence-only ON PURPOSE: they also serve
  the `--exec` auto-registration and harness-scaffold minters (plan-review
  F13 — this is the "why the others exist" answer). No `--allow-empty`
  bypass flag on an integrity ledger: a real placeholder is
  `printf '{}' > f.json` away; a flag people press reflexively defeats the
  check it bypasses.
- help line advertises the flags: `artifact-register <campaign> <path>
  [--kind K] [--note N]` (the current line hides a flag that exists — the
  review's #2 misclaim was born here; `--help` text is updateable, it is not
  golden-pinned, help_test pins only structure).
  NOT doing: content-hash dedupe across paths — deliberate stance at
  internal/state/artifacts_register.go:44-45 ("Same bytes is not the same
  citation: the evidence that a live bind names is the ROW ID").

**B3. oracle kind enum.** Add TWO values: `"other"` and
`"data-availability"` (plan-review F11: an enum entry costs one array line
now and a data migration later; blob DA is a recurring L2 category), plus a
sibling `kind_note` optional string legal for any value. Verified zero Go
consumers branch on the oracle-kind strings (repo grep: the twap/spot-amm/
sequencer-uptime names appear nowhere in internal/*.go — the
oracle-MANIPULATION hits are bug classes). Touch:
assets/schema/protocol_model.schema.json:436 + manifest regen +
KNOWN_DIVERGENCES row. Add an `oracles --example`? No — covered by B1's
`model --example`.

### P1 — medium, the review's wants with real work content

**B4. validation error dump — ONE flag: `--error-dump FILE`.**
`Validate` (schema.go:86) flattens leaves then calls `assemble` (which
truncates); REFACTOR, do not clone (plan-review F12: two flatteners drift):
export the existing leaf list — `SchemaViolations(data, name, max)` returns
the same `[]leaf` (path+message) `Validate` already builds before
assembling; `Validate` itself becomes `assemble(SchemaViolations(...))`.
Failure printers (cmd_ingest_print.go:60-74 printIngestFailure,
cmd_model.go:148-155, cmd_scope.go:337-339) write the JSON-lines file ONLY
when validation failed (file exists ⟺ violations ≥ 1; zero-violation runs
create nothing — this is the parse contract for agents). Default bytes
unchanged → golden tests stay green. When the flag is absent and leaves >
max, append ONE new stderr line after the existing block: `full errors:
webv2 schema <name> — or re-run with --error-dump F` (stderr lines are the
sanctioned disclosure channel).

**B5. probes output.** (a) `probes list --summary`: counts per axis +
open/undispositioned + the missing/warning lines, no row table. (b) lift
the two quota disclosures from r.Out to r.Err ("  warning:
floor-reserve-exceeds-total…" surface.go:226-247 and "  missing: …"
:321-324) — the stream split is the documented convention (warnings ride
stderr, cf. artifact-register r35 F1); update cmd_probes_test.go pins
deliberately, in one commit. (c) the review's "run --emit floods stdout
with blind rows" claim is refuted at HEAD (probes_run prints aggregates
only) — no fix; the row-flood pain is `list`, and the cap + `--json` is
already the answer.

**B6. invariant-verify.** (a) heal-pointer on the "unknown artifact 'X'"
error (state/artifacts.go:121 text is test-pinned EXACT (`err.Error() !=
"unknown artifact 'ART-nope'"` in 3 tests), so the pointer is a SECOND
stderr line rendered by cmd_invariant_verify.go:101: `register it first:
webv2 artifact-register <campaign> X --kind invariants` — and it doubles as
the discoverability fix for --kind. (b) batch form `--invariants
INV-1,INV-2,...` (or repeat the positional — today's usage line already
takes `campaign inv_id`, so the clean shape is a flag): loops the existing
VerifyInvariantStatement per id against the SAME registered artifact, gates
all per-invariant checks first; prints per-id lines COMMIT-THEN-PRINT
(plan-review F7): any refusal means nothing written, and the output is
`aborted: INV-3 refused: <reason>; nothing written` at exit 2 — never an
`attested` line for state that does not exist. Partial success is NOT
intended (all-or-nothing, the cmd_answered_batch.go discipline; the audit
projection counts attestations and must never half-see a batch). On commit:
one `INV-x: attested` line per id, in argument order. Events stay
one-per-invariant — the hash chain and audit's per-attestation projection
must not see a fused row.

### P0-class by value, P1-class by cost — the discovery-leverage pair

**B7 (= review #8). anchor cross-link.** RESOLVED FIRST, per plan-review F1/F5,
by replay on the handoff campaign (campaigns/C-f4e27261f7):
- **Canonical key: `contracts[].path` — the snapshot-relative model path**
  (`l1/rollup/Rollup.sol`) + optional `#Function`. It already exists:
  probe rows carry `contract` (name) + `consumer`/`asserter` + lines, the
  structural index keys nodes as `path#Contract`, and the model maps
  name→path. Priority `components` hold contract NAMES (LC rows hold
  state-machine ids like `rollup/BatchLifecycle`) — both resolve to the key
  through the model, deterministically.
- **Legacy campaigns: query-time resolution, NO migration.** The name→path
  join needs only artifacts the campaign already holds; B8 runs against
  C-f4e27261f7 TODAY (the §5 replay proves it — the whole convergence check
  was a 30-line script over the campaign's own JSON). B7's mint-time anchor
  stamps are a *pre-materialization* of that join for ranking speed, not a
  precondition for correctness.
- **Collision rule:** match on FULL path segments, never basename. The
  morph model has 0 basename collisions across 57 contracts — but the fix
  must not rely on that; ship the two-same-basename-contracts-in-different-
  dirs fixture test (F5).
- Design:
  - planner stamps `anchors` (canonical-key form) at mint time for LC-*/Q-*
    rows (it already knows the contract from the state machine / role —
    plan_lifecycle.go's surfaces);
  - new shared helper (internal/probes or a small internal/anchorlink):
    `Matches(components/anchors)` ↔ surface rows ↔ finding affected files;
  - render surfaces, all additive — **stderr + `--json` fields only, no new
    stdout lines** (plan-review F8 decision: presence-gated stdout is safe
    only if no golden fixture converges; the empirical campaign converges
    7 Rollup rows × 12 priorities, so fixtures plausibly do too — settle it
    with the convergence grep at implementation, and until then stdout
    gains nothing): `--json` per row gains `linked_priorities`, per priority
    gains `linked_rows`, and `brief`'s JSON gains a `convergent_leads`
    block (stderr summary line: "convergent anchors: 2 — `brief --json`").
  - `answered --disposition` on a row whose anchor names an OPEN priority
    records the link event (invariant_links.json is the precedent door,
    zz_r42_links_forward_test.go pins the atomic writer).

**B8 (= A9). `webv2 anchors` query verb.** Reuses B7's helper: input =
campaign + `file[:line|function]` pattern; output = every surface row,
OPEN priority, finding, and invariant-link that names it, grouped by store
with its disposition/status and the command to act on it. This is the
"at which stage is this asserted?" reminder machine: when rows and
priorities co-name a function, the output ends with the L-03 lens line
(enforcement-timing) so the operator is pointed at the question the stores
conspired to hide. **Acceptance test ships in B8's commit** (plan-review
F4): a fixture-replay over the C-f4e27261f7 artifacts asserting
`anchors <C> Rollup.sol#commitBatch` returns rows 34589e8588/594befa6cf +
open priorities Q-008/Q-050/Q-098/Q-100, and `anchors <C>
L1ERC20Gateway.sol#onDropMessage` returns row a047e6509f. The premise is
already measured (§5): both golds sat in the pre-hypothesis surface, so
this test must pass, not merely exist.

**B9 (= A10). discovery-hygiene note at ingest/mint — CAPPED and
SUPPRESSIBLE.** Presence-gated stderr block, never blocking (see rationale
above). Plan-review F6 is right that an uncapped file-level match floods:
empirically a Rollup payload matches 7 rows + 12 priorities. So: at most
**3 lines, ranked by specificity** — exact `path#function` match >
asserter-side match > file-only (the G-01 row survives function-level
ranking; the generic Q-* trust-boundary noise drops out), one line per
match, naming the row/priority and ending with the `answered` command.
Suppression: `--no-hints` + `WEBV2_NO_HINTS=1` — an un-silenceable note is
a parsing hazard for the agent operator, and a note learned-to-ignore costs
attention and returns nothing. The round-1 near-miss is the counterfactual:
F-e1108876 (filed pre-reveal, cites commitBatch/finalizeBatch — the same
functions as undispositioned row 34589e8588) would have printed the top
line at write time.

**B10 — disposition throughput (plan-review F2; promoted by §5's replay).**
The replay's verdict: the round-1 miss was throughput, not information.
BOTH gold shapes sat in tier-0 surface rows (34589e8588 rank-1; G-02's
custody row), undispositioned, while the bootstrap's own lens rule ("any
undispositioned row keeps the lens OPEN") first bites at end-of-pass LENS
closure — an operator who stops at stage 5/17 never meets it. Push (B9)
and pull (B8) do not change that; so:
(a) **the forcing function goes on the CONFIRMED path, not the HYPOTHESIS
path** — refines NOT-doing #3: `gate <C> <F>` and the `move … CONFIRMED`
check gain one failing check: "an undispositioned tier-0 / assertion_gap≥3
surface row cites THIS finding's own affected anchors", rendered in gate's
diagnose-as-command style with the exact `answered` heal. Costs no FP
budget (CONFIRMED is where the budget already bites), throttles nothing on
the cheap hypothesis side, stays per-finding (unrelated blind axes never
block a promotion), and converts the review's own objection — "after B1–B9
ship, 0/40 can still be 0/40" — because a finding can no longer CONFIRM
past a machine question about the same code.
(b) **a cheap bulk-discharge route for the drain (a) triggers**:
`probes <C> pending` (ranked: tier, assertion_gap, then B7 convergence
count) + extend the Q-* batch discipline (cmd_answered_batch.go) to probe
rows — one status per call; tier-0 keeps requiring per-row reasons that
cite the row's own code (the bootstrap's anti-dismissal-prose rule;
`--reason-all` is legal only below tier-0).

**WIRING RULE (plan-review F3, adopted broadly): no new verb or flag ships
without its runbook line, same commit.** The operator is an LLM agent
reading AGENT_BOOTSTRAP.md (the mode section, lines 20-23; and the review
session's own "Agent: GLM"); a capability the runbook never names is dead
code. This binds B1 (`schema`), B5/B10 (surface views), B6b, B7 renders,
B8, B9 — and P2's `--version` line. The bootstrap already commands surface
discharge at lens closure (line 155: "A stale surface or any
undispositioned row keeps the lens OPEN"); the wiring adds (i) `anchors` in
the stage-4 reading list and (ii) B10(a)'s gate rule in the CONFIRMED
checklist — the behavioral delta, in prose, with every verb it mentions.

### P2 — docs & polish

- runbook: document the exit-code trichotomy (`run` → 3 model halt, 2
  scheduler halt, 0 complete) at the RUNBOOK.md:159 and
  AGENT_BOOTSTRAP.md:130 lines — the exit-3 claim in review #6 is ALREADY
  true at HEAD (pinned by cmd_run_test.go, re-run green); the review's
  sighting was pre-rebuild, and the docs' silence on the exit-2 path is the
  only real gap.
- Phase 0 bootstrap: add `webv2 --version` to the trust-before-work list
  (A11); brief warns when a campaign's `framework_build` changes mid-flight.
- `webv2 version` as a verb alias of `--version` (the review ran it; today
  it is "unknown command" — one line in commandByName, additive).

## Explicitly NOT doing (design stances, recorded so round 3 doesn't re-litigate)

1. **Artifact content dedupe across paths** — rows are citations, not
   blobs (artifacts_register.go:44-45); the refresh/ghost machinery already
   handles the same-PATH case; audit §11 re-derives by id.
2. **Changing `assemble()` truncation text** — generated golden
   (schema_golden_test.go, "DO NOT EDIT BY HAND"); additive dump instead.
3. **Blocking gates on undispositioned surface at HYPOTHESIS ingest** — the
   FP budget is CONFIRMED-only today (eval §5.2), so hard-gating discovery
   on lens closure would punish exactly the behavior the eval wants to
   price. B9 is a NOTE. The teeth move to the CONFIRMED path (B10a), where
   the budget already applies pressure and cheap hypothesis volume stays
   unthrottled. If round 3 still wants HYPOTHESIS-side teeth, the right
   lever is the FP-budget change (count POSSIBLE weighted), not a new
   refusal.
4. **`probes run --emit` row flood fixes** — the flood does not exist at
   HEAD (aggregate-only output; per-row listing is `probes list`, capped,
   with `--json` escape).

## §5 — falsification replay on the handoff campaign (answers plan-review Q2/Q4/Q5)

Ran the B7/B8 convergence check directly against
`../morph/campaigns/C-f4e27261f7/artifacts/` (30-line script over
probe_surface.json + campaign_plan.json + protocol_model.json):

- **Q2: 2/2 gold findings were ON the mechanical surface, pre-hypothesis,
  undispositioned.** Not one anecdote — the whole gold set.
  G-01: row `34589e8588` (tier-0, rank-1, axis enforcement-timing,
  consumer `commitBatch@204`, asserter `finalizeBatch@496`) whose `why`
  states the root cause almost verbatim: "commitBatch#204 guards
  prev:state:root with a SENTINEL check (prevStateRoot != bytes32(0)) —
  any non-zero value passes it"; plus open priorities Q-008/Q-050/Q-098/
  Q-100 naming commitBatch, and LC-008 naming the whole
  commit→challenge→finalize→prove lifecycle. G-02: row `a047e6509f`
  (custody-primitive, `L1ERC20Gateway::onDropMessage@74`, why names the
  burn-vs-transfer sibling disagreement at `_deposit#122`); a sibling row
  on the ETH gateway's drop path too.
- **Q5: no backfill needed** — the join computes from existing artifacts;
  the model maps names→snapshot paths with 0 basename collisions (57
  contracts), LC components name state machines, Q components name
  contracts, and probe rows carry contract+consumer+asserter+lines.
  Canonical key = `path#Function` (B7).
- **Q4 stays open** until implementation (fixture grep for convergence),
  but the decision is already conservative: B7 renders add no stdout lines.
- **Implication for the thesis (review §1):** both supply-side and
  forcing-function readings are supported — the lead was in the row itself
  (a single surface row contains consumer AND asserter of the misplaced
  check; no cross-link was even needed for G-01) — what failed was
  DISCHARGE. Hence B10 sits next to B7/B8, and the plan-review's warning
  ("B7/B8 add surface to an operator already over-surfaced") is accepted
  as load-bearing, not cosmetic.

## Answers to the plan-review's five Phase-B questions

1. LLM agent operator: YES (AGENT_BOOTSTRAP.md mode section; review
   session agent was GLM). F3 adopted as the same-commit WIRING RULE,
   extended to every new verb/flag, not just B7/B8/B9.
2. Gold-on-surface share: 2/2 (§5). B7/B8 keep value; B10 shares the top
   tier as the throughput answer — the replay supports both, and the
   single-row consumer/asserter finding says B10's drain was the cheaper
   half of the win.
3. FP-budget owner/timeline: the operator owns
   `../web3sec-final/targets/gold-findings.json` + `scripts/eval-gold.py`;
   no timeline. Named dependency, and B10a is deliberately shaped to be
   budget-independent (it gates CONFIRMED, where the current budget already
   bites, so B9/B10(a)'s value needs no teeth borrowed from the eval
   change) — F9 accepted: under today's rules B9's note alone steers
   attention; the forcing function is B10a, not prose.
4. Golden-fixture convergence: deferred to B7 implementation (one grep);
   pre-decided conservatively — stdout gains no B7 lines at all.
5. Backfill vs fallback: fallback-by-derivation, no migration (§5, Q5).

## Suggested order (revised per plan-review §4, with cut line)

**Phase A — cheap, unblocks the next session:** B1 → B2 → B3 → B5b
(quota warnings to stderr, one commit, deliberate pin update) → B6a (heal
pointer) → exit-code doc line. Each with its runbook line (WIRING RULE).

**Phase B — spec gate before thesis work:** the F1/F5/F8 closures are
already written into B7 (canonical key, no-migration resolution,
stderr/--json-only renders); remaining: the basename-collision fixture and
the convergence grep. Draft the §5 replay as the Go acceptance test
fixture-first — it must reproduce on Go data what the script showed,
before B7/B8 code is trusted.

**Phase C — the miss-prevention core, value-first:** B7 helper → B10a
(gate/move CONFIRMED check + its bootstrap checklist line) → B10b
(pending view + batch discharge) → B9 (capped, suppressible) → B8
(+ acceptance test in-commit). Runbook wiring in each commit.

**Phase D:** B4 → B5a → B6b → A11 revision → remaining P2.

**Cut line, in order:** drop B4, then B5a, then B7's render surfaces (keep
the helper — B8/B9/B10 need it), then B6b. **Never cut:** runbook wiring
for anything that ships, the B8 acceptance replay, or B10a (the only
forcing function the 0/40 datum actually answers).

A11 revision (F14): keep the one-time `--version` Phase 0 line and the
warn-once brief notice, but the real deliverable is ATTRIBUTION —
`framework_build` rides new artifact rows and attestation events (additive
key; check the campaign_state schema allows it on rows, else event-payload
only), so a future review never grades round-2 behavior against a
round-1 binary. New verbs' exit codes follow the house convention
(refusal/usage → 2, runtime → 1; B1/B2/B4/B6/B8 all refuse at 2) and the
P2 doc line covers them (F15).

## Process notes (carried from round-1 triage, unchanged)

Each B item lands with its own commit + Go regression test (fixed behavior
gets a test, not a golden step); assets edits regen via
`python3 scripts/sync-asset-manifest.py`; intentional byte divergences from
the deprecated Python twin take a `docs/archive/KNOWN_DIVERGENCES.md` D-row
(B3, B2's kind-message, B5b's stream move, B10a's new gate check all
qualify); green bar per merge: `go test ./...` + `webv2 selftest --full`.


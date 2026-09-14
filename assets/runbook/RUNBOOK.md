# webv2 operator runbook (Go)

One operator, one campaign at a time. This is the **Go binary** runbook: a
single static `webv2` executable with all assets embedded (`go:embed`) — no
interpreter, no venv, no module tree. Commands assume you run them from the
**workspace** (the directory that holds `campaigns/`): `--root` defaults to `.`
(your cwd), so it is omitted throughout; pass `--root WORKSPACE` only when
pinning a different workspace. Every command shown is the real signature —
**if this document and the code disagree, the code wins and this file is a bug**
(report it, don't work around it).

The Python twin (`web3sec-final`) was **retired 2026-09-09** and is not
maintained. This runbook is the source of truth for the Go binary. The
historical divergence ledger is frozen at `docs/archive/KNOWN_DIVERGENCES.md`
— new Go-only changes need no row there; they need only a test.

## 0. Setup

```bash
webv2 selftest            # fast self-check (~3s): build sweep + walkthrough + cli audit. Expect ALL PASS.
webv2 selftest --full     # adds the ported suite (go test ./...). One-time / developer only; never at agent startup.
```

Build a fresh release binary (static, CGO-free, assets embedded):

```bash
scripts/release.sh        # -> dist/webv2  (build + static proof + standalone walkthrough; exit 0 only when green)
```

Install it where your shell finds it (first PATH entry shadows any other
`webv2`):

```bash
install -m755 dist/webv2 ~/.local/bin/webv2
```

Tooling expected on PATH (**absence degrades capability, does not block**):
`git`; `forge`/`cast` (Foundry); `docker` with a **running** daemon (E4+
evidence — the container profiles execute a real `docker run` in
`$WEBV2_DOCKER_IMAGE`, default `ghcr.io/foundry-rs/foundry:latest`); an
optional `gvisor` and a fork-RPC endpoint for `fork-runner` (point
`FORK_RPC_URL` / `WEBV2_FORK_RPC_URL` at your anvil fork).

`solc` is downloaded by the container on first use. With the network cut
(networkless / gvisor / vm-snapshot profiles), a missing solc binary is an
**environment failure, not a harness bug**. Provision it one of two ways:
preinstall the svm layout (`~/.svm/<version>/solc-<version>`) into a custom
image, or point `WEBV2_SOLC_DIR` at a host dir with that layout — it is
bind-mounted into every container at `/home/foundry/.svm`. A failed exec is
classified on the spot (`classify`, §6): an environment failure says so and
tells you NOT to spend a fresh-context retry.

Check what this box can actually run before spending passes on evidence it
cannot produce:

```bash
webv2 env doctor            # read-only: docker cli/daemon, image presence + digest, fork-RPC reachability, per-profile readiness, solc cache
webv2 env doctor <C-xxx>    # + checks the box against the evidence floor THIS campaign needs (exit 1 while it cannot)
```

Exit codes are one convention across every verb: **0** did what was asked
(including a truthful empty result), **1** is a decision or integrity failure
(gate not passed, verification refused, content too short), **2** is the
"the thing you named does not exist or was not given" family — argparse
refusals, missing rows, unknown ids, missing prerequisite state (an index
before `probes run`, a plan before `answered`). A 2 never means "wrong"; it
means "nothing to operate on — fix the invocation or the precondition".

## 1. The fast path: the pipeline

`webv2 run` walks the phase machine and **halts honestly at the first stage
that needs a model** — it never fakes progress. The 17 canonical stages, in
fixed order:

| # | stage id | kind | phase |
|---|----------|------|-------|
| 1 | `scope` | deterministic | SCOPE |
| 2 | `snapshot` | deterministic | SNAPSHOT |
| 3 | `structural-index` | deterministic | STRUCTURAL_INDEX |
| 4 | `protocol-model` | model | PROTOCOL_INTELLIGENCE |
| 5 | `campaign-planning` | mixed | CAMPAIGN_PLANNING |
| 6 | `discovery` | model | DISCOVERY |
| 7 | `dedup` | mixed | CANDIDATE_INTEL |
| 8 | `hostile-review` | model | HOSTILE_REVIEW |
| 9 | `reproduction` | mixed | REPRODUCTION |
| 10 | `chaining` | deterministic | CHAINING |
| 11 | `maximal-exploitation` | model | MAXIMAL_EXPLOITATION |
| 12 | `independent-verification` | model | INDEPENDENT_VERIFICATION |
| 13 | `risk-calibration` | deterministic | RISK_CALIBRATION |
| 14 | `mainnet-fork-poc` | model | MAINNET_FORK_POC |
| 15 | `bounty-gate` | deterministic | BOUNTY_GATE |
| 16 | `report` | deterministic | REPORTING |
| 17 | `learning` | model | LEARNING |

```bash
webv2 run <C-xxx>                        # walk; halts at the first model stage (exit 3)
webv2 run <C-xxx> --until discovery      # walk only through this stage
webv2 run <C-xxx> --max-stages 1         # budget the walk
webv2 log <C-xxx> --tail 50              # tail the event log
webv2 verify <C-xxx>                     # event-log integrity check (hash chain)
```

When `run` halts, the `needs_model` report names the stage, its **prompt
file**, its budget class, and the structured output to feed back. Run that
model stage out-of-band (read the prompt, produce the artifact), ingest it
(§4/§5), then `webv2 run <C-xxx>` again — completed stages skip.

Model stage → prompt file (the pack is embedded; the paths are the repo
paths, also under `assets/prompts/`):

| stage id | adapter id | prompt |
|----------|-----------|--------|
| `protocol-model` | `protocol-model` | `prompts/37_protocol_knowledge_graph.md` |
| `discovery` | `discovery-specialist` | `prompts/39_trajectory_dispatch.md` |
| `hostile-review` | `adversarial-critic` | `prompts_legacy/22_adversarial_critic.md` |
| `maximal-exploitation` | `maximal-exploitation` | `prompts/44_maximal_exploitation.md` |
| `independent-verification` | `independent-verification` | `prompts/45_independent_verification.md` |
| `mainnet-fork-poc` | `mainnet-fork-poc` | `prompts/46_mainnet_fork_poc.md` |
| `learning` | `reflection` | `prompts/42_learning_memory_reflection.md` |

**Exit codes (the CLI contract):** `0` success · `1` handled error (a stage
not done in `prove --stage`, a failing `gate C F`, an `env doctor` that
cannot run the campaign, a lifecycle `move DISPROVED` missing
`--adjacent`/`--adjacent-clear`) · `2` usage error or refused transition ·
`3` `run` halted at the first model stage.

## 2. Start a campaign

```bash
webv2 init --program "Acme Protocol Immunefi"   # -> initialized C-xxxxxxxx at campaigns/C-xxxxxxxx
```

`init` also drops this runbook and `AGENT_BOOTSTRAP.md` into the campaign
directory so the working repo carries its own operating docs.

```bash
webv2 scope <C-xxx> --policy policy.json        # program identity + gate scope (bounty policy)
```

The policy file follows `schema/bounty_policy.schema.json`. **Known issues and
exclusions go in NOW** — they block findings at the gate later. The gate scope
is a case-insensitive substring match of the target contract name (and the
source path it resolves to) against the policy's scope/exclusion lists.

## 3. Pin reality

```bash
webv2 snap <C-xxx> ./target-repo                          # source pin
webv2 snap <C-xxx> ./target-repo --deployment d.json      # + deployment pin (verified from chain)
webv2 snap <C-xxx> ./target-repo --deployment d.json --chain c.json   # + chain pin (fork target)
webv2 snap <C-xxx> ./target-repo --exclude NAME           # prune more names (repeatable, comma-separated)
```

- A `foundry.toml` in the target is read **automatically**: `snap` prints a
  `toolchain:` line (build system + solc version) and records it in the
  snapshot's `config` — consumed by the manifest's `toolchain_fingerprint` and
  `doctor`'s solc probe. It reads `solc` first and falls back to legacy `sol`.
  An explicit `config` argument wins over detection.
- **The pin follows git.** When the target is a checkout, the pin is the git
  ladder (`git-clean` / `git-dirty` + `rev-parse HEAD`) and the snapshot covers
  the repository the target belongs to. `git` walks UP from the target, so
  pointing `snap` at a plain subdirectory of a larger repository pins that
  whole repository — check the code under audit out as its own repo (as a real
  audit target is) before pinning it.
- **The pin sets scope, and the prune is recorded.** Every pin prunes
  bulk/generated directories by default (`data/`, `datasets/`, `.scratch/`,
  `webv2-workspace/`, `build/`, `dist/`, Python tooling caches). `--exclude`
  adds names at any path depth. Whatever is dropped is **not hidden**: the
  top-level names land in the snapshot's `source.excluded`, a
  `snapshot.excluded` log event, and an `EXCLUDED from the pin` console line.
  If one of those names is in scope, re-pin with a tighter target — a silent
  scope drop is how target drift happens.
- **Unverified deployments flag coverage gaps** — audit the deployed code, not
  the repository. Re-pinning identical content verifies the existing copy's
  hash; a mutated pin refuses the run instead of being silently reused.

## 4. Recon + protocol model

```bash
webv2 index <C-xxx> --src ./target-repo      # rebuild the structural index (contract graph, no compiler)
webv2 model <C-xxx> model.json               # load a protocol model (schema-validated; seeds invariants)
webv2 model <C-xxx>                          # show the loaded model
webv2 model <C-xxx> model.json --facts facts.json          # merge operator facts (DNS/dependency)
webv2 model <C-xxx> model.json --facts ./manifests --facts-observed-at 2026-01-02
```

**Recon is not free.** A `webv2 sinks` run stamps itself into the campaign
state (`recon.sinks`: the `--src` tree and the time — replaced on re-run,
never per-file detail) and the `webv2 prescreen` artifact carries its
snapshot; closing the primitive-symmetry lens (L-04, the divergence-gate
close) refuses while either is missing, naming the exact
`webv2 prescreen <C-xxx> --src SRC` / `webv2 sinks <C-xxx> --src SRC`
commands to run — recon is cheap by design, so skipping it is never the
honest exit.

**Facts are operator assertions, and the framework never resolves anything.**
`--facts` merges dated, attributed `dns`/`dependency` objects onto
`components[]`, joined on `(kind,url)` or `(kind,path)`: a fact that matches no
component, matches two, or repeats a `dns`/`dependency` for one component is an
error (a typo must never be dropped silently). A JSON document carries its own
`observed_at` per fact; a **directory** of offline manifests
(`remappings.txt`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`,
`Cargo.lock`, `go.sum`, `foundry.lock`) has no date inside it, so
`--facts-observed-at YYYY-MM-DD` is required and is **never** taken from the
clock. There is deliberately no local DNS lookup: a DNS fact is something the
operator observed and wrote down (with its date and its source) — nothing in
the run resolves, guesses, or refreshes a record. Without `--facts` the verb
emits exactly its pre-I4 bytes; with it, one summary line is appended after the
load report.

**Seeding is part of the load, and a half-load is loud.** The load prints how
many invariants it registered into the guardrail registry and logs
`invariants.seed_empty` when it seeds nothing (the CLI warns on stderr). The
stage's completion proof requires the seeded registry — every declared
invariant must be registered, and a model that declares none fails the proof
("a protocol without invariants is not auditable"). Refine the model before
moving on; it must carry a liveness invariant per state machine.

**The index is v3, and the version is a fact, not a formality.** Each function
node carries `guards[]` (auth/sentinel/arithmetic facts from its own body),
`uses[]` (line-tagged read/write/emit/param uses with `concept_keys`), and
every contract carries `contract_closure` (the transitive inheritance chain).
External-call edges include **cast and chained forms**
(`IERC20(_token).burn(...)`, `a.b().method(`). `probes run`
rejects a `parse_version 2` index and names the rebuild instead of reading a
tree with no cast-form calls as a tree with no calls:
`webv2 index <C-xxx> --src <target>`.

## 4a. Candidate probes — the mechanical surface (before the plan)

Six deterministic probes read the structural index (v3) plus the protocol model
and emit **rows** — anchors, never claims. A row is an obligation to look: it
sets no finding status and costs no FP budget. No model calls, no new
dependency — same inputs, same rows.

```bash
webv2 probes <C-xxx> run                              # build/refresh the surface (artifacts/probe_surface.json)
webv2 probes <C-xxx> run --emit                       # + turn every emitted row into a plan priority (needs a plan on disk)
webv2 probes <C-xxx> run --emit --per-axis N --total N   # the quota knobs (a 0 quota is refused, exit 2)
webv2 probes <C-xxx> list [--axis L-0n|AXIS] [--all] [--json]
webv2 probes <C-xxx> blank --axis L-0n|AXIS --anchor-blind K --reason "..." --actor NAME
```

Every value flag above takes argparse's two spellings interchangeably:
`--per-axis 2` and `--per-axis=2`, `--axis=L-01` and `--axis L-01` (CLI-wide,
and scripts should assume it).

On a fresh campaign the honest order is: `probes C-xxx run` (build the
surface) → §5 `plan C-xxx` (creates the plan) → `probes C-xxx run --emit`
(attach the obligations). The surface is a pure function of the index, so the
second run is free; `--emit` is idempotent by `row_id` (re-running updates
`surface_sha` and reopens rows whose anchors moved; rows absent from the new
surface are reported as orphaned, never silently pruned).

**The six probes and their anchor enums** (a row discharge must name an anchor
from the row's *own* probe):

| probe | axis | lens | anchor enum |
|-------|------|------|-------------|
| `assertion-strength` | `enforcement-timing` | L-03 | `consumer`, `asserter`, `concept` |
| `custody-primitive` | `primitive-symmetry` | L-04 | `consumer`, `base`, `custody`, `sibling` |
| `trust-assumption` | `incentive-inversion` | L-02 | `actor`, `invariant` |
| `sequential-cursor` | `liveness` | L-01 | `guard`, `cursor`, `stranded_entry` |
| `short-circuitable-guard` | `guard-short-circuit` | L-01 | `guard`, `sentinel`, `safety` |
| `accumulator-basis-skew` | `accumulator-skew` | L-01 | `rounded`, `plain`, `accumulator`, `companion` |

**A row is ranked** by exactly `(tier, -assertion_gap, n_siblings, name)`:
tier 0 = unprivileged or adversarial/semi-trusted actor, tier 2 = trusted,
tier 1 = unresolvable (a modifier the trust join cannot resolve is never
silently trusted); `assertion_gap = 4 - own_class` for `assertion-strength`,
0 elsewhere; `n_siblings` counts non-test-double siblings only; `name` is the
function's sort name. The artifact publishes the key list it used (`rank`).

**The axis closure is four-state.** `sites` is what the probe *saw*; `rows` is
what survived its discriminator:

| surface for the axis | closure requires |
|---|---|
| `sites == 0` → `no-sites` | closes — nothing to rank. |
| `sites > 0, rows == 0` → `blind` | stays **open** until a `probes blank` attestation cites one of the axis's published `blind[]` keys, with a written reason (≥ 10 chars) and a named actor. |
| `rows > 0, emitted < min(per_axis, rows)` → `under-filled` | `missing[]` **blocker**: raise `--per-axis` or disposition the tail. |
| otherwise → `emitted` | closes only when **every emitted row of the axis is terminal**, each disposition still matches the row's shape, and the surface is fresh. |

**Discharging a row names the field it claims is safe.** Only `answered`,
`not-applicable` and `deprioritized` discharge a row; each **requires**
`--anchor <field>`, machine-checked against the row's own probe enum and real
value; the recorded `closed_ref` becomes that anchor's citation.

**A dismissal close to the money has to run — and has to name something.**
A row that is tier 0, or whose `assertion_gap` is 3 or more (the row asserts
that far past its evidence), is held to two rules. The first is about the
WORDS: such a row may not be discharged on a compensating-control argument —
"liveness-only", "the owner can revert", "not exploitable", "never
permanently", "no economic impact" and the like; `answered` refuses that
closure and names what it wants instead, a refutation that RUNS (`--ref
EXEC-xxx`, an exec record on disk, or `--ref INV-n`, a registered invariant).
The second is about the ARGUMENT: whatever the wording, the reason has to name
something from the row's own surface entry — the contract, the function it is
about, the base it inherits, the siblings it is symmetric to, the concept keys
it asserts. "the flow looked fine when I traced it" is refused, because there
is nothing in it a reader can open; "`L1TokenGateway` pays out along the path
it asserts" is accepted, because the next person can go and look. The refusal
lists the symbols it would have taken. Both rules have one escape, and it is a
signature, not a synonym: `--override-dismissal --override-reason "<why it is
safe>"` closes the row, logs `probe.dismissal_overridden` with your actor and
the written reason, and the report's **Disposition review** section keeps the
dismissal AND the override in front of every later reader.

**A sentinel guard is not an answer — the value that passes it is.** The
third rule in this family runs on a row whose own guard is a zero-check
(`own_form=sentinel`: `stateRoot != bytes32(0)` and its kin). A zero-check
cannot express the truth of the value it guards — every non-zero value
passes it — so "the assertion exists" is not a closure. Closing such a row
`answered` or `not-applicable` demands `--passes VALUE`: the value that
passes the check, recorded on the priority as its `passes` field. The value
must be checkable: it names a symbol from the row's own surface entry, or
it is a concrete literal (a decimal integer, a hex number or
Ethereum-style address 0x…, `bytes32(0x…)`, a boolean, or a quoted string).
Junk (`TBD`, `zzz`, `n/a` — bare or quoted) and sub-3-character values are
refused, and the SAME floor is applied to a supplied `--passes` on every
closure, any route — a flag is never inert. The escape hatch is the same
signature as above — `--override-dismissal
--override-reason` closes a sentinel row without a value, logged and
reviewed exactly like any other override.

**"The check lives elsewhere" is a concession — price the window it opens.**
The fourth rule in this family runs on a tier-0 row anchored on `asserter`
(`--anchor asserter`): that anchor concedes the row's own consumer does not
enforce the check — it is asserted at a later lifecycle stage, and the interim
window between the two is exactly what the row asks about. Closing such a row
demands the consequence be priced: `--finding F-xxx` (a filed finding that
records the window) or `--interim STATEMENT` — a consequence statement that
cites a symbol from the row's own surface entry ("until `finalizeBatch` runs,
`prev:state` stays stale in `commitBatch`"); prose that names nothing from the
row is refused. The statement is recorded on the priority as its `interim`
field, the finding id as `interim_finding`. The escape hatch is the same
signature as above — `--override-dismissal --override-reason` — logged and
reviewed exactly like any other override. Closures recorded before this gate
existed are swept by `webv2 deferred <C-xxx>`: it lists every tier-0 closure
whose reason vocabulary implies a failure consequence (`unfinalizable`,
`stranded`, `frozen`, `revert-forever`, `owner clears`, ...) and prices none
of it. The sweep reports; it never mutates — the fix is a re-answer.

A separate, unglamorous rule runs on EVERY closure at any tier: a reason or
`--ref` that names a finding, exec record or invariant must name one that
exists — `F-1a2b3c4d5e6f` that was never written is refused as fabricated, by
typo or by invention. Affected-site paths carry the same claim discipline:
an `affected.path` must live INSIDE the pinned tree — absolute paths,
backslash paths, and anything walking through `..` (or an empty segment)
are refused at intake, because every later reader (the snapshot-compatibility
gate, report.md) cites them against the pin. The pricing flags are held to the same discipline on
every closure, any route: `--finding` must be a filed, LIVE finding (a
terminal one — DISPROVED, OUT_OF_SCOPE, INFORMATIONAL, DUPLICATE,
SUPERSEDED — records nothing about a window that is still open) and
`--interim` a statement of at least 3 characters; a ghost or terminal ref is
refused before anything is written. And a disposition gate that stands down
because the priority's probe row no longer resolves against the current
surface says so on stderr — a skipped gate is not a passed gate. That is
the difference the gate buys: not "do not dismiss", but "a dismissal this
close to the money is a decision someone signs".

**A stale surface keeps the lens open.** The gate compares `surface.index_sha`
with the current index's content hash. A **mismatch** names the re-emit
(`probes C-xxx run --emit`); **no current index at all** names
`index C-xxx --src <target>` (rebuild first, then re-emit).

## 4b. The two mechanical tables (read before you attest a lens)

Two `--json`-able views read the same structural index the probes read. They
decide nothing; they are how the operator checks a lens attestation against the
code instead of against memory.

```bash
webv2 enforce <C-xxx> "<storage-var>" [--contract 0xabc...]   # L-03: where a variable is written, where it is read
webv2 symmetry <C-xxx> [--family 0xdef...]                    # L-04: the per-family (direction, asset) custody matrix
```

`enforce` prints every write and read site of one storage variable or concept
key, ordered by call-graph depth from an entry point, each with the assertions
its function carries — plus the (write, read) stage pairs **no assertion about
that variable covers**. Those uncovered pairs are what the `assertion-strength`
rows are about; `--json` is the same table.

`symmetry` prints, per inheritance family, the (direction, asset) cell each
member implements and the divergences between members:

```
member-disagreement   siblings use different primitives for one cell — which
                      one is the custody model?
funding-mismatch      a forward path mints/burns while a recovery path moves
                      the asset out of a balance the member never held — who
                      funds the difference?
```

A family with no disagreement prints its cells and **no question** — the matrix
is an obligation to look, never a claim. Use it before `answered L-04` so the
quoted primitives come from the code rather than from the plan text.

## 4c. Deployment facts: what the code cannot answer

The snapshot answers **which code** is deployed; the bytecode hash in
`--deployment d.json` is a claim about bytes, not about values. A fact that
exists only in the instance is invisible to the index, to `enforce`, to
`symmetry` and to every probe — and a hypothesis that turns on one is
UNVERIFIED until the number is quoted in the finding.

Read these before you call a lifecycle transition safe, and put the command
you ran in the finding's evidence:

| fact | where it lives | how to read it |
| --- | --- | --- |
| constructor arguments | deploy script / `broadcast/*.json` / verified source | `forge inspect <C> abi` for the signature, then the broadcast receipt, or the explorer's Constructor Args |
| owner-set caps and thresholds | live storage | `cast call <addr> "<capGetter>()(uint256)"` (or `storageLayout` + `cast storage`) |
| slot maps seeded at `initialize` | initializer args, not the setter code | compare the deployed `initialize(...)` calldata with the code's assumptions |
| relayer / oracle / messenger addresses | live storage, or an `immutable` baked into the runtime code | `cast call` the getter; an immutable has no storage slot — read the deploy calldata or `forge inspect <C> deployedBytecode` |
| role grants made after deploy | governance txs, not `grantRole` calls in the repo | the chain's logs — a role the code never grants may still be held |
| timelock delays, challenge windows, bonds | constructor/config, often changeable | read the getter, then read who can change it and when it last changed |

The three that bite hardest in practice, because the code reads as correct:
an owner-set cap (the cap decides whether the set that must fill can ever
fill — a set that cannot fill never finalizes), an initializer slot map
(which index is authoritative for a given key decides whether a write lands
in an empty cell), and a messenger / relayer threshold (the quorum number
decides whether a challenge can ever be met). None of them is a bug in the
source; all of them are exploitable or fatal at the deployed value.

The rule: if exploitability depends on a number you did not read from the
deployment, the hypothesis is not disproved by the code either — say which
value you assumed, and read it. `webv2 snap --dry-run` tells you whether the
pin covers the working tree; it says nothing about the instance. When the
value is genuinely unreadable (unverified source, no RPC), record that as a
coverage gap on the priority rather than closing it.

## 5. Plan, dispatch, ingest

```bash
webv2 plan <C-xxx>                          # READ-ONLY view of the existing plan (no file = no write)
webv2 plan <C-xxx> --rebuild                # archive the outgoing plan to superseded/campaign_plan.NNNN.json, regenerate
webv2 answered <C-xxx> Q-xxx answered --reason "..." --ref EXEC-xxx   # close a plan priority
webv2 answered <C-xxx> Q-xxx not-applicable --reason "considered, doesn't apply"
webv2 deferred <C-xxx> [--json]              # sweep: tier-0 closures that defer the check (anchor asserter / consequence vocabulary) without pricing it — report only
webv2 ingest <C-xxx> --json-file payload.json [--trajectory T] [--stage S] [--answers-priority Q-xxx]
webv2 ingest <C-xxx> --from slither --json-file slither.json   # detector lane: every Medium/High/Critical check becomes a HYPOTHESIS with provenance.sast_tools
webv2 ingest <C-xxx> --from aderyn --json-file aderyn.json     # detector lane (aderyn): every high_issues row becomes a HYPOTHESIS with provenance.sast_tools
webv2 ingest --example                       # the validated payload template (PURE JSON on stdout; legend on stderr)
```

`webv2 ingest --example` **is** the contract: the template is schema-validated
and the closed-enum legend is walked from `schema/finding.schema.json` (never
hand-maintained). Pipe it: `webv2 ingest --example 2>/dev/null > payload.json`,
fill it in, then `webv2 ingest <C-xxx> --json-file payload.json`. A payload
that fails validation reports **every** error, not just the first. Ingest
validates schema, fingerprints dedup, and intake-checks: an unknown bug class
returns a taxonomy advisory (closest known classes, conservative E5 floor); a
missing `economic_impact` on an economic trajectory is warned. The accepted
line names the floor the class pins — `ingested F-xxx [HYPOTHESIS] (class
bridge-message, CONFIRMED floor E6)` — read through the same lookup the
CONFIRMED gate runs (instance `floors set` overrides included), and a class
stricter than the loosest known class also prints the class-floor advisory, so
a taxonomy choice is never a silent evidence wall. **Never
hand-write a finding file** — ingest is the only path in.

**Both polarities of every lifecycle transition.** A transition can accept
what it must reject (attacker wins: fake root finalizes, double spend
settles) or refuse what it must accept (nobody wins: the cursor never
advances, the queue never drains, the withdrawal never lands). Stage 38 now
requires one priority per polarity and the restrictive question has to name
what gets stuck; the H trajectory in Stage 39 works both arms. When you read
the plan, check that the second arm exists before you accept a lens
attestation — L-01 liveness is the restrictive arm's lens, and "no economic
impact, liveness only" is not a disposition the gate accepts on a live row.

The detector lane (`--from slither`) is evidence, not verdict: tool findings
enter as HYPOTHESES like any other. The accepted input is **real Slither JSON**
(`slither src --json out.json`: `results.detectors[]` with locations in
`elements[].source_mapping`) — an earlier revision read a
`vertices[]`/array-`results` shape that Slither never emits, so every real run
produced zero hypotheses silently (corrected in Wave I; see
`--from aderyn` below). When you resolve a dedup candidate as
`same` and exactly one side is tool-flagged, the SURVIVOR records
`dedup_meta.corroborated_by` (only when it is itself the non-tool side) —
worth +0.5 acceptance. The `brief` shows a computed TOOL FLAGS section (tool
findings by critic verdict, corroborated ids) so detector false-positive
rates stay visible without touching the score.

`--from aderyn` is the same lane over Aderyn JSON (`aderyn src --output
out.json`): only `high_issues.issues[]` is admitted — Aderyn has no Medium band,
so `high` is its High/Critical analogue — and `issue_count`/`detectors_used`
are informational only. Aderyn exits 0 even when it has findings, so **never
read the exit code as the verdict; the JSON is the signal.** An issue with no
anchorable instance is dropped, exactly as a Slither flag with no location is.

**Wave G tranche 2 — measurement, soundness layers, bounded proofs.**
The gold-eval suite (`schema/evalsuite` pack, 19 cases — two of them older
pragmas, so the suite is not a single-compiler monoculture) scores a campaign when
its program matches — the audit gains a `## eval` section with recall/precision
behind Wilson intervals (`internal/wilson`; small samples render wide, and that
is the point). Per-class search weights ride `taxonomy/class_weights.json` and
ship **neutral by design** — graduation needs a real `corpus-surface --backtest`
`improves` verdict, never a feeling. `mitigscan` detects *structural defenses*
at ingest (CEI ordering with no loop, function-modifier guards, EIP-712 domain
separation, pull-ledger effects) into `dedup_meta.mitigation_present`: a −1.0
acceptance demotion, **never a dismissal** — policy acceptances live on the
separate `bounty.accepted_risk` rail (cited via `reference_url` when the policy
provides one); the two layers may coexist on one finding and never mix.
Invariants can generate harness scaffolds (`verify --scaffold`) — the model
writes ONLY between the BODY markers, and a mapped run (`verify
--harness-result`) lands a rung: `counterexample` (a real model),
`PROVEN-BOUNDED (k)` (bounded — an admission, not an oracle), or
`inconclusive`; nothing promotes a status from the harness side. At mint,
`--verify-reruns` records 3x variance and stale-fork advisories on the evidence
(fail-open: advisories never block a mint). Operator correctness: `amend`
bumps `claim_version` (old critic verdicts re-stale by design), `supersede`
retires a finding to SUPERSEDED (terminal, excluded from live/precision views,
evidence COPIED forward), and `answered` batches dispose behind the same gates
all-or-nothing. `report --format immunefi` exports intake-shaped files per
submission-ready finding; the brief shows per-lens cost yield and — only when
`auto_tune` is set in the bounty policy — auto-deprioritizes a lens whose
Wilson-upper precision is under 10% (n≥10 required; zero-hit trip starts at
n=35, not n=20: the CI is the law).

**Wave G tranche 3 — beyond-contract scope, cross-chain assumptions, post-patch proof.**
`components[]` on the protocol model tracks non-contract surfaces (frontend,
relayer, keeper-service, domain, offchain-service) as tracked-but-opaque:
pinned by snapshot, cited by path+hash in findings, never indexed by
structidx — findings on components arrive as model findings and flow through
dedup/gate/report like contract findings. Two new canonical classes
(`frontend-injection`, `infra-boundary`) with two data-only playbooks; no
scanners ship with them. Per-hop cross-chain assumptions ride
`chain_assumptions[]` (chains[] stays plain strings — legacy models unchanged)
and render as assumption tables in `brief` + report; a `BRIDGES` hop touching
an undeclared chain (or a bridged chain with no finality declared) lists an
ASSUMPTION GAP row. Two structidx archetypes pre-screen the code side:
`signature-no-separator` (verify-shaped entry points with no chain-id/domain
parameter evidence) and `proof-accepted-without-depth-gate`, both hint-only
via `prescreen`. After a patch, `verify --post-patch F-xxx --exec EXEC-xxx`
regresses the finding: the new exec's exit vector against the baseline repro
gives `still_reproducible` / `fixed` / `indeterminate`, recorded as
`verification.patch_regression` beside the immunize clause — plus an advisory
changed-surface diff (capped at 50 rows) and a plant check over changed files
(the patch must not plant anything new). Fail-open throughout: verdicts never
move status.

**Wave I — external feedback: dates on eval cases, baseline floors, band
precision, operator facts, four bridge predicates, SWC + disclosure.**
Six items landed, and three of them changed what a number on your screen
*means*, so read this before you quote one.

*Eval cases now carry a date, and a date can strike a case out.* Suite rows
gained `deployed_at` — when the bug lived on-chain or the advisory published —
beside `created_at`, which stays the ingestion stamp. At scoring time
`--backtest` excludes a held-out case whose date is strictly older than the
newest dev case, and excludes a held-out case that is a near-duplicate
(Jaccard ≥ 0.8 over class + root-cause + file basenames + repo) of any dev
row. The run prints one line, `held-out excluded: <N> temporal, <M> near-dup`,
and those rows never rank. **Nothing is deleted or rewritten** — exclusion is
a scoring-time filter, so a re-run on a fixed dataset shows you what changed
instead of hiding it. An unparseable `deployed_at` fails the row closed (it
does not rank) and the run open (the run continues); if every held-out row is
excluded you hit the ordinary empty-held-out exit, not a silent zero.

*Never quote a recall without the floor beside it.* `--backtest --baseline
NAME` (repeatable; NAME ∈ always, never, slither, aderyn) prints a baseline
block after the `verdict:` line. `always` flags everything — it is the price
of recall, printed as recall; `never` flags nothing and prints
`precision: 0/0 (95% CI n/a)`, never a fabricated 0%. The tool baselines run
the real binary once per resolved source root; a case with no local checkout
(a GitHub URL, an empty `gold.locations`) is **skipped, never counted as a
miss** (`skipped: <k>/<n> cases (no local checkout)`), and a binary that is
missing or fails on every root prints a single SKIPPED line and the command
still exits 0. The block is advisory: it never moves the verdict or the exit
code, and it always prints in roster order, whatever order you passed the
flags.

*Acceptance scores are not probabilities.* The `## eval` section gains an
acceptance-band precision table — `[0,1)`, `[1,2)`, `[2,4)`, `[4+Inf)` — giving
gold-anchored vs live findings in suite-matched programs with a Wilson
interval per band, plus a fabrication ledger. "Fabricated" means the record
itself retracted the finding as disproved (`critic_verdict == "disproved"` or
status `DISPROVED`); superseded, duplicate and out-of-scope rows are NOT
fabrications and are not counted as such. Expected calibration error was
refused as inapplicable to a score that is an additive evidence sum. Both
blocks appear only when there is something to report.

*Operator facts are dated assertions, never lookups.* `model <C> [file]
--facts PATH` merges `dns`/`dependency` objects onto `components[]`; a fact
matching no component, two components, or repeating a fact type on one
component is an error. Extracting from a directory of manifests
(`remappings.txt`, lockfiles) requires `--facts-observed-at YYYY-MM-DD`, and
the date is never taken from the clock — a fact's date is something a human
asserted. Nothing on this path resolves a name or opens a socket.

*Four more bridge predicates — hint-only, by construction.* `prescreen` gained
`threshold_without_enforcement`, `relayer_single_key`,
`merkle_proof_no_length_check` and `verifier_default_on` (high criticality,
`bridge-message` playbook). They read the structural index, which carries no
state values, so they tell you where to look and never that a bug is there;
the archetype descriptions say exactly what each one cannot see.

*SWC cross-references, and a disclosure bundle that is recorded, not
enforced.* Taxonomy classes may carry an `swc` id and then render
`[OWASP SC06; SWC-104]`; the ids were fetched verbatim from the SWC registry
on 2026-09-11, and that registry warns its own content has not been thoroughly
updated since 2020 — the alias is a cross-reference for a reader, never an
authority. Coverage is partial: rows without an `swc` key are byte-identical
to before. `publish --disclosure FILE` attaches a bundle whose prose stays
campaign-local while the shared record carries only its sha256 and embargo
date, and the framework does **not** refuse, delay, or suppress a publish
while an embargo is open — the extra line ends `— recorded, not enforced` so a
recorded embargo is never mistaken for an enforced one.

**Assign trajectories so components get ≥ 2 orthogonal angles:** A-code,
B-economic, C-state-machine, D-attacker, E-historical, F-integration, G-drift,
H-lifecycle (consensus/rollup commit→challenge→finalize game reasoning: model
the full game and the adversary WINNING it).

Closing statuses **require** `--reason`; "answered" should carry the evidence
`--ref`. An answer with neither is flagged in the report's Answer-quality
section. `not-applicable` is the honest "considered, doesn't apply" — do not
abuse `answered` for it.

**Lenses.** The same `answered` verb routes LENS ids (L-01 liveness, L-02
incentive-inversion, L-03 enforcement-timing, L-04 primitive-symmetry). Each
lens is seeded with candidate families from the protocol model and closes ONLY
when every seeded family is attested with a written reason + named actor:

```bash
webv2 answered <C-xxx> L-0X answered --families a,b,c --reason "..." --actor NAME
webv2 answered <C-xxx> L-0X not-applicable --families a,b,c --reason "..." --actor NAME
```

`none-applicable` is the only honest close for a model-less lens. Closing
**L-04** means QUOTING the token-movement primitive per family, not naming
verbs:

```bash
webv2 answered <C-xxx> L-04 answered --families a,b,c \
  --symmetry "lock=transferIn;payout=transferOut;slash=burn" --reason "..." --actor NAME
```

Quote them from `webv2 symmetry <C-xxx>` (§4b) — the matrix prints every
member's primitive per (direction, asset) and flags the disagreements, so the
attestation is checkable against the index. A blank primitive does not count
(exit 2 names the missing families; the gate keeps the lens OPEN until every
seeded family has a quoted primitive).

**Narrating a divergence is not reconciling it.** When the surface carries
funding-mismatch or member-disagreement divergence rows (the matrix flagged
them; you are closing the lens that owns them), the attestation must
RECONCILE every one of them — the same falsifiability law the probe rows
obey, applied to the lens closure:

```bash
webv2 answered <C-xxx> L-04 answered --families a,b,c \
  --symmetry "..." \
  --reconcile "ROWID=primitive:Symbol#L<line>|primitive:Symbol#L<line>;ROWID=F-<12 hex>" \
  --reason "..." --actor NAME
```

Per row, the two legal exits: (a) per MEMBER, a
`primitive:Symbol#L<line>` cite — the funding primitive and the exact
line, where the Symbol must appear on the row's own surface entry (the
matrix row names them: contract, consumer, base, forward); or (b) the id
of a FILED, LIVE finding that records the answer. The L-04 close refuses an
attestation that doesn't reconcile the divergence rows it covers: "The 42
divergences are benign duals" with no cite is refused: the refusal names
every unreconciled row and both exits, and nothing is written. An empty or
blank `--reconcile` spec is refused at the parse layer (it would overwrite
the stored reconciliation with zero records), and the flag is consumed by
one route only — an L-04 primitive-symmetry CLOSURE: on a `Q-*` priority,
or a lens status that is not a closure, it is refused and the stored
reconciliation survives untouched. The probe-row flags are never inert on
a lens route either: `--anchor`, `--passes`, `--interim` and `--finding`
price a probe row, so they are refused on an L-* closure (exit 2 names the
route). Citing a symbol that is not on the
row, or a finding that was never filed, is refused as what it is. A
re-attestation of an already-closed lens rides its stored reconciliation;
a REOPENED lens must re-attest it.

A CONFIRMED high/critical finding
re-opens the closed lens whose family produced it (shown as REOPENED in
`plan`) — re-attest it.

## 5a. Floors and budget are DATA, decided by the operator

Evidence floors are not fixed by the framework's table — that table
(`CLASS_CONFIRM_FLOOR`, §Evidence) is the **default**, and the campaign may
record per-class overrides. The override is the sanctioned alternative to
editing framework source: actor-attributed, written reason, one hash-chained
`floor_policy.set` event, audited exactly like an artifact hash. Every gate,
queue and deficit follows the effective floor (override or default).

```bash
webv2 floors <C-xxx>                                   # effective table (defaults + overrides)
webv2 floors <C-xxx> set reentrancy E5 --actor NAME --reason "mainnet fork reachable for vault tests"
webv2 floors <C-xxx> unset reentrancy --actor NAME --reason "fork infra gone — back to default"
webv2 floors <C-xxx> --json
```

The cost ceiling works the same way — a decision, not a meter:

```bash
webv2 budget <C-xxx>                                    # spend vs ceiling (no-limit stated plainly)
webv2 budget <C-xxx> --set 5000 --actor NAME            # set max_total_cost_usd
webv2 budget <C-xxx> --clear --actor NAME               # remove the ceiling
webv2 budget <C-xxx> --set-discovery N --actor NAME     # set max_discovery_findings
```

Unset means unbounded (the brief says so); set means the pipeline **HALTS**
the moment recorded spend crosses the ceiling — an overrun becomes an explicit
operator decision (raise the ceiling or stop), never a silent one.
`budget <C-xxx>` also reports the discovery position (findings risen vs the
deterministic discovery ceiling). Since the slot reform the ceiling meters
**risen** findings, not hypotheses: bare HYPOTHESIS ingest is free —
suspicion costs nothing — and a finding's slot is charged exactly ONCE, at
its FIRST rise above the E0 baseline, whether that rise is an evidence item
above E0 (`mint`/`add`) or the first status promotion whose floor is above
E0. Hitting the ceiling refuses that rise with an error naming the command
that raises it (`budget <C-xxx> --set-discovery N`); every later add to an
already-risen finding is free.

## 6. Triage → dedup → review

```bash
webv2 dedup <C-xxx>                                   # deterministic three-tier sweep (merge / cluster / flag)
webv2 dedup-signature <C-xxx> F-xxx --root-cause "attacker-controlled exchange rate creates unbacked withdrawal value" [--cwe CWE-20]
webv2 dedup-signature <C-xxx> F-xxx --economic "the protocol's own reserve is drained in one block"
webv2 resolve-candidate <C-xxx> F-xxx F-yyy --verdict same     # tier-3 flag: same merges the younger
webv2 resolve-candidate <C-xxx> F-xxx F-yyy --verdict distinct --note "different root cause"
webv2 ack <C-xxx> [F-xxx]                             # in-code acknowledgements (stub/TODO/known-issue) around the finding
webv2 rank <C-xxx>                                    # acceptance-ranked table — which of the findings matter
webv2 verdict <C-xxx> F-xxx --verdict confirmed --reason "no compensating control"
webv2 recall <C-xxx> --finding F-xxx --mode negative   # recorded graph-memory consult (gate REQUIRES negative/comparative)
webv2 move <C-xxx> F-xxx POSSIBLE --reason "triage: the mechanism is falsifiable"
webv2 move <C-xxx> F-xxx CONFIRMED --reason "gates passed"
webv2 move <C-xxx> F-xxx DUPLICATE --of F-other --reason "same root cause, same site"   # a DUPLICATE must name its target (--of; see the state machine below)
webv2 amend <C-xxx> F-xxx --title "corrected title" --note "why"   # correct a filed finding in place (bumps claim_version, never moves status)
webv2 supersede <C-xxx> F-new --of F-old   # retire F-old to SUPERSEDED; its evidence is COPIED into F-new, never moved
webv2 gate <C-xxx> F-xxx                              # read-only per-finding CONFIRMED dry-run (exit 1 while checks fail)
```

`dedup` is deterministic: tier-1 near-identical candidates merge, tier-2 form
clusters, tier-3 near-duplicates are **flagged** for a human/operator verdict
via `resolve-candidate`. Then the hostile critic reviews POSSIBLE-bound
candidates (`verdict`) and a negative/comparative graph-memory consult is
recorded (`recall --mode negative` — the CONFIRMED gate requires it).

A finding filed under the wrong class is corrected with `amend --class`: re-file
by *true root cause* and attest the match in `--note`; the floor is recomputed
from the new class on the next gate read (never retroactively promoted, and
re-filing to a stricter class raises the bar with the evidence untouched).

**Tier-2/3 signatures are never hand-written hex.** `dedup-signature` takes the
target-agnostic sentence ("attacker-controlled exchange rate creates unbacked
withdrawal value", not a file or function name) and hashes it; exactly one of
`--root-cause` / `--economic` applies, and a tier-2 signature may carry `--cwe`.
Two findings whose sentences hash the same are the same root cause reached
through different syntax, which is the point — but a matching signature does not
merge anything. Pairs the sweep cannot auto-merge (different code sites, same
signature) are **flagged on both sides**, so `resolve-candidate --verdict
same|distinct` adjudicates them; the same-spot auto-merge path is untouched.

A manual self-duplicate — the same root-cause class on the same affected path,
filed twice — is retired with `webv2 supersede <C-xxx> F-new --of F-old`: the
retired copy leaves the live and precision views WITH its evidence copied
forward. Adjudicating it false-positive is not that op — it calls a real bug
wrong and moves the precision line (§6b below).

`ack` scans the pinned source for an in-code acknowledgement (stub, TODO,
known-issue comment) in the code that would have to change for the finding to
matter. A live acknowledgement **demotes** the acceptance likelihood by one
point and is recorded as an advisory in the gate output — it never blocks: the
owner's own comment is context for the reviewer, not a gate condition. The
finding stays; `rank` prints the demotion marker.

`rank` is the read-only acceptance table over **every live finding**: score,
band, evidence, critic and the demotion markers, in the order the policy asks
for (`submission_budget.rank_by` — the acceptance score, or severity band when
the policy says severity), with the critic-disproved (disqualified) ids named
below the table. It writes nothing — `gate` is what persists the score onto the
findings — and it ranks the whole live set, not only the rows the report's
precision block had budget for. An unscoped campaign has no acceptance key and
says so before printing a severity order.

**The status state machine** (`move` is the ONLY transition path; terminal
statuses absorb). Status floors: HYPOTHESIS E0, NEEDS_RESEARCH E0,
PROVISIONALLY_VALID E1, POSSIBLE E2, CONFIRMED E5, CHAIN E4.

```
HYPOTHESIS  -> NEEDS_RESEARCH | PROVISIONALLY_VALID | POSSIBLE | DISPROVED | OUT_OF_SCOPE | DUPLICATE | INFORMATIONAL
NEEDS_RESEARCH -> POSSIBLE | PROVISIONALLY_VALID | DISPROVED | OUT_OF_SCOPE | DUPLICATE | INFORMATIONAL
PROVISIONALLY_VALID -> POSSIBLE | NEEDS_RESEARCH | DISPROVED | OUT_OF_SCOPE | DUPLICATE | INFORMATIONAL
POSSIBLE    -> CONFIRMED | NEEDS_RESEARCH | DISPROVED | OUT_OF_SCOPE | DUPLICATE | INFORMATIONAL
CONFIRMED   -> DISPROVED | DUPLICATE | CHAIN | OUT_OF_SCOPE | INFORMATIONAL
CHAIN       -> CONFIRMED | DISPROVED
DISPROVED / OUT_OF_SCOPE / INFORMATIONAL  -> (terminal)
DUPLICATE   -> HYPOTHESIS   (the one reopen edge — see below)
```

**A move TO `DUPLICATE` must name its target**: `--of F-yyy` (the same flag
`supersede` uses). The target has to exist and must not be the finding
itself — a ghost id, a self-merge and a re-target of an already-recorded
merge are all refused before anything is written. The pointer is recorded
on the finding as `duplicate_of`. `--of` is consumed by the merge route
only, and a flag is never inert: on any non-DUPLICATE move it is refused at
exit 2 naming DUPLICATE as the route that reads it (the reopen clears the
pointer without ever looking at `--of`).

**`DUPLICATE` is terminal for every reader but the operator's undo.** The
dedup block, the report and the queue treat it as closed; the one legal way
out is `move <C-xxx> F-xxx HYPOTHESIS --reason "wrong merge"`, which clears
the recorded `duplicate_of` pointer (a stale one would keep the merge alive
for every reader) and leaves the finding a hypothesis again — evidence and
history stay attached, only the merge pointer goes.

A `HYPOTHESIS -> CONFIRMED` jump is refused (exit 2) — walk it through
`POSSIBLE` first. A DISPROVED on a **lifecycle** finding must name the
adjacent unchecked property before it counts as coverage:
`move <C-xxx> F-xxx DISPROVED --reason R --adjacent 'the other root in the
same struct'` (spawns an OPEN SIBLING priority the queue must drain) or
`--adjacent-clear` (sibling already checked; logs `sibling_cleared`, no new
priority). Missing both on a lifecycle disproof exits 2.

### 6a. The evidence ladder (CLI-only — no scripts for the phases)

```bash
webv2 exec <C-xxx> --profile docker-networkless --command "forge test --match-test poc" --workdir poc --finding F-xxx --dry-run
webv2 exec <C-xxx> --profile docker-networkless --command "forge test --match-test poc" --workdir poc --finding F-xxx
webv2 mint <C-xxx> F-xxx --exec EXEC-xxx --description "unit PoC drains" --tier T2 --type foundry-test
webv2 verify <C-xxx> --exec EXEC-xxx --finding F-xxx --verifier verifier-b --description "same block, same drain"
webv2 impact <C-xxx> F-xxx --extractable 1200000 --artifact impact-dump.json --description "1.2M at fork depth"
webv2 classify <C-xxx> EXEC-xxx        # classify a FAILED exec: environment / setup / logic / unknown
```

- `exec` runs the sandboxed command and writes the EXEC record. `--dry-run`
  previews the exact `docker run` argv **without** executing (works with no
  docker; nothing executed, no record written). `--env K=V` passes container
  env vars (validated up front; keys, not values, land in the ledger). A
  sandbox **preflight** runs before the exec (daemon / image / solc-cache /
  workdir) and a FAIL blocks with the exact fix named — a missing workdir
  never burns a run.
- `mint` is **idempotent per exec** (an exec backs one evidence item per
  finding — re-minting is a no-op); `--type` is validated against the schema
  enum. A REFUSED mint (e.g. the invariant guardrail) **rolls the recorded
  attempt back** (`repro.attempt_rolled_back`) — the EXEC citation survives:
  fix the guardrail and retry the SAME exec, no fresh sandbox run demanded.
- Forge output is checked for **MEANINGFULNESS** before minting: "No tests
  found" (Ran 0 tests) or a failing suite cannot back evidence — the output
  must show a test actually ran and passed. Truncated logs are rejected.
- A FAILED exec is classified on the spot: **ENVIRONMENT** (daemon down, image
  missing, solc download cut — fix the environment, do NOT spend a
  fresh-context retry), **SETUP** (retry in a fresh context with the failure
  record), **LOGIC** (the only class that argues the hypothesis).
- `verify --exec` enforces **independence** (a fresh exec + a reporter
  different from the original reproducer) — that is E6.
- `gate <C-xxx> F-xxx` dry-runs the CONFIRMED gate on ONE finding (read-only,
  any status): it prints every live clause with its verdict (✓ / ✗ + the fix)
  and a `since last attempt:` delta built from the last refused attempt. Run it
  before attempting the `move`.

**Sequence coverage is keyed off the deployment pin, not the step count.** A
finding that declares a multi-step/multi-actor `exploit_sequence` must be
proven by a multi-tx sequence PoC — but ONLY when the active snapshot has a
fork target (a deployment or chain pin):

```bash
webv2 sequence run    <C-xxx> spec.json --finding F-xxx   # T4 PoC under fork-runner (needs FORK_RPC_URL)
webv2 sequence verify <C-xxx> F-xxx [--exec EXEC-xxx]     # do the attempts have verified coverage?
```

Off-chain (no pin) the multi-step sequence is proven through the normal
ladder, because steps in a logic bug are not transactions.

### 6b. Non-gold adjudication: the three verdicts

The eval join scores every live finding that anchors no gold case as a false
positive, which conflates three states of the world. `adjudicate` writes the
verdict down, and the tally it prints is the same accounting the audit's
`## eval` section renders:

```bash
webv2 adjudicate <C-xxx> F-xxx --verdict additional-true-positive --basis dataset-cross-check --reason "real, and the suite has no case for this code site" --actor NAME
webv2 adjudicate <C-xxx> F-xxx --verdict false-positive --basis reproduction --reason "the PoC reverts on the caller's own guard" --actor NAME
webv2 adjudicate <C-xxx> F-xxx --verdict assumption-gated --assumption "the oracle is updatable by any caller" --basis code-argument --reason "real only while that assumption holds" --actor NAME
webv2 adjudicate <C-xxx>                              # list the recorded rows
```

- **additional-true-positive** — a claim about the **GOLD DATASET**, not about
  the campaign: the finding is real and the answer key simply does not contain
  it. It is not a claim that the campaign found more bugs than the suite
  records, and it moves no status and no evidence.
- **false-positive** — the finding is wrong.
- **assumption-gated** — the finding is real only if the named `--assumption`
  holds; `--assumption` is required with this verdict and meaningful only
  there.

An FP says the BUG is wrong; a second copy of a live finding (same class, same
affected path) is not wrong, it is double-booked — `webv2 supersede <C-xxx>
F-new --of F-old` retires it WITH its evidence copied forward, and `adjudicate`
nudges the twin's id on stderr rather than let the FP move the precision line.

`--verdict`, `--basis`, `--actor` and `--reason` (≥ 10 written characters) are
required to record a row; `--severity` defaults to `tbd`, `--exec` cites the
exec record the verdict rests on, and `--json` prints the rows with the tally
as one object. A row **replaces** the prior row for the same finding. A verdict
moves the **adjusted precision the audit section prints**: a finding
adjudicated additional-true-positive or assumption-gated leaves the
false-positive penalty, and the remaining penalty is what `adjusted precision`
excludes. Omit the finding to list the rows.

A row the state file holds that validation refuses is not silently dropped:
the tally counts it on its own `invalid adjudication rows (refused by
validation)` line, and the `--json` view carries the matching
`invalid_adjudications` key only when that count is non-zero. When the
campaign state itself no longer validates the eval join never runs, so the
listing ends with `eval join unavailable: campaign state does not validate`
and withholds every counter rather than printing a table of zeroes.

## 7. Independent verification (E6) and impact (E7)

Classes whose effective CONFIRMED floor is E6 (`share-price-inflation`,
`economic-invariant`, `bridge-message`, `cross-chain-replay`) and every
confirmed finding benefit from a second pair of hands. The queue follows the
campaign's effective floor — a finding already at/above its floor is defence
in depth, not a requirement:

```bash
webv2 verify <C-xxx> --queue                            # the E6 verification queue (mandatory-first, skips E6+)
webv2 verify <C-xxx> --exec EXEC-xxx --finding F-xxx --verifier verifier-b --description "same block, same drain"
```

Independence is **enforced, not asserted**: the exec must be one not already
cited on the finding, and its reporter must differ from the original
reproducer. A single agent in two identities defeats it — do not do that.

Quantified impact mints E7 against a registered artifact:

```bash
webv2 artifact-register <C-xxx> impact-dump.json --kind poc
webv2 impact <C-xxx> F-xxx --extractable 4000000 --artifact ART-xxx --description "4.0M extractable at fork depth"
```

### Who pays, and why the bug makes them pay (check14)

An impact figure alone does not say the program will pay: a bug the protocol
cannot lose money on is a curiosity. `exploit` records the paid-exploitability
answer the `paid-exploitability` gate check reads:

```bash
webv2 exploit <C-xxx> F-xxx --paid --arg "LP principal is at risk in the same block as the mint, ..."   # >= 200 chars
webv2 exploit <C-xxx> F-xxx --unpaid --arg "the only victim is the attacker's own test contract, ..."
```

`--paid`/`--unpaid` is exclusive and one of them is required, and `--arg` is the
argument the reviewer reads. The check only asks about findings that are
CONFIRMED/CHAIN **and** carry `extractable_usd > 0`; anything else passes as
"no extractable claim to answer".

- `--paid --arg "..."` — the argument must be at least 200 characters (who
  pays, and why this bug makes them pay). Missing or too short: the check fails,
  and a per-finding `waive ... paid-exploitability --subject F-xxx` is the
  recorded alternative.
- `--unpaid --arg "..."` — a **legitimate answer**, not a failure: it records
  why the finding is not payable ("the only victim is the attacker's own test
  contract"). The check passes and the gate prints the not-payable argument.

### The patch clause: what `immunize` records (check12)

The gate's `immunization` check asks whether a *fix* exists. `immunize` records
that claim and its basis — it never applies a patch, and it runs nothing. The
patch is your work; what the framework refuses to do is take it on trust:

```bash
webv2 immunize <C-xxx> F-xxx --poc-exec EXEC-xxx \
  --patch "clamp the exchange rate to the last valid oracle value before minting" \
  --mutations "zero-amount deposit;first-depositor rounding;donation to the vault" \
  --actor you
```

Every clause in that record exists for a reason:

- `--poc-exec` is the **proven unpatched** PoC: a `fork-runner` exec that exited
  0 and was minted on the finding as E5/E6 fork evidence. A unit-test exec is
  refused, with the command that fixes it — a patch that blocks a unit test but
  not the fork is a coincidence of the harness, not a patch.
- `--patch` (≥ 10 chars) says what the fix changes and why that blocks the
  exploit.
- **exactly three** `--mutations` (≥ 5 chars each) are the boundary variants: a
  patch tested against the one PoC path may hold that path and leave its
  neighbours open.
- `--actor` attributes the claim; `at` and the artifact id go on the record.
- `--bypass "which mutation, what it extracted"` is the honest failure path. The
  record is still written — the record IS the artifact — but
  `boundary_bypass_found=true` and the gate fails with `bypass` rather than
  pretending the attempt never happened.

Know what this buys and what it does not: the basis is the **unpatched** PoC, so
the framework pins the claim to a proven exploit and to a named actor, but it
does not re-run the patched build. Running the patched fork and reading its
failure is still your step (`exec --profile fork-runner …`).

**What the gate asks for depends on the program, not on us.**
`check12` reads `poc_requirements.patch_clause` from the bounty policy:

| value | what clears the check | the boundary mutations are |
|---|---|---|
| `verification` (default when the key is absent) | the `immunize` record above | a blocker |
| `prose` | a written recommendation on the finding (`verification.recommendation`, ≥ 40 chars: the function, the change, the snippet) | an advisory note |
| `none` | nothing — the program does not ask for a fix | an advisory note |

Most programs want a recommendation and never raise a payout for a tested patch,
so `verification` on such a program spends your time for nothing — say so in the
policy once instead of waiving it finding by finding. The boundary-mutation
record is written in **every** mode: a mutation that still extracts under the
patch means a misdiagnosed root cause, which is duplicate risk whatever the
program asked for. Only its gate authority changes. A policy naming any other
value is refused when it loads, never silently defaulted.

### When no dollar figure is defensible (unpriceable impact)

An `address[255]`-shaped target, a test constant, a capacity argument that
cannot be priced — the framework used to force a number anyway, and the number
was theater. Record the decision instead:

```bash
webv2 impact <C-xxx> F-xxx --unpriceable --ceiling 'liquidity in the pool at fork depth, not priced' \
  --reason 'the only figure available is a test constant' --actor you
```

`economic_impact.priceable=false` + `ceiling` land on the finding, one
`finding.unpriceable` event is logged, and the economic-class E7 clause is
satisfied as a **named decision** — `gate C F` prints it with the ceiling and
`audit` cross-checks the projection against the log (a hand-edited
`priceable:false` with no event fails). The report renders
`UNPRICEABLE (ceiling: …)` where the dollar figure used to go. A later priced
`impact` reverses it and restores the E7 requirement. Passing `--unpriceable`
together with `--extractable`/`--max-loss`/`--artifact` exits 2.

## 8. Chains, calibration, bounty gate

```bash
webv2 chains <C-xxx>        # capability links + chain proposals (CONFIRMED members only; a chain materializes from the weakest member's floor)
webv2 chain <C-xxx> F-aaa F-bbb [F-ccc] [--title T] [--note N]    # materialize the chain (writes a CHAIN super-finding)
webv2 chain <C-xxx> F-aaa F-bbb --unproven [--note N]             # ... at HYPOTHESIS level: a LEAD, never counted as confirmed
webv2 terminals <C-xxx>     # reachable economic terminal states (EOA baseline -> asset extraction)
webv2 privileged <C-xxx>    # per-privilege-role attacker track (baseline, exposure band, constraints + terminal paths)
webv2 adversarial-game <C-xxx> F-xxx --who-profit NAME --mechanism M --interplay I   # required of a live liveness finding
webv2 gate <C-xxx>          # submission-readiness gate against the pinned policy (unknown checks never count as pass)
webv2 gate --explain <CHECK>  # what a single gate check means
```

`chains` **proposes**; `chain` **materializes**, and it is the only command that
creates a chain super-finding (`move … CHAIN` changes a status; it does not
build a chain). Without `--unproven` every member must be CONFIRMED (or
an existing CHAIN) on one shared source pin and the result is a CHAIN.
`--unproven` is the honest form for a lead: any member status, mixed pins
allowed, each capability link stamped with its member's evidence level, and
**no** super-finding — so the result never inflates the confirmed count.

A **liveness** finding — the trigger is one shared predicate,
`IsLivenessFinding`, so no prose heuristic gets to disagree with the gate:
a `root_cause.class` in {`chain-freeze`, `sequencer-halt`, `liveness`} (a
class-typed freeze owes the clause even when no `economic_impact` object
exists), an `economic_impact.kind == "liveness"`, or a granted capability
whose terminal is liveness loss — additionally needs the adversarial game:
who profits while the protocol is degraded, how the profit is
realised, and why that interplay cannot be undone by the challenge path. All
three flags are required and each answer must be at least 20 characters; the
gate refuses a live liveness finding without it (live = the open statuses
plus CONFIRMED/CHAIN — a dead terminal disposition owes nothing) — the
discovery completion
proof blocks the divergence-era exit and the bounty gate's `adversarial-game`
check re-validates the stored clause — and it is waivable per finding (`waive
<C-xxx> adversarial-game --subject F-xxx --reason "..."`).

## 9. Report + learning

```bash
webv2 report <C-xxx>                                   # regenerate the report (a view — surfaces thin coverage instead of hiding it)
webv2 artifact-reconcile <C-xxx> [--dry]               # re-hash the artifact registry after any external rewrite
webv2 memory <C-xxx>                                   # list the campaign's learning memory
webv2 memory <C-xxx> --approve MEM-xxxx --by "your-name"   # record a HUMAN approval (the agent never approves its own memory)
webv2 memory <C-xxx> --reflect "the fork needed an explicit block number" [--round N]   # append one reflection entry
webv2 memory <C-xxx> --reject MEM-xxxx --reason "real but unreachable" [--rejection-class not-exploitable]
webv2 publish <C-xxx> --actor NAME                     # publish confirmed knowledge to the shared store (cross-campaign)
webv2 publish <C-xxx> --actor NAME --global            # -> user-global tier (~/.webv2/shared-memory, or WEBV2_GLOBAL_MEMORY_DIR)
webv2 publish <C-xxx> --actor NAME --disclosure FILE # attach a disclosure bundle (JSON): its sha256 + embargo date ride the record, its prose stays campaign-local
webv2 globalize --actor NAME                           # mark stored rows scope=global (recalled by EVERY campaign, whatever its program)
webv2 shared [--verify]                                # the shared store, both tiers: view + integrity check
```

The report is a regenerated view: Results leads with the confirmed findings
(count + per-bug-class breakdown); the bounty submission state is a sub-metric
because the gate measures submission packaging (patch immunization, policy),
not finding severity. **Results also prints an "All findings" table — every
finding, not only the confirmed ones** (id + title, status, evidence, critic
verdict, risk score+band, stored acceptance score, submission-ready, chain
membership), ordered by status (confirmed/chain → hypothesis → dismissed) and
then by live acceptance score, with the critic-disproved rows last in their
group. Read that table before concluding a campaign is thin: a `confirmed: 0`
headline with a full table under it means the findings exist and none has
cleared the gate yet. A campaign with **no policy loaded** prints
`NO POLICY LOADED` and names the fix — its report is unscored (no acceptance
ranking, no submission budget, no accepted-risks check), and `rank` says the
same thing. That notice is present precisely so a missing scope cannot look like
a clean campaign.

**Memory is written by the agent, approved by the human, and rejected with a
reason.** `--reflect` appends one trajectory-reflection entry to
`learnings.jsonl` (the learning proof requires one; before this flag no command
could write it). `--reject MEM-xxx --reason "..."` is the missing other half of
`--approve`: the reason is required and lands in the `memory.rejected` event (the
row carries only the status and, optionally, one of the schema's three
rejection classes — `invalid-hypothesis`, `not-exploitable`,
`below-threshold`). Rejecting a row that is already approved or promoted is
refused: that is a revocation, not a rejection. The **Answer quality** section flags every "answered"
priority with no evidence ref and every N/A/deprioritized closure with no
reason. A publish that adds nothing prints "nothing changed — <reason>" plus
the next command, never silence. **Approve memory only after a human reads the
candidate** — the agent never approves its own memory.

**A disclosure bundle is operator-supplied, campaign-local, and NOT enforced.**
`publish --disclosure FILE` reads a bundle (schema `disclosure`: `finding_ids`,
`summary`, `impact`, `embargo_until`, optional `affected`/`references`/
`contact`/`reporter_credit`) and refuses it, exit 1, unless every cited finding
EXISTS in the campaign, is CONFIRMED or CHAIN, is part of this publish, and is
cited once. The bundle is written to
`<campaign>/artifacts/disclosure-bundle.json` and registered there; the publish
RECORD carries only `disclosure_sha256` and `disclosure_embargo_until` — the
prose never enters the shared store, which is a cross-campaign surface. When a
bundle is attached the publish prints one extra line, e.g. `disclosure: bundle
1a2b3c4d5e6f (2 findings), embargo_until 2026-10-01 — recorded, not enforced`.
The embargo is a POLICY FIELD: the framework does not refuse, delay, or
suppress a publish while an embargo is open — an embargo is an agreement
between the researcher and the program, and the tool's only job is to make the
state legible so a recorded embargo is never mistaken for an enforced one.
A publish without `--disclosure` is byte-identical to before (no artifact, no
record fields).

### 9a. The scorecard: one read-only view of the campaign

`report` and `brief` answer what the campaign concluded; `scorecard` answers
what it actually did, and it writes nothing while answering:

```bash
webv2 scorecard <C-xxx>                                # campaign, surface, findings, process, eval
webv2 scorecard <C-xxx> --no-surface                   # skip the surface walk (a large pin on a slow filesystem)
webv2 scorecard <C-xxx> --json                         # the same sections as one object, the same numbers
```

Every row is derived from what is already on disk — campaign state, the
hash-chained event log, the exec ledgers, `findings/` and the stored
adjudications. The command never writes, logs or scores, and a section whose
data source is absent says so in words instead of printing a zero that reads
as a measurement.

The **surface** section walks the pinned tree through `srcclass` and splits it
into implementation / test-double / library / interface / other rows — the
count covers EVERYTHING the pin kept, so a config, a README or a data file is
its own `other` bucket rather than silently inflating product code. It exists
because a file count is arithmetically right and materially misleading: "153
files" silently includes foundry test doubles, vendored libraries and config,
so the composition, not the total, is what the operator reads. `--no-surface`
omits the section entirely rather than printing it empty.

The **eval** section is the gold-eval join, and it prints **both** precisions:
the raw precision, in which every unanchored live finding counts as a false
positive, and the adjudication-adjusted precision, which removes the findings
adjudicated additional-true-positive or assumption-gated from the penalty
denominator. A campaign whose program matches no suite case says so rather
than printing a zero.

**`ingest --lint` is the rehearsal:** the payload runs the EXACT ingest
pipeline — schema, then ledger checks (including `exec_ref` resolution), then
the gate math — and prints byte-identical acceptance/refusal output, but
writes nothing: no state, no events, no finding file, and no discovery-budget
charge. Exit 0 accepted, nonzero refused, like the real thing. Use it before a
multi-item payload when the EXECs are already in the ledger (`exec_ref`) or
after any schema doubt.

**`--gold FILE` grades a held-out target whose answer key cannot ship in the
binary.** The embedded suite is the dev pack, and a real held-out target
matches none of it, so its eval section would be skipped and every precision
number unreachable. `--gold` loads an operator-supplied `evaluation_case`
JSON array at grading time and uses those rows INSTEAD of the embedded suite
(replace, never merge — a synthetic dev row must not score against a real
held-out campaign). When a sha256 sidecar sits beside the pack (the store
convention `<stem>.sha256`, or `cases.sha256` in the same directory) it is
verified against the file's raw bytes; the eval section then prints the
provenance, `gold pack: <path> (sha256 <first 12 hex>)`, or, when there was
no sidecar, `gold pack: <path> (unverified - no sha256 sidecar found)`. A
missing file, a pack that is not a JSON array, a row that fails
`evaluation_case` validation (the error names its `case_id`), a duplicate
`case_id` and a drifting sidecar (the error prints both hashes) are all
refused, exit 1 — a mis-typed gold row must never quietly shrink the answer
key. The same flag and the same provenance line serve `adjudicate`, whose
tally is computed from the same suite. **The pack is an ANSWER KEY:
grading-time input, never part of a campaign run, and a campaign agent must
never be handed it** — exactly the leakage rule the held-out split enforces. A held-out row may additionally
carry `gold.match_mechanisms`: when present, class+location are NOT enough —
the finding's `root_cause.mechanism` sentence must contain the phrase's full
vocabulary (identifier-folded, stop-words exempt; `root:<class>` pins
class-level equality; a phrase needs AT LEAST TWO non-stopword content
words or it anchors nothing — a one-word phrase is a coin flip, and words
like `no`, `not`, `cannot`, `without`, `set` are deliberately NOT
stop-words because negation and domain nouns are load-bearing). This is how a grader refuses the *near-miss inflation*
mode: a same-outcome-different-mechanism finding (a chain freeze reached by a
timeout latch, when the gold freeze comes from a fake prev-state root) scores
as miss + unanchored-true-positive, never as a hit. Absent means the
historical join, so every pre-existing pack — including the embedded dev
suite — is bit-identical in behavior; an empty or non-array list fails CLOSED; malformed ENTRIES
are skipped without poisoning the valid ones (per-entry, order-free). Phrasing note: containment is exact-word after folding, so gold
phrases should name load-bearing identifiers (prevStateRoot), not inflected
verbs (commit/committed do not match). A malformed entry anchors nothing by itself (fail-closed per entry; an empty or non-array list anchors no finding at all).

The **containment** section has exactly one trigger, and the pin decides it:
the campaign directory sitting inside the target being pinned, so the
campaign's own notes, findings and logs are physically part of the tree an
agent reads as target source. `snap` warns on stderr at pin time; the section
replays the flag the pin recorded, so the warning survives a walk that never
sees the target again.

## 10. End of round

```bash
webv2 audit <C-xxx> [--json]     # full integrity audit (event-log chain, artifacts, execs, findings, projection, relations, floor policy, snapshots — including a named active pin whose directory is gone — plus, once the campaign prices anything, the price_table reconciliation of prices.json against the logged price.set decisions; a hand-edited USD figure is drift)
webv2 prove <C-xxx> [--stage S]  # completion proofs: is a stage DONE because its artifacts prove it? (exit 1 while not done)
webv2 complete <C-xxx> --actor NAME --reason R    # close the pass: phase COMPLETE; the cockpit stops suggesting work
webv2 waive <C-xxx> discovery --subject L-02 --reason "..." --actor NAME   # waive one completion-proof subject (default '*': the whole stage)
```

The `<stage>` on a waiver is validated: a typo'd stage would record a row
nothing ever consults (the proof stays red while `waive` reports success),
so it is refused at exit 2 naming the valid vocabulary — the pipeline stage
ids plus the check rails `adversarial-game`, `accepted-risk`,
`paid-exploitability`, `immunization`.

`audit` re-checks the event-log hash chain, re-hashes every registered
artifact and exec output, re-validates every finding, cross-checks the state
projection (including `floor_policy`) against the log, verifies the relation
graph, and **re-derives the probe surface** from the current index + model and
compares it row-id by row-id against `probe_surface.json` (row set both ways,
each row's `shape_sha`, and every disposition's stamp) — a hand-edited anchor
keeps its `row_id`, so only the re-derivation can see it. A **non-zero exit at
round end means something on disk no longer matches the record** — do not
carry the campaign forward until you know what changed.

**Discovery closes** only when the work queue is drained AND the divergence
gate is closed: all four canonical lenses resolved with every seeded family
attested, and ≥ 4 distinct canonical bug classes named via
`priorities[].bug_class`. `prove <C-xxx> --stage discovery` shows exactly what
is still open; a subject is waivable with a written justification.

**Maximal-exploitation completion proof** is the sibling gate: it holds only
when every CONFIRMED (and CHAIN) finding carries a variant ladder whose
disposition is `complete` or waived. Open one per finding with
`webv2 ladder <C-xxx> start <F-xxx>` (finding is positional), close it
`complete` or waive it; `prove <C-xxx> --stage maximal-exploitation` names the
findings still missing one.

**Torn log recovery (by hand, no tool).** There is deliberately no `verify`
repair verb: a repair path would have to say what a rewritten chain *claims*,
and rewriting the chain is the one thing the log exists to prevent. The
recovery is the procedure below, and it is lossy by construction — an
append-only log that was cut mid-write cannot be undone, only cut back to the
last record that fully existed.

1. **See the failure.** Two shapes, from the same torn file.

   The framing guard refuses the *next* write, and its last clause is the fix:

   ```
   error: validation: refusing to append to campaigns/<C-xxx>/events.jsonl: the
   file does not end in a newline (torn write or external edit) — its last record
   is incomplete and appending would merge two records into one unreadable line;
   restore the file from a snapshot or truncate the partial line, then re-run
   ```

   `webv2 verify <C-xxx>` is the diagnostic: it names the first unreadable line
   and exits **1**. It reports the **line number, not a byte offset**, and the
   parenthesised text is the JSON decoder's own message — `EOF` and
   `unexpected EOF` are the usual ones, `invalid character ...` means the tear
   landed inside a line:

   ```json
   {
     "events": 3,
     "ok": false,
     "problems": [
       "line 3: not valid JSON (unexpected EOF) — integrity past this point is unverifiable"
     ],
     "chained": 0,
     "legacy_unchained": 0,
     "malformed_lines": 1
   }
   ```

   `events` counts the unreadable line, so it is one MORE than the number of
   surviving events; `chained`/`legacy_unchained` are 0 whenever a malformed
   line is present (the checks past it are skipped, by design — the verdict is
   always produced, it is the integrity that is unknown). A handful of verbs
   die first with a terse `error: EOF` when they read the log before writing
   it — that is the same tear, and `verify` is what says where it is.

2. **Preserve the evidence, in its own step.** The torn copy is what the
   post-mortem is read from; it is never deleted in the step that truncates the
   log.

   ```bash
   cp campaigns/<C-xxx>/events.jsonl \
      campaigns/<C-xxx>/events.jsonl.torn-$(date -u +%Y%m%d)
   ```

3. **Cut back to the last complete record.** Every event carries its
   predecessor's hash, so a prefix cut at a record boundary is still a valid
   chain — that is why the recovery is a truncation and never an edit.

   ```bash
   python3 - campaigns/<C-xxx>/events.jsonl <<'PY'
   import sys
   p = sys.argv[1]
   d = open(p, 'rb').read()
   i = d.rfind(b'\n')
   open(p, 'wb').write(d[:i + 1] if i >= 0 else b'')
   PY
   ```

   **The cost is real and it is not silent:** every event after the cut is
   LOST. Those side effects must be redone through the CLI (re-running the
   command appends a fresh event), and the loss — the cut time, the surviving
   `seq`, and which side effects were redone — is recorded in the campaign
   notes. The chain cannot tell you what you dropped; the torn copy is the only
   record that anything existed there at all.

4. **Re-verify.**

   ```bash
   webv2 verify <C-xxx>
   ```

   If the tear was the in-flight final record — the ordinary crash-mid-append
   case, where the state projection was never updated — this now prints
   `"ok": true` and exits 0 over the surviving prefix. **If instead it reports**

   ```
   "state event tail does not match the log suffix"
   ```

   then the tear ate whole records: `campaign_state.json` is a *projection*
   that still mirrors events the log no longer has. The log is the record, so
   the projection is re-derived FROM it, never the other way round:

   ```bash
   python3 - campaigns/<C-xxx> <<'PY'
   import json, sys
   d = sys.argv[1]
   rec = [json.loads(l) for l in open(d + '/events.jsonl') if l.strip()]
   st = json.load(open(d + '/campaign_state.json'))
   st['events'] = rec[-1000:]        # the state mirror keeps the last 1000
   json.dump(st, open(d + '/campaign_state.json', 'w'),
             indent=2, ensure_ascii=True)
   PY
   webv2 doctor <C-xxx>              # re-serializes through the CLI's own writer
   webv2 verify <C-xxx>              # "ok": true, exit 0
   ```

   `doctor` is what makes the hand-edit safe: it loads the state and rewrites it
   with the tool's serializer, so no hand-rolled formatting rides along in the
   file.

5. **Keep the torn copy** beside the log (`events.jsonl.torn-<date>`) and only
   now carry on. Do not delete it in this step — it is the evidence for the lost
   events, and the only thing that can answer "what did the writer believe it
   had written?".

## Evidence levels, floors, and the gate

**The E0–E7 ladder** (the TRUST axis — monotonic, no skipping):

| level | meaning |
|-------|---------|
| E0 | raw hypothesis, no evidence |
| E1 | plausibility / static reasoning |
| E2 | static reachability (no execution) |
| E3 | (reserved) |
| E4 | isolated/container execution (a real run under a sandbox profile) |
| E5 | mainnet-fork execution (fork-runner against live state) |
| E6 | independent reproduction (a second pair of hands, or a cross-chain witness) |
| E7 | quantified economic impact (cites a registered artifact) |

Evidence at level **≥ E4 must name the sandbox profile** it was produced
under. Container profiles (`docker-networkless`, `docker-gvisor`, `vm-snapshot`)
cap at E4; `fork-runner` reaches E5.

**Evidence type groups** (the COMPLEMENTARY axis — what kind of knowledge an
item carries; a gate clause is "at least one item of a type in S at level ≥ L"):

| group | types |
|-------|-------|
| static | `reasoning`, `static-analysis` |
| reachability | `reachability` |
| invariant | `invariant-test`, `symbolic-witness` |
| local-poc | `unit-test`, `foundry-test`, `fuzz` |
| fork-poc | `fork-test`, `trace`, `balance-delta` |
| independent-repro | `differential`, `historical-analog`, `manual` |
| economic | `balance-delta`, `manual` |

**Status floors** (the minimum evidence level to REACH a status):
HYPOTHESIS E0 · NEEDS_RESEARCH E0 · PROVISIONALLY_VALID E1 · POSSIBLE E2 ·
CONFIRMED **E5** · CHAIN E4.

**`CLASS_CONFIRM_FLOOR`** (per-class CONFIRMED floor — the default the
campaign may override via `floors set`):

| floor | classes |
|-------|---------|
| E4 | `access-control`, `signature-replay`, `upgrade-initializer`, `authorization`, `reentrancy`, `logic-error`, `dos-griefing`, `token-integration`, `share-price-accounting` |
| E5 | `oracle-manipulation`, `flash-loan`, `liquidation-logic` |
| E6 | `share-price-inflation`, `economic-invariant`, `bridge-message`, `cross-chain-replay` |

Classes whose exploitability is fully determined by code semantics (no
dependence on live mainnet state) are fully provable in a local unit harness
(E4). Economic/oracle/bridge classes need fork reality (E5) or cross-chain
witnesses (E6): their impact lives in mainnet state. The **economic
confirmation classes** (`oracle-manipulation`, `flash-loan`,
`share-price-inflation`, `economic-invariant`, `liquidation-logic`) carry the
full three-stage CONFIRMED requirement: local proof the logic fires, live-state
proof it fires against real data (fork OR independent repro), and an economic
quantification.

## CLI cheat sheet

Every command is `webv2 [--root DIR] <command> [args]`. From the workspace,
omit `--root` (it defaults to `.`).

```
webv2 init --program PROG                                          create a campaign (drops RUNBOOK.md + AGENT_BOOTSTRAP.md into it)
webv2 status <C> [--verbose]                                       campaign status (JSON)
webv2 doctor <C> [--state-only] [--snapshot-only] [--json]         health check + repair (oversized stage notes; reports pin scope + sandbox preflight)
webv2 env doctor [<C>] [--json]                                    read-only environment doctor (docker, image, fork-RPC, per-profile, solc)
webv2 complete <C> --actor A --reason R                            close the pass (phase COMPLETE; cockpit stops suggesting work)
webv2 prove <C> [--stage S]                                        completion proofs (exit 1 while a stage is not done)
webv2 waive <C> <stage> [--subject S] --reason R --actor A         waive one completion-proof subject (default '*': the whole stage)

webv2 scope <C> --policy policy.json | webv2 scope --example        load the bounty policy (program identity + gate scope) / print a valid template
webv2 snap <C> <target> [--deployment F] [--chain F] [--exclude NAME] [--dry-run]   pin a source snapshot (+ deployment/chain pins; foundry.toml read automatically); --dry-run previews ladder, prune set and untracked files, recording nothing; --exclude matches EXACT base names (no globs) and a pattern that matched nothing is named on stdout
webv2 index <C> --src SRC                                          rebuild the structural index for the active pin
webv2 model <C> [file] [--json] [--facts P] [--facts-observed-at D]    load a protocol model (seeds invariants) / show the loaded one; --facts merges operator-supplied DNS/dependency facts (offline only, no lookup)
webv2 plan <C> [file] [--rebuild] [--json]                         read-only plan view; --rebuild archives + regenerates (both polarities of every lifecycle transition belong in it — §4c/§5)
webv2 answered <C> <priority|L-0X> [<priority>...] <status> [--reason R] [--reason-all R] [--ref R] [--anchor FIELD] [--families a,b,c] [--symmetry fam=prim;...] [--actor A]   # one status over ONE OR MORE rows: gates run per row all-or-nothing (first refusal names its row, zero mutations)
webv2 probes <C> run [--emit --per-axis N --total N] | list [--axis L-0n|AXIS] [--all] [--json] | blank --axis L-0n|AXIS --anchor-blind K --reason R --actor A
webv2 ingest <C> --json-file F (or -) [--trajectory T] [--stage S] [--answers-priority Q-xxx]   |  webv2 ingest --example
webv2 prompts {list,show} [name]                                   print the embedded stage prompts (no framework checkout needed; show accepts full name, stem, or stage number)

webv2 run <C> [--until STAGE] [--max-stages N]                     walk the pipeline; halt at the first model stage (exit 3)
webv2 log <C> [--tail N]                                           tail the event log
webv2 verify <C> [--queue] [--exec E --finding F --verifier V --description D]   # log integrity / E6 queue / record an independent verification
webv2 verify <C> --scaffold halmos|forge-fuzz|minicertora --invariant INV-xxx   # write the harness scaffold artifact (the model fills the BODY region only; outside it is scaffold)
webv2 verify <C> --harness-result INV-xxx --exec EXEC-xxx [--kind halmos|forge-fuzz|minicertora]   # map a harness run to its rung: counterexample / PROVEN-BOUNDED / inconclusive (bounded — never an unbounded proof)
webv2 verify <C> --post-patch F-xxx --exec EXEC-xxx [--snapshot SNAP-xxx]   # regress a finding against a post-patch run: still_reproducible / fixed / indeterminate (fail-open; status never moves; --finding/--verifier/--description are ignored)
webv2 audit <C> [--json]                                           full integrity audit
webv2 brief <C> [--json] [--deep]                                  operator cockpit (where it is + decisions waiting; pure view)
webv2 scorecard <C> [--json] [--no-surface]                        one read-only view: surface, findings, process, eval

webv2 move <C> <finding> TO_STATUS --reason R [--actor A] [--adjacent SIBLING] [--adjacent-clear] [--of FINDING]   # the ONLY status-transition path; --of REQUIRED for DUPLICATE (target exists, != self)
webv2 amend <C> <finding> [--title T] [--class C] [--claim K] [--note N] [--actor A]   # correct a filed finding (bumps claim_version; status never moves)
webv2 supersede <C> <new> --of <old> [--actor A]   # old -> SUPERSEDED; evidence COPIED into new (re_parented_from), old array untouched
webv2 mint <C> <finding> --exec E --description D [--tier T1|T2|T3|T4] [--type TYPE] [--verify-reruns]   # record+mint evidence (idempotent per exec); --verify-reruns re-runs the PoC 3x (flaky advisories ride the evidence, fail-open)
webv2 verdict <C> <finding> --verdict V --reason R [--outlook O --outlook-reason R]   hostile-critic verdict
webv2 recall <C> --finding F [--mode negative|comparative] [--note N]   # recorded graph-memory consult
webv2 gate <C> [F-xxx] | webv2 gate --explain <CHECK>              bounty gate / per-finding CONFIRMED dry-run
webv2 adjudicate <C> [<finding>] [--json] [--verdict V] [--severity S] [--basis B] [--assumption TEXT] [--exec EXEC] [--actor A] [--reason R]   non-gold verdict (moves the adjusted precision)
webv2 impact <C> <finding> --extractable USD [--max-loss USD] [--artifact ART] | --unpriceable --ceiling C --reason R --actor A
webv2 sequence run <C> SPEC.json --finding F [--workdir W]         # T4 multi-tx PoC under fork-runner
webv2 sequence verify <C> F-xxx [--exec E]                         # do the attempts have verified coverage?

webv2 dedup <C>                                                    deterministic three-tier dedup sweep
webv2 dedup-signature <C> F-xxx (--root-cause SENTENCE [--cwe C] | --economic SENTENCE)   record a tier-2/3 signature (the sentence is hashed; never hand-write the hex)
webv2 resolve-candidate <C> F-xxx F-yyy --verdict same|distinct [--note N] [--actor A]
webv2 prioritize <C>                                               deterministic triage view
webv2 repro-queue <C>                                              candidates ordered for repro
webv2 ack <C> [F-xxx]                                              in-code acknowledgement scan (stub/TODO/known-issue) -> acceptance demotion
webv2 rank <C>                                                     acceptance-ranked table (which findings matter)

webv2 chains <C>                                                   capability links + chain proposals
webv2 chain <C> <F> <F> [<F>...] [--unproven] [--title T] [--note N]   materialize a chain (--unproven = a lead, no super-finding)
webv2 terminals <C>                                                reachable economic terminal states
webv2 privileged <C>                                               bounded privileged-role attacker track
webv2 adversarial-game <C> F-xxx --who-profit W --mechanism M --interplay I   adversarial-game answers (required of a live liveness finding)
webv2 exploit <C> F-xxx (--paid | --unpaid) [--arg A]              who pays, and why the bug makes them pay (check14)
webv2 enforce <C> NAME [--contract 0x..] [--json]                  write/read stage table for one variable or concept key (L-03)
webv2 symmetry <C> [--family 0x..] [--json]                        family custody-primitive matrix + divergences (L-04)
webv2 cost <C> --kind K --amount USD [--trajectory T] [--actor A]  record an operator-reported cost row
webv2 yields <C>                                                   cost-adjusted discovery yield (advisory)
webv2 relations <C> [--rebuild]                                    research memory graph (typed edges)
webv2 resemble <C> <finding>                                       capability-coverage delta (derived)

webv2 floors <C> [--json] [set|unset CLASS FLOOR --actor A --reason R]   # effective evidence floors + operator overrides
webv2 budget <C> [--set USD] [--clear] [--set-discovery N] [--actor A] [--json]
webv2 price <C> {set,table} [asset] [usd] [--source S] [--as-of TS] [--actor A]   # the asset-price table (every USD figure names its row)
webv2 price-basis <C> <finding> PRICE-xxx                          pin a finding's USD figures to a price-table row
webv2 execs <C> [--id E] [--json]                                  the exec ledger (every sandboxed command + verdict)
webv2 classify <C> EXEC-xxx                                        classify a FAILED exec (environment/setup/logic/unknown)

webv2 exec <C> --profile P --command CMD [--workdir W] [--finding F] [--timeout T] [--env K=V] [--dry-run]   # sandboxed run -> EXEC record
webv2 artifact-register <C> PATH [--kind poc|detector|trace|...] [--note N]
webv2 artifact-list <C> [--kind K]                                 list registered artifacts
webv2 artifact-reconcile <C> [--dry]                               re-hash the registry after an external rewrite
webv2 invariant-verify <C> INV-xxx (--artifact ART | --exec E)     CHECKED_AGAINST_CODE (pass exactly one)
webv2 invariant-contradict <C> INV-xxx --evidence FILE#L|ART-xxx   mark an invariant CONTRADICTED (falsified by code)
webv2 hint <C> --kind priority|exclusion|detector|note --content C [--source-ref ID] [--actor A]

webv2 corpus-surface <C> [--backtest [--top N]]                     deterministic corpus sweep (advisory; registered artifact); --backtest replays acceptance priors A/B over the adjudicated store — verdict improves ONLY if the Wilson lower bound strictly rises (--top requires --backtest)
webv2 sinks <C> --src SRC [--json]                                 value-flow backward slice from asset sinks
webv2 prescreen <C> --src SRC [--force ARCH] [--json]              archetype pre-screen over the index
webv2 forkdiff <C> --src SRC [--json]                              match the target against baseline reference trees
webv2 recency <C> --target GIT-REPO --src SRC [--json]             recency-weighted file prioritization
webv2 baseline {add NAME --path P [--source-url U] [--license L] | list | remove NAME}

webv2 publish <C> --actor A [--global] [--disclosure FILE]         publish confirmed knowledge to the shared store (--disclosure: hash+embargo on the record, prose stays local)
webv2 globalize --actor A [--program KEY]                          mark stored rows scope=global
webv2 shared [--verify]                                            the shared store, both tiers: view + integrity check
webv2 memory <C> [--approve MEM-xxx --by NAME | --reflect TEXT [--round N] | --reject MEM-xxx --reason R [--rejection-class C]]   list memory / approve / reflect / reject
webv2 report <C> [--format md|immunefi]                            regenerate the report (a view); --format immunefi writes one intake-shaped file per submission-ready finding (checklist-first, never a blocker)

webv2 ladder <C> {start,show,explore,add,repro,disprove,set-maximal,complete,waive,reopen,report} <F> [RUNG] [AXIS] [--name N] [--description D] [--axes A] [--capital C] [--ratio R] [--removes R] [--note NOTE] [--reason REASON] [--exec EXEC] [--actor ACTOR]
webv2 immunize <C> F-xxx --poc-exec EXEC --patch P --mutations "M1 desc;M2 desc;M3 desc" [--bypass M] [--actor A]
webv2 precondition <C> F-xxx "DESCRIPTION" --enforced|--not-enforced
webv2 shield <C> F-xxx [--extraction] --reason R [--actor A]       plausibility-shield adjudication

webv2 sft {lint|add|list|split|report|backfill|export} ...         SFT critical-bug reasoning dataset tooling
webv2 selftest [--full]                                            one-command self-check (fast / + go test ./...)
webv2 help                                                         this usage
```

`ladder` note: `explore <F> <AXIS> --note "..."` (natural form — the trailing
positional binds to the axis; a note ≥ 10 chars). `add` takes `--name
--description --axes --capital --ratio --removes`; `repro` takes `--exec
EXEC-xxx`; `disprove`/`waive` take `--reason`; `complete`/`waive` take
`--actor`. `immunize` takes **exactly three** boundary mutations, each
described in ≥ 5 chars.

`minicertora` note: a `--scaffold minicertora` invariant whose statement reads
`template:<name> of <Contract>.<Function>` seeds the BODY window from the archetype library — the seven
shipped names are `wrap-unchecked`, `rounding-drain`, `access-control-mint`, `tx-origin-auth`,
`privilege-escalation`, `unchecked-callback`, `value-transfer-accounting` — starting content the model may
rewrite inside the window only; an unknown name is refused.
Two further names the architecture's §L5 list carries are deliberately NOT templates, for different
reasons: `donation-accounting` has no corpus ground-truth spec to adapt a body from (nothing to be
faithful to), and `cap-respected` is not a rule body at all — it rides the `invariant:` statement form
below, which is the induction scaffold.
Only exact lowercase-hyphen template names inside that pattern are honored: a
near-miss (uppercase, underscore, extra text) silently falls through to the
plain skeleton — check the artifact if you meant a template.
A statement reading `invariant:<slug> of <Contract>.<State> <op> <expr>` (`op` ∈ `>= <= == > <`) renders an induction scaffold:
`invariant <rule-name>()` plus the reviewed `assert <State> <op> <expr>;` pinned OUTSIDE the BODY window (extra asserts only inside).
A mapped `counterexample` also writes the runnable bridged PoC `artifacts/harness/<INV>/poc-<INV>.json` — the
`sequence_poc` a real `webv2 sequence run <C> <path> --finding F` consumes. A re-verify overwrites that one path,
byte-identically when nothing changed; nothing is written when the witness cannot be replayed, and stderr names
why (`verify: poc for 'INV' not written: <reason>`). To ground its `final_storage` readings, drop the operator
sidecar `artifacts/harness/<INV>/layout.json` beside it — a JSON object of `"<Contract>.<var>": "<decimal slot>"`
plus optional `"<Contract>": "0x…"` address companions. Stderr speaks only for SHAPE: a malformed sidecar is
ignored with a note and the PoC is written layoutless, while a WELL-SHAPED sidecar that grounds nothing (unknown
contract, non-decimal slot, symbolic reading) is silently a layoutless PoC — the grounding law is the bridge's, so
check the artifact if you meant to ground a reading.

## Environment variables

| var | meaning |
|-----|---------|
| `WEBV2_DOCKER_IMAGE` | the container image for the docker profiles (default `ghcr.io/foundry-rs/foundry:latest`) |
| `WEBV2_SOLC_DIR` | a host dir with the svm solc layout, bind-mounted to the container's `~/.svm` (for network-cut profiles) |
| `FORK_RPC_URL` / `WEBV2_FORK_RPC_URL` | the anvil fork RPC for `fork-runner` (E5/E6) |
| `WEBV2_GLOBAL_MEMORY_DIR` | the user-global shared-memory tier (default `~/.webv2/shared-memory`) |

## Hard rules for the operator

- **Never bypass `move`** — there is no legitimate path around the state
  machine and the CONFIRMED gate bundle.
- **Never hand-edit the record** — no event log, finding JSON, or registered
  artifact. Every side effect goes through the public CLI. Sanctioned mutation
  of a registered artifact goes through the refresh path (`artifact-register`
  re-registers). A path holds **one** registry row: re-registering it under a
  different `--kind` migrates that row (the refresh event records
  `kind_migrated: old→new`) and prunes any ghost rows at the same path. If
  something outside the CLI rewrote a registered file, the audit stays red until
  `artifact-reconcile` re-hashes the registry — run it with `--dry` first.
- **E4+ evidence MUST trace to a real EXEC record** in the campaign's exec
  ledger that exited 0, belongs to the finding, and names its sandbox profile.
  **E7 MUST cite a registered artifact.**
- **Never approve your own memory** without reading it; approvals are
  attributed and human-gated.
- **The sandbox policy refusal is final** — fix the intent, not the command
  string.
- **`unknown ≠ secure`**: unswept surfaces go back on the queue, not in the
  report as clean.
- **Plan both polarities of a lifecycle transition.** "A bad root can
  finalize" and "a good root can never finalize" are different bugs; the plan
  owes one priority each, and the restrictive question must name what gets
  stuck (§5).
- **A value you did not read from the deployment is an assumption.** Caps,
  slot maps, quorum thresholds and post-deploy role grants live in the
  instance, not the source — read them or record a coverage gap (§4c).
- **One root cause per report to the program**; variants of the same bug are
  dedup work, not extra submissions.
- **One writer per campaign.** Never run `webv2` against the same campaign
  root concurrently — the event log is a single-writer append-only chain; two
  writers fork it and `verify`/`audit` will (correctly) report a broken chain.
- **If this runbook and the code disagree, the code wins** — file it and fix
  the runbook. A wrong operator document is a live bug.
- External claims (tool metrics, benchmark numbers) enter assets, playbooks,
  and prompts only per `docs/eval-methodology.md`; a baked-in number without a
  provenance row renders as uncorroborated.


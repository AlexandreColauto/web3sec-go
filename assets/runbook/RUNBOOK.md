# webv2 operator runbook (Go)

One operator, one campaign at a time. This is the **Go binary** runbook: a
single static `webv2` executable with all assets embedded (`go:embed`) — no
interpreter, no venv, no module tree. Commands assume you run them from the
**workspace** (the directory that holds `campaigns/`): `--root` defaults to `.`
(your cwd), so it is omitted throughout; pass `--root WORKSPACE` only when
pinning a different workspace. Every command shown is the real signature —
**if this document and the code disagree, the code wins and this file is a bug**
(report it, don't work around it).

The Python twin (`web3sec-final`) is **deprecated and not maintained**. This
runbook is the source of truth for the Go binary. Where the two twins still
differ, `KNOWN_DIVERGENCES.md` in the repo is the ledger.

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
```

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
(`IMorphERC20Upgradeable(_token).burn(...)`, `a.b().method(`). `probes run`
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

**A stale surface keeps the lens open.** The gate compares `surface.index_sha`
with the current index's content hash. A **mismatch** names the re-emit
(`probes C-xxx run --emit`); **no current index at all** names
`index C-xxx --src <target>` (rebuild first, then re-emit).

## 4b. The two mechanical tables (read before you attest a lens)

Two `--json`-able views read the same structural index the probes read. They
decide nothing; they are how the operator checks a lens attestation against the
code instead of against memory.

```bash
webv2 enforce <C-xxx> "prevStateRoot" [--contract 0xabc...]   # L-03: where a variable is written, where it is read
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

## 5. Plan, dispatch, ingest

```bash
webv2 plan <C-xxx>                          # READ-ONLY view of the existing plan (no file = no write)
webv2 plan <C-xxx> --rebuild                # archive the outgoing plan to superseded/campaign_plan.NNNN.json, regenerate
webv2 answered <C-xxx> Q-xxx answered --reason "..." --ref EXEC-xxx   # close a plan priority
webv2 answered <C-xxx> Q-xxx not-applicable --reason "considered, doesn't apply"
webv2 ingest <C-xxx> --json-file payload.json [--trajectory T] [--stage S] [--answers-priority Q-xxx]
webv2 ingest --example                       # the validated payload template (PURE JSON on stdout; legend on stderr)
```

`webv2 ingest --example` **is** the contract: the template is schema-validated
and the closed-enum legend is walked from `schema/finding.schema.json` (never
hand-maintained). Pipe it: `webv2 ingest --example 2>/dev/null > payload.json`,
fill it in, then `webv2 ingest <C-xxx> --json-file payload.json`. A payload
that fails validation reports **every** error, not just the first. Ingest
validates schema, fingerprints dedup, and intake-checks: an unknown bug class
returns a taxonomy advisory (closest known classes, conservative E5 floor); a
missing `economic_impact` on an economic trajectory is warned. **Never
hand-write a finding file** — ingest is the only path in.

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
  --symmetry "deposit=burn;withdraw=mint;drop=safeTransfer" --reason "..." --actor NAME
```

Quote them from `webv2 symmetry <C-xxx>` (§4b) — the matrix prints every
member's primitive per (direction, asset) and flags the disagreements, so the
attestation is checkable against the index. A blank primitive does not count
(exit 2 names the missing families; the gate keeps the lens OPEN until every
seeded family has a quoted primitive). A CONFIRMED high/critical finding
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
`budget <C-xxx>` also reports the discovery position (findings recorded vs the
deterministic discovery ceiling); hitting that ceiling halts ingest with an
error naming the command that raises it.

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
webv2 gate <C-xxx> F-xxx                              # read-only per-finding CONFIRMED dry-run (exit 1 while checks fail)
```

`dedup` is deterministic: tier-1 near-identical candidates merge, tier-2 form
clusters, tier-3 near-duplicates are **flagged** for a human/operator verdict
via `resolve-candidate`. Then the hostile critic reviews POSSIBLE-bound
candidates (`verdict`) and a negative/comparative graph-memory consult is
recorded (`recall --mode negative` — the CONFIRMED gate requires it).

**Tier-2/3 signatures are never hand-written hex.** `dedup-signature` takes the
target-agnostic sentence ("attacker-controlled exchange rate creates unbacked
withdrawal value", not a file or function name) and hashes it; exactly one of
`--root-cause` / `--economic` applies, and a tier-2 signature may carry `--cwe`.
Two findings whose sentences hash the same are the same root cause reached
through different syntax, which is the point — but a matching signature does not
merge anything. Pairs the sweep cannot auto-merge (different code sites, same
signature) are **flagged on both sides**, so `resolve-candidate --verdict
same|distinct` adjudicates them; the same-spot auto-merge path is untouched.

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
DISPROVED / DUPLICATE / OUT_OF_SCOPE / INFORMATIONAL  -> (terminal)
```

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

A **liveness** finding (the freeze is the bug) additionally needs the
adversarial game: who profits while the protocol is degraded, how the profit is
realised, and why that interplay cannot be undone by the challenge path. All
three flags are required and each answer must be at least 20 characters; the
`adversarial-game` check fails on a live liveness finding without it, and is
waivable per finding (`waive <C-xxx> adversarial-game --subject F-xxx --reason
"..."`).

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

## 10. End of round

```bash
webv2 audit <C-xxx> [--json]     # full integrity audit (event-log chain, artifacts, execs, findings, projection, relations)
webv2 prove <C-xxx> [--stage S]  # completion proofs: is a stage DONE because its artifacts prove it? (exit 1 while not done)
webv2 complete <C-xxx> --actor NAME --reason R    # close the pass: phase COMPLETE; the cockpit stops suggesting work
webv2 waive <C-xxx> discovery --subject L-02 --reason "..." --actor NAME   # waive one completion-proof subject (default '*': the whole stage)
```

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

webv2 scope <C> --policy policy.json                               load the bounty policy (program identity + gate scope)
webv2 snap <C> <target> [--deployment F] [--chain F] [--exclude GLOB]   pin a source snapshot (+ deployment/chain pins; foundry.toml read automatically)
webv2 index <C> --src SRC                                          rebuild the structural index for the active pin
webv2 model <C> [file] [--json]                                    load a protocol model (seeds invariants) / show the loaded one
webv2 plan <C> [file] [--rebuild] [--json]                         read-only plan view; --rebuild archives + regenerates
webv2 answered <C> <priority|L-0X> <status> [--reason R] [--ref R] [--anchor FIELD] [--families a,b,c] [--symmetry fam=prim;...] [--actor A]
webv2 probes <C> run [--emit --per-axis N --total N] | list [--axis L-0n|AXIS] [--all] [--json] | blank --axis L-0n|AXIS --anchor-blind K --reason R --actor A
webv2 ingest <C> --json-file F (or -) [--trajectory T] [--stage S] [--answers-priority Q-xxx]   |  webv2 ingest --example

webv2 run <C> [--until STAGE] [--max-stages N]                     walk the pipeline; halt at the first model stage (exit 3)
webv2 log <C> [--tail N]                                           tail the event log
webv2 verify <C> [--queue] [--exec E --finding F --verifier V --description D]   # log integrity / E6 queue / record an independent verification
webv2 audit <C> [--json]                                           full integrity audit
webv2 brief <C> [--json] [--deep]                                  operator cockpit (where it is + decisions waiting; pure view)

webv2 move <C> <finding> TO_STATUS --reason R [--actor A] [--adjacent SIBLING] [--adjacent-clear]   # the ONLY status-transition path
webv2 mint <C> <finding> --exec E --description D [--tier T1|T2|T3|T4] [--type TYPE]   # record+mint evidence (idempotent per exec)
webv2 verdict <C> <finding> --verdict V --reason R                 hostile-critic verdict
webv2 recall <C> --finding F [--mode negative|comparative] [--note N]   # recorded graph-memory consult
webv2 gate <C> [F-xxx] | webv2 gate --explain <CHECK>              bounty gate / per-finding CONFIRMED dry-run
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

webv2 corpus-surface <C>                                           deterministic corpus sweep (advisory; registered artifact)
webv2 sinks <C> --src SRC [--json]                                 value-flow backward slice from asset sinks
webv2 prescreen <C> --src SRC [--force ARCH] [--json]              archetype pre-screen over the index
webv2 forkdiff <C> --src SRC [--json]                              match the target against baseline reference trees
webv2 recency <C> --target GIT-REPO --src SRC [--json]             recency-weighted file prioritization
webv2 baseline {add NAME --path P [--source-url U] [--license L] | list | remove NAME}

webv2 publish <C> --actor A [--global]                             publish confirmed knowledge to the shared store
webv2 globalize --actor A [--program KEY]                          mark stored rows scope=global
webv2 shared [--verify]                                            the shared store, both tiers: view + integrity check
webv2 memory <C> [--approve MEM-xxx --by NAME | --reflect TEXT [--round N] | --reject MEM-xxx --reason R [--rejection-class C]]   list memory / approve / reflect / reject
webv2 report <C>                                                   regenerate the report (a view)

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
- **One root cause per report to the program**; variants of the same bug are
  dedup work, not extra submissions.
- **One writer per campaign.** Never run `webv2` against the same campaign
  root concurrently — the event log is a single-writer append-only chain; two
  writers fork it and `verify`/`audit` will (correctly) report a broken chain.
- **If this runbook and the code disagree, the code wins** — file it and fix
  the runbook. A wrong operator document is a live bug.


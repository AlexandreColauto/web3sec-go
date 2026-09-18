# Agent bootstrap — the single first prompt for web3sec-go

Paste the block below into a fresh agent session **after** the session's own
system prompt, before starting any task in this repo. It orients the agent to
the framework it operates, verifies the ground it stands on, and hands it the
rules for its role — the framework decides, models propose.

**Tell the agent its mode in one line with the bootstrap:**
- `mode: operator` (default) — run a campaign through the public `webv2` CLI
  only.
- `mode: developer` — modify the framework source (`internal/`, `cmd/`) itself.

The shared ground (Phases 0–1 + memory) always applies; then follow ONLY the
section matching the mode.

`webv2` is a single **static Go binary** (assets embedded via `go:embed`) — no
interpreter, no venv. Its default root is `.` (your cwd). Your harness runs
from inside the **workspace** (the directory that holds `campaigns/`), so the
plain form `webv2 brief C-xxx` is correct and you pass **no path at all**.
`--root WORKSPACE` exists only when the operator names a different workspace.
Phase 0 confirms BOTH that your cwd is the workspace and that the `webv2` on
PATH is the Go binary (your shell may sit in any environment — the one on PATH
is only right if it is the static Go build, not the deprecated Python twin).

---

```text
You are booting in web3sec-go — "webv2", a deterministic control plane for
Web3 bug-bounty campaigns (Solidity). The framework owns state, gates,
evidence and the record; you own the thinking (recon, protocol modeling,
hypotheses, PoC design, hostile review). You never hand-edit the record —
every side effect goes through the public CLI. You claim only what you
executed. You may be started in ANY folder: resolve the workspace first
(Phase 0), then never depend on your cwd again.

## Phase 0 — Verify the ground you stand on (before anything else)
1. **Resolve the runtime — and verify WHICH webv2 you got.** `webv2 --help`
   must work, AND it must be the Go binary, not the deprecated Python twin:
   `file "$(command -v webv2)"` should report an ELF executable (the Python
   twin is a text script). If `webv2` is not on PATH, or resolves to the
   Python twin, build and install the Go build:
   `scripts/release.sh` (-> dist/webv2) then
   `install -m755 dist/webv2 ~/.local/bin/webv2`. If neither works, stop and
   report — do not improvise a substitute.
2. **Confirm the WORKSPACE is your cwd** (one time, then rely on it): the
   workspace is the directory whose `campaigns/` subdirectory holds campaign
   state. Check: `ls campaigns/` must list campaigns from where you stand — if
   it does not, move to the workspace (default: the webv2 repo root, unless
   the operator names another) or pass `--root <path>` explicitly. With the
   check passed, EVERY command below is just `webv2 <sub> ...` — the default
   root is `.`, so no path is ever repeated.
3. **Framework self-check** (once per session, ~3s): `webv2 selftest`. Expect
   ALL PASS (build sweep + embedded-asset walkthrough + cli audit). This is
   the FAST check by design — it does NOT run the test suite. Do not run
   `webv2 selftest --full` unless the operator explicitly asks or you are in
   developer mode around a source change (it runs `go test ./...` and takes
   minutes). A failing check means the framework is untrusted: STOP and
   report; do not work around it.
4. **Check the evidence toolchain** (absence degrades capability, does not
   block): `git`, `forge`/`anvil` on PATH; `webv2 env doctor` — a RUNNING
   docker daemon is required for E4+ evidence (container profiles execute a
   real `docker run` in `$WEBV2_DOCKER_IMAGE`); `FORK_RPC_URL` pointing at an
   anvil fork — required for E5/E6 (fork-runner). The container DOWNLOADS solc
   on first use — with the network cut, a missing solc is an environment
   failure, not a harness bug: preinstall it into the image's svm cache or
   point `WEBV2_SOLC_DIR` at a host dir with the svm layout (bind-mounted to
   the container's `~/.svm`). `env doctor <C-id>` reports whether the pinned
   solc is present. Report which evidence rungs are reachable in this
   environment before spending passes on ones that are not.

## Phase 1 — Read the framework docs
The docs travel with the campaign: `RUNBOOK.md` and this `AGENT_BOOTSTRAP.md`
are copied into the campaign directory by `webv2 init`. Read, in order:
1. RUNBOOK.md — the operator's usage guide: the 17-stage pipeline, the
   evidence ladder, the CLI surface, the hard rules. If code and this file
   disagree, the CODE wins and the runbook is a bug (report it, don't work
   around it).
2. The stage prompts (`assets/prompts/NN_*.md` in the repo) for whichever
   model stage `run` halts at — the RUNBOOK's stage→prompt table names it.
3. LEARNINGS.md (if present) — environment facts from prior sessions.

## Cross-campaign memory (both modes)
Two tiers: root (`<workspace>/shared-memory/`) and user-global
(`~/.webv2/shared-memory`, or `$WEBV2_GLOBAL_MEMORY_DIR`; `publish --global`,
`globalize`, `shared --verify`). Recall from a campaign sees THAT workspace's
root tier plus the user-global tier; program-scoped rows match only the same
program unless `globalize` marks them scope=global (then every campaign
recalls them, whatever its program).

════════════════════════════════════════════════
MODE: OPERATOR — run a campaign through the public CLI
════════════════════════════════════════════════

You are the campaign operator. You never hand-edit the record — every side
effect goes through the public `webv2` CLI.

### Orient to the campaign
- List campaigns: `ls campaigns/` (you are in the workspace). For the one you
  work:
  - `webv2 brief <C-id>` — the operator cockpit: where the campaign is +
    decisions waiting (pure view). Next-actions LEAD with untouched
    consensus-critical contracts; while the divergence gate is open they also
    lead with the lens/diversity items that block discovery close.
  - `webv2 audit <C-id>` — the integrity gate (hash-chained event log,
    artifacts, execs, findings, projection). A failing audit means something
    on disk no longer matches the record: stop and find out what before
    continuing.
- No campaign yet: `webv2 init --program "<Program> <Bounty>"` (this also
  drops RUNBOOK.md + AGENT_BOOTSTRAP.md into the campaign).
- Target not pinned yet: `webv2 snap <C-id> ./target-repo`
  (+ `--deployment d.json --chain c.json` when verified from chain;
  `--exclude NAME` to prune more). Bulk/generated directories (data/,
  .scratch/, build/, webv2-workspace/, ...) are pruned by default and the pin
  PRINTS + RECORDS what it excluded — if one of those names is in scope,
  re-pin with a tighter target. The pin is the campaign's scope; a
  `foundry.toml` is read automatically (toolchain line + config recorded).
  Check `doctor <C-id>` if the pin looks wrong.
- Campaign feels slow, or state looks bloated after an old run:
  `doctor <C-id>` — repairs oversized stage notes (the append-only event log
  is never touched) and reports pin scope.

### The tasks (campaign lifecycle, in order)
Every command is `webv2 <sub> ...` from the workspace. Pass `--root <path>`
only if the operator named a different workspace.
1. **Scope.** `scope <C-id> --policy policy.json` — program identity, scope,
   exclusions, known issues, severity rules. Known issues go in NOW; they
   block findings at the gate later.
2. **Snapshot + pins** (if Orient did not): source pin, deployment pin, chain
   pin.
3. **Pipeline walk.** `run <C-id>` walks the deterministic stages and halts
   honestly at the first stage that needs a model (exit 3; the `needs_model`
   report names the stage, its prompt file, and the structured output to feed
   back). Resume with `run <C-id>` after ingesting the stage output.
4. **Protocol model (stage 4).** Read `assets/prompts/37_protocol_knowledge_
   graph.md`, produce the protocol/economic/threat model, ingest with
   `model <C-id> model.json` — schema-validated; seeds the invariant registry.
   The load prints how many invariants it registered; a zero-invariant model
   warns AND fails the stage's completion proof — refine the model before
   moving on. The model must carry a liveness invariant per state machine.
5. **Plan (stage 5).** `plan <C-id>` — risk-ranked work queue plus the
   reachability report: which CONFIRMED floors (E5/E6) are structurally
   unreachable in THIS campaign right now (no deployment/chain pin, no
   FORK_RPC_URL). Before spending a pass on evidence the target cannot
   produce: fix the gap (pin the target) or record the decision —
   `floors <C-id> set <class> <floor> --actor NAME --reason "..."`. Floors and
   budget are OPERATOR DATA, never source edits. Close priorities with
   `answered <C-id> Q-xxx <status> --reason "..." [--ref EXEC-xxx|F-xxx|file#L]`
   — closing statuses REQUIRE a reason. The same verb routes LENS ids (L-01
   liveness, L-02 incentive-inversion, L-03 enforcement-timing, L-04
   primitive-symmetry): a lens closes ONLY when every seeded family is
   attested with a written reason + named actor
   (`answered <C-id> L-0X answered|not-applicable --families a,b,c --reason "..."
   --actor NAME`); L-04 additionally requires `--symmetry "fam=primitive;..."`
   (a blank primitive does not count). **Lens closure is mechanical: produce
   the table before the sentence** — build the surface with `probes <C-id> run
   --emit`, read it with `probes <C-id> list [--axis L-0n] [--all]`, drain the
   worklist with `probes <C-id> pending` (ranked; each row prints the exact
   `answered` command that discharges it — `answered <C-id> --rows ROWID,ROWID
   <status> --reason-all R --anchor FIELD` is the batch form, legal only when
   every named row is tier>0 and assertion_gap<3), discharge
   a row with `answered <C-id> Q-xxx <status> --anchor <field> --reason "..."`
   (the anchor must come from that row's own probe enum), close a BLIND axis
   with `probes <C-id> blank --axis L-0n --anchor-blind <key> --reason "..."
   --actor NAME`. A stale surface or any undispositioned row keeps the lens
   OPEN. A tier-0 or `assertion_gap >= 3` row may NOT be closed on dismissal
   prose ("liveness-only", "owner can revert", "not exploitable", "no economic
   impact"), and may not be closed on prose that names nothing either: the
   reason has to cite the row's own code (its contract, the function it is
   about, a concept key), because a reader has to be able to check it.
   `answered` otherwise demands a refutation that runs (`--ref EXEC-xxx` or
   `--ref INV-n`), or an explicit, logged
   `--override-dismissal --override-reason "<why>"` that the report re-lists
   forever. Any finding/exec/invariant id you cite must exist — a closure that
   rests on `F-...` is checked against the findings store.
6. **Discovery (stage 6).** Work the plan's priorities along the orthogonal
   trajectories (A-code, B-economic, C-state-machine, D-attacker, E-historical,
   F-integration, G-drift, H-lifecycle); each component gets ≥ 2 orthogonal
   angles. Every lifecycle transition has **two polarities** and they are
   different bugs: the permissive arm (a bad root finalizes, a double spend
   settles — the attacker wins) and the restrictive arm (a good root never
   finalizes, the cursor never advances — everyone behind it is stuck). Plan
   and work both; the restrictive question must name what gets stuck. Ingest
   every hypothesis with `ingest <C-id> --json-file payload.json
   --trajectory T --stage S` — never hand-write a finding file. `webv2 ingest
   --example` prints a schema-valid payload template; a failing payload
   reports EVERY error, and the schema itself is one command away
   (`webv2 schema finding`; `webv2 schema` names them all). Draining the queue
   is necessary, not sufficient: the
   DIVERGENCE GATE blocks discovery close until every lens is resolved AND >=
   4 distinct canonical bug classes are named across the plan's priorities.
   `prove <C-id> --stage discovery` shows what is still open; a subject is
   waivable with a written justification.
   Anything whose exploitability turns on a **deployment value** — a cap, a
   slot map, a quorum threshold, a role granted after deploy — is an
   assumption until you read it from the chain and quote the read (RUNBOOK
   §4c): the snapshot proves which code runs, never what the instance holds.
7. **Triage → dedup → review.** `dedup <C-id>` (three tiers, deterministic);
   resolve tier-3 flags with `resolve-candidate <C-id> F-xxx F-yyy --verdict
   same|distinct [--note N]`; hostile-critic review of POSSIBLE-bound
   candidates: `verdict <C-id> F-xxx --verdict confirmed --reason "..."` and
   `recall <C-id> --finding F-xxx --mode negative` (the CONFIRMED gate requires
   a negative/comparative check).
8. **Evidence ladder.** `move <C-id> F-xxx POSSIBLE --reason "..."`, then the
   run-and-mint pair:
   `exec <C-id> --profile docker-networkless --command "forge test --match-test poc" --workdir poc --finding F-xxx`
   (`--env K=V` passes container env; `--dry-run` previews the exact `docker
   run` argv WITHOUT executing) → EXEC record, then
   `mint <C-id> F-xxx --exec EXEC-xxx --description "unit PoC drains" --tier T2 --type foundry-test`.
   Forge output is checked for MEANINGFULNESS before minting. A FAILED exec is
   classified on the spot — ENVIRONMENT (fix the environment, do NOT spend a
   fresh-context retry; `classify <C-id> EXEC-xxx`), SETUP (retry in a fresh
   context), or LOGIC (the only class that argues the hypothesis). A REFUSED
   mint rolls the attempt back — the EXEC citation survives: fix the guardrail
   and retry the SAME exec. Economic classes need fork evidence (E5); bridge /
   mechanism-design classes need E6:
   `verify <C-id> --exec EXEC-xxx --finding F-xxx --verifier <other-identity>
   --description "same block, same drain"` (independence is ENFORCED — fresh
   exec + different reporter; a single agent in two identities defeats it).
   Quantified impact mints E7: `impact <C-id> F-xxx --extractable USD
   --artifact dump.json`; when no dollar figure is defensible,
   `impact <C-id> F-xxx --unpriceable --ceiling '...' --reason "..." --actor you`.
   A multi-step/multi-actor `exploit_sequence` needs a sequence PoC ONLY when
   the pin has a fork target: `sequence run <C-id> spec.json --finding F-xxx`
   then `sequence verify <C-id> F-xxx`.
9. **Confirm.** `move <C-id> F-xxx CONFIRMED --reason "gates passed"` — the
   gate bundles evidence floor + critic verdict + a negative/comparative
   graph-memory recall + reproduction + snapshot compatibility, refuses
   anything less, and lists the deficits diagnostically. Before attempting the
   move, `gate <C-id> F-xxx` dry-runs that same gate on ONE finding (read-only):
   exactly which checks stand between it and CONFIRMED, and what fixes each.
   One more check bites here and nowhere else: an UNDISPOSITIONED probe-surface
   row of tier 0 (or assertion_gap >= 3) that cites the SAME code anchor as this
   finding's own `affected[]` entries is a machine question about that code, and
   `move <C-id> F-xxx CONFIRMED` refuses until it is answered — `gate <C-id>
   F-xxx` lists it as `probe-surface-undispositioned[<row-id>]` with the exact
   fix. Discharge it with
   `answered <C-id> <Q-id> answered --reason "<why the row is safe — cite the
   row's own code>" --anchor <field>` (a probe row's closure must name the field
   it claims is safe). A row no priority claims yet is minted first with
   `probes <C-id> run --emit`. Rows on unrelated anchors never block a promotion,
   and a campaign with no probe surface sees no new check at all. A
   CONFIRMED high/critical finding is an ANCHOR: confirming one AUTO-ADDS an
   ANCHOR re-scan priority to the plan — re-scan that finding's own lifecycle
   before declaring the surface swept.
10. **Chains, calibration, gate.** `chains <C-id>` (CONFIRMED members only;
    chains materialize from the weakest member's floor), then `gate <C-id>` —
    submission-readiness against the pinned policy; unknown checks never count
    as pass.
11. **Report + learning.** `report <C-id>` (a regenerated view; surfaces thin
    coverage instead of hiding it; Results leads with confirmed findings by
    class; the Answer-quality section flags any "answered" priority with no
    evidence ref). Memory is human-gated: `memory <C-id>` lists candidates;
    only after a human reads them, `memory <C-id> --approve MEM-xxx --by <human>`.
    The agent never approves its own memory.
12. **End of round.** `audit <C-id>` — a non-zero exit means disk no longer
    matches the record; do not carry the campaign forward until you know what
    changed. Then `prove <C-id>` — the completion proofs, including the
    divergence gate and the maximal-exploitation sibling gate (every CONFIRMED
    / CHAIN finding carries a variant ladder, `ladder <C-id> start <F-xxx>`).
    Then reflect (stage 17) and roll learnings into the next `plan`.

### Hard rules (the framework's law — enforced in code, not in prose)
- The orchestrator owns the flow; model stages are bounded workers that return
  structured data. You do not decide your own hypothesis is true — the
  deterministic gates do.
- Status changes ONLY through `move`.
- E4+ evidence MUST trace to a real EXEC record in the campaign's exec ledger
  that exited 0, belongs to the finding, and names its sandbox profile; E7
  MUST cite a registered artifact.
- Never hand-edit the event log, finding JSON, or registered artifacts.
- unknown ≠ secure: unswept surfaces go back on the queue, not in the report
  as clean.
- One root cause per submission; variants are dedup work, not extra
  submissions.
- A sandbox-policy refusal is final — fix the intent, not the command string.
- One writer per campaign — never run `webv2` against the same root
  concurrently.

### Report back (every round)
Workspace + campaign id + phase, what the framework said (brief/audit output),
findings moved and the evidence that moved them, decisions waiting on the
operator (floors, budget, pins, memory approvals), and the exact next actions
from `brief`.

════════════════════════════════════════════════
MODE: DEVELOPER — modify the framework source
════════════════════════════════════════════════

You are working in the framework's own Go source. The framework cannot be
trusted if its record can drift silently, so the FIRST duty of every task is
to keep the record honest and the suite green.

### Ground rules (non-negotiable)
- The framework NEVER calls a model. Model stages are prompts under
  `assets/prompts/`; the harness runs them and hands structured results back
  through the CLI (`ingest`, `model`, `plan`, ...).
- Status changes go ONLY through `move` (it enforces the transition table +
  CONFIRMED gate bundle). Never hand-edit finding JSON.
- E4+ evidence MUST trace to a real EXEC record in the campaign's exec ledger
  (`exec` / register path); E7 MUST cite a registered artifact. Forge output
  is checked for meaningfulness before minting.
- Evidence floors, cost ceilings and policy are OPERATOR DATA, never
  per-instance source edits: use `floors set`, `budget`, `scope` — each is
  actor-attributed and hash-chained into the event log.
- The event log is append-only + hash-chained; `webv2 audit` (or
  `brief --deep`) is the integrity check. A failing audit means something on
  disk no longer matches the record — stop and find out what before
  continuing.

### Environment
- Build: `go build ./...` with the repo's sandbox caches
  (GOCACHE/GOPATH/GOMODCACHE under `.scratch/`).
- The suite runs ONLY around source changes: before/after any
  `internal/`/`cmd/` edit, run `go test ./...` and `webv2 selftest --full`
  (adds the suite to the fast self-check). Fast `webv2 selftest` is the
  startup trust check; do not boot-strap with the suite.
- Rebuild the release binary after a source change: `scripts/release.sh`
  (-> dist/webv2), then reinstall if the operator uses the installed copy.

### Repo map
- `assets/`           — embedded trust-core data: `schema/` (jsonschema
  drafts; every write validates before touching disk), `prompts/` (v2 stage
  pack 31–50), `prompts_legacy/` (v1 pack), `archetypes/`, `playbooks/`,
  `runbook/` (this RUNBOOK.md + AGENT_BOOTSTRAP.md, copied into campaigns by
  `init`).
- `cmd/webv2/`        — the single main package.
- `internal/cli/`     — one file per command (`cmd_<name>.go`); the CLI is
  the only public surface.
- `internal/`         — the subsystems: state, pipeline, planner, findings,
  floors, dedup, audit, report, probes, structidx, snapshot, reproduction,
  maximization, bounty, taxonomy, adapter (the ONLY model boundary), ...
- `scripts/`          — `release.sh` (single-binary release), `golden.sh`
  (the Go-only golden suite), `runbook-walkthrough.sh` (asserts every
  documented command).

### Workflow for a task
1. Orient: `webv2 brief` is the operator cockpit; `webv2 audit` is the
   integrity gate.
2. Find the real code path (RUNBOOK first, then `internal/`) — never trust doc
   prose over code.
3. Make the smallest change that satisfies the intent; add a focused
   regression test in the matching `_test.go`.
4. Run `go test ./...`; run `webv2 selftest`; update the docs that describe
   the changed surface (RUNBOOK.md / AGENT_BOOTSTRAP.md). The Python twin is
   retired: changes are Go-only by definition — no divergence row is needed
   (the frozen ledger lives in `docs/archive/`), but a change to committed
   asset packs must be followed by `python3 scripts/sync-asset-manifest.py`.
5. Prove claims with executed commands, not reading code alone.
```

---

### Tips for using it
- Keep the block **as-is** after the system prompt; the phase order matters
  (unverified framework → no work; unresolved workspace → wrong roots).
- State the mode + workspace + campaign in one line, e.g. *"mode: operator.
  Workspace: /path/to/workspace. Campaign: C-xxx, phase SCOPE."*
- The binary is **static** — any source change requires a rebuild
  (`scripts/release.sh` → `install -m755 dist/webv2 ~/.local/bin/webv2`) before
  the installed command sees it. Fast `webv2 selftest` at startup; the suite
  only around source changes.
- The runbook and this bootstrap are copied into every campaign by `webv2
  init`, so a working campaign carries its own operating docs even in a fresh
  workspace.
- If the agent will work in this repo heavily, point it at `LEARNINGS.md` too
  (project lessons).

# v1.6 Phase 0: The Regression Suite — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Phase 0 regression suite in the `webv2` Go control plane — ScaBench target selection by derived-label set-cover weighted by gold-finding count, commit-SHA resolution with a local mirror, the snap-time contamination grep, double-transcription key quality, commit-before-reveal, fresh targets from post-2025-08 contest reports, and one already-exploited control target that unblocks P1's Phase 2 spike — with **one real target runnable end-to-end first**, before any breadth.

**Architecture:** Every offline deliverable is a deterministic record-or-refuse change in a new `internal/regression` package plus the matching `assets/schema/regression_*.schema.json` key, one new CLI verb (`regress`, ord 96), and one presence-gated audit section (`regression_suite`) appended last in `internal/audit/sections/register.go`. Records live in the campaign (`campaigns/<cid>/regression/`), so they inherit the ledger, the determinism pins and the single-writer lock; the suite *composition* is a repo-level, schema-validated file under `$WEBV2_EVAL_DIR/regression/` with a sha256 sidecar, matching the eval store's discipline. The operator half of each task — dataset download, repo checkout, mirror, report fetch, harness run — is called out per task as an explicit step with the exact command, what to record, and where; nothing in the Go half assumes a network.

**Tech Stack:** Go 1.26 (module `websec`, floor `go 1.26.2`), stdlib only; draft-07 JSON Schema validated through `internal/validation`; plain-Go same-package tests over `t.TempDir()` campaigns; the repo's own gates (`go vet`, `go test ./...`, `scripts/verify-full.sh`).

---

## Global Constraints

Every task below implicitly includes this section. Values are copied verbatim from the P1 plan's Global Constraints and `docs/superpowers/plans/2026-09-21-v16-roadmap.md` §4, with the v1.6 additions the roadmap added after P1.

- **Go floor** `go 1.26.2`, module `websec`; **stdlib only** — no new dependency, ever. `python3` and `git` are *operator* tools and *test* tools (a test that shells out to either must `t.Skip` when the tool is missing), never runtime dependencies of the binary.
- **Asset manifest:** any edit under `assets/` requires `python3 scripts/sync-asset-manifest.py` in the same change, or `assets.TestAssetPackManifest` fails.
- **Schema discipline:** `additionalProperties: false`; every new key is added to the schema *and* validated on the write path with `validation.Validate(v, name, 1)`. A new schema file is also a new entry in `validation.knownSchemas` (`internal/validation/schema.go:15`) — that list's **order is contractual** (it is rendered verbatim in the unknown-schema error text), so append, never insert.
- **Ledger law:** exactly one hash-chained event per mutation, written through `findings.SaveThenLog` or `(*state.Campaign).Log(eventType string, ref *string, data *validation.Value) (validation.Value, error)`; the projection write unwinds if the log write fails.
- **Determinism pins:** `WEBV2_NOW`, `WEBV2_UUID`, `WEBV2_FINDING_IDS`. Never call `time.Now()` or mint a raw UUID in a new record — route through `state.NowIso()` / `state.NewID`.
- **Byte-pinned surfaces:** CLI help/usage/error text is asserted verbatim in `internal/cli/*_test.go`; a new verb registers via `register(command{ord: N, name: "...", line: "...", run: ...})` in its own `cmd_*.go` `init()`, with `ord` = current maximum + 1 (measured: **95** at the time of writing, so `regress` is **96**). `internal/cli/testdata/p3_args_golden.json` holds one entry per *existing* verb and does **not** need regenerating for a new verb at a fresh ord (P1 added three verbs and the fixture stayed byte-identical) — but the audit section set *is* pinned, so read the next bullet.
- **Audit sections** are appended at the end of `internal/audit/sections/register.go`, never interleaved. `scripts/verify-full.sh`'s `p2_sections_ok` and `scripts/check-golden.py`'s `EXPECTED_SECTIONS` both pin the rendered section list for campaigns that are *not* regression targets, so **`regression_suite` must be presence-gated** (`return validation.Value{}, sections.ErrSkip` when the campaign has no regression target). That is why no gate script changes in this plan; Task 1 Step 11 proves it.
- **Gate checks** carry a `BountyRemediation` entry (`internal/bounty/remediation.go`) or `gate explain` regresses. This plan adds no bounty gate check.
- **Tests** are plain Go, same package, `t.TempDir()` campaigns, never Docker, never a network, never a model. **Every** `go` invocation in this plan carries the prefix `GOCACHE=$PWD/.scratch/gocache` (the default `~/.cache/go-build` is read-only in this environment, so a bare `go test` fails on the first build). Full gate: `GOCACHE=$PWD/.scratch/gocache go test ./... -count=1`, then `scripts/verify-full.sh` (14 steps, whose final line is `VERIFY-FULL GREEN: all 14 steps pass`).
- **Realism law.** A test that matches on a framework literal — an id shape, a status string, an enum member, a key name — must be built from a value the real producer emitted, never from a hand-written fixture. Where two vocabularies must agree (the derived-label vocabulary and `taxonomy.CanonicalClasses()`; the score keys this plan pins and the keys `scripts/eval-gold.py` actually prints; the `shape` enum and the four shapes §3a names), pin them EQUAL to each other in a test that reads both, so they cannot drift apart silently.
- **One end-to-end branch test per plan.** Task 1 drives the real verbs in sequence — add target, pin it, record a run, then read it back through `audit` — and asserts the joined-up result. Task 10 adds the suite-level equivalent. Scoped task reviews structurally cannot see cross-task wiring; these two tests are the whole-branch review's substrate.
- **A gate that ships red gets fixed or counted.** `scripts/verify-full.sh` and the pre-commit gate must be green before this plan's work starts; if a red is genuinely out of scope, record it in `docs/gates/` with a count that must not grow.
- **D9 freeze.** The spec changes only in response to a measurement. When this plan's exit criteria run, record the measurement in `docs/gates/v16-P0.md` and cite it in any spec change.
- **No network in the build or test loop.** The plan was written on a machine with no route to github.com, api.github.com or pypi.org; that machine's network came up on 2026-09-21 and the ScaBench checkout now exists locally at `/home/xand/webv2-p0/scabench` (see *Operator prerequisites* §2 and *The dataset, as it actually is*). The rule does not change: the Go half of every task is written and tested against **operator-committed or synthetic input files**, and the network half is an operator step with the exact command and the exact record. A network that happens to be up is a convenience for the operator, never a build dependency.
- **Operator output never enters the build.** Mirrors, checkouts and downloaded reports live outside the module tree (`$WEBV2_P0_DIR`, default `.scratch/p0/`); the only operator artefacts that are committed are the reviewed, schema-validated records under `eval/regression/` and the gate documents under `docs/gates/`.

---

## Step 0 — re-verify this plan's premises before touching anything

This plan was written against the tree as of 2026-09-21 and every "the repo already has X" claim below is a *premise*, not a fact, by the time you read it. Run this block first, mechanically, and stop if any line disagrees:

```bash
cd /home/xand/Projects/dsh-plugins/websec2/web3sec-go
export GOCACHE=$PWD/.scratch/gocache

# 1. the tree is green before you start (the "a gate that ships red" rule)
GOCACHE=$PWD/.scratch/gocache go test ./... -count=1

# 2. the ord maximum — the `regress` verb takes the next slot
rg -o 'ord: [0-9]+' internal/cli/*.go | rg -o '[0-9]+' | sort -n | tail -1   # expect 95

# 3. the audit section registry's LAST entry — the new section appends after it
rg -n 'register\("v16_coverage"' internal/audit/sections/register.go           # expect :47

# 4. the two gate scripts pin the section list for non-regression campaigns
rg -n 'always = \[' scripts/verify-full.sh
rg -n -A18 'EXPECTED_SECTIONS' scripts/check-golden.py | head -20

# 5. the ScaBench area really is empty: no dataset code, no picker, no pin tooling
ls internal/datasets/                     # expect: aderyn  defihacklabs  slither
rg -c -i 'set.cover|setcover|resolved_sha|checkout_sources|contamination' internal assets scripts
#   expect no matches at all (the four concepts are ABSENT in code)

# 6. the dataset's own shape claim, as the repo already recorded it
cat internal/taxonomy/testdata/config/taxonomy_scabench.yaml
#   expect: "carries NO category labels (each finding is exactly
#   {finding_id, severity, title, description})" and "default: unmapped"

# 7. the vocabulary the derived labels must land on, and its real size
cat > .scratch/classcount.go <<'EOF'
package main

import (
	"fmt"
	"sort"

	"websec/internal/taxonomy"
)

func main() {
	c := taxonomy.CanonicalClasses()
	ks := make([]string, 0, len(c))
	for k := range c {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	fmt.Println(len(ks), ks)
}
EOF
GOCACHE=$PWD/.scratch/gocache go run ./.scratch/classcount.go
#   expect: 25 [access-control authorization bridge-message centralization-risk
#   chain-freeze cross-chain-replay donation dos-griefing economic-invariant
#   flash-loan frontend-injection infra-boundary liquidation-logic liveness
#   logic-error oracle-manipulation precision-rounding reentrancy sequencer-halt
#   share-price-accounting share-price-inflation signature-replay
#   token-integration unchecked-external-call upgrade-initializer]
#   — 25, NOT the 23 §3a says; the plan pins the labels to this live set and
#   records the discrepancy in the gate record (Task 11 §5) rather than editing
#   the spec (D9: a spec change cites a measurement).
rm -f .scratch/classcount.go

# 8. the offline scorer this plan's run record ingests, and its pinned key set
python3 - <<'PY'
import re, pathlib
doc = pathlib.Path("scripts/eval-gold.py").read_text()
m = re.search(r"\{found, missed, false_positives.*?\}", doc, re.S)
print(" ".join(m.group(0).split()))
PY
#   expect: {found, missed, false_positives, pass, bonus, verdict, verdict_note,
#            operator_confirmed}

# 9. the snapshot record already carries a git commit, which is what a pin binds to
rg -n 'git_commit' internal/snapshot/pin.go assets/schema/snapshot.schema.json | head

# 10. the schema-name registry a new schema must join (order is contractual)
rg -n -A12 'var knownSchemas' internal/validation/schema.go

# 11. the dataset's REAL shape and counts, before any task reads it as a flat
#     list of findings. Every command is in Operator prerequisites §7; the
#     headline: 31 projects, 32 codebases, 555 findings, 114 high, 10 unpinned.
export SCABENCH=/home/xand/webv2-p0/scabench
export DS="$SCABENCH/datasets/curated-2025-08-18/curated-2025-08-18.json"
python3 -c 'import json,collections;d=json.load(open("'$DS'"));
print(len(d),"projects",len([c for p in d for c in p["codebases"]]),"codebases",
      len([v for p in d for v in p["vulnerabilities"]]),"findings",
      collections.Counter(v["severity"] for p in d for v in p["vulnerabilities"]))'
#   expect: 31 projects 32 codebases 555 findings Counter({'medium': 237, 'low': 184,
#   'high': 114, 'informational': 20})  — a LIST OF PROJECTS, not a flat list, and a
#   fourth severity value §3a does not mention.
```

If the ord maximum moved, take the next free slot; if `v16_coverage` is no longer last, append after whatever is last and update the two gate-script lists in the same commit; if `go test ./...` is not green before you start, that is the first thing to fix — not something to discover at Task 10.

**Premise 7 is a correction, not a formality.** `framework-plan-v1.6.md` §3a says the derived labels bucket onto "ARGUS's **23-class** taxonomy"; the live vocabulary is `taxonomy.CanonicalClasses()` and it holds **25** classes today (`chain-freeze`, `frontend-injection`, `infra-boundary`, `liveness`, `sequencer-halt` are the extra five). This plan pins the derived labels to the **live** set and Task 3 asserts the two are equal, so the day the taxonomy grows the label bucketing follows it instead of silently drifting. The spec's "23" is recorded as stale in `docs/gates/v16-P0.md` (Task 11) rather than edited here — D9: a spec change cites a measurement.

**Premise 11 is a correction too, and a bigger one.** This plan was written from §3a's prose while the machine was offline, and the prose describes the ground truth as a flat list of vulnerability rows carrying a commit. The real snapshot is a list of **31 projects**, each with `codebases[]` (where the commit lives) and `vulnerabilities[]` (where the findings live), with a fourth severity value, a ten-codebase pin problem, and two empty commit fields. The tasks below have been corrected against it; *Operator prerequisites §7 — The dataset, as it actually is* is the verified description, and every task that reads the dataset says which field it reads.

---

## Operator prerequisites — read this before Task 1

Everything the operator must have or do, in one place. Each task's *Operator step* refers back here for the environment and the recording rules.

**1. Network. Up as of 2026-09-21.** The plan was written offline (verified by the controller 2026-09-21: `github.com`, `api.github.com` and `pypi.org` all failed to connect, `http_code 000`). The network is now up and the checkout below was made over it. Re-check before an operator run:

```bash
for u in https://github.com https://api.github.com https://pypi.org; do
  printf '%s -> ' "$u"
  curl -sS -m 10 -o /dev/null -w '%{http_code}\n' "$u" || true
done
# offline: 000 for all three; connected: 200/301 (measured 2026-09-21: all three reachable).
# On this box curl needs --cacert /etc/ssl/certs/ca-certificates.crt (CURL_CA_BUNDLE
# points at a corrupt bundle); git is unaffected.
```

The plan's Go half does not need this. The operator steps do: the ScaBench checkout, every `git clone`/`fetch`, the contest-report fetch, and `ScaBench`'s own baseline runner's dependency install. **If the network is down, the offline half still lands** — that is the point of the per-task split. Record which operator steps ran and which did not in `docs/gates/v16-P0.md` (Task 11).

**2. The dataset. The checkout is already on this machine.** Phase 0 needs exactly one snapshot: `curated-2025-08-18` (§3a: *"There is exactly **one** ScaBench snapshot — `curated-2025-08-18`; no releases, no tags"* — verified 2026-09-21: `datasets/` holds exactly one directory, and `api.github.com/repos/scabench-org/scabench/{releases,tags}` both return `[]`). The upstream repo is:

```
https://github.com/scabench-org/scabench      # NOT scyfi-labs/ScaBench — that path 404s
main @ eec0020939a47bbc06a98a7348a90908b96f4b4d (committed 2025-10-04)
```

The checkout lives at `/home/xand/webv2-p0/scabench`; if it is missing, re-make it with `git clone --depth 1 https://github.com/scabench-org/scabench <dir>`. The operator reads the *derived* input files into this repo, never the raw repo:

| Operator artefact | Path (committed) | Produced by |
|---|---|---|
| the 114 `high` findings, as extracted (the four fields + the joined `project`) | `eval/scabench/curated-2025-08-18.json` | Task 3 operator step |
| the derived label map | `eval/scabench/labels-2025-08-18.json` | Task 3 operator step |
| the selected suite manifest | `eval/regression/suite.json` + `suite.sha256` | Task 4 / Task 10 operator step |
| the mirror index | `eval/regression/mirrors.json` | Task 5 operator step |
| the answer keys + their two transcriptions | `eval/scabench/keys/<target>/a.json`, `b.json` | Task 7 operator step |
| the control target's handoff record | `docs/gates/v16-P0-control-target.md` | Task 2 operator step |

**3. Tools.** `git` (`ls-remote`, `fetch --depth 1`, `rev-parse`, `bundle`), `python3` (the manifest sync, the offline gold scorer, the ScaBench scorer), disk under `$WEBV2_P0_DIR` for the mirrors, and — for the baseline runner and the control target's harness only — that project's build needs. The pinning job is far cheaper than a full `--mirror` per repo: `git fetch --depth 1 origin <full-sha>` of one selected repo measured **252 KB**, and `git ls-remote <repo> <ref>` resolves a `main` hint with no clone at all. Only the three abbreviated SHAs need history (`git clone --depth 50`, then `--unshallow` for `Idle-Labs/idle-tranches`, measured 11 MB). Budget **1–2 GB**, not 10–20, for six selected targets plus their worktrees; the old 10–20 GB figure assumed a full mirror of all 32 codebases and was never measured. `ScaBench`'s baseline runner additionally needs `pip install -r requirements.txt` (`llm`, `rich`) and an `OPENAI_API_KEY` — it calls an LLM and cannot run keyless. No Docker is required by this plan (the P0 harness is ScaBench's baseline runner and the control target's own harness, both operator-run); Docker remains P1's problem.

**4. Scratch.** Mirrors and checkouts live in `$WEBV2_P0_DIR` (default `.scratch/p0/`, which `.gitignore` already ignores). **Never** clone a target inside the repo tree: `internal/cli/cmd_scorecard.go` records a `campaign_inside_target` warning for exactly that geometry, and `snapshot.PinSourceSnapshot` prunes a store that would nest.

**5. Recording rules — identical in every task.**
- One *campaign per target*: `webv2 --root .scratch/p0/root init --program <name>`, then the `regress` verbs into that campaign.
- Every operator step ends by running `webv2 --root <root> audit <cid> --json` and pasting the `regression_suite` section into `docs/gates/v16-P0.md`; a section `problems` entry is a failure, not a note.
- The *only* things committed from an operator run are the files in the table above and the gate documents. Mirrors, checkouts and raw report HTML stay in `.scratch/`.
- An operator step that could not run because the network is down is recorded as `NOT RUN — offline`, never as passed. The exit criteria in `docs/gates/v16-P0.md` are then reported per criterion as `TEST-PROVEN` / `OPERATOR-RUN` / `NOT RUN — offline` (the `docs/gates/v16-P1.md` style: verified vs not, never one number for two different kinds of evidence).

**6. Not P0's problem.** `FORK_RPC_URL` belongs to P1's Task 10 spike. P0's job is the *other* half of that dependency: a real, confirmed, already-exploited finding with a sourced loss figure (Task 2). The cross-plan handoff is written down in Task 2 and consumed by P1 Task 10 Step 4.

**7. The dataset, as it actually is.** Everything in this subsection was measured against the checkout on 2026-09-21; each number carries the command that reproduces it. Do not take a number here on trust — re-run it. `DS` is the dataset file:

```bash
export SCABENCH=/home/xand/webv2-p0/scabench
export DS=$SCABENCH/datasets/curated-2025-08-18/curated-2025-08-18.json

# the file is a LIST OF 31 PROJECTS, not a flat list of findings
python3 -c 'import json;d=json.load(open("'$DS'"));print(len(d), sorted(d[0]))'
#   31 ['codebases', 'name', 'platform', 'project_id', 'vulnerabilities']

# each project: {project_id, name, platform, codebases[], vulnerabilities[]}
python3 -c 'import json;d=json.load(open("'$DS'"));print(sorted(d[0]["codebases"][0]), sorted(d[0]["vulnerabilities"][0]))'
#   codebase keys: commit codebase_id repo_url tarball_url tree_url
#   finding  keys: description finding_id severity title
#   -> the commit lives on the CODEBASE; the vulnerability record has no commit and no project

# counts: 32 codebases, 555 findings
python3 -c 'import json,collections;d=json.load(open("'$DS'"));
cbs=[c for p in d for c in p["codebases"]];v=[x for p in d for x in p["vulnerabilities"]];
print(len(d),"projects",len(cbs),"codebases",len(v),"findings");
print(collections.Counter(x["severity"] for x in v));
print(collections.Counter(p["platform"] for p in d))'
#   31 projects 32 codebases 555 findings
#   Counter({'medium': 237, 'low': 184, 'high': 114, 'informational': 20})
#   Counter({'code4rena': 19, 'sherlock': 10, 'cantina': 2})
#   -> §3a's "severity is high|medium|low only" is FALSE: there is a fourth value,
#      informational (20 rows). The label file below covers the 114 high rows only.

# exactly one project carries two codebases (Starknet Perpetual: one pinned
# codebase, one with an empty commit) -- a target is a PROJECT, but a checkout
# is a CODEBASE, so the target record must name both
python3 -c 'import json;d=json.load(open("'$DS'"));
print([(p["project_id"],[c["codebase_id"] for c in p["codebases"]]) for p in d if len(p["codebases"])>1])'

# the pin story: 10 of 32 codebases carry no usable pin
python3 -c 'import json,re;d=json.load(open("'$DS'"));
[print(c["commit"] or "(empty)", p["project_id"], c["codebase_id"], c["repo_url"])
 for p in d for c in p["codebases"] if not re.fullmatch(r"[0-9a-f]{40}", c["commit"])]'
```

**The ten unpinned codebases — this is Task 5's real workload**, not a one-project edge case (§3a names one project; there are ten codebases across ten projects, in three distinct failure modes):

| # | project_id | codebase_id | `commit` verbatim | `HintKind` | how to resolve |
|---|---|---|---|---|---|
| 1 | `code4rena_fenix-finance-invitational_2024_10` | `Fenix Finance Invitational_main` | `main` | mutable-ref | `git ls-remote <repo> main` |
| 2 | `code4rena_lambowin_2025_02` | `Lambo.win_main` | `main` | mutable-ref | `git ls-remote <repo> main` |
| 3 | `code4rena_loopfi_2025_02` | `LoopFi_main` | `main` | mutable-ref | `git ls-remote <repo> main` |
| 4 | `code4rena_bakerfi-invitational_2025_02` | `BakerFi Invitational_main` | `main` | mutable-ref | `git ls-remote <repo> main` |
| 5 | `code4rena_blackhole_2025_07` | `Blackhole_main` | `main` | mutable-ref | `git ls-remote <repo> main` |
| 6 | `code4rena_initia-move_2025_04` | `Initia Move_b36d06` | `""` (empty) | unknown | no ref at all — the dataset states nothing; resolve the repo's default branch and record it as `unknown` |
| 7 | `code4rena_starknet-perpetual_2025_06` | `Starknet Perpetual_main` | `""` (empty) | unknown | same; this project's *other* codebase is pinned (`9e48514c…`), so pick the codebase deliberately |
| 8 | `sherlock_oku_2024_12` | `Oku_9e31b4` | `9e31b40` | short-sha | `git clone --depth 50 <repo>` then `git rev-parse 9e31b40^{commit}` → `9e31b40fa8593905b9c1037c424d89ec2c886203` |
| 9 | `sherlock_idle-finance_2024_12` | `Idle Finance_b6e581` | `b6e5813` | short-sha | **not in a depth-50 clone** — needs `git fetch --unshallow`, then `b6e581375eab89871d47994abd34fb0d3ed7c86d` |
| 10 | `sherlock_symmio_2025_03` | `SYMMIO_cfe192` | `cfe1920` | short-sha | `git clone --depth 50 <repo>` then `cfe192090c339cffb07d2a50f6ba646299fbcfe0` |

Two further measured facts the tasks depend on:

- **`tarball_url` is not an independent pin.** Across all 32 codebases, `tarball_url == repo_url + "/archive/" + commit + ".tar.gz"` and `tree_url == repo_url + "/tree/" + commit`, with **zero** exceptions — it re-encodes the same `commit` field, so it inherits every ambiguity (`/archive/main.tar.gz` for the five mutable refs) and is **absent exactly when `commit` is empty** (29 of 32 carry one; `Liquid Ron_main` also has none, though its commit is a full SHA). It cannot substitute for the git checkout either: the pin binds to `snapshot.source.git_commit`, which `snapshot.PinSourceSnapshot` reads from `git rev-parse HEAD` and leaves `null` for a non-repo, so `PinTarget`'s equality check would refuse a tarball-only tree. **Decision: resolve and pin with git; keep the tarball as a cheap secondary check, never as the mirror.** See Task 5 Step 5.
- **`checkout_sources.py` is the tool §3a criticises, and it is worse than the spec says.** It clones `--depth 50`, then checks `current_commit.startswith(commit[:8])` (a prefix match, no verification), and it silently clones the default branch when `commit` is empty (`if commit:` guards the checkout). For the two empty-commit codebases it produces a mutable HEAD and reports success. Task 1's `AddTarget` therefore cannot require a non-empty hint (see Task 1 Step 4), and Task 5's mirror rule must cover `short-sha` and `unknown`, not just `mutable-ref`.

---

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `assets/schema/regression_target.schema.json` | the target record: identity, kind, shape, commit hint, resolved SHA, snapshot binding | 1 |
| `assets/schema/regression_run.schema.json` | the run record: normalized coarse score + the D8 label | 1 |
| `internal/regression/regression.go` | package doc, record IO, `writeThenLog` (the ledger law for file-backed records) | 1 |
| `internal/regression/target.go` | `AddTarget`, `PinTarget`, `LoadTarget`, the kind/shape vocabularies | 1 |
| `internal/regression/run.go` | `RecordRun`, `LoadRuns`, the scorer adapters' normalized shape | 1 |
| `internal/cli/cmd_regress.go` | the `regress` verb (ord 96): `target add/pin/list`, `run`, `status` | 1 |
| `internal/audit/sections/regressionsuite.go` | the presence-gated reader of both records | 1 |
| `internal/audit/sections/register.go` *(modify)* | append `regression_suite` last | 1 |
| `internal/validation/schema.go` *(modify)* | two new `knownSchemas` entries, appended | 1 |
| `internal/regression/control.go` | the already-exploited control target's shape + refusals | 2 |
| `docs/gates/v16-P0-control-target.md` | the control target's handoff to P1 Task 10 (operator-filled) | 2 |
| `internal/regression/labels.go` | title+description → canonical class bucketing | 3 |
| `internal/regression/select.go` | weighted greedy set-cover + shape/hold-out constraints | 4 |
| `internal/regression/pin.go` | commit-hint classification, mirror bookkeeping | 5 |
| `internal/regression/contamination.go` | the snap-time grep + fail-closed refusal | 6 |
| `internal/regression/keyquality.go` | two-transcription diff + disagreement rate | 7 |
| `internal/regression/goldcommit.go` | commit-before-reveal + the diagnostic gate | 8 |
| `internal/regression/fresh.go` | fresh-target registration refusals (window, key, grep, commit) | 9 |
| `internal/regression/suite.go` | the repo-level suite composition record + sidecar | 10 |
| `internal/cli/cmd_regress_suite.go` | `regress suite write/check` | 10 |
| `docs/gates/v16-P0.md` | the Phase 0 gate record | 11 |

---

### Task 1: One ScaBench target, end to end (the sequencing ruling)

**Why this is Task 1 and not Task 8.** The user's sequencing ruling: *"Sequence it so 'one ScaBench target end-to-end' lands first."* Rationale, in the user's words: the smallest end-to-end proof is worth more than breadth, and it has a second payoff — P0's already-exploited control target is the confirmed finding the Phase 2 spike (P1's Task 10) is missing. So the suite's *shape* machinery (selection, mirrors, fresh targets) is deliberately sequenced **after** one target has walked the whole pipeline: target record → resolved SHA → snapshot binding → coarse score → audit read-back. Everything later in this plan adds discipline to a pipeline that already runs.

The Phase 0 exit criterion this task is the first half of, quoted verbatim from `framework-plan-v1.6.md` Part 7, line 427:

> Suite runnable end-to-end on one ScaBench target via ScaBench's own baseline runner; control target runs under its own harness; every snapshot carries a resolved SHA; every fresh-target snapshot passes the contamination grep; every key carries a recorded double-transcription disagreement rate; fresh targets carry our own answer keys with the ledger hash committed before any diagnostic use

**Offline vs operator, in this task.**
- **Built and tested offline (the machinery, Steps 1–20):** the two record shapes, their writers and refusals, the snapshot↔SHA binding check, the coarse-score normalization, the presence-gated audit reader, the CLI verb, the end-to-end branch test. Every test runs with no network, no dataset and no model.
- **Operator step (Step 21, needs network + the dataset):** the ScaBench checkout (already on disk — see prerequisites §2), the target checkout, `snap`, ScaBench's baseline runner, the scorer, and the recording. If the network or the LLM key is missing, this step is recorded `NOT RUN — offline`; the machinery is still landed and green.

**Files:**
- Create: `assets/schema/regression_target.schema.json`
- Create: `assets/schema/regression_run.schema.json`
- Create: `internal/regression/regression.go`
- Create: `internal/regression/target.go`
- Create: `internal/regression/run.go`
- Create: `internal/regression/target_test.go`
- Create: `internal/regression/run_test.go`
- Create: `internal/cli/cmd_regress.go`
- Create: `internal/cli/cmd_regress_test.go`
- Create: `internal/audit/sections/regressionsuite.go`
- Create: `internal/audit/sections/regressionsuite_test.go`
- Modify: `internal/audit/sections/register.go` (append `register("regression_suite", RegressionSuite)` after `v16_coverage`)
- Modify: `internal/validation/schema.go` (append `"regression_target", "regression_run"` to `knownSchemas`)
- Modify: `assets/testdata/asset_manifest.json` (regenerated, never hand-edited)

**Interfaces:**
- Consumes: `state.Init`, `state.Open`, `state.NewID(prefix string, n int) string`, `state.NowIso() string`, `(*state.Campaign).Log(eventType string, ref *string, data *validation.Value) (validation.Value, error)`, `validation.{VObj,VStr,VInt,VBool,VArr,VNull,ObjAt,ObjStr,HasKey,Validate,WriteJson,ReadJson,Sha256File,KV}`, `sections.ErrSkip`, `sections.KV`, `t14Dispatch`, `t14Open`, `t14ArgparseErr`, `t14Unrecognized`, `looksLikeOption`.
- Produces (later tasks and Phase 3–4 depend on these exact names):
  - `regression.Dir(c *state.Campaign) string`, `regression.TargetsDir`, `regression.RunsDir`
  - `regression.TargetKinds []string`, `regression.TargetShapes []string`
  - `regression.TargetSpec{Kind, Program, RecordID, CodebaseID, Repo, Shape, CommitHint string}`
  - `regression.AddTarget(c *state.Campaign, spec TargetSpec) (validation.Value, error)`
  - `regression.PinSpec{TargetID, ResolvedSHA, SnapshotID, ResolvedBy string}`
  - `regression.PinTarget(c *state.Campaign, spec PinSpec) (validation.Value, error)`
  - `regression.LoadTargets(c *state.Campaign) ([]validation.Value, error)`
  - `regression.Target(c *state.Campaign, id string) (validation.Value, bool, error)`
  - `regression.Scorers []string`, `regression.RunSpec{...}`, `regression.RecordRun`, `regression.LoadRuns`
  - `regression.NormalizeScore(scorer string, raw validation.Value) (validation.Value, error)`
  - audit section name `"regression_suite"`, CLI verb `regress` at ord 96
  - ledger events: `regression.target.added`, `regression.target.pinned`, `regression.run.recorded`

- [ ] **Step 1: Write the target schema**

Create `assets/schema/regression_target.schema.json`. `resolved_sha` is optional in the *schema* and mandatory in the *writer* at pin time, because a target is legitimately un-pinned between `add` and `pin` — and the audit section must be able to report that state rather than crash on it:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://web3sec.local/schema/regression_target.schema.json",
  "title": "WebSec Regression Target",
  "description": "One target in the v1.6 Part 3a regression suite (framework-plan-v1.6.md §3a). The record lives in the campaign that audits the target, so it inherits the ledger, the determinism pins and the single-writer lock. kind names the provenance: 'scabench' (the curated-2025-08-18 snapshot), 'fresh' (our own target built from a post-2025-08 contest report), 'control' (the already-exploited control target, separately sourced) and 'diagnosed' (the campaign this hardening was derived from, retained but relabeled as training data, never eval). commit_hint is the dataset's own commit field — ScaBench's is a hint, not a pin; resolved_sha is the concrete SHA the checkout actually landed on, and snapshot_id binds it to the immutable snapshot that recorded that checkout.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "target_id", "campaign_id", "kind", "program", "shape",
    "created_at", "schema_version"
  ],
  "properties": {
    "target_id": { "type": "string", "pattern": "^T-[a-f0-9]{12}$" },
    "campaign_id": { "type": "string", "minLength": 3 },
    "kind": {
      "enum": ["scabench", "fresh", "control", "diagnosed"],
      "description": "which of §3a's target provenances this row is"
    },
    "program": { "type": "string", "minLength": 1 },
    "record_id": {
      "type": "string",
      "minLength": 1,
      "description": "the target's id WITHIN its source dataset or report — for a ScaBench target this is the project's `project_id` (e.g. code4rena_coded-estate-invitational_2024_12), verbatim, because selection, hold-out and the shapes map are all per PROJECT; the only bridge back to the raw record"
    },
    "codebase_id": {
      "type": "string",
      "minLength": 1,
      "description": "the dataset's own `codebases[].codebase_id` for the tree this target pins — REQUIRED when a project carries more than one codebase (Starknet Perpetual carries two, one of them unpinned), because the commit lives on the CODEBASE, not the project; optional otherwise, where it is recorded for the same reason the raw project_id is"
    },
    "repo": { "type": "string", "minLength": 1 },
    "shape": {
      "enum": [
        "vault-erc4626", "lending-liquidation", "bridge-messaging",
        "non-rollup-l2-or-oracle", "diagnosed-campaign", "already-exploited"
      ],
      "description": "§3a's composition constraint, as one closed vocabulary: the four ScaBench target shapes (which are assigned to PROJECTS), the diagnosed campaign (relabeled training), and the already-exploited control target"
    },
    "commit_hint": {
      "type": "string",
      "description": "the commit field as the dataset states it — a mutable ref like 'main' is a legal hint and an illegal pin, and the empty string is also a legal hint (two codebases record no ref at all), so minLength must not be 1 here"
    },
    "resolved_sha": {
      "type": "string",
      "pattern": "^[0-9a-f]{40}$",
      "description": "the concrete SHA the checkout landed on (§3a: 'Phase 0 resolves every commit to a concrete SHA at first checkout, mirrors the repos locally, and records the resolved SHA in the campaign snapshot')"
    },
    "snapshot_id": {
      "type": "string",
      "minLength": 8,
      "description": "the campaign snapshot that recorded this checkout; the pin is only valid when that snapshot's source.git_commit equals resolved_sha"
    },
    "resolved_by": { "type": "string", "minLength": 1 },
    "created_at": { "type": "string", "minLength": 20 },
    "schema_version": { "const": 1 }
  }
}
```

- [ ] **Step 2: Write the run schema, and note what it refuses to be**

Create `assets/schema/regression_run.schema.json`. The two `const` keys are the D8 labelling discipline (§3a: *"every number it produces is labeled as such and never reported as a detection rate"*) made structural: a run record that does not say `rediscovery` cannot be written at all, and `is_detection_rate` is pinned false so no later reader can reinterpret the number:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://web3sec.local/schema/regression_run.schema.json",
  "title": "WebSec Regression Run",
  "description": "One coarse-tracking run of the regression suite against one target (§3a Discipline: 'Use ScaBench's own scorer for coarse tracking only'). score is the suite's own normalized object, never a scorer's raw output: the adapters in internal/regression/run.go translate each scorer's vocabulary into these four counts and one verdict, so a scorer change is one adapter, not a schema change. measurement is pinned to 'rediscovery' and is_detection_rate to false because every target — ScaBench or contest-report — is a disclosed, already-judged contest; the number this record carries measures closure discipline and rediscovery, and must never be quoted as a detection rate.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "run_id", "campaign_id", "target_id", "scorer", "score",
    "measurement", "is_detection_rate", "created_at", "schema_version"
  ],
  "properties": {
    "run_id": { "type": "string", "pattern": "^RUN-[a-f0-9]{12}$" },
    "campaign_id": { "type": "string", "minLength": 3 },
    "target_id": { "type": "string", "pattern": "^T-[a-f0-9]{12}$" },
    "scorer": { "enum": ["eval-gold", "scabench-judge"] },
    "score_file_sha256": {
      "type": "string",
      "pattern": "^[0-9a-f]{64}$",
      "description": "sha256 of the scorer output this run ingested; present for eval-gold, absent when the judge's report was transcribed by hand"
    },
    "report_url": {
      "type": "string",
      "minLength": 1,
      "description": "where the scorer's own report lives — the provenance for a transcribed score"
    },
    "artifact_id": { "type": "string", "minLength": 1 },
    "score": {
      "type": "object",
      "additionalProperties": false,
      "required": ["found", "missed", "false_positives", "verdict"],
      "properties": {
        "found": { "type": "integer", "minimum": 0 },
        "missed": { "type": "integer", "minimum": 0 },
        "false_positives": { "type": "integer", "minimum": 0 },
        "verdict": { "type": "string", "minLength": 1 },
        "verdict_note": { "type": "string" }
      }
    },
    "measurement": { "const": "rediscovery" },
    "is_detection_rate": { "const": false },
    "notes": { "type": "string", "maxLength": 2000 },
    "created_at": { "type": "string", "minLength": 20 },
    "schema_version": { "const": 1 }
  }
}
```

- [ ] **Step 3: Register both schemas, sync the manifest, prove the pack is intact**

```bash
python3 scripts/sync-asset-manifest.py
GOCACHE=$PWD/.scratch/gocache go test ./assets -run TestAssetPackManifest -count=1
GOCACHE=$PWD/.scratch/gocache go test ./internal/validation -run 'TestAssetsEmbedded|TestKnownSchemas' -count=1
```

Expected: the manifest test passes; `internal/validation/assets_test.go`'s embedded-set test **fails** until you append the two names to `knownSchemas` in `internal/validation/schema.go`:

```go
	"sft_example", "probe_surface", "class_weights", "taxonomy_aliases",
	"operator_facts", "disclosure",
	"regression_target", "regression_run",
```

Append at the end — the list's order is rendered verbatim in the unknown-schema error text. Then re-run the two commands above; both pass.

- [ ] **Step 4: Write the failing tests for the target record**

Create `internal/regression/target_test.go`:

```go
package regression

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

func regressionCampaign(t *testing.T, id string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme Program", state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// gitTarget writes a one-file tree, git-inits it, commits, and returns the
// directory plus the commit a REAL producer will record for it. Copied from
// internal/snapshot/ladder_test.go's gitSetup on purpose (small helpers are
// duplicated, not exported — the house rule): the snapshot the binding is
// tested against must come from snapshot.PinSourceSnapshot, never from a
// hand-written record.
func gitTarget(t *testing.T) (string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Vault.sol"),
		[]byte("contract Vault {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = dir, env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	runGit("-c", "init.defaultBranch=main", "init", "-q")
	runGit("add", "-A")
	runGit("commit", "-q", "-m", "init")
	return dir, runGit("rev-parse", "HEAD")
}

func TestAddTargetRefusesAnUnknownKindAndShape(t *testing.T) {
	c := regressionCampaign(t, "C-regressaddbad1")
	for _, spec := range []TargetSpec{
		{Kind: "vendor-dump", Program: "Acme", Shape: "vault-erc4626"},
		{Kind: "scabench", Program: "Acme", Shape: "vault-ish"},
		{Kind: "scabench", Program: "", Shape: "vault-erc4626"},
	} {
		if _, err := AddTarget(c, spec); err == nil {
			t.Fatalf("AddTarget accepted %+v", spec)
		}
	}
	targets, err := LoadTargets(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 0 {
		t.Fatalf("%d target(s) survived a refused add", len(targets))
	}
}

func TestPinTargetBindsTheSnapshotToTheResolvedSHA(t *testing.T) {
	c := regressionCampaign(t, "C-regresspin0001")
	target, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme Vault", RecordID: "acme-vault",
		Repo: "acme/vault", Shape: "vault-erc4626", CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	tid := validation.ObjStr(target, "target_id")

	dir, sha := gitTarget(t)
	snap, err := snapshot.PinSourceSnapshot(c, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	sid := validation.ObjStr(snap, "snapshot_id")
	if got := validation.ObjStr(validation.ObjAt(snap, "source"), "git_commit"); got != sha {
		t.Fatalf("the real producer recorded commit %q, want %q", got, sha)
	}

	pinned, err := PinTarget(c, PinSpec{
		TargetID: tid, ResolvedSHA: sha, SnapshotID: sid, ResolvedBy: "operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(pinned, "resolved_sha"); got != sha {
		t.Fatalf("resolved_sha = %q, want %q", got, sha)
	}
	if got := validation.ObjStr(pinned, "snapshot_id"); got != sid {
		t.Fatalf("snapshot_id = %q, want %q", got, sid)
	}
}

func TestPinTargetRefusesAHintInsteadOfASHA(t *testing.T) {
	c := regressionCampaign(t, "C-regresspinhint1")
	target, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	// §3a: "at least one project (Fenix Finance) records "commit": "main" —
	// a mutable ref. ScaBench's commit field is a hint, not a pin." Measured,
	// it is five codebases, not one (see *The dataset, as it actually is*), but
	// the fixture only needs the one value §3a named.
	_, err = PinTarget(c, PinSpec{
		TargetID: validation.ObjStr(target, "target_id"),
		ResolvedSHA: "main", SnapshotID: "src-abc123def456", ResolvedBy: "op",
	})
	if err == nil || !strings.Contains(err.Error(), "40-hex") {
		t.Fatalf("err = %v, want a refusal naming the 40-hex requirement", err)
	}
}

func TestPinTargetRefusesASnapshotThatDisagreesWithTheSHA(t *testing.T) {
	c := regressionCampaign(t, "C-regresspinmis1")
	target, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := gitTarget(t)
	snap, err := snapshot.PinSourceSnapshot(c, dir, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	other := strings.Repeat("a", 40)
	_, err = PinTarget(c, PinSpec{
		TargetID:    validation.ObjStr(target, "target_id"),
		ResolvedSHA: other,
		SnapshotID:  validation.ObjStr(snap, "snapshot_id"),
		ResolvedBy:  "op",
	})
	if err == nil || !strings.Contains(err.Error(), "git_commit") {
		t.Fatalf("err = %v, want a refusal naming the snapshot's git_commit", err)
	}
}

// TestWriteThenLogUnwindsTheRecordWhenTheLedgerWriteFails is the ledger-law
// test the P1 self-review found missing: every writer in this package claims
// "unwind on log failure" and nothing exercised it. A directory where the
// event log should be makes every append fail, so the projection must not
// survive.
func TestWriteThenLogUnwindsTheRecordWhenTheLedgerWriteFails(t *testing.T) {
	c := regressionCampaign(t, "C-regressunwind1")
	blocked := filepath.Join(t.TempDir(), "events-as-a-directory")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	c.EventsPath = blocked
	if _, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
	}); err == nil {
		t.Fatal("AddTarget accepted a target whose ledger event could not be written")
	}
	paths, err := filepath.Glob(filepath.Join(TargetsDir(c), "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 0 {
		t.Fatalf("the projection survived a failed ledger write: %v", paths)
	}
}
```

- [ ] **Step 5: Run them to verify they fail**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/regression -count=1`

Expected: FAIL to compile — `undefined: AddTarget`, `undefined: LoadTargets`, `undefined: PinTarget`, `undefined: TargetsDir`, `undefined: TargetSpec`, `undefined: PinSpec`.

- [ ] **Step 6: Implement the package and the target record**

Create `internal/regression/regression.go`:

```go
// Package regression is the v1.6 Part 3a regression suite's record layer: one
// campaign per target, one target record, its pin, its runs, and (from Task 3
// onward) its derived labels, mirror bookkeeping, contamination grep, answer
// keys and commit-before-reveal record.
//
// Every durable side effect is one schema-validated file plus exactly one
// hash-chained ledger event, written together or not at all (writeThenLog).
// The records live in the campaign (campaigns/<cid>/regression/) rather than
// in a repo-level store so they inherit the ledger, the determinism pins, the
// single-writer lock and the audit — the same reason execs/ and chains/ do.
// The one repo-level artefact is the suite COMPOSITION (internal/regression/
// suite.go, Task 10), because a suite spans campaigns.
package regression

import (
	"fmt"
	"os"
	"path/filepath"

	"websec/internal/state"
	"websec/internal/validation"
)

// Dir is the campaign-scoped home of every regression record.
func Dir(c *state.Campaign) string { return filepath.Join(c.Dir, "regression") }

// TargetsDir is the directory of target records (one per target).
func TargetsDir(c *state.Campaign) string { return filepath.Join(Dir(c), "targets") }

// RunsDir is the directory of run records.
func RunsDir(c *state.Campaign) string { return filepath.Join(Dir(c), "runs") }

func targetPath(c *state.Campaign, id string) string {
	return filepath.Join(TargetsDir(c), id+".json")
}

func runPath(c *state.Campaign, id string) string {
	return filepath.Join(RunsDir(c), id+".json")
}

// kv is the vet-clean keyed KV constructor (unkeyed cross-package literals are
// rejected by go vet).
func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

// contains reports membership in a small closed vocabulary.
func contains(vocab []string, s string) bool {
	for _, v := range vocab {
		if v == s {
			return true
		}
	}
	return false
}

// writeThenLog is the ledger law for a file-backed record: the record file and
// its one ledger event land together or not at all. The file is written first
// (it is the projection), the event second (it is the audit trail), and a
// failed log write REMOVES the file it just wrote, so no unrecorded projection
// can survive. Every writer in this package goes through here; there is no
// second path.
func writeThenLog(c *state.Campaign, path string, doc validation.Value, schema,
	eventType string, ref *string, data validation.Value) (validation.Value, error) {
	if err := validation.Validate(doc, schema, 1); err != nil {
		return validation.VNull(), err
	}
	if err := validation.WriteJson(path, doc, ""); err != nil {
		return validation.VNull(), err
	}
	if _, err := c.Log(eventType, ref, &data); err != nil {
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			return validation.VNull(), fmt.Errorf(
				"ledger write failed (%v) and the projection could not be unwound "+
					"(%v) — the campaign store needs a manual clean", err, rmErr)
		}
		return validation.VNull(), err
	}
	return doc, nil
}
```

Create `internal/regression/target.go`:

```go
package regression

import (
	"fmt"
	"os"
	"path/filepath"

	"websec/internal/state"
	"websec/internal/validation"
)

// TargetKinds is §3a's closed vocabulary of target provenances.
var TargetKinds = []string{"scabench", "fresh", "control", "diagnosed"}

// TargetShapes is §3a's composition constraint as one closed vocabulary: the
// four ScaBench target shapes plus the two named rows (the diagnosed campaign,
// retained but relabeled training data, and the already-exploited control).
var TargetShapes = []string{
	"vault-erc4626", "lending-liquidation", "bridge-messaging",
	"non-rollup-l2-or-oracle", "diagnosed-campaign", "already-exploited",
}

// sha40Re is the only pin shape §3a accepts: a concrete commit, never a ref.
var sha40Re = regexp.MustCompile(`^[0-9a-f]{40}$`)

// TargetSpec is one target's identity at registration time. RecordID is the
// dataset's PROJECT id (selection and hold-out are per project); CodebaseID is
// the dataset's codebase id for the tree actually pinned, because the commit
// lives on the codebase — one project (Starknet Perpetual) carries two.
type TargetSpec struct {
	Kind       string
	Program    string
	RecordID   string
	CodebaseID string
	Repo       string
	Shape      string
	CommitHint string
}

// AddTarget records one target. It refuses an unknown kind or shape and an
// empty program, and (for a ScaBench target) an empty commit hint that is not
// backed by a named record and repo — a target whose dataset row was not read
// is not a target. An empty hint IS a legal value: the dataset emits it for two
// codebases (Initia Move_b36d06, Starknet Perpetual_main), so refusing it
// outright would make two of the 32 codebases unrepresentable (see *The
// dataset, as it actually is*).
func AddTarget(c *state.Campaign, spec TargetSpec) (validation.Value, error) {
	if !contains(TargetKinds, spec.Kind) {
		return validation.VNull(), fmt.Errorf(
			"unknown target kind %q (known: %v)", spec.Kind, TargetKinds)
	}
	if !contains(TargetShapes, spec.Shape) {
		return validation.VNull(), fmt.Errorf(
			"unknown target shape %q (known: %v)", spec.Shape, TargetShapes)
	}
	if spec.Program == "" {
		return validation.VNull(), fmt.Errorf("a target must name its program")
	}
	// The dataset's commit field is a HINT, and for two codebases the hint is
	// the empty string — a real value the producer emitted, not a missing row.
	// The row's provenance is still required, and Task 5's pin rule demands a
	// mirror for an `unknown` hint exactly as it does for `main`.
	if spec.Kind == "scabench" && spec.CommitHint == "" &&
		(spec.RecordID == "" || spec.Repo == "") {
		return validation.VNull(), fmt.Errorf(
			"a scabench target with an empty dataset commit field must still name "+
				"its --record-id and --repo: the dataset's commit field is empty "+
				"for Initia Move_b36d06 and Starknet Perpetual_main, and an empty "+
				"hint is a value to record, not a licence to skip the row")
	}
	tid := state.NewID("T", 12)
	doc := validation.VObj(
		kv("target_id", validation.VStr(tid)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("kind", validation.VStr(spec.Kind)),
		kv("program", validation.VStr(spec.Program)),
		kv("shape", validation.VStr(spec.Shape)),
		kv("created_at", validation.VStr(state.NowIso())),
		kv("schema_version", validation.VInt(1)),
	)
	if spec.RecordID != "" {
		doc.O = validation.SetOrAppend(doc.O, "record_id", validation.VStr(spec.RecordID))
	}
	if spec.CodebaseID != "" {
		doc.O = validation.SetOrAppend(doc.O, "codebase_id", validation.VStr(spec.CodebaseID))
	}
	if spec.Repo != "" {
		doc.O = validation.SetOrAppend(doc.O, "repo", validation.VStr(spec.Repo))
	}
	if spec.CommitHint != "" {
		doc.O = validation.SetOrAppend(doc.O, "commit_hint", validation.VStr(spec.CommitHint))
	}
	data := validation.VObj(
		kv("target_id", validation.VStr(tid)),
		kv("kind", validation.VStr(spec.Kind)),
		kv("program", validation.VStr(spec.Program)),
		kv("shape", validation.VStr(spec.Shape)),
	)
	return writeThenLog(c, targetPath(c, tid), doc, "regression_target",
		"regression.target.added", &tid, data)
}

// PinSpec is one pin attempt: the concrete SHA the checkout landed on, the
// snapshot that recorded that checkout, and who resolved it.
type PinSpec struct {
	TargetID    string
	ResolvedSHA string
	SnapshotID  string
	ResolvedBy  string
}

// PinTarget binds a target to a resolved commit and to the snapshot that
// recorded it. Three refusals, all §3a's source-pinning rule:
//
//   - the SHA must be a concrete 40-hex commit — "ScaBench's commit field is a
//     hint, not a pin";
//   - the named snapshot must exist in this campaign;
//   - that snapshot's source.git_commit must EQUAL the resolved SHA, which is
//     what makes "every snapshot carries a resolved SHA" a checked fact rather
//     than a claim about the operator's shell history.
func PinTarget(c *state.Campaign, spec PinSpec) (validation.Value, error) {
	target, ok, err := Target(c, spec.TargetID)
	if err != nil {
		return validation.VNull(), err
	}
	if !ok {
		return validation.VNull(), fmt.Errorf("no target %s in campaign %s",
			spec.TargetID, c.CampaignID)
	}
	if !sha40Re.MatchString(spec.ResolvedSHA) {
		return validation.VNull(), fmt.Errorf(
			"resolved SHA %q is not a 40-hex commit — a ref (\"main\", \"v1.2.3\", "+
				"a short hash) is a hint, not a pin; resolve it against the local "+
				"mirror first", spec.ResolvedSHA)
	}
	snap, ok, err := readSnapshot(c, spec.SnapshotID)
	if err != nil {
		return validation.VNull(), err
	}
	if !ok {
		return validation.VNull(), fmt.Errorf("no snapshot %s in campaign %s",
			spec.SnapshotID, c.CampaignID)
	}
	commit := validation.ObjStr(validation.ObjAt(snap, "source"), "git_commit")
	if commit != spec.ResolvedSHA {
		return validation.VNull(), fmt.Errorf(
			"snapshot %s records source.git_commit %q, not the resolved SHA %q — "+
				"pin the checkout you actually resolved, not a different tree",
			spec.SnapshotID, commit, spec.ResolvedSHA)
	}
	doc := copyTargetWith(target, spec)
	data := validation.VObj(
		kv("target_id", validation.VStr(spec.TargetID)),
		kv("resolved_sha", validation.VStr(spec.ResolvedSHA)),
		kv("snapshot_id", validation.VStr(spec.SnapshotID)),
		kv("resolved_by", validation.VStr(spec.ResolvedBy)),
	)
	tid := spec.TargetID
	return writeThenLog(c, targetPath(c, tid), doc, "regression_target",
		"regression.target.pinned", &tid, data)
}

// copyTargetWith returns the target document with the pin keys set or
// appended, preserving every existing key's position (the ordered-JSON
// discipline: a rewrite must not reorder a record).
func copyTargetWith(target validation.Value, spec PinSpec) validation.Value {
	out := validation.VObj()
	for _, kvp := range target.O {
		out.O = append(out.O, kvp)
	}
	out.O = validation.SetOrAppend(out.O, "resolved_sha", validation.VStr(spec.ResolvedSHA))
	out.O = validation.SetOrAppend(out.O, "snapshot_id", validation.VStr(spec.SnapshotID))
	if spec.ResolvedBy != "" {
		out.O = validation.SetOrAppend(out.O, "resolved_by", validation.VStr(spec.ResolvedBy))
	}
	return out
}

// readSnapshot reads campaigns/<cid>/snapshots/<id>/snapshot.json, the
// immutable store internal/state/campaign_snapshot.go:277 points at.
func readSnapshot(c *state.Campaign, id string) (validation.Value, bool, error) {
	if id == "" {
		return validation.VNull(), false, nil
	}
	path := filepath.Join(c.Dir, "snapshots", id, "snapshot.json")
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return validation.VNull(), false, nil
		}
		return validation.VNull(), false, err
	}
	doc, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), false, err
	}
	return doc, true, nil
}

// LoadTargets is every target record in the campaign, in file order.
func LoadTargets(c *state.Campaign) ([]validation.Value, error) {
	names, err := validation.ListPrefixedOptional(TargetsDir(c), "T-", ".json")
	if err != nil {
		return nil, err
	}
	out := make([]validation.Value, 0, len(names))
	for _, p := range names {
		doc, err := validation.ReadJson(p)
		if err != nil {
			return nil, err
		}
		out = append(out, doc)
	}
	return out, nil
}

// Target is one target record by id.
func Target(c *state.Campaign, id string) (validation.Value, bool, error) {
	path := targetPath(c, id)
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return validation.VNull(), false, nil
		}
		return validation.VNull(), false, err
	}
	doc, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), false, err
	}
	return doc, true, nil
}
```

Two details to check before you run it: (a) `validation.ListPrefixedOptional` returns
**full paths**, already sorted (`internal/validation/filelist.go:33-51` appends
`filepath.Join(dir, name)`), so both loaders pass `p` straight to `ReadJson` — do not
`filepath.Join` again; (b) add `"regexp"` to the import block.

- [ ] **Step 7: Run the target tests**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/regression -run 'Target|WriteThenLog' -count=1`

Expected: PASS (all five tests). If `TestPinTargetBindsTheSnapshotToTheResolvedSHA` skips, `git` is not on PATH — install it or record the skip; the test is the only proof of the binding.

- [ ] **Step 8: Write the failing tests for the run record**

Create `internal/regression/run_test.go`:

```go
package regression

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// evalGoldFixture is a REAL scorer output: every key below is one
// scripts/eval-gold.py actually prints (its docstring's contract, and
// TestEvalGoldKeysMatchTheRealScorer runs the script itself when python3 is
// present). Hand-writing a smaller object here would test a vocabulary the
// scorer does not have — the realism law.
const evalGoldFixture = `{
  "found": 3,
  "missed": 1,
  "false_positives": 2,
  "pass": true,
  "bonus": 0,
  "verdict": "pass",
  "verdict_note": "3 of 4 gold findings anchored",
  "operator_confirmed": false
}
`

func TestNormalizeScoreRefusesAKeyTheScorerDoesNotPrint(t *testing.T) {
	raw, err := validation.ParseOrdered([]byte(evalGoldFixture))
	if err != nil {
		t.Fatal(err)
	}
	good, err := NormalizeScore("eval-gold", raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(good, "found"); got.Kind != validation.Int || got.I != 3 {
		t.Fatalf("found = %v, want 3", got)
	}
	// An unknown key is refused, not ignored: a scorer that grew a key must be
	// re-read by a human, not silently half-ingested.
	raw.O = validation.SetOrAppend(raw.O, "detection_rate", validation.VFloat(0.75))
	if _, err := NormalizeScore("eval-gold", raw); err == nil ||
		!strings.Contains(err.Error(), "detection_rate") {
		t.Fatalf("err = %v, want a refusal naming the unknown key", err)
	}
	if _, err := NormalizeScore("vendor-scorer", raw); err == nil {
		t.Fatal("NormalizeScore accepted an unknown scorer")
	}
}

func TestRecordRunCarriesTheD8LabelAndRefusesAnUnknownTarget(t *testing.T) {
	c := regressionCampaign(t, "C-regressrun0001")
	target, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	scoreFile := filepath.Join(t.TempDir(), "score.json")
	if err := os.WriteFile(scoreFile, []byte(evalGoldFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	run, err := RecordRun(c, RunSpec{
		TargetID:  validation.ObjStr(target, "target_id"),
		Scorer:    "eval-gold",
		ScoreFile: scoreFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(run, "measurement"); got != "rediscovery" {
		t.Fatalf("measurement = %q, want rediscovery (§3a D8)", got)
	}
	if got := validation.ObjAt(run, "is_detection_rate"); got.Kind != validation.Bool || got.B {
		t.Fatalf("is_detection_rate = %v, want false", got)
	}
	if got := validation.ObjStr(run, "score_file_sha256"); len(got) != 64 {
		t.Fatalf("score_file_sha256 = %q, want 64 hex", got)
	}
	// The transcribed judge path: no file, but a cited report.
	judge, err := RecordRun(c, RunSpec{
		TargetID: validation.ObjStr(target, "target_id"),
		Scorer:   "scabench-judge",
		Found:    3, Missed: 1, FalsePositives: 2, Verdict: "pass",
		ReportURL: "https://example.test/report/1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(judge, "report_url"); got == "" {
		t.Fatal("a transcribed judge score must cite its report")
	}
	// A transcribed score with no citation is refused.
	if _, err := RecordRun(c, RunSpec{
		TargetID: validation.ObjStr(target, "target_id"),
		Scorer:   "scabench-judge",
		Found:    3, Verdict: "pass",
	}); err == nil {
		t.Fatal("RecordRun accepted a transcribed score with no report_url")
	}
	// A run for a target that does not exist is refused.
	if _, err := RecordRun(c, RunSpec{
		TargetID: "T-000000000000", Scorer: "eval-gold", ScoreFile: scoreFile,
	}); err == nil {
		t.Fatal("RecordRun accepted a run for an unknown target")
	}
	runs, err := LoadRuns(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Fatalf("%d run record(s), want 2", len(runs))
	}
}
```

- [ ] **Step 9: Run it to verify it fails**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/regression -run 'NormalizeScore|RecordRun' -count=1`

Expected: FAIL to compile — `undefined: NormalizeScore`, `undefined: RunSpec`, `undefined: RecordRun`, `undefined: LoadRuns`.

- [ ] **Step 10: Implement the run record and its scorer adapters**

Create `internal/regression/run.go`:

```go
package regression

import (
	"fmt"
	"os"
	"path/filepath"

	"websec/internal/state"
	"websec/internal/validation"
)

// Scorers is the closed vocabulary of coarse scorers this suite ingests.
// §3a: "Use ScaBench's own scorer for coarse tracking only" — and the
// framework's own offline gold scorer is the second, deterministic half.
var Scorers = []string{"eval-gold", "scabench-judge"}

// evalGoldKeys is the exact stdout key set of scripts/eval-gold.py, pinned
// from that script's own docstring contract. TestEvalGoldKeysMatchTheRealScorer
// runs the real script (when python3 is on PATH) and compares, so this list
// cannot drift away from the scorer it claims to read.
var evalGoldKeys = []string{
	"found", "missed", "false_positives", "pass", "bonus", "verdict",
	"verdict_note", "operator_confirmed",
}

// RunSpec is one run to record. eval-gold reads ScoreFile; scabench-judge
// takes the operator's transcription of the judge's report plus the report's
// own URL — the suite never parses the judge, it records what the operator
// read and where they read it.
type RunSpec struct {
	TargetID       string
	Scorer         string
	ScoreFile      string
	Found          int64
	Missed         int64
	FalsePositives int64
	Verdict        string
	VerdictNote    string
	ReportURL      string
	ArtifactID     string
	Notes          string
}

// NormalizeScore translates one scorer's own vocabulary into the suite's
// coarse score. It refuses an unknown scorer, a missing key, and an unknown
// key: a scorer whose output grew a field must be re-read by a human, never
// half-ingested.
func NormalizeScore(scorer string, raw validation.Value) (validation.Value, error) {
	switch scorer {
	case "eval-gold":
		if raw.Kind != validation.Obj {
			return validation.VNull(), fmt.Errorf(
				"eval-gold output must be one JSON object, got %v", raw.Kind)
		}
		for _, kvp := range raw.O {
			if !contains(evalGoldKeys, kvp.K) {
				return validation.VNull(), fmt.Errorf(
					"eval-gold output carries key %q, which this adapter does not "+
						"know — re-read scripts/eval-gold.py's contract and extend "+
						"evalGoldKeys deliberately", kvp.K)
			}
		}
		out := validation.VObj()
		for _, k := range []string{"found", "missed", "false_positives"} {
			v := validation.ObjAt(raw, k)
			if v.Kind != validation.Int {
				return validation.VNull(), fmt.Errorf(
					"eval-gold output key %q is %v, want an integer", k, v.Kind)
			}
			out.O = validation.SetOrAppend(out.O, k, v)
		}
		verdict := validation.ObjStr(raw, "verdict")
		if verdict == "" {
			return validation.VNull(), fmt.Errorf(
				"eval-gold output carries no verdict string")
		}
		out.O = validation.SetOrAppend(out.O, "verdict", validation.VStr(verdict))
		if note := validation.ObjStr(raw, "verdict_note"); note != "" {
			out.O = validation.SetOrAppend(out.O, "verdict_note", validation.VStr(note))
		}
		return out, nil
	case "scabench-judge":
		if raw.Kind != validation.Obj {
			return validation.VNull(), fmt.Errorf(
				"a transcribed judge score must be an object")
		}
		return raw, nil
	}
	return validation.VNull(), fmt.Errorf(
		"unknown scorer %q (known: %v)", scorer, Scorers)
}

// RecordRun writes one run record. Two refusals beyond NormalizeScore's: the
// target must exist in this campaign, and a transcribed (judge) score must
// cite the report it was transcribed from — an uncited number is exactly the
// kind of fact this suite exists to refuse.
func RecordRun(c *state.Campaign, spec RunSpec) (validation.Value, error) {
	if !contains(Scorers, spec.Scorer) {
		return validation.VNull(), fmt.Errorf(
			"unknown scorer %q (known: %v)", spec.Scorer, Scorers)
	}
	if _, ok, err := Target(c, spec.TargetID); err != nil {
		return validation.VNull(), err
	} else if !ok {
		return validation.VNull(), fmt.Errorf("no target %s in campaign %s",
			spec.TargetID, c.CampaignID)
	}
	var raw validation.Value
	sha := ""
	switch spec.Scorer {
	case "eval-gold":
		if spec.ScoreFile == "" {
			return validation.VNull(), fmt.Errorf(
				"eval-gold needs --score-file (the scorer's stdout, saved)")
		}
		data, err := os.ReadFile(spec.ScoreFile)
		if err != nil {
			return validation.VNull(), err
		}
		raw, err = validation.ParseOrdered(data)
		if err != nil {
			return validation.VNull(), err
		}
		sha, err = validation.Sha256File(spec.ScoreFile)
		if err != nil {
			return validation.VNull(), err
		}
	case "scabench-judge":
		if spec.ReportURL == "" {
			return validation.VNull(), fmt.Errorf(
				"a transcribed judge score must cite --report-url — an uncited " +
					"number is not a measurement")
		}
		if spec.Found < 0 || spec.Missed < 0 || spec.FalsePositives < 0 {
			return validation.VNull(), fmt.Errorf("score counts cannot be negative")
		}
		if spec.Verdict == "" {
			return validation.VNull(), fmt.Errorf("a transcribed score needs --verdict")
		}
		raw = validation.VObj(
			kv("found", validation.VInt(spec.Found)),
			kv("missed", validation.VInt(spec.Missed)),
			kv("false_positives", validation.VInt(spec.FalsePositives)),
			kv("verdict", validation.VStr(spec.Verdict)),
		)
		if spec.VerdictNote != "" {
			raw.O = validation.SetOrAppend(raw.O, "verdict_note",
				validation.VStr(spec.VerdictNote))
		}
	}
	score, err := NormalizeScore(spec.Scorer, raw)
	if err != nil {
		return validation.VNull(), err
	}
	rid := state.NewID("RUN", 12)
	doc := validation.VObj(
		kv("run_id", validation.VStr(rid)),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("target_id", validation.VStr(spec.TargetID)),
		kv("scorer", validation.VStr(spec.Scorer)),
		kv("score", score),
		// §3a D8, structural: the label is not a comment, it is a required
		// const in the schema and it is written on every path.
		kv("measurement", validation.VStr("rediscovery")),
		kv("is_detection_rate", validation.VBool(false)),
		kv("created_at", validation.VStr(state.NowIso())),
		kv("schema_version", validation.VInt(1)),
	)
	if sha != "" {
		doc.O = validation.SetOrAppend(doc.O, "score_file_sha256", validation.VStr(sha))
	}
	if spec.ReportURL != "" {
		doc.O = validation.SetOrAppend(doc.O, "report_url", validation.VStr(spec.ReportURL))
	}
	if spec.ArtifactID != "" {
		doc.O = validation.SetOrAppend(doc.O, "artifact_id", validation.VStr(spec.ArtifactID))
	}
	if spec.Notes != "" {
		doc.O = validation.SetOrAppend(doc.O, "notes", validation.VStr(spec.Notes))
	}
	data := validation.VObj(
		kv("run_id", validation.VStr(rid)),
		kv("target_id", validation.VStr(spec.TargetID)),
		kv("scorer", validation.VStr(spec.Scorer)),
		kv("score", score),
		kv("measurement", validation.VStr("rediscovery")),
	)
	return writeThenLog(c, runPath(c, rid), doc, "regression_run",
		"regression.run.recorded", &rid, data)
}

// LoadRuns is every run record in the campaign, in file order.
func LoadRuns(c *state.Campaign) ([]validation.Value, error) {
	names, err := validation.ListPrefixedOptional(RunsDir(c), "RUN-", ".json")
	if err != nil {
		return nil, err
	}
	out := make([]validation.Value, 0, len(names))
	for _, p := range names {
		doc, err := validation.ReadJson(p)
		if err != nil {
			return nil, err
		}
		out = append(out, doc)
	}
	return out, nil
}
```

`filepath` and `os` are both used here; keep the import list honest.

- [ ] **Step 11: Add the cross-language pin on the scorer's key set**

Append to `internal/regression/run_test.go`:

```go
// TestEvalGoldKeysMatchTheRealScorer runs the real scorer and compares its
// actual stdout keys with evalGoldKeys. It is the realism law applied across
// languages: the Go adapter and the Python scorer cannot drift apart without
// a red test. Skipped when python3 is absent (a missing operator tool is a
// skip, never a silent pass).
func TestEvalGoldKeysMatchTheRealScorer(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	camp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(camp, "findings"), 0o755); err != nil {
		t.Fatal(err)
	}
	gold := filepath.Join(t.TempDir(), "gold.json")
	if err := os.WriteFile(gold, []byte(`[]`), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3",
		filepath.Join(repo, "scripts", "eval-gold.py"),
		"--gold", gold, "--campaign", camp)
	cmd.Dir = repo
	out, _ := cmd.Output() // a malformed/empty campaign is a legitimate exit 2
	if len(out) == 0 {
		t.Skip("the scorer printed nothing for an empty campaign — the key-set " +
			"contract is unverifiable here; check scripts/eval_gold_test.py instead")
	}
	raw, err := validation.ParseOrdered(out)
	if err != nil {
		t.Fatalf("scorer stdout is not one JSON object: %v\n%s", err, out)
	}
	got := make([]string, 0, len(raw.O))
	for _, kvp := range raw.O {
		got = append(got, kvp.K)
	}
	want := append([]string(nil), evalGoldKeys...)
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("scorer keys %v != evalGoldKeys %v — the adapter and the scorer "+
			"have drifted", got, want)
	}
}
```

Add `"os/exec"` and `"sort"` to that file's imports.

- [ ] **Step 12: Run the regression package's tests**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/regression -count=1`

Expected: PASS. `TestEvalGoldKeysMatchTheRealScorer` either passes or skips; a *failure* means the adapter's key list is wrong — fix the list, never the scorer.

- [ ] **Step 13: Write the failing CLI test for the verb**

Create `internal/cli/cmd_regress_test.go`:

```go
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRegressOneTargetEndToEnd is this plan's end-to-end branch test: it
// drives the real verbs in sequence — add a target, pin it, record a run,
// read it all back through `audit` — and asserts the joined-up result. It is
// the test that would have caught the P1 "feed validated the declaration and
// never recorded it" defect, which no scoped task review could see.
func TestRegressOneTargetEndToEnd(t *testing.T) {
	_, root := t15Campaign(t, "Acme")
	cid := campaignIDOf(t, root)

	code, out, errS := run(t, "--root", root, "regress", cid, "target", "add",
		"--kind", "scabench", "--program", "Acme Vault",
		"--record-id", "acme-vault", "--repo", "acme/vault",
		"--shape", "vault-erc4626", "--commit-hint", "main")
	if code != 0 {
		t.Fatalf("target add exit %d: out=%q err=%q", code, out, errS)
	}
	tid := firstID(out, "T-")
	if tid == "" {
		t.Fatalf("target add printed no T- id: %q", out)
	}

	// Half-pinned state must be RED, and the red must name the reason: the
	// exit criterion is "every snapshot carries a resolved SHA", so a target
	// that has not been pinned is a suite problem, not a blank.
	code, out, errS = run(t, "--root", root, "audit", cid, "--json")
	if code == 0 {
		t.Fatalf("audit PASSed with an unpinned target: %q", out)
	}
	if !strings.Contains(out+errS, "resolved_sha") {
		t.Fatalf("the unpinned-target problem does not name resolved_sha: %q", out+errS)
	}

	// Pin against a real snapshot taken from a real git tree.
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "Vault.sol"),
		[]byte("contract Vault {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitInitCommit(t, target)
	code, out, errS = run(t, "--root", root, "snap", cid, target)
	if code != 0 {
		t.Fatalf("snap exit %d: out=%q err=%q", code, out, errS)
	}
	snapID := firstID(out, "src-")
	if snapID == "" {
		t.Fatalf("snap printed no snapshot id: %q", out)
	}
	sha := gitRevParse(t, target)

	code, out, errS = run(t, "--root", root, "regress", cid, "target", "pin",
		tid, "--resolved-sha", sha, "--snapshot", snapID, "--actor", "operator")
	if code != 0 {
		t.Fatalf("target pin exit %d: out=%q err=%q", code, out, errS)
	}

	score := filepath.Join(t.TempDir(), "score.json")
	if err := os.WriteFile(score, []byte(evalGoldCLIFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS = run(t, "--root", root, "regress", cid, "run",
		"--target", tid, "--scorer", "eval-gold", "--score-file", score)
	if code != 0 {
		t.Fatalf("run exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "rediscovery") {
		t.Fatalf("the run output does not carry the D8 label: %q", out)
	}

	code, out, errS = run(t, "--root", root, "audit", cid, "--json")
	if code != 0 {
		t.Fatalf("audit exit %d after pin+run: out=%q err=%q", code, out, errS)
	}
	for _, want := range []string{"regression_suite", sha, "rediscovery"} {
		if !strings.Contains(out, want) {
			t.Fatalf("audit --json does not carry %q: %q", want, out)
		}
	}

	// status is the human view, and it must carry the same label.
	code, out, errS = run(t, "--root", root, "regress", cid, "status")
	if code != 0 {
		t.Fatalf("status exit %d: out=%q err=%q", code, out, errS)
	}
	if !strings.Contains(out, "measurement: rediscovery") {
		t.Fatalf("status = %q, want the measurement label", out)
	}
}

const evalGoldCLIFixture = `{
  "found": 3, "missed": 1, "false_positives": 2, "pass": true,
  "bonus": 0, "verdict": "pass", "verdict_note": "3 of 4 anchored",
  "operator_confirmed": false
}
`

func TestRegressRefusalsAreExit1AndArgparseErrorsAreExit2(t *testing.T) {
	_, root := t15Campaign(t, "Acme")
	cid := campaignIDOf(t, root)
	// usage error (argparse contract)
	code, _, errS := run(t, "--root", root, "regress", cid, "target", "add",
		"--kind", "scabench", "--program", "Acme", "--shape", "vault-erc4626")
	if code != 2 || !strings.Contains(errS, "usage: webv2 regress") {
		t.Fatalf("code = %d err = %q, want 2 with the usage block", code, errS)
	}
	// refusal (a real answer of "no")
	code, _, errS = run(t, "--root", root, "regress", cid, "target", "pin",
		"T-000000000000", "--resolved-sha", strings.Repeat("a", 40),
		"--snapshot", "src-abc123def456")
	if code != 1 || !strings.Contains(errS, "no target") {
		t.Fatalf("code = %d err = %q, want 1 naming the missing target", code, errS)
	}
}
```

Two helpers this test needs already exist in the package's other tests in spirit — check before adding: `campaignIDOf` may not exist (use the campaign dir name: `filepath.Base` of the single entry under `<root>/campaigns`), and `firstID`/`gitInitCommit`/`gitRevParse` do not exist. Add them to `cmd_regress_test.go`:

```go
func campaignIDOf(t *testing.T, root string) string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(root, "campaigns"))
	if err != nil || len(ents) != 1 {
		t.Fatalf("campaigns dir: %v (%d entries)", err, len(ents))
	}
	return ents[0].Name()
}

func firstID(s, prefix string) string {
	i := strings.Index(s, prefix)
	if i < 0 {
		return ""
	}
	j := i
	for j < len(s) && (s[j] == '-' || (s[j] >= '0' && s[j] <= '9') ||
		(s[j] >= 'a' && s[j] <= 'f')) {
		j++
	}
	return s[i:j]
}

func gitInitCommit(t *testing.T, dir string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	for _, args := range [][]string{
		{"-c", "init.defaultBranch=main", "init", "-q"},
		{"add", "-A"}, {"commit", "-q", "-m", "init"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = dir, env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func gitRevParse(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}
```

- [ ] **Step 14: Run it to verify it fails**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/cli -run TestRegress -count=1`

Expected: FAIL — `unrecognized arguments: regress` (the verb is not registered yet), exit 2.

- [ ] **Step 15: Implement the verb**

Create `internal/cli/cmd_regress.go`:

```go
package cli

// cmd_regress: `webv2 regress <campaign> {target add|pin|list, run, status}` —
// the v1.6 Part 3a regression suite's record surface. One campaign per target;
// every record is schema-validated and ledgered (internal/regression).
//
// Exit codes: 0 recorded, 2 argparse/usage error, 1 refusal (a real answer of
// "no": unknown target, an unpinnable SHA, a scorer this suite does not read).

import (
	"fmt"
	"strings"

	"websec/internal/regression"
	"websec/internal/state"
	"websec/internal/validation"
)

const (
	regressUsage = `usage: webv2 regress [-h] campaign {target,run,status} ...
`

	regressHelp = `usage: webv2 regress [-h] campaign {target,run,status} ...

positional arguments:
  campaign

options:
  -h, --help       show this help message and exit

subcommands:
  target add       record one regression target
  target pin       bind a target to a resolved 40-hex SHA and its snapshot
  target list      list the campaign's targets
  run              record one coarse score for a target
  status           the human view of the suite records
`
)

func runRegress(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return regressCmd(root, args, r) })
}

// regressCmd hand-parses the verb (the house pattern for a new verb whose
// subcommands each take a different flag set — see runScope,
// internal/cli/cmd_scope.go). Positionals: campaign, action, subject.
func regressCmd(root string, args []string, r *Runner) error {
	var pos []string
	vals := map[string]string{}
	asJSON := false
	valueFlags := map[string]bool{
		"--kind": true, "--program": true, "--record-id": true, "--repo": true,
		"--codebase-id": true,
		"--shape": true, "--commit-hint": true, "--resolved-sha": true,
		"--snapshot": true, "--actor": true, "--target": true, "--scorer": true,
		"--score-file": true, "--found": true, "--missed": true,
		"--false-positives": true, "--verdict": true, "--verdict-note": true,
		"--report-url": true, "--artifact": true, "--notes": true,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			fmt.Fprint(r.Out, regressHelp)
			return nil
		case a == "--json":
			asJSON = true
		case strings.HasPrefix(a, "--") && strings.Contains(a, "="):
			k, v, _ := strings.Cut(a, "=")
			if !valueFlags[k] {
				return t14Unrecognized(a)
			}
			vals[k] = v
		case valueFlags[a]:
			if i+1 >= len(args) || looksLikeOption(args[i+1]) {
				return t14ArgparseErr(regressUsage, "regress",
					"argument %s: expected one argument", a)
			}
			vals[a] = args[i+1]
			i++
		case strings.HasPrefix(a, "-"):
			return t14Unrecognized(a)
		default:
			pos = append(pos, a)
		}
	}
	// Every later task that adds a flag adds its name — WITH the leading "--",
	// because that is the key this parser stores — to valueFlags above. The
	// tasks say so individually; this is the one place the convention lives.
	if len(pos) < 2 {
		return t14ArgparseErr(regressUsage, "regress",
			"the following arguments are required: campaign, action")
	}
	c, err := t14Open(root, pos[0])
	if err != nil {
		return err
	}
	switch pos[1] {
	case "target":
		if len(pos) < 3 {
			return t14ArgparseErr(regressUsage, "regress",
				"the following arguments are required: target_cmd")
		}
		switch pos[2] {
		case "add":
			return regressTargetAdd(c, vals, r)
		case "pin":
			if len(pos) < 4 {
				return t14ArgparseErr(regressUsage, "regress",
					"the following arguments are required: target_id")
			}
			return regressTargetPin(c, pos[3], vals, r)
		case "list":
			return regressTargetList(c, asJSON, r)
		}
		return t14ArgparseErr(regressUsage, "regress",
			"argument target_cmd: invalid choice: %q "+
				"(choose from 'add', 'pin', 'list')", pos[2])
	case "run":
		return regressRun(c, vals, r)
	case "status":
		return regressStatus(c, asJSON, r)
	}
	return t14ArgparseErr(regressUsage, "regress",
		"argument regress_cmd: invalid choice: %q (choose from 'target', 'run', 'status')",
		pos[1])
}

func regressTargetAdd(c *state.Campaign, vals map[string]string, r *Runner) error {
	for _, k := range []string{"--kind", "--program", "--shape"} {
		if vals[k] == "" {
			return t14ArgparseErr(regressUsage, "regress",
				"the following arguments are required: %s", k)
		}
	}
	doc, err := regression.AddTarget(c, regression.TargetSpec{
		Kind: vals["--kind"], Program: vals["--program"],
		RecordID: vals["--record-id"], CodebaseID: vals["--codebase-id"],
		Repo: vals["--repo"],
		Shape: vals["--shape"], CommitHint: vals["--commit-hint"],
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "regression target %s added (%s, %s)\n",
		validation.ObjStr(doc, "target_id"), vals["--kind"], vals["--shape"])
	return nil
}

func regressTargetPin(c *state.Campaign, tid string, vals map[string]string, r *Runner) error {
	for _, k := range []string{"--resolved-sha", "--snapshot"} {
		if vals[k] == "" {
			return t14ArgparseErr(regressUsage, "regress",
				"the following arguments are required: %s", k)
		}
	}
	doc, err := regression.PinTarget(c, regression.PinSpec{
		TargetID: tid, ResolvedSHA: vals["--resolved-sha"],
		SnapshotID: vals["--snapshot"], ResolvedBy: vals["--actor"],
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "pinned %s to %s at snapshot %s\n",
		validation.ObjStr(doc, "target_id"),
		validation.ObjStr(doc, "resolved_sha"),
		validation.ObjStr(doc, "snapshot_id"))
	return nil
}

func regressTargetList(c *state.Campaign, asJSON bool, r *Runner) error {
	targets, err := regression.LoadTargets(c)
	if err != nil {
		return err
	}
	if asJSON {
		fmt.Fprintln(r.Out, validation.CanonSpaced(validation.VArr(targets...)))
		return nil
	}
	if len(targets) == 0 {
		fmt.Fprintln(r.Out, "no regression targets recorded")
		return nil
	}
	for _, t := range targets {
		fmt.Fprintf(r.Out, "%s  %-9s %-24s %-22s sha=%s\n",
			validation.ObjStr(t, "target_id"), validation.ObjStr(t, "kind"),
			validation.ObjStr(t, "program"), validation.ObjStr(t, "shape"),
			orDash(validation.ObjStr(t, "resolved_sha")))
	}
	return nil
}

func regressRun(c *state.Campaign, vals map[string]string, r *Runner) error {
	if vals["--target"] == "" || vals["--scorer"] == "" {
		return t14ArgparseErr(regressUsage, "regress",
			"the following arguments are required: --target, --scorer")
	}
	spec := regression.RunSpec{
		TargetID: vals["--target"], Scorer: vals["--scorer"],
		ScoreFile: vals["--score-file"], Verdict: vals["--verdict"],
		VerdictNote: vals["--verdict-note"], ReportURL: vals["--report-url"],
		ArtifactID: vals["--artifact"], Notes: vals["--notes"],
	}
	for _, f := range []struct {
		flag string
		dst  *int64
	}{
		{"--found", &spec.Found}, {"--missed", &spec.Missed},
		{"--false-positives", &spec.FalsePositives},
	} {
		if v := vals[f.flag]; v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return t14ArgparseErr(regressUsage, "regress",
					"argument %s: invalid int value: %q", f.flag, v)
			}
			*f.dst = n
		}
	}
	doc, err := regression.RecordRun(c, spec)
	if err != nil {
		return err
	}
	score := validation.ObjAt(doc, "score")
	fmt.Fprintf(r.Out, "regression run %s recorded for %s: found=%s missed=%s "+
		"false_positives=%s verdict=%s\n", validation.ObjStr(doc, "run_id"),
		validation.ObjStr(doc, "target_id"),
		validation.IntText(validation.ObjAt(score, "found")),
		validation.IntText(validation.ObjAt(score, "missed")),
		validation.IntText(validation.ObjAt(score, "false_positives")),
		validation.ObjStr(score, "verdict"))
	// D8, in the operator's face: the number just recorded is not a detection
	// rate and must never be quoted as one (§3a, Part 10 item 4).
	fmt.Fprintln(r.Out, "measurement: rediscovery — this is not a detection rate")
	return nil
}

func regressStatus(c *state.Campaign, asJSON bool, r *Runner) error {
	targets, err := regression.LoadTargets(c)
	if err != nil {
		return err
	}
	runs, err := regression.LoadRuns(c)
	if err != nil {
		return err
	}
	if asJSON {
		fmt.Fprintln(r.Out, validation.CanonSpaced(validation.VObj(
			kvT("targets", validation.VArr(targets...)),
			kvT("runs", validation.VArr(runs...)),
		)))
		return nil
	}
	fmt.Fprintf(r.Out, "%d target(s), %d run(s)\n", len(targets), len(runs))
	for _, t := range targets {
		fmt.Fprintf(r.Out, "%s  %-9s %-24s sha=%s snapshot=%s\n",
			validation.ObjStr(t, "target_id"), validation.ObjStr(t, "kind"),
			validation.ObjStr(t, "program"),
			orDash(validation.ObjStr(t, "resolved_sha")),
			orDash(validation.ObjStr(t, "snapshot_id")))
	}
	for _, run := range runs {
		fmt.Fprintf(r.Out, "%s  target=%s scorer=%s verdict=%s "+
			"measurement: %s\n", validation.ObjStr(run, "run_id"),
			validation.ObjStr(run, "target_id"), validation.ObjStr(run, "scorer"),
			validation.ObjStr(validation.ObjAt(run, "score"), "verdict"),
			validation.ObjStr(run, "measurement"))
	}
	return nil
}

// orDash renders an absent key as a dash rather than an empty field, so a
// missing pin reads as missing.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func init() {
	register(command{ord: 96, name: "regress",
		line: "regress <campaign>            the Phase 0 regression suite's records",
		run:  runRegress})
}
```

Add `"strconv"` to the imports. `kvT` is the CLI package's vet-clean KV helper (used by `t15Finding` in `cmd_dedup_test.go`) — confirm it exists in non-test code (`rg -n 'func kvT' internal/cli/`); if it is test-only, use `validation.KV{K: ..., V: ...}` directly.

- [ ] **Step 16: Run the CLI test**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/cli -run TestRegress -count=1`

Expected: PASS. Then confirm the argparse fixture did not move:

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/cli -run TestP3ArgparseGolden -count=1`

Expected: PASS, with `internal/cli/testdata/p3_args_golden.json` unmodified (`git diff --stat` shows nothing for it).

- [ ] **Step 17: Write the failing audit-section test**

Create `internal/audit/sections/regressionsuite_test.go`:

```go
package sections

import (
	"errors"
	"strings"
	"testing"

	"websec/internal/regression"
	"websec/internal/state"
	"websec/internal/validation"
)

func regressSectionCampaign(t *testing.T, id string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "Acme", state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestRegressionSuiteIsPresenceGated is the test that protects the pinned
// section lists in scripts/verify-full.sh and scripts/check-golden.py: a
// campaign that is not a regression target must render NOTHING, so those two
// gates do not need editing when this section lands.
func TestRegressionSuiteIsPresenceGated(t *testing.T) {
	c := regressSectionCampaign(t, "C-regsectgate01")
	if _, err := RegressionSuite(c); !errors.Is(err, ErrSkip) {
		t.Fatalf("a campaign with no regression target must ErrSkip, got %v", err)
	}
}

func TestRegressionSuiteReportsAnUnpinnedTargetAndGoesGreenAfterThePin(t *testing.T) {
	c := regressSectionCampaign(t, "C-regsectread01")
	target, err := regression.AddTarget(c, regression.TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	sec, err := RegressionSuite(c)
	if err != nil {
		t.Fatal(err)
	}
	problems := validation.ObjAt(sec, "problems")
	if len(problems.A) != 1 {
		t.Fatalf("%d problem(s), want exactly the unpinned-target one", len(problems.A))
	}
	if !strings.Contains(problems.A[0].S, "resolved_sha") {
		t.Fatalf("problem = %q, want it to name resolved_sha", problems.A[0].S)
	}
	if got := validation.ObjAt(sec, "ok"); got.Kind != validation.Bool || got.B {
		t.Fatalf("ok = %v, want false while a target is unpinned", got)
	}
	// A run for a target that was never registered is a problem too — it
	// cannot be reached through the writer, so it is written by hand here,
	// exactly the drift the section exists to catch.
	if err := writeRunFor(t, c, target); err != nil {
		t.Fatal(err)
	}
	sec, err = RegressionSuite(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjAt(sec, "ok"); got.Kind != validation.Bool || got.B {
		t.Fatalf("ok = %v, want false while the target is still unpinned", got)
	}
}
```

`writeRunFor` must go through the REAL writer (the realism law), so it is a two-line helper: `regression.RecordRun(c, regression.RunSpec{...})` with a temp score file. Write it in the test file:

```go
func writeRunFor(t *testing.T, c *state.Campaign, target validation.Value) error {
	t.Helper()
	score := filepath.Join(t.TempDir(), "score.json")
	if err := os.WriteFile(score, []byte(`{"found":1,"missed":0,
		"false_positives":0,"pass":true,"bonus":0,"verdict":"pass",
		"verdict_note":"one anchored","operator_confirmed":false}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := regression.RecordRun(c, regression.RunSpec{
		TargetID: validation.ObjStr(target, "target_id"),
		Scorer:   "eval-gold", ScoreFile: score,
	})
	return err
}
```

(Add `"os"` and `"path/filepath"` to the test's imports.)

- [ ] **Step 18: Implement the section and register it**

Create `internal/audit/sections/regressionsuite.go`:

```go
// regressionsuite.go is the v1.6 Part 3a regression-suite section: the reader
// for the target and run records internal/regression writes.
//
// PRESENCE-GATED, deliberately. scripts/verify-full.sh's p2_sections_ok and
// scripts/check-golden.py's EXPECTED_SECTIONS both pin the rendered section
// list for campaigns that are not regression targets; a campaign with no
// target record returns ErrSkip and renders nothing, so neither gate script
// changes when this section lands. A campaign that IS a regression target
// always renders it.
//
// problems carries the four states that cannot be true of a healthy suite:
// a target with no resolved SHA (the exit criterion is "every snapshot
// carries a resolved SHA"), a resolved SHA that is not a 40-hex commit, a
// target whose bound snapshot records a DIFFERENT commit, and a run whose
// measurement label is not the D8 rediscovery label.
package sections

import (
	"fmt"

	"websec/internal/regression"
	"websec/internal/state"
	"websec/internal/validation"
)

// RegressionSuite is the section: {checked, targets, runs, measurement,
// problems, ok} or ErrSkip when the campaign has no regression target.
func RegressionSuite(c *state.Campaign) (validation.Value, error) {
	targets, err := regression.LoadTargets(c)
	if err != nil {
		return validation.Value{}, err
	}
	if len(targets) == 0 {
		return validation.Value{}, ErrSkip
	}
	runs, err := regression.LoadRuns(c)
	if err != nil {
		return validation.Value{}, err
	}
	problems := []validation.Value{}
	targetRows := make([]validation.Value, 0, len(targets))
	byID := map[string]validation.Value{}
	for _, t := range targets {
		tid := validation.ObjStr(t, "target_id")
		byID[tid] = t
		sha := validation.ObjStr(t, "resolved_sha")
		sid := validation.ObjStr(t, "snapshot_id")
		n := 0
		for _, run := range runs {
			if validation.ObjStr(run, "target_id") == tid {
				n++
			}
		}
		targetRows = append(targetRows, validation.VObj(
			KV("target_id", validation.VStr(tid)),
			KV("kind", validation.VStr(validation.ObjStr(t, "kind"))),
			KV("program", validation.VStr(validation.ObjStr(t, "program"))),
			KV("shape", validation.VStr(validation.ObjStr(t, "shape"))),
			KV("commit_hint", validation.VStr(validation.ObjStr(t, "commit_hint"))),
			KV("resolved_sha", validation.VStr(sha)),
			KV("snapshot_id", validation.VStr(sid)),
			KV("runs", validation.VInt(int64(n))),
		))
		switch {
		case sha == "":
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"target %s (%s) carries no resolved_sha — Phase 0 exits only when "+
					"every snapshot carries a resolved SHA", tid,
				validation.ObjStr(t, "program"))))
		case !sha40.MatchString(sha):
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"target %s resolved_sha %q is not a 40-hex commit", tid, sha)))
		case sid == "":
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"target %s carries a resolved SHA but no snapshot binding", tid)))
		}
	}
	runRows := make([]validation.Value, 0, len(runs))
	for _, run := range runs {
		tid := validation.ObjStr(run, "target_id")
		runRows = append(runRows, validation.VObj(
			KV("run_id", validation.VStr(validation.ObjStr(run, "run_id"))),
			KV("target_id", validation.VStr(tid)),
			KV("scorer", validation.VStr(validation.ObjStr(run, "scorer"))),
			KV("score", validation.ObjAt(run, "score")),
			KV("measurement", validation.VStr(validation.ObjStr(run, "measurement"))),
		))
		if _, ok := byID[tid]; !ok {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"run %s names target %s, which has no target record",
				validation.ObjStr(run, "run_id"), tid)))
		}
		if got := validation.ObjStr(run, "measurement"); got != "rediscovery" {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"run %s carries measurement %q, not the D8 rediscovery label",
				validation.ObjStr(run, "run_id"), got)))
		}
	}
	return validation.VObj(
		KV("checked", validation.VInt(int64(len(targets)+len(runs)))),
		KV("targets", validation.VArr(targetRows...)),
		KV("runs", validation.VArr(runRows...)),
		KV("measurement", validation.VStr("rediscovery")),
		KV("problems", validation.VArr(problems...)),
		KV("ok", validation.VBool(len(problems) == 0)),
	), nil
}
```

Add the shared pin regex next to the section (a `var sha40 = regexp.MustCompile(...)` in `regressionsuite.go`, or reuse the one `internal/regression` exports — do not export a regexp for one reader: duplicate the four-line helper, the house rule for small helpers).

Then append to `internal/audit/sections/register.go`, immediately after the `v16_coverage` line:

```go
	// v1.6 Phase 0: the regression suite's records. PRESENCE-GATED (ErrSkip
	// when the campaign has no regression target), so the section lists the
	// two gate scripts pin are unchanged for every campaign that is not a
	// regression target. Registered LAST, after v16_coverage.
	register("regression_suite", RegressionSuite)
```

- [ ] **Step 19: Run the audit tests**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/audit/... ./internal/cli -count=1`

Expected: PASS, including `internal/audit`'s own section-count assertions if any exist (`rg -n 'v16_coverage' internal/audit/*_test.go internal/cli/cmd_audit_test.go` first; if a test pins the rendered section list for a fixture campaign, it must NOT change — if it does, the presence gate is wrong, not the test).

- [ ] **Step 20: Prove the two pinned gate scripts are untouched**

```bash
GOCACHE=$PWD/.scratch/gocache go test ./... -count=1
git diff --stat scripts/verify-full.sh scripts/check-golden.py internal/cli/testdata/p3_args_golden.json
```

Expected: the suite is green and the three files show **no diff**. A diff here means the section is not presence-gated (or the verb moved an existing usage string) — fix the code, not the fixture.

- [ ] **Step 21: Operator step — one real ScaBench target, end to end (needs network)**

Everything below is operator work; it is **not** testable here and must be recorded as `NOT RUN — offline` when the network is down.

```bash
# 0. prerequisites (§ Operator prerequisites): network up, the ScaBench checkout
#    present, git available.
export WEBV2_P0_DIR="$PWD/.scratch/p0"
export SCABENCH=/home/xand/webv2-p0/scabench          # already cloned; see prerequisites §2
export DS="$SCABENCH/datasets/curated-2025-08-18/curated-2025-08-18.json"
mkdir -p "$WEBV2_P0_DIR"
# 1. (only if the checkout is missing) clone the dataset once (read-only
#    reference; never a target). The upstream is scabench-org/scabench — the
#    scyfi-labs/ScaBench path this plan used to cite 404s.
[ -d "$SCABENCH" ] || git clone --depth 1 https://github.com/scabench-org/scabench "$SCABENCH"
# 2. pick ONE project AND one of its codebases from the dataset. The file is a
#    list of projects; the commit is on codebases[]. Do not read it as a flat
#    list of findings.
python3 - "$DS" <<'PY'
import json, sys
for p in json.load(open(sys.argv[1])):
    for c in p["codebases"]:
        print(p["project_id"], "|", c["codebase_id"], "|", repr(c["commit"]), "|", c["repo_url"])
PY
#    ... pick one line whose commit is a full 40-hex SHA (22 of 32 are; see the
#    unpinned table for the other ten) and clone the TARGET into the mirror
#    area — never inside this repo. A shallow fetch by SHA is enough and is
#    measured at ~250 KB; --mirror is not needed for the pin.
mkdir -p "$WEBV2_P0_DIR/mirror"
git init -q "$WEBV2_P0_DIR/mirror/<codebase>"
git -C "$WEBV2_P0_DIR/mirror/<codebase>" remote add origin "https://github.com/<org>/<repo>"
git -C "$WEBV2_P0_DIR/mirror/<codebase>" fetch --depth 1 origin '<commit-hint>'
git -C "$WEBV2_P0_DIR/mirror/<codebase>" checkout -q FETCH_HEAD
git -C "$WEBV2_P0_DIR/mirror/<codebase>" rev-parse HEAD
#    ^ record the printed 40-hex SHA: that is the resolved SHA.
#    The checkout is NOT optional: `snap` reads the commit from `git rev-parse
#    HEAD`, so a repo left on an unborn HEAD snapshots with git_commit null and
#    `target pin` then refuses (its equality check).
git -C "$WEBV2_P0_DIR/mirror/<codebase>" worktree add \
    "$WEBV2_P0_DIR/target/<codebase>" '<resolved-sha>'
#    For a `main` hint, skip the clone: `git ls-remote https://github.com/<org>/<repo> main`
#    prints the SHA directly. For a short SHA, clone --depth 50 and rev-parse it
#    (Idle Finance's b6e5813 needs --unshallow first). See Task 5 Step 5.
# 3. the campaign for this target
webv2 --root "$WEBV2_P0_DIR/root" init --program '<program>'
webv2 --root "$WEBV2_P0_DIR/root" snap <cid> "$WEBV2_P0_DIR/target/<codebase>"
webv2 --root "$WEBV2_P0_DIR/root" regress <cid> target add \
    --kind scabench --program '<program>' --record-id '<project_id>' \
    --codebase-id '<codebase_id>' \
    --repo '<org>/<repo>' --shape '<one of the four shapes>' \
    --commit-hint '<the dataset's own commit field, verbatim>'
#    ^ --codebase-id is required when the project carries two codebases
#      (Starknet Perpetual), optional otherwise. An empty --commit-hint is legal
#      and is exactly what Initia Move and Starknet Perpetual record.
webv2 --root "$WEBV2_P0_DIR/root" regress <cid> target pin <T-id> \
    --resolved-sha '<40-hex>' --snapshot '<src-id>' --actor "$(whoami)"
# 4. run the campaign against the pinned target (the ordinary stages), then
#    run ScaBench's own baseline runner against the same tree. The runner is
#    baseline-runner/baseline_runner.py (there is no baseline/run.py), it
#    REQUIRES --source, and it calls an LLM: pip install -r requirements.txt and
#    export OPENAI_API_KEY first, or record this half NOT RUN.
python3 "$SCABENCH/baseline-runner/baseline_runner.py" \
    --project '<project_id>' --source "$WEBV2_P0_DIR/target/<codebase>" \
    --output "$WEBV2_P0_DIR/out" --model gpt-5-mini
#    output file: "$WEBV2_P0_DIR/out/baseline_<project_id>.json"
# 5. record the coarse score. eval-gold reads OUR campaign, but its --gold is
#    NOT our answer-key file: it requires an OBJECT
#    {gold_findings:[{gold_id, title, match_criteria, primary_functions?}],
#     scoring:{pass, bonus, false_positive_budget:"... at most N FPs ..."}}
#    (the budget is parsed by the regex `(\d+)\s*\+?\s*FPs?\b`, so the string
#    must literally say "N FPs" — "at most 3" fails the parse), and it
#    hard-codes PASS_GOLD_ID "G-01" / BONUS_GOLD_ID "G-02", which no
#    ScaBench finding_id can be. Build the gold file from the project's high
#    rows with gold_id = the dataset's finding_id, and read `found`/`missed` as
#    the measurement: `verdict` is FAIL by construction for a ScaBench target,
#    because the G-01/G-02 pass concept does not transfer. The exit criterion's
#    real scorer is ScaBench's own (scorer arm `scabench-judge`, below).
python3 - "$DS" '<project_id>' > "$WEBV2_P0_DIR/gold-<project_id>.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); pid = sys.argv[2]
p = next(x for x in d if x["project_id"] == pid)
hi = [v for v in p["vulnerabilities"] if v["severity"] == "high"]
json.dump({"gold_findings": [
    {"gold_id": v["finding_id"], "title": v["title"],
     "match_criteria": (v["title"] + " " + v["description"])[:400]}
    for v in hi],
    "scoring": {"pass": "(ScaBench target: no G-01/G-02 pass concept)",
                "bonus": "(none)", "false_positive_budget": "at most 3 FPs"}},
    sys.stdout)
PY
python3 scripts/eval-gold.py --gold "$WEBV2_P0_DIR/gold-<project_id>.json" \
    --campaign "$WEBV2_P0_DIR/root/campaigns/<cid>" > "$WEBV2_P0_DIR/score.json"
webv2 --root "$WEBV2_P0_DIR/root" regress <cid> run \
    --target <T-id> --scorer eval-gold --score-file "$WEBV2_P0_DIR/score.json"
webv2 --root "$WEBV2_P0_DIR/root" audit <cid> --json
```

**The judge path is not a URL transcription.** The official ScaBench scorer is the external Nethermind AuditAgent algorithm (`pip install "git+https://github.com/NethermindEth/auditagent-scoring-algo"`), driven by `python -m scoring_algo.cli evaluate` with `OPENAI_API_KEY`, `MODEL`, `REPOS_TO_RUN` and `DATA_ROOT`; the in-repo `scoring/scorer_v2.py` is **deprecated** by ScaBench's own README. It needs per-project truth files at `$DATA_ROOT/source_of_truth/<project_id>.json` (write each dataset project verbatim — the README has the snippet) and your findings renamed to `$DATA_ROOT/<SCAN_SOURCE>/<project_id>_results.json`. ScaBench also ships **pre-computed GPT-5 baselines for all 31 projects** at `datasets/curated-2025-08-18/baseline-results/baseline_<project_id>.json` — a network-free cross-check for the coarse score, and the reason the runner half can be skipped without losing the comparison.

**Record:** the `regression_suite` section of that `audit --json` (paste it), the resolved SHA, the snapshot id, the dataset commit field verbatim, and the scorer output path — into `docs/gates/v16-P0.md` under *"Suite runnable end-to-end on one ScaBench target"*. If step 4's runner cannot run on this machine (no `OPENAI_API_KEY` is the likely reason), record the target as `PINNED, RUNNER NOT RUN — <reason>`: a pinned target with no run is honest; a claimed run with no output is not.

- [ ] **Step 22: Commit**

```bash
git add assets/schema/regression_target.schema.json assets/schema/regression_run.schema.json \
        assets/testdata/asset_manifest.json internal/regression internal/cli/cmd_regress.go \
        internal/cli/cmd_regress_test.go internal/audit/sections/regressionsuite.go \
        internal/audit/sections/regressionsuite_test.go internal/audit/sections/register.go \
        internal/validation/schema.go
git commit -m "feat(v16-p0): one regression target end to end — records, regress verb, audit section"
```

---

### Task 2: The already-exploited control target, and the P1 spike handoff

**The cross-plan dependency, written down.** P1's Phase 2 exit criterion is half done: the arithmetic half is test-proven, the extraction half needs *"a defensible `extractable_usd` on one already-confirmed finding"*. `docs/gates/v16-P1.md` §7b records the blocker verbatim:

> No finding in the real campaign is CONFIRMED (§5), so there is no confirmed finding to name and **no `extractable_usd` has been produced**.
>
> **What unblocks it, precisely:** a mainnet fork RPC URL and its pinned block number (`FORK_RPC_URL` is unset on this machine; Docker itself is up), plus one already-confirmed finding on a real target.

**This task produces the second half of that sentence.** §3a names the same artefact as a Phase 0 deliverable:

> **The already-exploited control target** is the only element that touches novelty, and it is audit data, not incident data — probably not in ScaBench at all. It needs separate sourcing with a pinned pre-patch commit and its own harness; it will not run under ScaBench's baseline runner. Phase 0 budgets for both, which is why Phase 0 is two weeks.

So: one control target, separately sourced, pinned to a **pre-patch** commit, with its own harness, carrying the public loss figure *and its citation*; plus a recorded handoff naming the campaign, the finding, and the `extractable_usd` P1 Task 10 Step 4 will consume. After this task, P1's Task 10 is blocked on `FORK_RPC_URL` **only**.

**Offline vs operator, in this task.**
- **Built and tested offline (Steps 1–7):** the `incident`/`control`/`handoff` record shapes and every refusal — an uncited loss figure, a missing or non-40-hex pre-patch pin, a pre-patch SHA equal to the patch SHA, a handoff naming a finding that is not CONFIRMED, a handoff with a non-positive `extractable_usd`. Plus the audit problem line that keeps a half-finished control target red.
- **Operator step (Step 8, needs network + a real incident):** source the project, clone the pre-patch commit, run its harness, ingest + confirm the finding, record the handoff. On an offline machine this is `NOT RUN — offline`, and P1's Task 10 stays blocked on *both* halves — say so, do not claim otherwise.

**Files:**
- Create: `internal/regression/control.go`
- Create: `internal/regression/control_test.go`
- Modify: `assets/schema/regression_target.schema.json` (add `incident`, `control`, `handoff`)
- Modify: `internal/cli/cmd_regress.go` (add `target add-control` and `target handoff`)
- Modify: `internal/cli/cmd_regress_test.go` (the two new refusals)
- Modify: `internal/audit/sections/regressionsuite.go` (the control-target problem lines)
- Create: `docs/gates/v16-P0-control-target.md`
- Modify: `assets/testdata/asset_manifest.json` (regenerated)

**Interfaces:**
- Consumes: `regression.{AddTarget,Target,TargetsDir,copyTargetWith,writeThenLog,sha40Re,kv,contains}`, `findings.LoadFinding(c *state.Campaign, findingID string) (validation.Value, error)`, `state.NowIso`.
- Produces: `regression.ControlSpec{TargetID, IncidentURL, IncidentDate string, LossUSD float64, LossSource, PrePatchSHA, PatchSHA, HarnessRunner, HarnessCommand string}`, `regression.RecordControl(c, spec ControlSpec) (validation.Value, error)`, `regression.HandoffSpec{TargetID, FindingID, ExtractableUSD float64, Source, RecordedBy string}`, `regression.RecordHandoff(c, spec HandoffSpec) (validation.Value, error)`; ledger events `regression.control.recorded`, `regression.control.handoff`.

- [ ] **Step 1: Extend the target schema**

In `assets/schema/regression_target.schema.json`, add three keys to `properties` (keep the existing keys' order; append these before `created_at`):

```json
    "incident": {
      "type": "object",
      "additionalProperties": false,
      "required": ["url", "date", "loss_usd", "loss_source"],
      "description": "the public record of the exploit this control target exists to exercise: where it is written down, when it happened, how much was lost, and WHERE THAT FIGURE CAME FROM. loss_source is mandatory because an uncited loss number is the kind of fact this suite refuses everywhere else",
      "properties": {
        "url": { "type": "string", "minLength": 1 },
        "date": { "type": "string", "minLength": 10 },
        "loss_usd": { "type": "number", "exclusiveMinimum": 0 },
        "loss_source": { "type": "string", "minLength": 1 },
        "postmortem_url": { "type": "string", "minLength": 1 }
      }
    },
    "control": {
      "type": "object",
      "additionalProperties": false,
      "required": ["pre_patch_sha", "patch_sha", "harness"],
      "description": "§3a: the control target needs a pinned PRE-PATCH commit and its own harness — it will not run under ScaBench's baseline runner. patch_sha is recorded so the pre-patch pin is unambiguous: a target whose two SHAs are equal is a target nobody pinned",
      "properties": {
        "pre_patch_sha": { "type": "string", "pattern": "^[0-9a-f]{40}$" },
        "patch_sha": { "type": "string", "pattern": "^[0-9a-f]{40}$" },
        "harness": {
          "type": "object",
          "additionalProperties": false,
          "required": ["runner"],
          "properties": {
            "runner": { "type": "string", "minLength": 1 },
            "command": { "type": "string", "minLength": 1 },
            "notes": { "type": "string", "maxLength": 2000 }
          }
        }
      }
    },
    "handoff": {
      "type": "object",
      "additionalProperties": false,
      "required": ["finding_id", "extractable_usd", "source", "recorded_at"],
      "description": "the P1 handoff: the confirmed finding on this control target and the extractable figure the Phase 2 spike (P1 plan Task 10) consumes. It lives on the control target's own record so the two plans' dependency is one file, not a paragraph",
      "properties": {
        "finding_id": { "type": "string", "pattern": "^F-[0-9a-f]{6,16}$" },
        "extractable_usd": { "type": "number", "exclusiveMinimum": 0 },
        "source": { "type": "string", "minLength": 1 },
        "recorded_at": { "type": "string", "minLength": 20 },
        "recorded_by": { "type": "string", "minLength": 1 }
      }
    },
```

Run `python3 scripts/sync-asset-manifest.py` and `GOCACHE=$PWD/.scratch/gocache go test ./assets ./internal/regression -count=1`. Expected: PASS (the existing target tests still pass — new optional keys change no existing record).

- [ ] **Step 2: Write the failing tests**

Create `internal/regression/control_test.go`:

```go
package regression

import (
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

const (
	shaPre  = "1111111111111111111111111111111111111111"
	shaPost = "2222222222222222222222222222222222222222"
)

func controlTarget(t *testing.T, c *state.Campaign) string {
	t.Helper()
	target, err := AddTarget(c, TargetSpec{
		Kind: "control", Program: "Exploited Protocol",
		RecordID: "exploited-protocol", Repo: "org/exploited-protocol",
		Shape: "already-exploited", CommitHint: shaPre,
	})
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(target, "target_id")
}

func TestRecordControlRefusesAnUncitedOrUnpinnedIncident(t *testing.T) {
	c := regressionCampaign(t, "C-regctlrefuse1")
	tid := controlTarget(t, c)
	good := ControlSpec{
		TargetID: tid, IncidentURL: "https://example.test/incident",
		IncidentDate: "2025-09-01", LossUSD: 12500000,
		LossSource: "post-mortem §2 (recovered funds excluded)",
		PrePatchSHA: shaPre, PatchSHA: shaPost,
		HarnessRunner: "foundry", HarnessCommand: "forge test --match-test test_exploit",
	}
	cases := []struct {
		name string
		mut  func(*ControlSpec)
		want string
	}{
		{"no loss citation", func(s *ControlSpec) { s.LossSource = "" }, "loss_source"},
		{"no incident url", func(s *ControlSpec) { s.IncidentURL = "" }, "incident"},
		{"zero loss", func(s *ControlSpec) { s.LossUSD = 0 }, "loss_usd"},
		{"no pre-patch pin", func(s *ControlSpec) { s.PrePatchSHA = "main" }, "pre-patch"},
		{"pre-patch equals patch", func(s *ControlSpec) { s.PatchSHA = shaPre }, "same commit"},
		{"no harness", func(s *ControlSpec) { s.HarnessRunner = "" }, "harness"},
	}
	for _, tc := range cases {
		spec := good
		tc.mut(&spec)
		if _, err := RecordControl(c, spec); err == nil ||
			!strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want a refusal naming %q", tc.name, err, tc.want)
		}
	}
	doc, err := RecordControl(c, good)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(validation.ObjAt(doc, "control"), "pre_patch_sha"); got != shaPre {
		t.Fatalf("pre_patch_sha = %q, want %q", got, shaPre)
	}
	if got := validation.ObjAt(validation.ObjAt(doc, "incident"), "loss_usd"); got.F != 12500000 {
		t.Fatalf("loss_usd = %v, want 12500000", got)
	}
}

// TestRecordHandoffRequiresAConfirmedFinding is the P1 dependency as a test:
// the spike needs "one already-confirmed finding", so a handoff naming a
// finding that is not CONFIRMED is refused. The positive case stamps CONFIRMED
// through the store's own writer — reaching it through findings.Transition
// needs E5 evidence and a sandbox, which is the operator step's job, not this
// test's; what is under test here is the shape of a CONFIRMED finding.
func TestRecordHandoffRequiresAConfirmedFinding(t *testing.T) {
	c := regressionCampaign(t, "C-reghandoff001")
	tid := controlTarget(t, c)
	payload := validation.VObj(
		kv("title", validation.VStr("Reentrancy drains the vault")),
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("reentrancy")),
			kv("description", validation.VStr("the mechanism described in detail here")),
		)),
		kv("affected", validation.VArr(validation.VObj(
			kv("path", validation.VStr("src/V.sol")),
			kv("function", validation.VStr("withdraw")),
		))),
		kv("attacker", validation.VObj(
			kv("profile", validation.VStr("arbitrary EOA")),
			kv("capabilities", validation.VArr()),
		)),
	)
	finding, err := findings.IngestHypothesis(c, payload, "code", "control", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(finding, "finding_id")

	// Not CONFIRMED yet: refused, and the refusal names the status.
	_, err = RecordHandoff(c, HandoffSpec{
		TargetID: tid, FindingID: fid, ExtractableUSD: 900000,
		Source: "reproduction on the pre-patch commit", RecordedBy: "operator",
	})
	if err == nil || !strings.Contains(err.Error(), "status") {
		t.Fatalf("err = %v, want a refusal naming the finding's status", err)
	}

	// Stamp CONFIRMED through the store's writer.
	moved := finding
	moved.O = validation.SetOrAppend(moved.O, "status", validation.VStr("CONFIRMED"))
	if err := findings.SaveFinding(c, &moved); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordHandoff(c, HandoffSpec{
		TargetID: tid, FindingID: fid, ExtractableUSD: 0,
		Source: "s", RecordedBy: "operator",
	}); err == nil || !strings.Contains(err.Error(), "extractable_usd") {
		t.Fatalf("err = %v, want a refusal naming extractable_usd", err)
	}
	doc, err := RecordHandoff(c, HandoffSpec{
		TargetID: tid, FindingID: fid, ExtractableUSD: 900000,
		Source: "reproduction on the pre-patch commit", RecordedBy: "operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	ho := validation.ObjAt(doc, "handoff")
	if got := validation.ObjStr(ho, "finding_id"); got != fid {
		t.Fatalf("handoff.finding_id = %q, want %q", got, fid)
	}
	if got := validation.ObjFloat(ho, "extractable_usd"); got != 900000 {
		t.Fatalf("handoff.extractable_usd = %v, want 900000", got)
	}
	// A handoff on a non-control target is refused: the handoff is the control
	// target's own artefact, not a general-purpose note.
	other, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RecordHandoff(c, HandoffSpec{
		TargetID: validation.ObjStr(other, "target_id"), FindingID: fid,
		ExtractableUSD: 1, Source: "s", RecordedBy: "operator",
	}); err == nil || !strings.Contains(err.Error(), "control") {
		t.Fatalf("err = %v, want a refusal naming the control kind", err)
	}
}
```

`validation.ObjFloat` may not exist — check `rg -n 'func ObjFloat' internal/jval/`; if it does not, read the value with `validation.ObjAt(ho, "extractable_usd").F`. Do not add an accessor for one test.

- [ ] **Step 3: Run them to verify they fail**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/regression -run 'RecordControl|RecordHandoff' -count=1`

Expected: FAIL to compile — `undefined: ControlSpec`, `undefined: RecordControl`, `undefined: HandoffSpec`, `undefined: RecordHandoff`.

- [ ] **Step 4: Implement the control record and the handoff**

Create `internal/regression/control.go`:

```go
package regression

import (
	"fmt"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ControlSpec is one already-exploited control target (§3a): separately
// sourced, pinned to a PRE-PATCH commit, with its own harness and the public
// loss figure plus its citation.
type ControlSpec struct {
	TargetID      string
	IncidentURL   string
	IncidentDate  string
	LossUSD       float64
	LossSource    string
	PostmortemURL string
	PrePatchSHA   string
	PatchSHA      string
	HarnessRunner string
	HarnessCommand string
}

// RecordControl attaches the control block to an already-registered target of
// kind "control". Every refusal here is a way the control target could look
// finished while proving nothing.
func RecordControl(c *state.Campaign, spec ControlSpec) (validation.Value, error) {
	target, ok, err := Target(c, spec.TargetID)
	if err != nil {
		return validation.VNull(), err
	}
	if !ok {
		return validation.VNull(), fmt.Errorf("no target %s in campaign %s",
			spec.TargetID, c.CampaignID)
	}
	if got := validation.ObjStr(target, "kind"); got != "control" {
		return validation.VNull(), fmt.Errorf(
			"target %s is kind %q — the control block belongs to a control target",
			spec.TargetID, got)
	}
	if spec.IncidentURL == "" || spec.IncidentDate == "" {
		return validation.VNull(), fmt.Errorf(
			"the incident needs --incident-url and --incident-date: the control " +
				"target is sourced from a published record, and an unsourced one " +
				"is just a guess with a pin")
	}
	if spec.LossUSD <= 0 {
		return validation.VNull(), fmt.Errorf(
			"incident loss_usd must be positive (got %v)", spec.LossUSD)
	}
	if spec.LossSource == "" {
		return validation.VNull(), fmt.Errorf(
			"the incident loss figure needs --loss-source: an uncited number is " +
				"the fact this suite refuses everywhere else")
	}
	if !sha40Re.MatchString(spec.PrePatchSHA) {
		return validation.VNull(), fmt.Errorf(
			"the pre-patch pin %q is not a 40-hex commit — §3a requires a pinned " +
				"PRE-PATCH commit, and a ref is not a pin", spec.PrePatchSHA)
	}
	if !sha40Re.MatchString(spec.PatchSHA) {
		return validation.VNull(), fmt.Errorf(
			"the patch pin %q is not a 40-hex commit", spec.PatchSHA)
	}
	if spec.PrePatchSHA == spec.PatchSHA {
		return validation.VNull(), fmt.Errorf(
			"pre-patch and patch SHAs are the same commit (%s) — nobody pinned "+
				"the vulnerable revision", spec.PrePatchSHA)
	}
	if spec.HarnessRunner == "" {
		return validation.VNull(), fmt.Errorf(
			"the control target needs its own harness (--harness-runner): §3a is " +
				"explicit that it will not run under ScaBench's baseline runner")
	}
	incident := validation.VObj(
		kv("url", validation.VStr(spec.IncidentURL)),
		kv("date", validation.VStr(spec.IncidentDate)),
		kv("loss_usd", validation.VFloat(spec.LossUSD)),
		kv("loss_source", validation.VStr(spec.LossSource)),
	)
	if spec.PostmortemURL != "" {
		incident.O = validation.SetOrAppend(incident.O, "postmortem_url",
			validation.VStr(spec.PostmortemURL))
	}
	harness := validation.VObj(kv("runner", validation.VStr(spec.HarnessRunner)))
	if spec.HarnessCommand != "" {
		harness.O = validation.SetOrAppend(harness.O, "command",
			validation.VStr(spec.HarnessCommand))
	}
	control := validation.VObj(
		kv("pre_patch_sha", validation.VStr(spec.PrePatchSHA)),
		kv("patch_sha", validation.VStr(spec.PatchSHA)),
		kv("harness", harness),
	)
	doc := copyTargetWithKeys(target, []validation.KV{
		kv("incident", incident), kv("control", control),
	})
	data := validation.VObj(
		kv("target_id", validation.VStr(spec.TargetID)),
		kv("incident_url", validation.VStr(spec.IncidentURL)),
		kv("loss_usd", validation.VFloat(spec.LossUSD)),
		kv("pre_patch_sha", validation.VStr(spec.PrePatchSHA)),
		kv("patch_sha", validation.VStr(spec.PatchSHA)),
	)
	tid := spec.TargetID
	return writeThenLog(c, targetPath(c, tid), doc, "regression_target",
		"regression.control.recorded", &tid, data)
}

// HandoffSpec is the P1 handoff: which confirmed finding on the control
// target, and the extractable figure P1's Task 10 spike consumes.
type HandoffSpec struct {
	TargetID      string
	FindingID     string
	ExtractableUSD float64
	Source        string
	RecordedBy    string
}

// RecordHandoff records the control target's handoff. Three refusals, all of
// them the P1 dependency stated as code: the target must be the control
// target, the finding must EXIST, and it must be CONFIRMED — because P1's
// Phase 2 exit criterion says "one already-confirmed finding", and a handoff
// naming a POSSIBLE finding would re-create exactly the blocker this task
// exists to remove.
func RecordHandoff(c *state.Campaign, spec HandoffSpec) (validation.Value, error) {
	target, ok, err := Target(c, spec.TargetID)
	if err != nil {
		return validation.VNull(), err
	}
	if !ok {
		return validation.VNull(), fmt.Errorf("no target %s in campaign %s",
			spec.TargetID, c.CampaignID)
	}
	if got := validation.ObjStr(target, "kind"); got != "control" {
		return validation.VNull(), fmt.Errorf(
			"target %s is kind %q — the P1 handoff belongs to the control target",
			spec.TargetID, got)
	}
	if _, ok := validation.ObjAt(target, "control").O, true; !hasKey(target, "control") {
		return validation.VNull(), fmt.Errorf(
			"control target %s has no control block yet — record the incident and "+
				"the pre-patch pin first", spec.TargetID)
	}
	finding, err := findings.LoadFinding(c, spec.FindingID)
	if err != nil {
		return validation.VNull(), fmt.Errorf(
			"handoff names finding %s, which this campaign does not have: %w",
			spec.FindingID, err)
	}
	if got := validation.ObjStr(finding, "status"); got != "CONFIRMED" {
		return validation.VNull(), fmt.Errorf(
			"finding %s has status %q, not CONFIRMED — the Phase 2 spike needs one "+
				"already-confirmed finding, so a handoff for a %s finding would "+
				"leave P1 Task 10 blocked", spec.FindingID, got, got)
	}
	if spec.ExtractableUSD <= 0 {
		return validation.VNull(), fmt.Errorf(
			"handoff extractable_usd must be positive (got %v)",
			spec.ExtractableUSD)
	}
	if spec.Source == "" {
		return validation.VNull(), fmt.Errorf(
			"the handoff needs --source: how the extractable figure was derived")
	}
	handoff := validation.VObj(
		kv("finding_id", validation.VStr(spec.FindingID)),
		kv("extractable_usd", validation.VFloat(spec.ExtractableUSD)),
		kv("source", validation.VStr(spec.Source)),
		kv("recorded_at", validation.VStr(state.NowIso())),
	)
	if spec.RecordedBy != "" {
		handoff.O = validation.SetOrAppend(handoff.O, "recorded_by",
			validation.VStr(spec.RecordedBy))
	}
	doc := copyTargetWithKeys(target, []validation.KV{kv("handoff", handoff)})
	data := validation.VObj(
		kv("target_id", validation.VStr(spec.TargetID)),
		kv("finding_id", validation.VStr(spec.FindingID)),
		kv("extractable_usd", validation.VFloat(spec.ExtractableUSD)),
		kv("source", validation.VStr(spec.Source)),
	)
	tid := spec.TargetID
	return writeThenLog(c, targetPath(c, tid), doc, "regression_target",
		"regression.control.handoff", &tid, data)
}

// hasKey reports whether an ordered object carries a key. `validation.HasKey`
// does the same thing; this local copy exists only so the package's readers do
// not have to know that jval's export is spelled HasObjKey. The audit section's
// copy (Task 2 Step 8) is named hasKeyS because it lives in a different package
// and the two are never visible together.
func hasKey(v validation.Value, key string) bool {
	for _, kvp := range v.O {
		if kvp.K == key {
			return true
		}
	}
	return false
}

// copyTargetWithKeys returns the target document with extra keys appended in
// the order given, preserving every existing key's position.
func copyTargetWithKeys(target validation.Value, extra []validation.KV) validation.Value {
	out := validation.VObj()
	out.O = append(out.O, target.O...)
	for _, kvp := range extra {
		out.O = validation.SetOrAppend(out.O, kvp.K, kvp.V)
	}
	return out
}
```

Delete the dead `if _, ok := validation.ObjAt(target, "control").O, true; !hasKey(...)` line — it is a typo trap in this plan's own draft; the real guard is the `hasKey(target, "control")` check alone:

```go
	if !hasKey(target, "control") {
		return validation.VNull(), fmt.Errorf(
			"control target %s has no control block yet — record the incident and "+
				"the pre-patch pin first", spec.TargetID)
	}
```

- [ ] **Step 5: Run the tests**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/regression -count=1`

Expected: PASS, including the six refusal cases and the two handoff refusals.

- [ ] **Step 6: Wire the two CLI subcommands and the audit problem lines**

In `internal/cli/cmd_regress.go`, add `"add-control"` and `"handoff"` to the `target` switch, and the two flag sets to `valueFlags`: `--incident-url`, `--incident-date`, `--loss-usd`, `--loss-source`, `--postmortem-url`, `--pre-patch-sha`, `--patch-sha`, `--harness-runner`, `--harness-command`, `--finding`, `--extractable-usd`, `--source`. The handlers:

```go
func regressTargetAddControl(c *state.Campaign, vals map[string]string, r *Runner) error {
	// The target row first (kind=control, shape=already-exploited), then the
	// control block — two records, because the target is a target even before
	// its incident is sourced, and the audit section must be able to say so.
	target, err := regression.AddTarget(c, regression.TargetSpec{
		Kind: "control", Program: vals["--program"],
		RecordID: vals["--record-id"], Repo: vals["--repo"],
		Shape: "already-exploited", CommitHint: vals["--pre-patch-sha"],
	})
	if err != nil {
		return err
	}
	loss, err := strconv.ParseFloat(vals["--loss-usd"], 64)
	if err != nil {
		return t14ArgparseErr(regressUsage, "regress",
			"argument --loss-usd: invalid float value: %q", vals["--loss-usd"])
	}
	doc, err := regression.RecordControl(c, regression.ControlSpec{
		TargetID: validation.ObjStr(target, "target_id"),
		IncidentURL: vals["--incident-url"], IncidentDate: vals["--incident-date"],
		LossUSD: loss, LossSource: vals["--loss-source"],
		PostmortemURL: vals["--postmortem-url"],
		PrePatchSHA: vals["--pre-patch-sha"], PatchSHA: vals["--patch-sha"],
		HarnessRunner: vals["--harness-runner"], HarnessCommand: vals["--harness-command"],
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "control target %s recorded (pre-patch %s)\n",
		validation.ObjStr(doc, "target_id"), vals["--pre-patch-sha"])
	return nil
}

func regressTargetHandoff(c *state.Campaign, tid string, vals map[string]string, r *Runner) error {
	usd, err := strconv.ParseFloat(vals["--extractable-usd"], 64)
	if err != nil {
		return t14ArgparseErr(regressUsage, "regress",
			"argument --extractable-usd: invalid float value: %q",
			vals["--extractable-usd"])
	}
	doc, err := regression.RecordHandoff(c, regression.HandoffSpec{
		TargetID: tid, FindingID: vals["--finding"], ExtractableUSD: usd,
		Source: vals["--source"], RecordedBy: vals["--actor"],
	})
	if err != nil {
		return err
	}
	ho := validation.ObjAt(doc, "handoff")
	fmt.Fprintf(r.Out, "handoff recorded: target %s -> finding %s, "+
		"extractable_usd=%s (P1 Task 10 consumes this)\n", tid,
		validation.ObjStr(ho, "finding_id"),
		validation.ObjFloatText(ho, "extractable_usd"))
	return nil
}
```

`validation.ObjFloatText` does not exist either — print with `fmt.Fprintf(r.Out, "%v", validation.ObjAt(ho, "extractable_usd").F)` and do not add an accessor.

In `internal/audit/sections/regressionsuite.go`, extend the per-target switch and add two problems for a control target:

```go
		if validation.ObjStr(t, "kind") == "control" {
			if !hasKeyS(t, "control") {
				problems = append(problems, validation.VStr(fmt.Sprintf(
					"control target %s carries no control block (incident + pre-patch "+
						"pin + harness) — §3a's control target is sourced separately, "+
						"pinned pre-patch and run under its own harness", tid)))
			}
			if !hasKeyS(t, "handoff") {
				problems = append(problems, validation.VStr(fmt.Sprintf(
					"control target %s carries no P1 handoff — the Phase 2 spike's "+
						"extraction half stays blocked until a CONFIRMED finding and "+
						"its extractable_usd are recorded here", tid)))
			}
		}
```

with the local helper (duplicated on purpose, four lines):

```go
// hasKeyS reports whether an ordered object carries a key.
func hasKeyS(v validation.Value, key string) bool {
	for _, kvp := range v.O {
		if kvp.K == key {
			return true
		}
	}
	return false
}
```

Add `--json`-visible fields for the control rows so `status` and the audit show the handoff: `KV("control_pre_patch_sha", ...)`, `KV("handoff_finding_id", ...)`, `KV("handoff_extractable_usd", ...)` (empty string when absent — a section may not print a zero that reads as a measurement).

- [ ] **Step 7: Run the CLI + audit tests, then the whole suite**

```bash
GOCACHE=$PWD/.scratch/gocache go test ./internal/regression ./internal/audit/... ./internal/cli -count=1
GOCACHE=$PWD/.scratch/gocache go test ./... -count=1
```

Expected: PASS. Add to `internal/cli/cmd_regress_test.go` one test that `target add-control` without `--loss-source` exits 1 and names `loss_source`, and one that a handoff for a non-CONFIRMED finding exits 1 — the same refusals as Step 2, now through the verb.

- [ ] **Step 8: Operator step — source the control target (needs network)**

```bash
# 1. Pick ONE project that was publicly exploited AND has a published record.
#    §3a: audit data, not incident data — so the source is a contest/post-mortem
#    pair, and the pre-patch commit is the revision the exploit landed on.
# 2. Mirror and resolve the pre-patch commit (same three commands as Task 1
#    Step 21; the patch commit comes from the project's fix PR).
webv2 --root "$WEBV2_P0_DIR/root" init --program '<exploited project>'
webv2 --root "$WEBV2_P0_DIR/root" snap <cid> "$WEBV2_P0_DIR/target/<repo>-prepatch"
webv2 --root "$WEBV2_P0_DIR/root" regress <cid> target add-control \
    --program '<project>' --record-id '<slug>' --repo '<org>/<repo>' \
    --incident-url '<published record>' --incident-date '<YYYY-MM-DD>' \
    --loss-usd '<figure>' --loss-source '<where the figure comes from>' \
    --postmortem-url '<url>' --pre-patch-sha '<40-hex>' --patch-sha '<40-hex>' \
    --harness-runner '<foundry|hardhat|custom>' \
    --harness-command '<the command that demonstrates the exploit>'
webv2 --root "$WEBV2_P0_DIR/root" regress <cid> target pin <T-id> \
    --resolved-sha '<40-hex pre-patch>' --snapshot '<src-id>' --actor "$(whoami)"
# 3. run the control target's OWN harness at the pre-patch pin
cd "$WEBV2_P0_DIR/target/<repo>-prepatch" && <harness command>
# 4. ingest the finding and confirm it. The externally-reported exec record is
#    the sanctioned docker-free path (see scripts/verify-full.sh seed_p2_exec
#    for the exact record shape) — the operator runs the exploit by hand, then
#    records what ran.
webv2 --root "$WEBV2_P0_DIR/root" ingest <cid> --json-file finding.json \
    --trajectory code --stage control
webv2 --root "$WEBV2_P0_DIR/root" artifact-register <cid> '<exec record dir>' --kind report
webv2 --root "$WEBV2_P0_DIR/root" mint <cid> <F-id> --exec <EXEC-id> \
    --description '<what ran, at which pinned commit>' --tier T2 --type foundry-test
webv2 --root "$WEBV2_P0_DIR/root" verdict <cid> <F-id> --verdict confirmed \
    --reason 'reproduced at the pre-patch pin'
# 5. the handoff P1 consumes
webv2 --root "$WEBV2_P0_DIR/root" regress <cid> target handoff <T-id> \
    --finding <F-id> --extractable-usd '<figure>' \
    --source '<how the figure was derived>' --actor "$(whoami)"
webv2 --root "$WEBV2_P0_DIR/root" audit <cid> --json
```

**Record** in `docs/gates/v16-P0-control-target.md`, in the `docs/gates/v16-P1.md` style (verified vs not):

```markdown
# v1.6 Phase 0 — the already-exploited control target

**Verdict: <OPERATOR-RUN | NOT RUN — offline>.**

## 1. The target
program / repo / pre-patch SHA / patch SHA / snapshot id / the four `regress`
commands as run, with the `audit --json` `regression_suite` section pasted.

## 2. The incident and its citation
the incident url, date, loss figure, and `loss_source` verbatim. If the figure
could not be sourced, say so — an uncited number is refused by the writer, so
its presence here means it was cited somewhere.

## 3. The harness
the runner, the exact command, the commit it ran at, and what it printed.

## 4. The P1 handoff (the point of this task)
campaign id, finding id, `extractable_usd`, its `source`, the status of the
finding as `audit` reports it.

**What this unblocks:** P1's Phase 2 extraction half, which
`docs/gates/v16-P1.md` §7b recorded as blocked on "a mainnet fork RPC URL and
its pinned block number ... plus one already-confirmed finding on a real
target". This record supplies the second half. `FORK_RPC_URL` remains unset,
so P1 Task 10 Step 3 still cannot run — say exactly that, and nothing more.

## 5. What this does NOT prove
one incident is not a detection rate; the control target exercises the
PATCHED-KNOWN path (§C7.2), not novelty; and `extractable_usd` here is the
framework's figure for one finding, not a general claim.
```

- [ ] **Step 9: Commit**

```bash
git add assets/schema/regression_target.schema.json assets/testdata/asset_manifest.json \
        internal/regression/control.go internal/regression/control_test.go \
        internal/cli/cmd_regress.go internal/cli/cmd_regress_test.go \
        internal/audit/sections/regressionsuite.go docs/gates/v16-P0-control-target.md
git commit -m "feat(v16-p0): already-exploited control target and the P1 spike handoff"
```

---

### Task 3: Derived labels — bucketing title+description onto the taxonomy

§3a, verbatim:

> **Composition.** ScaBench's `curated-2025-08-18` ground truth has exactly four fields per vulnerability — `finding_id`, `severity`, `title`, `description` — no class label, no taxonomy; severity is `high|medium|low` only. Class labels are derived by bucketing the 114 `high` findings onto ARGUS's 23-class taxonomy from title plus description, then picking six targets by greedy set-cover over the derived classes, **weighted by gold-finding count** — 114 high findings across 31 projects is under four per project, so an unweighted pick of six yields maybe 15–25 gold findings and per-class measurements at n≈1–3; a target with one gold finding costs the same checkout and yields almost no signal.

> The label-bucketing is our own classification, not ScaBench's — a named source of error (Part 10).

**Measured against the real snapshot, three claims in that quote are wrong** (commands in *Operator prerequisites §7 — The dataset, as it actually is*; re-run them, do not trust this paragraph):

| §3a says | the snapshot says | what it changes here |
|---|---|---|
| "severity is `high\|medium\|low` only" | there is a fourth value, **`informational`** (20 rows); the 555 rows are 114 high / 237 medium / 184 low / 20 informational | the label file is the **114 `high` rows only**, and `DeriveLabels` refuses anything else rather than silently counting a medium as gold |
| "exactly four fields per vulnerability" | true **of the vulnerability record**, but the record is **nested**: the file is a list of 31 projects, each with `codebases[]` and `vulnerabilities[]`, and the commit lives on the **codebase** | the extractor walks projects → vulnerabilities and joins in **`project_id`** (selection is per project) and **`codebase_id`** (a checkout is per codebase); a flat read of the file does not work |
| "114 high findings across 31 projects is under four per project" | the mean is 3.68, but it is **not a bound**: median 2, **max 12** (MANTRA DEX), and **11 of 31 projects carry 4 or more** | the fixture and the "unweighted pick" arithmetic below are corrected; the weighting argument survives, the number does not |

The fourth claim — "bucketing the 114 `high` findings" — **verifies exactly: 114**. And §3a's "an unweighted pick of six yields maybe 15–25 gold findings" is true only of a *random* six (E[gold] = 6 × 3.68 ≈ 22); the six projects with the most high findings carry **54 of 114** (MANTRA DEX 12, Cork Protocol 11, Coded Estate 9, Oku 8, BakerFi 7, Perennial V2 7). So "weighted beats unweighted" is **not** a claim that weighting finds more findings than picking the biggest — it is a claim that weighting buys *class coverage per checkout*, and Task 4's fixture must be built to show that, not to show a count.

The repo already agrees with the first sentence, in its own words — `internal/taxonomy/testdata/config/taxonomy_scabench.yaml`:

> The ScaBench curated snapshot carries NO category labels (each finding is exactly {finding_id, severity, title, description}), so this map is deliberately a no-op: every finding ingests as bug_class 'unmapped'.

**Do not touch that map.** It describes the *ingest* path, where a dataset label is normalized; ScaBench has none, so `unmapped` is correct there. This task builds the *separate* classification §3a asks for: a reviewed, deterministic rule table over title+description whose output is a committed label file, so selection can be re-derived and argued with.

**Offline vs operator, in this task.**
- **Built and tested offline (Steps 1–6):** the rule table, the classifier, the vocabulary pin against `taxonomy.CanonicalClasses()`, the coverage arithmetic, the label-file schema and the sidecar writer, the repo-level CLI action.
- **Operator step (Step 7, needs the dataset):** extract the 114 `high` rows from the snapshot (**project → vulnerabilities, `severity == "high"`, `project` = `project_id`**), run the classifier, **review the `unmapped` bucket by hand** (that review is the named source of error, so it is recorded, not implied), commit the extracted rows and the label file.

**Files:**
- Create: `assets/schema/regression_labels.schema.json`
- Create: `internal/regression/repofile.go`
- Create: `internal/regression/labels.go`
- Create: `internal/regression/labels_test.go`
- Modify: `internal/cli/cmd_regress.go` (repo-level `labels` action)
- Modify: `internal/validation/schema.go` (append `"regression_labels"`)
- Modify: `assets/testdata/asset_manifest.json` (regenerated)

**Interfaces:**
- Consumes: `taxonomy.CanonicalClasses() map[string]struct{}`, `validation.{ParseOrdered,ReadJson,Sha256File,Sha256Hex}`, `state.NowIso`.
- Produces: `regression.LabelRule{Class string, Phrases []string}`, `regression.LabelRules []LabelRule`, `regression.Classify(title, description string) (class string, rule string)`, `regression.DeriveLabels(rows []validation.Value, dataset, snapshotDate string) (validation.Value, error)`, `regression.LoadLabels(path string) (validation.Value, error)`, `regression.WriteRepoRecord(path string, doc validation.Value, schema string) error`, `regression.ReadRepoRecord(path string) (validation.Value, error)`, and the label-file keys `{dataset, snapshot_date, created_at, rows[], counts{}, unmapped_reviewed, schema_version}`. Task 4 consumes `rows[].{finding_id, class, severity}`.

- [ ] **Step 1: Write the label-file schema**

Create `assets/schema/regression_labels.schema.json`. The rows carry `rule` — *which* rule fired — because a classification nobody can re-derive is an opinion:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://web3sec.local/schema/regression_labels.schema.json",
  "title": "WebSec Regression Derived Labels",
  "description": "The derived class labels for one ScaBench snapshot (§3a: the snapshot carries no class label, so the labels are OUR classification and a named source of error). This file is the reviewable artefact between the dataset and the set-cover picker: it is deterministic from the rule table in internal/regression/labels.go, it records WHICH rule fired per row, and it records whether a human reviewed the rows no rule matched. 'unmapped' is a legitimate value — it means the rule table did not classify this row, which is information, not a failure.",
  "type": "object",
  "additionalProperties": false,
  "required": ["dataset", "snapshot_date", "created_at", "rows", "counts", "schema_version"],
  "properties": {
    "dataset": { "type": "string", "minLength": 1 },
    "snapshot_date": { "type": "string", "minLength": 10 },
    "created_at": { "type": "string", "minLength": 20 },
    "rows": {
      "type": "array",
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["finding_id", "project", "severity", "class", "rule"],
        "properties": {
          "finding_id": { "type": "string", "minLength": 1 },
          "project": {
            "type": "string",
            "minLength": 1,
            "description": "the dataset's `project_id` for this row, joined in by the extractor — the vulnerability record carries no project of its own. Selection is by PROJECT (\"picking six targets\", \"hold out by project\"), so this is the picker's key and it must be the id, not the display name (one project's `name` is '2024.09.13 - Final - Perennial V2 Update 3 Audit Report'; the ids are stable slugs)"
          },
          "severity": {
            "enum": ["high", "medium", "low", "informational"],
            "description": "the dataset's real severity vocabulary, all four values (measured: 114 high, 237 medium, 184 low, 20 informational). The enum lists all four because they are the literals the producer emits; THIS FILE carries only the 114 `high` rows, which is what makes `gold_findings` in the selection mean gold. `DeriveLabels` enforces the high-only scope; the enum exists so the schema never contradicts the producer"
          },
          "class": { "type": "string", "pattern": "^[a-z0-9-]{3,64}$" },
          "rule": {
            "type": "string",
            "description": "the phrase that fired, or 'unmapped' when nothing matched"
          }
        }
      }
    },
    "counts": {
      "type": "object",
      "additionalProperties": { "type": "integer", "minimum": 0 },
      "description": "class -> row count, including the 'unmapped' bucket"
    },
    "unmapped_reviewed": {
      "type": "boolean",
      "description": "true only after a human read every 'unmapped' row and decided to leave it unmapped (or extended the rule table and re-ran). Absent or false means the labels are machine output nobody has looked at"
    },
    "reviewed_by": { "type": "string", "minLength": 1 },
    "schema_version": { "const": 1 }
  }
}
```

- [ ] **Step 2: Write the failing tests**

Create `internal/regression/labels_test.go`:

```go
package regression

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/taxonomy"
	"websec/internal/validation"
)

// TestLabelRulesNameOnlyCanonicalClasses is the realism law applied to the
// vocabulary: the rule table and taxonomy.CanonicalClasses() are two
// vocabularies that must agree, so the test reads BOTH and pins them equal.
// It also records the live size — framework-plan-v1.6 §3a says "23-class
// taxonomy" and the live set is larger, so this assertion is where that
// discrepancy would bite.
func TestLabelRulesNameOnlyCanonicalClasses(t *testing.T) {
	canonical := taxonomy.CanonicalClasses()
	if len(canonical) == 0 {
		t.Fatal("taxonomy.CanonicalClasses() is empty — the pin would be vacuous")
	}
	if len(LabelRules) == 0 {
		t.Fatal("LabelRules is empty — a classifier with no rules maps everything " +
			"to unmapped and the set-cover has nothing to cover")
	}
	for _, rule := range LabelRules {
		if _, ok := canonical[rule.Class]; !ok {
			t.Errorf("LabelRule %q names class %q, which is not in the canonical "+
				"taxonomy — the labels would not join to anything downstream",
				rule.Phrases[0], rule.Class)
		}
		if len(rule.Phrases) == 0 {
			t.Errorf("LabelRule for %q has no phrases", rule.Class)
		}
		for _, p := range rule.Phrases {
			if strings.TrimSpace(p) == "" || len(strings.Fields(p)) == 0 {
				t.Errorf("LabelRule for %q carries an empty phrase", rule.Class)
			}
		}
	}
}

func TestClassifyIsDeterministicAndCaseInsensitive(t *testing.T) {
	class, rule := Classify("Reentrancy in withdraw()", "the callback re-enters before the balance is written")
	if class == "unmapped" {
		t.Fatalf("the reentrancy rule did not fire (rule=%q) — either the rule "+
			"table lost its entry or Classify's matching broke", rule)
	}
	again, againRule := Classify("Reentrancy in withdraw()", "the callback re-enters before the balance is written")
	if class != again || rule != againRule {
		t.Fatalf("Classify is not deterministic: (%q,%q) then (%q,%q)",
			class, rule, again, againRule)
	}
	upper, _ := Classify("REENTRANCY IN WITHDRAW()", "THE CALLBACK RE-ENTERS")
	if upper != class {
		t.Fatalf("case changed the class: %q vs %q", upper, class)
	}
	if got, _ := Classify("Deposit works as documented", "nothing unusual"); got != "unmapped" {
		t.Fatalf("an unmatched row = %q, want unmapped", got)
	}
}

func TestDeriveLabelsRefusesARowMissingTheDatasetsFields(t *testing.T) {
	good := validation.VObj(
		kv("finding_id", validation.VStr("S-1")),
		kv("project", validation.VStr("acme-vault")),
		kv("severity", validation.VStr("high")),
		kv("title", validation.VStr("Reentrancy in withdraw")),
		kv("description", validation.VStr("the callback re-enters before the write")),
	)
	// §3a: the snapshot has "exactly four fields per vulnerability" — plus the
	// project the extractor joins in (the row's own file), which selection needs.
	for _, missing := range []string{
		"finding_id", "project", "severity", "title", "description",
	} {
		bad := validation.VObj()
		for _, kvp := range good.O {
			if kvp.K != missing {
				bad.O = append(bad.O, kvp)
			}
		}
		if _, err := DeriveLabels([]validation.Value{bad}, "scabench", "2025-08-18"); err == nil ||
			!strings.Contains(err.Error(), missing) {
			t.Errorf("missing %s: err = %v, want a refusal naming it", missing, err)
		}
	}
	labels, err := DeriveLabels([]validation.Value{good}, "scabench", "2025-08-18")
	if err != nil {
		t.Fatal(err)
	}
	counts := validation.ObjAt(labels, "counts")
	if len(counts.O) == 0 {
		t.Fatal("counts is empty")
	}
	if got := validation.ObjAt(labels, "rows").A[0]; validation.ObjStr(got, "class") != "reentrancy" {
		t.Fatalf("class = %q, want reentrancy", validation.ObjStr(got, "class"))
	}
}

// TestRepoRecordRoundTripsWithItsSidecar: the label file and its sha256
// sidecar are written together, and a hand edit is detectable.
func TestRepoRecordRoundTripsWithItsSidecar(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labels.json")
	doc, err := DeriveLabels([]validation.Value{validation.VObj(
		kv("finding_id", validation.VStr("S-1")),
		kv("project", validation.VStr("acme-oracle")),
		kv("severity", validation.VStr("high")),
		kv("title", validation.VStr("Oracle price is stale")),
		kv("description", validation.VStr("the stale oracle price is read without a freshness check")),
	)}, "scabench", "2025-08-18")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteRepoRecord(path, doc, "regression_labels"); err != nil {
		t.Fatal(err)
	}
	back, err := ReadRepoRecord(path)
	if err != nil {
		t.Fatal(err)
	}
	if validation.CanonSpaced(back) != validation.CanonSpaced(doc) {
		t.Fatal("the record did not round-trip")
	}
	// A hand edit is caught by the sidecar.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw[:len(raw)-2], []byte("  \n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadRepoRecord(path); err == nil {
		t.Fatal("ReadRepoRecord accepted a hand-edited file (sidecar mismatch)")
	}
}
```

- [ ] **Step 3: Run them to verify they fail**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/regression -run 'Label|Classify|Derive|RepoRecord' -count=1`

Expected: FAIL to compile — `undefined: LabelRules`, `undefined: Classify`, `undefined: DeriveLabels`, `undefined: WriteRepoRecord`, `undefined: ReadRepoRecord`.

- [ ] **Step 4: Implement the repo-level record helper**

Create `internal/regression/repofile.go`:

```go
package regression

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"websec/internal/validation"
)

// WriteRepoRecord writes one repo-level regression artefact plus its sha256
// sidecar, in the eval store's own discipline (internal/evalstore: cases.json
// + cases.sha256): the sidecar always describes the file just written, so a
// hand edit is detectable drift rather than silent truth. Used by the derived
// labels (Task 3) and the suite composition (Task 10).
func WriteRepoRecord(path string, doc validation.Value, schema string) error {
	if err := validation.Validate(doc, schema, 1); err != nil {
		return err
	}
	if err := validation.WriteJson(path, doc, ""); err != nil {
		return err
	}
	digest, err := validation.Sha256File(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path+".sha256", []byte(digest+"\n"), 0o644)
}

// ReadRepoRecord reads a repo-level artefact and verifies its sidecar. A
// missing sidecar is a refusal, not a warning: an unverifiable answer key or
// suite composition is exactly the drift the sidecar exists to catch.
func ReadRepoRecord(path string) (validation.Value, error) {
	raw, err := os.ReadFile(path + ".sha256")
	if err != nil {
		return validation.VNull(), fmt.Errorf(
			"%s has no sha256 sidecar (%v) — an unverifiable record is refused",
			path, err)
	}
	want := strings.TrimSpace(string(raw))
	got, err := validation.Sha256File(path)
	if err != nil {
		return validation.VNull(), err
	}
	if want != got {
		return validation.VNull(), fmt.Errorf(
			"%s has been edited since it was written (sidecar %s, file %s)",
			filepath.Base(path), want, got)
	}
	return validation.ReadJson(path)
}
```

- [ ] **Step 5: Implement the rule table and the classifier**

Create `internal/regression/labels.go`. The table below is a **starting point, not a finished classifier**: the operator extends it while reviewing the unmapped bucket (Step 7), and every extension is a diff in this file, reviewed like code:

```go
package regression

import (
	"fmt"
	"strings"

	"websec/internal/state"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

// LabelRule is one classification rule: a canonical class and the phrases
// whose presence in title+description assigns it. Phrases are matched
// case-folded, on word boundaries, longest-first — so a specific phrase beats
// a generic one regardless of table order.
type LabelRule struct {
	Class   string
	Phrases []string
}

// LabelRules is §3a's derived bucketing, as data. It is deliberately a
// starting table: ScaBench's snapshot carries no labels, so the classification
// is ours and a named source of error (Part 10). TestLabelRulesNameOnlyCanonical-
// Classes pins every Class to taxonomy.CanonicalClasses(), so a rule cannot
// name a class the framework does not have.
//
// Extend it by reviewing the `unmapped` bucket in a labels file (Task 3 Step 7)
// and adding the phrases the review found — never by guessing at scale.
var LabelRules = []LabelRule{
	{Class: "reentrancy", Phrases: []string{
		"reentran", "re-entran", "read-only reentrancy", "callback reenters"}},
	{Class: "oracle-manipulation", Phrases: []string{
		"oracle manipul", "price manipul", "stale price", "stale oracle",
		"spot price", "twap manipulation"}},
	{Class: "share-price-inflation", Phrases: []string{
		"share inflation", "first depositor", "donation attack",
		"inflate the share", "exchange rate manipulation"}},
	{Class: "precision-rounding", Phrases: []string{
		"rounding", "round down", "precision loss", "truncat", "integer division",
		"off-by-one in the accounting"}},
	{Class: "access-control", Phrases: []string{
		"missing access control", "missing onlyowner", "unprotected function",
		"anyone can call", "no authorization", "permissionless call"}},
	{Class: "liquidation-logic", Phrases: []string{
		"liquidation", "bad debt", "insolven", "underwater position",
		"health factor"}},
	{Class: "cross-chain-replay", Phrases: []string{
		"replay", "message replay", "same signature", "nonce reuse",
		"cross-chain replay"}},
	{Class: "signature-replay", Phrases: []string{
		"signature malleab", "ecrecover", "permit replay"}},
	{Class: "unchecked-external-call", Phrases: []string{
		"unchecked call", "unchecked return", "ignores the return value",
		"low-level call"}},
	{Class: "dos-griefing", Phrases: []string{
		"denial of service", "grief", "block the withdrawal", "revert the loop",
		"unbounded loop"}},
	{Class: "liveness", Phrases: []string{
		"liveness", "stuck", "cannot withdraw", "frozen funds", "halt"}},
	{Class: "upgrade-initializer", Phrases: []string{
		"initializ", "uninitialized", "upgrade", "implementation slot"}},
	{Class: "bridge-message", Phrases: []string{
		"bridge", "cross-chain message", "message verification",
		"relayer", "merkle proof verification"}},
	{Class: "economic-invariant", Phrases: []string{
		"economic invariant", "invariant broken", "accounting mismatch",
		"supply mismatch"}},
	{Class: "flash-loan", Phrases: []string{"flash loan", "flashloan"}},
	{Class: "token-integration", Phrases: []string{
		"fee-on-transfer", "rebasing token", "erc20 with fee", "weird token"}},
	{Class: "logic-error", Phrases: []string{
		"wrong variable", "incorrect comparison", "logic error",
		"incorrect state update"}},
}

// Classify assigns one canonical class from title+description. It returns the
// class and the phrase that fired ("unmapped" when nothing did) so a label is
// always explainable. Longest phrase wins, then the earliest table position —
// a total order, so the result does not depend on map iteration.
func Classify(title, description string) (string, string) {
	hay := strings.ToLower(title + "\n" + description)
	bestClass, bestPhrase := "", ""
	for _, rule := range LabelRules {
		for _, p := range rule.Phrases {
			lp := strings.ToLower(strings.TrimSpace(p))
			if lp == "" || !containsWord(hay, lp) {
				continue
			}
			if len(lp) > len(bestPhrase) {
				bestClass, bestPhrase = rule.Class, p
			}
		}
	}
	if bestClass == "" {
		return "unmapped", "unmapped"
	}
	return bestClass, bestPhrase
}

// containsWord is a substring test on a word-ish boundary: the phrase must not
// be glued to another letter on either side, so "reentran" does not match
// inside a longer unrelated token.
func containsWord(hay, needle string) bool {
	for i := 0; ; {
		j := strings.Index(hay[i:], needle)
		if j < 0 {
			return false
		}
		start := i + j
		end := start + len(needle)
		leftOK := start == 0 || !isLetter(hay[start-1])
		rightOK := end == len(hay) || !isLetter(hay[end])
		if leftOK && rightOK {
			return true
		}
		i = start + 1
	}
}

func isLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// DeriveLabels classifies every row of one snapshot. It refuses a row that
// does not carry the dataset's four fields verbatim (§3a: "exactly four fields
// per vulnerability") plus the project the extractor joined in, so a schema
// drift in the snapshot surfaces here rather than as silently-unmapped rows.
func DeriveLabels(rows []validation.Value, dataset, snapshotDate string) (validation.Value, error) {
	if dataset == "" || snapshotDate == "" {
		return validation.VNull(), fmt.Errorf(
			"DeriveLabels needs the dataset name and snapshot date — a label file " +
				"whose provenance is blank cannot be re-derived")
	}
	out := make([]validation.Value, 0, len(rows))
	counts := []validation.KV{}
	seen := map[string]int{}
	order := []string{}
	for i, row := range rows {
		for _, k := range []string{
			"finding_id", "project", "severity", "title", "description",
		} {
			if validation.ObjStr(row, k) == "" {
				return validation.VNull(), fmt.Errorf(
					"row %d is missing %s — ScaBench's curated snapshot has exactly "+
						"finding_id, severity, title, description (plus the project the "+
						"extractor joins in); anything else is a different dataset or a "+
						"different snapshot", i, k)
			}
		}
		sev := validation.ObjStr(row, "severity")
		// The label file is the snapshot's HIGH findings and nothing else:
		// §3a's set-cover is over the 114 gold findings, so a medium row in
		// here would inflate `gold_findings` and the coverage arithmetic. The
		// snapshot's real severity vocabulary is high|medium|low|informational
		// (114/237/184/20) — informational is NOT a typo and is the reason this
		// guard cannot say "high|medium|low only".
		if sev != "high" {
			return validation.VNull(), fmt.Errorf(
				"row %d (%s) has severity %q; this label file covers the snapshot's "+
					"high findings only — the 114 gold findings §3a's set-cover is "+
					"over. The snapshot's other rows (237 medium, 184 low, 20 "+
					"informational) are not labelled here; filter the extraction to "+
					"severity == \"high\"", i, validation.ObjStr(row, "finding_id"), sev)
		}
		class, rule := Classify(validation.ObjStr(row, "title"),
			validation.ObjStr(row, "description"))
		out = append(out, validation.VObj(
			kv("finding_id", validation.VStr(validation.ObjStr(row, "finding_id"))),
			kv("project", validation.VStr(validation.ObjStr(row, "project"))),
			kv("severity", validation.VStr(sev)),
			kv("class", validation.VStr(class)),
			kv("rule", validation.VStr(rule)),
		))
		if _, ok := seen[class]; !ok {
			order = append(order, class)
		}
		seen[class]++
	}
	for _, class := range order {
		counts = append(counts, validation.KV{K: class,
			V: validation.VInt(int64(seen[class]))})
	}
	doc := validation.VObj(
		kv("dataset", validation.VStr(dataset)),
		kv("snapshot_date", validation.VStr(snapshotDate)),
		kv("created_at", validation.VStr(state.NowIso())),
		kv("rows", validation.VArr(out...)),
		kv("counts", validation.VObj(counts...)),
		kv("schema_version", validation.VInt(1)),
	)
	return doc, nil
}

// LabelCounts is the per-class row count from a label file.
func LabelCounts(labels validation.Value) map[string]int {
	out := map[string]int{}
	for _, kvp := range validation.ObjAt(labels, "counts").O {
		out[kvp.K] = int(kvp.V.I)
	}
	return out
}

// UnmappedCount is the size of the bucket a human must review.
func UnmappedCount(labels validation.Value) int { return LabelCounts(labels)["unmapped"] }

// LoadLabels reads a label file and verifies its sidecar.
func LoadLabels(path string) (validation.Value, error) { return ReadRepoRecord(path) }
```

`taxonomy` is imported for its doc reference only in this file — if the compiler complains about an unused import, drop the import and let the *test* hold the pin (the test imports taxonomy itself). Keep the comment.

- [ ] **Step 6: Add the repo-level CLI action and run everything**

`internal/cli/cmd_regress.go`'s dispatcher gains a repo-level branch. Document it in the usage text and dispatch on the shape of the first positional:

```go
	// The first positional is either a campaign id (^C-) or one of the
	// repo-level actions, which operate on the eval store rather than on a
	// campaign: `labels` (this task), `select` (Task 4), `suite` (Task 10).
	if !strings.HasPrefix(pos[0], "C-") {
		// The repo-level actions need the CLI's root, and the global --root was
		// consumed before this verb ran, so hand it down under the parser's own
		// key convention (leading dashes).
		vals["--root"] = root
		switch pos[0] {
		case "labels":
			return regressLabels(vals, r)
		case "select":
			return regressSelect(vals, r)
		case "suite":
			return regressSuite(vals, r)
		}
		return t14ArgparseErr(regressUsage, "regress",
			"argument action: invalid choice: %q (choose from 'labels', 'select', "+
				"'suite', or a campaign id)", pos[0])
	}
```

`regressLabels` in this task (`regressSelect`/`regressSuite` land in Tasks 4 and 10 — declare them then, and leave the switch arms out until those tasks exist so the package compiles):

```go
// regressLabels derives the label file from a snapshot's rows:
//
//	webv2 regress labels --rows <rows.json> --out <labels.json> \
//	    [--dataset scabench] [--snapshot-date 2025-08-18]
//
// --rows is a JSON array of the snapshot's rows as extracted, verbatim.
func regressLabels(vals map[string]string, r *Runner) error {
	if vals["--rows"] == "" || vals["--out"] == "" {
		return t14ArgparseErr(regressUsage, "regress",
			"the following arguments are required: --rows, --out")
	}
	raw, err := os.ReadFile(vals["--rows"])
	if err != nil {
		return err
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		return err
	}
	if doc.Kind != validation.Arr {
		return fmt.Errorf("--rows must be a JSON array of rows, got %v", doc.Kind)
	}
	dataset, snapDate := vals["--dataset"], vals["--snapshot-date"]
	if dataset == "" {
		dataset = "scabench"
	}
	if snapDate == "" {
		snapDate = "2025-08-18"
	}
	labels, err := regression.DeriveLabels(doc.A, dataset, snapDate)
	if err != nil {
		return err
	}
	if err := regression.WriteRepoRecord(vals["--out"], labels, "regression_labels"); err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "%d row(s) labelled, %d unmapped -> %s\n",
		len(doc.A), regression.UnmappedCount(labels), vals["--out"])
	fmt.Fprintf(r.Out, "unmapped rows are the named source of error (§3a): read "+
		"them, extend LabelRules where a rule is missing, and re-run before "+
		"committing — set unmapped_reviewed only after that.\n")
	return nil
}
```

Add `"os"` to `cmd_regress.go`'s imports, add the four flags to `valueFlags` (`--rows`, `--out`, `--dataset`, `--snapshot-date`), and change the "required: campaign, action" guard to require only one positional before the repo-level branch.

Run:

```bash
python3 scripts/sync-asset-manifest.py
GOCACHE=$PWD/.scratch/gocache go test ./internal/regression ./internal/cli ./assets -count=1
GOCACHE=$PWD/.scratch/gocache go test ./internal/validation -count=1
```

Expected: PASS (the validation package needs `"regression_labels"` appended to `knownSchemas`).

- [ ] **Step 7: Operator step — label the real snapshot (needs the dataset)**

```bash
# 0. the checkout (§ Operator prerequisites §2). The dataset is ONE file, not a
#    directory of per-project files: datasets/curated-2025-08-18/curated-2025-08-18.json
export SCABENCH=/home/xand/webv2-p0/scabench
export DS="$SCABENCH/datasets/curated-2025-08-18/curated-2025-08-18.json"
mkdir -p "$WEBV2_P0_DIR" eval/scabench
# 1. extract the 114 high rows, keeping the vulnerability record's four fields
#    verbatim and joining in the dataset's own identifiers. The file is a LIST
#    OF 31 PROJECTS with nested codebases[] and vulnerabilities[] — there is no
#    flat findings list and no per-project file to glob. The join is
#    `project_id` (selection and hold-out are per PROJECT) and the severity
#    filter is load-bearing: without it the 555 rows land here and every
#    downstream `gold_findings` count is 555, not 114.
python3 - "$DS" <<'PY' > eval/scabench/curated-2025-08-18.json
import json, sys
projects = json.load(open(sys.argv[1]))
rows = []
for p in projects:
    for v in p["vulnerabilities"]:
        if v["severity"] != "high":
            continue
        rows.append({
            "finding_id": v["finding_id"],
            "project": p["project_id"],
            "severity": v["severity"],
            "title": v["title"],
            "description": v["description"],
        })
assert len(rows) == 114, f"expected 114 high rows, got {len(rows)}"
json.dump(rows, sys.stdout)
PY
# 2. derive the labels (DeriveLabels refuses a non-high row, so a mis-extraction
#    fails here rather than inflating the coverage)
webv2 regress labels --rows eval/scabench/curated-2025-08-18.json \
    --out eval/scabench/labels-2025-08-18.json
# 3. READ THE UNMAPPED ROWS. This is the review the schema records.
python3 - <<'PY'
import json
d = json.load(open("eval/scabench/labels-2025-08-18.json"))
for r in d["rows"]:
    if r["class"] == "unmapped":
        print(r["finding_id"], r["severity"], r["title"])
PY
# 4. for each unmapped row, either add the phrase that names its mechanism to
#    LabelRules (internal/regression/labels.go) and re-run step 2, or decide
#    the row is genuinely unclassifiable and leave it. Record which by setting
#    unmapped_reviewed: true and reviewed_by in the label file (a two-line
#    python3 edit, then re-run WriteRepoRecord's sidecar step:
python3 - <<'PY'
import json, hashlib, pathlib
p = pathlib.Path("eval/scabench/labels-2025-08-18.json")
d = json.loads(p.read_text())
d["unmapped_reviewed"] = True
d["reviewed_by"] = "<operator>"
p.write_text(json.dumps(d, indent=1) + "\n")
pathlib.Path(str(p) + ".sha256").write_text(
    hashlib.sha256(p.read_bytes()).hexdigest() + "\n")
PY
# 5. verify the file still validates and the counts are what you expect
python3 -c 'import json; d=json.load(open("eval/scabench/labels-2025-08-18.json")); print(len(d["rows"]), d["counts"])'
#    expect 114 rows, and the class counts summing to 114.
```

**Record** in `docs/gates/v16-P0.md`: the row count, the `counts` object verbatim, how many rows stayed `unmapped` and why, and the spec-vs-live class-count discrepancy (Step 2's test prints the live size; §3a says 23 — the live set is **25**, verified by reading `internal/findings/levels.go`'s `CLASS_CONFIRM_FLOOR` ∪ `internal/taxonomy/taxonomy.go`'s `defaultCompatClasses`). **Also record** the number of `high` rows found — measured **114**, exactly what §3a says, so this one is now a closed item rather than an open question (Task 11 §5).

- [ ] **Step 8: Commit**

```bash
git add assets/schema/regression_labels.schema.json assets/testdata/asset_manifest.json \
        internal/regression/repofile.go internal/regression/labels.go \
        internal/regression/labels_test.go internal/cli/cmd_regress.go \
        internal/validation/schema.go eval/scabench/curated-2025-08-18.json \
        eval/scabench/labels-2025-08-18.json \
        eval/scabench/labels-2025-08-18.json.sha256
git commit -m "feat(v16-p0): derived class labels for the ScaBench snapshot"
```

---

### Task 4: Weighted set-cover selection and stratification

§3a, verbatim, is the whole specification of this task:

> then picking six targets by greedy set-cover over the derived classes, **weighted by gold-finding count** — 114 high findings across 31 projects is under four per project, so an unweighted pick of six yields maybe 15–25 gold findings and per-class measurements at n≈1–3; a target with one gold finding costs the same checkout and yields almost no signal. Constrained to the four target shapes below plus the diagnosed campaign:

> - One vault/ERC-4626-style target (share-inflation, rounding)
> - One lending/liquidation market (insolvency, bad-debt dynamics)
> - One bridge/cross-chain messaging target (verification config, replay)
> - One non-rollup L2 or oracle-driven protocol
> - The diagnosed campaign itself, retained but relabeled as training data, not eval
> - One already-publicly-exploited target, to exercise §C7.2's PATCHED-KNOWN path before it ships

> Anti-pattern to avoid: the diagnosed campaign was an L2/rollup — heavily liveness- and sequencing-shaped. An unstratified suite would skew toward exactly the angle just found under-weighted, at the expense of hy4's top expected-value classes.

**Two numbers in that quote do not survive contact with the snapshot** (Task 3's measurement table; re-run `Operator prerequisites §7` rather than trusting this). "Under four per project" is a **mean**, not a bound: the high-finding counts run 1 … 12 (median 2, mean 3.68), and 11 of 31 projects carry four or more. And "an unweighted pick of six yields maybe 15–25 gold findings" describes a *random* six (6 × 3.68 ≈ 22); the six biggest projects by high count carry **54 of 114**. So the selector's justification is **class coverage per checkout**, not raw finding count — a greedy weighted by gold count still prefers the project that covers an uncovered class *and* carries weight, which is what the fixture below must demonstrate. Do not build a fixture that "proves" weighting beats picking the six biggest on count; on this data it does not.

Phase 0's scope row adds the held-out rule: **"2 held out by project"**. So the selector's job is exactly: given the label file (Task 3), a project→shape map, and the two projects reserved as held-out, pick the six and say what they cover.

**Offline vs operator, in this task.**
- **Built and tested offline (Steps 1–5):** the greedy, its weight function, the shape constraint, the hold-out partition, the coverage arithmetic, the refusals, and a synthetic fixture shaped like the real data (31 projects, 114 findings, a high-count distribution of median 2 / max 12, and a rare class living in one small project) that proves the weighted pick covers a class an unweighted pick misses.
- **Operator step (Step 6, needs the dataset):** assign a shape to each project (a judgement read off the project's code), name the two held-out projects, run the selector, commit the selection. Shapes are assigned to **`project_id`s** from the label file, never to display names.

**Files:**
- Create: `assets/schema/regression_selection.schema.json`
- Create: `internal/regression/select.go`
- Create: `internal/regression/select_test.go`
- Modify: `internal/cli/cmd_regress.go` (repo-level `select` action)
- Modify: `internal/validation/schema.go` (append `"regression_selection"`)
- Modify: `assets/testdata/asset_manifest.json` (regenerated)

**Interfaces:**
- Consumes: `regression.{LoadLabels,LabelCounts,WriteRepoRecord,TargetShapes,kv,contains}`.
- Produces: `regression.SelectSpec{Labels validation.Value, Shapes map[string]string, HeldOut []string, Picks int, DiagnosedProgram, ControlProgram string}`, `regression.Select(spec SelectSpec) (validation.Value, error)`, `regression.ScaBenchShapes []string`, and the selection keys `{dataset, snapshot_date, method, picks[], coverage{}, diagnosed_program, control_program, created_at, schema_version}` with `picks[].{project, shape, partition, gold_findings, classes[]}`. Task 10 consumes the selection file by path + sha256; the audit section reports the suite's coverage.

- [ ] **Step 1: Write the selection schema**

Create `assets/schema/regression_selection.schema.json`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://web3sec.local/schema/regression_selection.schema.json",
  "title": "WebSec Regression Suite Selection",
  "description": "The Phase 0 target selection (§3a): six targets chosen by greedy set-cover over the derived classes, weighted by gold-finding count, constrained to the four target shapes plus the diagnosed campaign (training data) and the already-exploited control target, with two of the six held out by project. This file is the reviewed, committed answer to 'which targets', with the coverage it achieves, so a later change to the suite is a diff against a measurement rather than a re-pick.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "dataset", "snapshot_date", "method", "picks", "coverage",
    "created_at", "schema_version"
  ],
  "properties": {
    "dataset": { "type": "string", "minLength": 1 },
    "snapshot_date": { "type": "string", "minLength": 10 },
    "method": { "const": "greedy-set-cover-weighted-by-gold-finding-count" },
    "picks": {
      "type": "array",
      "minItems": 4,
      "maxItems": 6,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["project", "shape", "partition", "gold_findings", "classes"],
        "properties": {
          "project": { "type": "string", "minLength": 1 },
          "shape": { "type": "string", "minLength": 1 },
          "partition": { "enum": ["dev", "held-out"] },
          "gold_findings": { "type": "integer", "minimum": 1 },
          "classes": { "type": "array", "items": { "type": "string" } }
        }
      }
    },
    "coverage": {
      "type": "object",
      "additionalProperties": false,
      "required": ["covered_findings", "total_findings", "covered_classes", "total_classes"],
      "properties": {
        "covered_findings": { "type": "integer", "minimum": 0 },
        "total_findings": { "type": "integer", "minimum": 0 },
        "covered_classes": { "type": "integer", "minimum": 0 },
        "total_classes": { "type": "integer", "minimum": 0 },
        "uncovered_classes": { "type": "array", "items": { "type": "string" } }
      }
    },
    "diagnosed_program": { "type": "string" },
    "control_program": { "type": "string" },
    "held_out": { "type": "array", "items": { "type": "string" } },
    "created_at": { "type": "string", "minLength": 20 },
    "schema_version": { "const": 1 }
  }
}
```

- [ ] **Step 2: Write the failing tests**

Create `internal/regression/select_test.go`. The fixture is built to mirror §3a's *measured* shape, not an invented one:

```go
package regression

import (
	"fmt"
	"strings"
	"testing"

	"websec/internal/validation"
)

// syntheticSnapshot mirrors the MEASURED totals of curated-2025-08-18, not
// §3a's prose about it: 31 projects and 114 high findings (measured; §3a's
// "under four per project" is a mean of 3.68, not a bound — the real median is
// 2 and the real max is 12). The CONCENTRATION here is a deliberate
// exaggeration of that distribution, not a measurement: it exists so that
// "pick the six biggest by count" is unmistakably a different pick from the
// weighted one, which is the property this fixture is here to test. The class
// distribution — the biggest projects clustered on two classes, a rare class
// living in one small project — is what makes the weighting matter.
func syntheticSnapshot(t *testing.T) validation.Value {
	t.Helper()
	rows := []validation.Value{}
	id := 0
	add := func(project, class string, n int) {
		for i := 0; i < n; i++ {
			id++
			rows = append(rows, validation.VObj(
				kv("finding_id", validation.VStr(fmt.Sprintf("S-%d", id))),
				kv("project", validation.VStr(project)),
				kv("severity", validation.VStr("high")),
				kv("title", validation.VStr(titleFor(class))),
				kv("description", validation.VStr("mechanism: " + class)),
			))
		}
	}
	// 27 filler projects, one finding each (27), classes cycling.
	filler := []string{"precision-rounding", "access-control", "dos-griefing",
		"logic-error", "unchecked-external-call", "upgrade-initializer",
		"token-integration"}
	for i := 0; i < 27; i++ {
		add(fmt.Sprintf("filler-%02d", i), filler[i%len(filler)], 1)
	}
	// Three big projects, all clustered on the same two classes. 27 + 32 + 32
	// + 20 + 3 = 114 findings across 31 projects, the measured totals.
	add("big-a", "reentrancy", 32)
	add("big-b", "reentrancy", 32)
	add("big-c", "precision-rounding", 20)
	// One small project carrying the rare class.
	add("rare-oracle", "oracle-manipulation", 3)
	// ... and the four shape carriers are among the fillers plus the rare one.
	labels, err := DeriveLabels(rows, "scabench", "2025-08-18")
	if err != nil {
		t.Fatal(err)
	}
	labels.O = validation.SetOrAppend(labels.O, "unmapped_reviewed", validation.VBool(true))
	return labels
}

// titleFor gives every class a title whose phrase the rule table matches —
// built from the rule table itself, so the fixture cannot drift from the
// classifier it is testing (the realism law, one level up).
func titleFor(class string) string {
	for _, rule := range LabelRules {
		if rule.Class == class {
			return rule.Phrases[0]
		}
	}
	return "no rule for " + class
}

func syntheticShapes() map[string]string {
	m := map[string]string{}
	for i := 0; i < 27; i++ {
		shape := []string{"vault-erc4626", "lending-liquidation",
			"bridge-messaging", "non-rollup-l2-or-oracle"}[i%4]
		m[fmt.Sprintf("filler-%02d", i)] = shape
	}
	m["big-a"] = "vault-erc4626"
	m["big-b"] = "lending-liquidation"
	m["big-c"] = "bridge-messaging"
	m["rare-oracle"] = "non-rollup-l2-or-oracle"
	return m
}

func TestSelectCoversTheRareClassAndAllFourShapes(t *testing.T) {
	labels := syntheticSnapshot(t)
	sel, err := Select(SelectSpec{
		Labels: labels, Shapes: syntheticShapes(),
		HeldOut: []string{"filler-00", "filler-01"},
		Picks:   6, DiagnosedProgram: "diagnosed-l2", ControlProgram: "exploited",
	})
	if err != nil {
		t.Fatal(err)
	}
	picks := validation.ObjAt(sel, "picks")
	if len(picks.A) != 6 {
		t.Fatalf("%d picks, want 6", len(picks.A))
	}
	heldOut := 0
	shapes := map[string]bool{}
	for _, p := range picks.A {
		shapes[validation.ObjStr(p, "shape")] = true
		if validation.ObjStr(p, "partition") == "held-out" {
			heldOut++
		}
	}
	for _, want := range ScaBenchShapes {
		if !shapes[want] {
			t.Errorf("shape %q is not covered by the picks", want)
		}
	}
	if heldOut != 2 {
		t.Errorf("%d held-out pick(s), want 2 (§3a: 2 held out by project)", heldOut)
	}
	// The rare class must be covered — this is what "weighted by gold-finding
	// count" buys and what an unweighted pick of the three big projects loses.
	cov := validation.ObjAt(sel, "coverage")
	if got := validation.ObjAt(cov, "covered_classes").I; got == 0 {
		t.Fatal("coverage.covered_classes = 0")
	}
	uncovered := validation.ObjAt(cov, "uncovered_classes")
	for _, c := range uncovered.A {
		if c.S == "oracle-manipulation" {
			t.Fatal("the weighted pick left oracle-manipulation uncovered — the " +
				"rare class is exactly what the weighting exists to catch")
		}
	}
}

func TestSelectIsDeterministic(t *testing.T) {
	spec := SelectSpec{
		Labels: syntheticSnapshot(t), Shapes: syntheticShapes(),
		HeldOut: []string{"filler-00", "filler-01"}, Picks: 6,
	}
	first, err := Select(spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Select(spec)
	if err != nil {
		t.Fatal(err)
	}
	if validation.CanonSpaced(first) != validation.CanonSpaced(second) {
		t.Fatal("Select is not deterministic across two runs of the same input")
	}
}

func TestSelectRefusesUnreviewedLabelsAndABadComposition(t *testing.T) {
	unreviewed := syntheticSnapshot(t)
	unreviewed.O = validation.SetOrAppend(unreviewed.O, "unmapped_reviewed",
		validation.VBool(false))
	base := SelectSpec{
		Labels: unreviewed, Shapes: syntheticShapes(),
		HeldOut: []string{"filler-00", "filler-01"}, Picks: 6,
	}
	if _, err := Select(base); err == nil ||
		!strings.Contains(err.Error(), "unmapped_reviewed") {
		t.Fatalf("err = %v, want a refusal naming the unreviewed bucket", err)
	}
	base.Labels = syntheticSnapshot(t)
	base.HeldOut = []string{"filler-00"}
	if _, err := Select(base); err == nil ||
		!strings.Contains(err.Error(), "held out") {
		t.Fatalf("err = %v, want a refusal naming the hold-out count", err)
	}
	base.HeldOut = []string{"filler-00", "not-a-project"}
	if _, err := Select(base); err == nil ||
		!strings.Contains(err.Error(), "not-a-project") {
		t.Fatalf("err = %v, want a refusal naming the unknown project", err)
	}
	base.HeldOut = []string{"filler-00", "filler-01"}
	base.Shapes = syntheticShapes()
	base.Shapes["filler-00"] = "mystery-shape"
	if _, err := Select(base); err == nil ||
		!strings.Contains(err.Error(), "mystery-shape") {
		t.Fatalf("err = %v, want a refusal naming the unknown shape", err)
	}
	base.Shapes = syntheticShapes()
	base.Picks = 8
	if _, err := Select(base); err == nil || !strings.Contains(err.Error(), "4") {
		t.Fatalf("err = %v, want a refusal naming the 4–6 target range", err)
	}
}
```

- [ ] **Step 3: Run them to verify they fail**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/regression -run TestSelect -count=1`

Expected: FAIL to compile — `undefined: Select`, `undefined: SelectSpec`, `undefined: ScaBenchShapes`.

- [ ] **Step 4: Implement the selector**

Create `internal/regression/select.go`:

```go
package regression

import (
	"fmt"
	"sort"

	"websec/internal/state"
	"websec/internal/validation"
)

// ScaBenchShapes is §3a's four ScaBench target shapes. The other two rows of
// the six (the diagnosed campaign, the already-exploited control target) are
// not picks from the snapshot: they are named separately in the selection.
var ScaBenchShapes = []string{
	"vault-erc4626", "lending-liquidation", "bridge-messaging",
	"non-rollup-l2-or-oracle",
}

// SelectSpec is one selection run.
type SelectSpec struct {
	Labels           validation.Value // the Task 3 label file
	Shapes           map[string]string
	HeldOut          []string
	Picks            int
	DiagnosedProgram string
	ControlProgram   string
}

// candidate is one project's coverage profile.
type candidate struct {
	project string
	shape   string
	classes map[string]int // class -> gold findings in this project
	total   int
}

// Select is §3a's picker: greedy set-cover over the derived classes, weighted
// by gold-finding count, constrained to one project per shape and to exactly
// two held-out projects.
//
// The weight of a class is its TOTAL gold-finding count across the snapshot,
// so covering a class that holds many findings is worth more than covering one
// that holds a single finding — §3a's point that "a target with one gold
// finding costs the same checkout and yields almost no signal". Greedy is
// deterministic here by construction: the argmax breaks ties on the project
// name, and no map is ever iterated for a decision.
func Select(spec SelectSpec) (validation.Value, error) {
	if spec.Picks == 0 {
		spec.Picks = 6
	}
	if spec.Picks < 4 || spec.Picks > 6 {
		return validation.VNull(), fmt.Errorf(
			"§3a selects 4–6 stratified targets; Picks=%d is outside that range",
			spec.Picks)
	}
	if !validation.ObjAt(spec.Labels, "unmapped_reviewed").B {
		return validation.VNull(), fmt.Errorf(
			"the label file's unmapped bucket has not been reviewed "+
				"(unmapped_reviewed is not true) — §3a calls the bucketing \"our own "+
				"classification, a named source of error\", so selection may not run "+
				"on labels nobody read")
	}
	if len(spec.HeldOut) != 2 {
		return validation.VNull(), fmt.Errorf(
			"Phase 0 holds out exactly 2 targets by project (§3a); got %d: %v",
			len(spec.HeldOut), spec.HeldOut)
	}
	for _, p := range spec.HeldOut {
		if _, ok := spec.Shapes[p]; !ok {
			return validation.VNull(), fmt.Errorf(
				"held-out project %q has no shape assigned — a held-out target is "+
					"still a target and must be stratified", p)
		}
	}
	for project, shape := range spec.Shapes {
		if !contains(ScaBenchShapes, shape) {
			return validation.VNull(), fmt.Errorf(
				"project %q has shape %q, which is not one of §3a's four ScaBench "+
					"shapes %v", project, shape, ScaBenchShapes)
		}
	}
	cands, classWeight, totalFindings, err := profile(spec.Labels, spec.Shapes)
	if err != nil {
		return validation.VNull(), err
	}
	if len(cands) < spec.Picks {
		return validation.VNull(), fmt.Errorf(
			"%d project(s) have a shape assigned, fewer than the %d picks — assign "+
				"a shape to more projects", len(cands), spec.Picks)
	}
	covered := map[string]bool{}
	chosen := []candidate{}
	pickOne := func(shape string) error {
		best, ok := bestCandidate(cands, shape, covered, classWeight, chosen)
		if !ok {
			return fmt.Errorf(
				"no project covers shape %q among the shaped projects — §3a's "+
					"composition requires one target of each shape", shape)
		}
		chosen = append(chosen, best)
		for class := range best.classes {
			covered[class] = true
		}
		return nil
	}
	// Pass 1: one target per shape, so the stratification is a constraint and
	// not an emergent property of the weights.
	for _, shape := range ScaBenchShapes {
		if err := pickOne(shape); err != nil {
			return validation.VNull(), err
		}
	}
	// Pass 2: fill the remaining slots by global weighted greedy.
	for len(chosen) < spec.Picks {
		best, ok := bestCandidate(cands, "", covered, classWeight, chosen)
		if !ok {
			return validation.VNull(), fmt.Errorf(
				"only %d of %d picks could be filled with positive coverage — the "+
					"snapshot's classes are exhausted", len(chosen), spec.Picks)
		}
		chosen = append(chosen, best)
		for class := range best.classes {
			covered[class] = true
		}
	}
	heldOutSet := map[string]bool{}
	for _, p := range spec.HeldOut {
		heldOutSet[p] = true
	}
	heldOutChosen := 0
	picks := make([]validation.Value, 0, len(chosen))
	for _, p := range chosen {
		partition := "dev"
		if heldOutSet[p.project] {
			partition = "held-out"
			heldOutChosen++
		}
		classes := make([]string, 0, len(p.classes))
		for c := range p.classes {
			classes = append(classes, c)
		}
		sort.Strings(classes)
		classVals := make([]validation.Value, 0, len(classes))
		for _, c := range classes {
			classVals = append(classVals, validation.VStr(c))
		}
		picks = append(picks, validation.VObj(
			kv("project", validation.VStr(p.project)),
			kv("shape", validation.VStr(p.shape)),
			kv("partition", validation.VStr(partition)),
			kv("gold_findings", validation.VInt(int64(p.total))),
			kv("classes", validation.VArr(classVals...)),
		))
	}
	if heldOutChosen != 2 {
		return validation.VNull(), fmt.Errorf(
			"%d of the 2 held-out projects were picked — a held-out target that is "+
				"not in the suite is not held out from anything; pick again or name "+
				"held-out projects the greedy actually selects", heldOutChosen)
	}
	uncovered := []validation.Value{}
	coveredCount := 0
	classes := make([]string, 0, len(classWeight))
	for c := range classWeight {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	for _, c := range classes {
		if covered[c] {
			coveredCount += classWeight[c]
		} else {
			uncovered = append(uncovered, validation.VStr(c))
		}
	}
	doc := validation.VObj(
		kv("dataset", validation.VStr(validation.ObjStr(spec.Labels, "dataset"))),
		kv("snapshot_date", validation.VStr(validation.ObjStr(spec.Labels, "snapshot_date"))),
		kv("method", validation.VStr("greedy-set-cover-weighted-by-gold-finding-count")),
		kv("picks", validation.VArr(picks...)),
		kv("coverage", validation.VObj(
			kv("covered_findings", validation.VInt(int64(coveredCount))),
			kv("total_findings", validation.VInt(int64(totalFindings))),
			kv("covered_classes", validation.VInt(int64(len(classWeight)-len(uncovered)))),
			kv("total_classes", validation.VInt(int64(len(classWeight)))),
			kv("uncovered_classes", validation.VArr(uncovered...)),
		)),
		kv("held_out", validation.VArr(strVals(spec.HeldOut)...)),
		kv("created_at", validation.VStr(state.NowIso())),
		kv("schema_version", validation.VInt(1)),
	)
	if spec.DiagnosedProgram != "" {
		doc.O = validation.SetOrAppend(doc.O, "diagnosed_program",
			validation.VStr(spec.DiagnosedProgram))
	}
	if spec.ControlProgram != "" {
		doc.O = validation.SetOrAppend(doc.O, "control_program",
			validation.VStr(spec.ControlProgram))
	}
	return doc, nil
}

// profile buckets the label rows by project and computes each class's total
// gold-finding count (the weight) and the snapshot's total.
//
// Invariant it relies on: the label file carries the snapshot's HIGH findings
// only (Task 3's DeriveLabels enforces it), so every row IS a gold finding and
// no severity filter is needed here. If that invariant ever breaks, this
// function silently counts a medium finding as gold and the coverage figure
// stops meaning what §3a means by it.
func profile(labels validation.Value, shapes map[string]string) (
	[]candidate, map[string]int, int, error) {
	byProject := map[string]*candidate{}
	order := []string{}
	classWeight := map[string]int{}
	total := 0
	for _, row := range validation.ObjAt(labels, "rows").A {
		project := validation.ObjStr(row, "project")
		class := validation.ObjStr(row, "class")
		if class == "" || class == "unmapped" {
			// An unmapped row is information about the rule table, not a
			// class to cover; it is counted in the totals so the coverage
			// figure stays honest about what was left out.
			total++
			continue
		}
		total++
		classWeight[class]++
		shape, ok := shapes[project]
		if !ok {
			continue // no shape assigned: not a candidate
		}
		c, ok := byProject[project]
		if !ok {
			c = &candidate{project: project, shape: shape, classes: map[string]int{}}
			byProject[project] = c
			order = append(order, project)
		}
		c.classes[class]++
		c.total++
	}
	out := make([]candidate, 0, len(order))
	for _, p := range order {
		out = append(out, *byProject[p])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].project < out[j].project })
	return out, classWeight, total, nil
}

// bestCandidate is the greedy step: the unchosen candidate with the highest
// weighted gain over still-uncovered classes. Ties break on project name, so
// the result never depends on iteration order.
func bestCandidate(cands []candidate, shape string, covered map[string]bool,
	classWeight map[string]int, chosen []candidate) (candidate, bool) {
	picked := map[string]bool{}
	for _, c := range chosen {
		picked[c.project] = true
	}
	best := candidate{}
	bestGain := -1
	for _, c := range cands {
		if picked[c.project] || (shape != "" && c.shape != shape) {
			continue
		}
		gain := 0
		for class := range c.classes {
			if !covered[class] {
				gain += classWeight[class]
			}
		}
		if gain > bestGain || (gain == bestGain && best.project != "" &&
			c.project < best.project) {
			best, bestGain = c, gain
		}
	}
	if best.project == "" || bestGain <= 0 {
		return candidate{}, false
	}
	return best, true
}

// strVals converts a []string to []validation.Value.
func strVals(items []string) []validation.Value {
	out := make([]validation.Value, 0, len(items))
	for _, s := range items {
		out = append(out, validation.VStr(s))
	}
	return out
}
```

- [ ] **Step 5: Wire the `select` CLI action and run everything**

Add to `valueFlags`: `--labels`, `--shapes`, `--held-out`, `--picks`, `--diagnosed`, `--control`. Add the `select` case to the repo-level switch:

```go
// regressSelect picks the suite's targets:
//
//	webv2 regress select --labels eval/scabench/labels-2025-08-18.json \
//	    --shapes shapes.json --held-out project-a,project-b \
//	    [--picks 6] [--diagnosed <program>] [--control <program>] \
//	    --out eval/regression/selection-2025-08-18.json
//
// --shapes is a JSON object {project: shape} over §3a's four ScaBench shapes.
func regressSelect(vals map[string]string, r *Runner) error {
	for _, k := range []string{"--labels", "--shapes", "--held-out", "--out"} {
		if vals[k] == "" {
			return t14ArgparseErr(regressUsage, "regress",
				"the following arguments are required: %s", k)
		}
	}
	labels, err := regression.LoadLabels(vals["--labels"])
	if err != nil {
		return err
	}
	rawShapes, err := os.ReadFile(vals["--shapes"])
	if err != nil {
		return err
	}
	shapeDoc, err := validation.ParseOrdered(rawShapes)
	if err != nil {
		return err
	}
	if shapeDoc.Kind != validation.Obj {
		return fmt.Errorf("--shapes must be a JSON object of {project: shape}")
	}
	shapes := map[string]string{}
	for _, kvp := range shapeDoc.O {
		if kvp.V.Kind != validation.Str {
			return fmt.Errorf("--shapes value for %q must be a string", kvp.K)
		}
		shapes[kvp.K] = kvp.V.S
	}
	picks := 6
	if v := vals["--picks"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return t14ArgparseErr(regressUsage, "regress",
				"argument --picks: invalid int value: %q", v)
		}
		picks = n
	}
	sel, err := regression.Select(regression.SelectSpec{
		Labels: labels, Shapes: shapes,
		HeldOut: splitCSV(vals["--held-out"]), Picks: picks,
		DiagnosedProgram: vals["--diagnosed"], ControlProgram: vals["--control"],
	})
	if err != nil {
		return err
	}
	if err := regression.WriteRepoRecord(vals["--out"], sel, "regression_selection"); err != nil {
		return err
	}
	cov := validation.ObjAt(sel, "coverage")
	fmt.Fprintf(r.Out, "%d target(s) selected -> %s\n", len(validation.ObjAt(sel, "picks").A),
		vals["--out"])
	fmt.Fprintf(r.Out, "coverage: %s of %s gold finding(s), %s of %s class(es)\n",
		validation.IntText(validation.ObjAt(cov, "covered_findings")),
		validation.IntText(validation.ObjAt(cov, "total_findings")),
		validation.IntText(validation.ObjAt(cov, "covered_classes")),
		validation.IntText(validation.ObjAt(cov, "total_classes")))
	return nil
}

// splitCSV splits a comma-separated flag value, dropping empty parts.
func splitCSV(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
```

Run:

```bash
python3 scripts/sync-asset-manifest.py
GOCACHE=$PWD/.scratch/gocache go test ./internal/regression ./internal/cli ./internal/validation ./assets -count=1
```

Expected: PASS. Add one CLI test that `regress select` with a one-project `--held-out` exits 1 and names the hold-out rule.

- [ ] **Step 6: Operator step — select the real suite (needs the dataset)**

```bash
# 1. assign a shape to every project you are willing to check out. The keys are
#    the label file's `project` values, which are the dataset's `project_id`
#    slugs — NOT the display names. Read the code: §3a's shapes are vault/ERC-4626,
#    lending/liquidation, bridge or cross-chain messaging, and a non-rollup L2 or
#    oracle-driven protocol.
#    Two of the 31 projects are awkward for the checkout, not the picker:
#      code4rena_starknet-perpetual_2025_06 carries TWO codebases (its `_main`
#      one has no commit at all) and code4rena_initia-move_2025_04 records an
#      empty commit — both are still pickable, but Task 5's mirror rule and the
#      target's --codebase-id are what make them checkable (see the unpinned
#      table in *The dataset, as it actually is*).
python3 -c 'import json;print(sorted({r["project"] for r in json.load(open("eval/scabench/labels-2025-08-18.json"))["rows"]}))'
cat > "$WEBV2_P0_DIR/shapes.json" <<'JSON'
{"<project-a>": "vault-erc4626", "<project-b>": "lending-liquidation",
 "<project-c>": "bridge-messaging", "<project-d>": "non-rollup-l2-or-oracle"}
JSON
# 2. name the two held-out projects (again by project_id). Choose them so the
#    suite's shapes stay covered; the selector refuses a hold-out the greedy
#    cannot pick.
webv2 regress select \
    --labels eval/scabench/labels-2025-08-18.json \
    --shapes "$WEBV2_P0_DIR/shapes.json" \
    --held-out '<project-a>,<project-c>' \
    --picks 6 --diagnosed '<the diagnosed campaign program>' \
    --control '<the control target program>' \
    --out eval/regression/selection-2025-08-18.json
```

**Record** in `docs/gates/v16-P0.md`: the selection file's `coverage` object verbatim, the six picks with their shapes and partitions, and — importantly — the coverage an *unweighted* pick would have reached, so §3a's claim that weighting buys real coverage is a measurement rather than an assertion. Compute it over the label file in a few lines of python3 (do NOT get it by editing the label file's `counts`: `Select` refuses a file whose sidecar no longer matches, and a hand-edited weight is not a measurement). Put the two numbers side by side, and state which reading of "unweighted" you used — *random six* or *six biggest by gold count* — because on this snapshot they are very different: a random six averages 22 of 114 gold findings, while the six biggest carry **54 of 114**. §3a's "15–25" is the random-six figure; the weighting argument is about classes, not counts.

- [ ] **Step 7: Commit**

```bash
git add assets/schema/regression_selection.schema.json assets/testdata/asset_manifest.json \
        internal/regression/select.go internal/regression/select_test.go \
        internal/cli/cmd_regress.go internal/validation/schema.go \
        eval/regression/selection-2025-08-18.json \
        eval/regression/selection-2025-08-18.json.sha256
git commit -m "feat(v16-p0): weighted set-cover target selection and stratification"
```

---

### Task 5: SHA resolution and the local mirror

§3a, verbatim:

> **Source pinning.** `checkout_sources.py` only verifies that `HEAD` prefix-matches the recorded commit, does no bytecode verification, and at least one project (Fenix Finance) records `"commit": "main"` — a mutable ref. Phase 0 resolves every commit to a concrete SHA at first checkout, mirrors the repos locally, and records the resolved SHA in the campaign snapshot. ScaBench's commit field is a hint, not a pin.

**"At least one project" is a floor, and a low one.** Measured against the snapshot, **ten of 32 codebases** carry no usable pin, in three distinct modes — five record `main` (Fenix Finance, Lambo.win, LoopFi, BakerFi, Blackhole), two record the **empty string** (Initia Move, Starknet Perpetual's `_main` codebase — not a mutable ref but *no ref at all*, and `checkout_sources.py` silently clones the default branch for them), and three record **abbreviated SHAs** (Oku `9e31b40`, Idle Finance `b6e5813`, SYMMIO `cfe1920`). The table with the resolution recipe for each is in *Operator prerequisites §7 — The dataset, as it actually is*; it is Task 5's real workload. This task's hint classifier therefore has to be right about all four kinds, and its mirror rule has to cover `short-sha` and `unknown`, not just `mutable-ref`.

Task 1 already refuses a non-40-hex pin and binds the snapshot's commit to it. This task adds the two facts Task 1 could not: **what kind of hint the dataset gave** (so a `main` is visible as a mutable ref rather than merely resolved), and **which local mirror the SHA was resolved against** (so the resolution is reproducible after the dataset or the network goes away).

**Offline vs operator, in this task.**
- **Built and tested offline (Steps 1–4):** the hint classifier, the mirror record shape and its refusals, the audit problem that keeps a mutable-ref pin without a mirror red.
- **Operator step (Step 5, needs network):** `git clone --mirror`, `rev-parse`, `git bundle create`, `sha256sum`, and the committed mirror index.

**Files:**
- Create: `internal/regression/pin.go`
- Create: `internal/regression/pin_test.go`
- Modify: `assets/schema/regression_target.schema.json` (add `hint_kind`, `mirror`)
- Modify: `internal/regression/target.go` (`PinTarget` requires the mirror for a mutable-ref hint)
- Modify: `internal/cli/cmd_regress.go` (`target pin` flags; new `target mirror` action)
- Modify: `internal/audit/sections/regressionsuite.go` (the mirror problem line)
- Modify: `assets/testdata/asset_manifest.json` (regenerated)

**Interfaces:**
- Consumes: `regression.{Target,PinTarget,sha40Re,writeThenLog,copyTargetWithKeys,hasKey}`.
- Produces: `regression.HintKinds []string`, `regression.HintKind(hint string) string`, `regression.MirrorSpec{TargetID, Kind, Path, SHA256 string, Bytes int64}`, `regression.RecordMirror(c, spec MirrorSpec) (validation.Value, error)`, `regression.LoadMirrorIndex(path string) (validation.Value, error)`; ledger event `regression.target.mirrored`. Task 9 consumes `HintKind` for fresh targets.

- [ ] **Step 1: Extend the schema and write the failing tests**

Add two keys to `assets/schema/regression_target.schema.json`:

```json
    "hint_kind": {
      "enum": ["full-sha", "short-sha", "mutable-ref", "unknown"],
      "description": "what KIND of thing the dataset's commit field was, recorded because §3a's whole point is that 'main' and a 40-hex commit are not the same claim — a mutable-ref hint that resolved cleanly today will resolve to a different tree tomorrow"
    },
    "mirror": {
      "type": "object",
      "additionalProperties": false,
      "required": ["kind", "path", "sha256"],
      "description": "the local mirror the resolved SHA was read from (§3a: 'mirrors the repos locally'). The SHA is a claim about a tree; the mirror is the tree, so the claim stays checkable after the network and the dataset are gone",
      "properties": {
        "kind": { "enum": ["git-mirror", "git-bundle", "tarball"] },
        "path": { "type": "string", "minLength": 1 },
        "sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
        "bytes": { "type": "integer", "minimum": 0 },
        "recorded_at": { "type": "string", "minLength": 20 }
      }
    },
```

Then create `internal/regression/pin_test.go`:

```go
package regression

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

func TestHintKindClassifiesTheDatasetsCommitField(t *testing.T) {
	cases := map[string]string{
		shaPre:                      "full-sha",
		"1111111":                   "short-sha",
		"main":                      "mutable-ref",
		"master":                    "mutable-ref",
		"develop":                   "mutable-ref",
		"v1.2.3":                    "mutable-ref",
		"refs/heads/main":           "mutable-ref",
		"HEAD":                      "mutable-ref",
		"":                          "unknown",
		"not a commit at all!!":     "unknown",
	}
	for hint, want := range cases {
		if got := HintKind(hint); got != want {
			t.Errorf("HintKind(%q) = %q, want %q", hint, got, want)
		}
	}
}

func TestPinTargetRequiresAMirrorForAMutableRefHint(t *testing.T) {
	c := regressionCampaign(t, "C-regpinmirror1")
	target, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Fenix", Shape: "lending-liquidation",
		CommitHint: "main", // §3a: Fenix Finance records "commit": "main"
	})
	if err != nil {
		t.Fatal(err)
	}
	tid := validation.ObjStr(target, "target_id")
	dir, sha := gitTarget(t)
	snap, err := snapshotPin(t, c, dir)
	if err != nil {
		t.Fatal(err)
	}
	sid := validation.ObjStr(snap, "snapshot_id")
	// Pinning a mutable-ref hint with no mirror is refused: the resolution is
	// not reproducible without the tree it was read from.
	_, err = PinTarget(c, PinSpec{
		TargetID: tid, ResolvedSHA: sha, SnapshotID: sid, ResolvedBy: "op",
	})
	if err == nil || !strings.Contains(err.Error(), "mirror") {
		t.Fatalf("err = %v, want a refusal naming the missing mirror", err)
	}
	if _, err := RecordMirror(c, MirrorSpec{
		TargetID: tid, Kind: "git-mirror",
		Path: ".scratch/p0/mirror/fenix.git", SHA256: strings.Repeat("b", 64),
		Bytes: 1024,
	}); err != nil {
		t.Fatal(err)
	}
	pinned, err := PinTarget(c, PinSpec{
		TargetID: tid, ResolvedSHA: sha, SnapshotID: sid, ResolvedBy: "op",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(pinned, "hint_kind"); got != "mutable-ref" {
		t.Fatalf("hint_kind = %q, want mutable-ref", got)
	}
	if !hasKey(pinned, "mirror") {
		t.Fatal("the pin carries no mirror block")
	}
	// A full-sha hint needs no mirror (the dataset already stated a pin), but
	// the hint kind is still recorded.
	other, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: sha,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PinTarget(c, PinSpec{
		TargetID: validation.ObjStr(other, "target_id"), ResolvedSHA: sha,
		SnapshotID: sid, ResolvedBy: "op",
	}); err != nil {
		t.Fatalf("a full-sha hint must pin without a mirror: %v", err)
	}
	// A SHORT sha is not a pin either — it is ambiguous by construction and it
	// is what three real codebases record (Oku 9e31b40, Idle Finance b6e5813,
	// SYMMIO cfe1920). It must be mirrored exactly like a mutable ref.
	short, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Oku", Shape: "vault-erc4626",
		CommitHint: "9e31b40",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PinTarget(c, PinSpec{
		TargetID: validation.ObjStr(short, "target_id"), ResolvedSHA: sha,
		SnapshotID: sid, ResolvedBy: "op",
	}); err == nil || !strings.Contains(err.Error(), "mirror") {
		t.Fatalf("a short-sha hint pinned without a mirror: err = %v", err)
	}
	// And an EMPTY hint is not a missing row: two real codebases record it
	// (Initia Move, Starknet Perpetual_main). It is `unknown`, so it needs a
	// mirror too — but the target itself must be creatable.
	empty, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Initia Move", Shape: "vault-erc4626",
		RecordID: "code4rena_initia-move_2025_04", Repo: "code-423n4/2025-01-initia-move",
	})
	if err != nil {
		t.Fatalf("an empty dataset commit field must be representable: %v", err)
	}
	if _, err := PinTarget(c, PinSpec{
		TargetID: validation.ObjStr(empty, "target_id"), ResolvedSHA: sha,
		SnapshotID: sid, ResolvedBy: "op",
	}); err == nil || !strings.Contains(err.Error(), "mirror") {
		t.Fatalf("an empty hint pinned without a mirror: err = %v", err)
	}
}

func TestRecordMirrorRefusesAnUnhashedOrEmptyMirror(t *testing.T) {
	c := regressionCampaign(t, "C-regpinmirror2")
	target, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626", CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	tid := validation.ObjStr(target, "target_id")
	for _, spec := range []MirrorSpec{
		{TargetID: tid, Kind: "git-mirror", Path: "", SHA256: strings.Repeat("b", 64)},
		{TargetID: tid, Kind: "git-mirror", Path: "/tmp/x", SHA256: "not-a-hash"},
		{TargetID: tid, Kind: "usb-stick", Path: "/tmp/x", SHA256: strings.Repeat("b", 64)},
		{TargetID: "T-000000000000", Kind: "git-mirror", Path: "/tmp/x", SHA256: strings.Repeat("b", 64)},
	} {
		if _, err := RecordMirror(c, spec); err == nil {
			t.Fatalf("RecordMirror accepted %+v", spec)
		}
	}
}
```

Add `snapshotPin` to the test file (it wraps `snapshot.PinSourceSnapshot`, the real producer):

```go
func snapshotPin(t *testing.T, c *state.Campaign, dir string) (validation.Value, error) {
	t.Helper()
	return snapshot.PinSourceSnapshot(c, dir, nil, nil)
}
```

with `"websec/internal/snapshot"` and `"websec/internal/state"` in the imports.

- [ ] **Step 2: Run them to verify they fail**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/regression -run 'HintKind|Mirror' -count=1`

Expected: FAIL to compile — `undefined: HintKind`, `undefined: RecordMirror`, `undefined: MirrorSpec`.

- [ ] **Step 3: Implement the classifier, the mirror record and the pin rule**

Create `internal/regression/pin.go`:

```go
package regression

import (
	"fmt"
	"regexp"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// HintKinds is the closed vocabulary of commit-hint shapes.
var HintKinds = []string{"full-sha", "short-sha", "mutable-ref", "unknown"}

var (
	shortShaRe = regexp.MustCompile(`^[0-9a-f]{7,39}$`)
	refLikeRe  = regexp.MustCompile(
		`^(?:HEAD|refs/[\w./-]+|(?:main|master|develop|dev|trunk|default)$|` +
			`v?\d+(?:\.\d+)*(?:[-.][\w.]+)?)$`)
)

// HintKind classifies the dataset's commit field. It exists because §3a's
// complaint about checkout_sources.py is not that it failed to resolve "main"
// — it is that resolving "main" produces a DIFFERENT answer every day, and the
// record has to say which kind of claim the dataset made.
func HintKind(hint string) string {
	h := strings.TrimSpace(hint)
	if h == "" {
		return "unknown"
	}
	if sha40Re.MatchString(h) {
		return "full-sha"
	}
	if shortShaRe.MatchString(h) {
		return "short-sha"
	}
	if refLikeRe.MatchString(h) {
		return "mutable-ref"
	}
	return "unknown"
}

// MirrorSpec is one local mirror of a target repo.
type MirrorSpec struct {
	TargetID string
	Kind     string
	Path     string
	SHA256   string
	Bytes    int64
}

// RecordMirror records the local mirror a resolved SHA was read from.
func RecordMirror(c *state.Campaign, spec MirrorSpec) (validation.Value, error) {
	target, ok, err := Target(c, spec.TargetID)
	if err != nil {
		return validation.VNull(), err
	}
	if !ok {
		return validation.VNull(), fmt.Errorf("no target %s in campaign %s",
			spec.TargetID, c.CampaignID)
	}
	if !contains([]string{"git-mirror", "git-bundle", "tarball"}, spec.Kind) {
		return validation.VNull(), fmt.Errorf(
			"unknown mirror kind %q (known: git-mirror, git-bundle, tarball)",
			spec.Kind)
	}
	if strings.TrimSpace(spec.Path) == "" {
		return validation.VNull(), fmt.Errorf(
			"a mirror record needs --mirror-path: a mirror nobody can find is not "+
				"a mirror")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(spec.SHA256) {
		return validation.VNull(), fmt.Errorf(
			"the mirror needs a 64-hex --mirror-sha256 (got %q) — without it the "+
				"mirror is an unverifiable claim about a directory", spec.SHA256)
	}
	mirror := validation.VObj(
		kv("kind", validation.VStr(spec.Kind)),
		kv("path", validation.VStr(spec.Path)),
		kv("sha256", validation.VStr(spec.SHA256)),
		kv("recorded_at", validation.VStr(state.NowIso())),
	)
	if spec.Bytes > 0 {
		mirror.O = validation.SetOrAppend(mirror.O, "bytes",
			validation.VInt(spec.Bytes))
	}
	doc := copyTargetWithKeys(target, []validation.KV{kv("mirror", mirror)})
	data := validation.VObj(
		kv("target_id", validation.VStr(spec.TargetID)),
		kv("mirror_kind", validation.VStr(spec.Kind)),
		kv("mirror_path", validation.VStr(spec.Path)),
		kv("mirror_sha256", validation.VStr(spec.SHA256)),
	)
	tid := spec.TargetID
	return writeThenLog(c, targetPath(c, tid), doc, "regression_target",
		"regression.target.mirrored", &tid, data)
}
```

Then in `target.go`'s `PinTarget`, immediately after the SHA shape check, add the hint rule and record the hint kind:

```go
	// Only a full 40-hex hint is self-pinning. The other three kinds are all
	// hints: a mutable ref moves, a short SHA is ambiguous, and an empty hint
	// states nothing at all. Ten of the snapshot's 32 codebases land in these
	// three buckets, so requiring a mirror only for `mutable-ref` would leave
	// five of the ten resolutions unreproducible.
	kind := HintKind(validation.ObjStr(target, "commit_hint"))
	if kind != "full-sha" {
		if !hasKey(target, "mirror") {
			return validation.VNull(), fmt.Errorf(
				"the dataset's commit field is a %s (%q) and target %s has no mirror "+
					"record — §3a: a ref is a hint, not a pin, and the resolution is "+
					"only reproducible against the mirrored tree; run "+
					"`regress <campaign> target mirror` first", kind,
				validation.ObjStr(target, "commit_hint"), spec.TargetID)
		}
	}
```

and in `copyTargetWith` add:

```go
	out.O = validation.SetOrAppend(out.O, "hint_kind", validation.VStr(HintKind(
		validation.ObjStr(target, "commit_hint"))))
```

- [ ] **Step 4: Add the audit problem line and the CLI actions, then run everything**

In `regressionsuite.go`'s per-target loop, add:

```go
		if kind != "" && kind != "full-sha" && !hasKeyS(t, "mirror") {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"target %s was pinned from a %s (%q) with no mirror record — the "+
					"resolution is not reproducible", tid, kind,
				validation.ObjStr(t, "commit_hint"))))
		}
```

where `kind := validation.ObjStr(t, "hint_kind")` is read once at the top of the loop body (it may be empty on a record written before this task — an empty hint_kind is not a problem, only a hint kind that is not `full-sha` without a mirror is).

In `cmd_regress.go`: add `--mirror-path`, `--mirror-kind`, `--mirror-sha256`, `--mirror-bytes` to `valueFlags`; add the `target mirror` subcommand dispatching to `regression.RecordMirror`; and extend `regressTargetPin`'s output line to print the hint kind (`hint=%s`), so the operator sees `mutable-ref` / `short-sha` / `unknown` in the terminal at pin time.

```bash
python3 scripts/sync-asset-manifest.py
GOCACHE=$PWD/.scratch/gocache go test ./internal/regression ./internal/audit/... ./internal/cli ./assets -count=1
```

Expected: PASS. Task 1's pin tests still pass — their hints are `main` (mutable-ref) with no mirror, so **they will now fail**: fix them by calling `RecordMirror` first, or by using a full-sha hint. Prefer the latter where the test is not about mirrors (`CommitHint: shaPre`), and keep one mutable-ref case with a mirror. This is the intended cost of the new rule; do not weaken the rule to keep a test green.

**The `tarball` mirror kind stays in the enum but is a second-class citizen, and the plan says so on purpose.** A tarball can be a mirror *record* — it is a verifiable byte-for-byte copy of the tree — but it cannot be the artifact the SHA was *resolved against*, because `snapshot.PinSourceSnapshot` takes `source.git_commit` from `git rev-parse HEAD` and a tarball has no git HEAD; `PinTarget`'s equality check would refuse the resulting snapshot. The enum keeps it so a record can say "this tarball corroborates the tree" without pretending it is the resolution source. See Step 5 for the decision.

- [ ] **Step 5: Operator step — mirror every selected repo (needs network)**

```bash
mkdir -p "$WEBV2_P0_DIR/mirror"
# Per SELECTED TARGET, not per project: a project may carry two codebases, so
# iterate the six targets' codebases (32 codebases exist in the snapshot; only
# the selected ones need a mirror).
#
# Resolve by hint kind — the recipe differs, and `git clone --mirror` is the
# most expensive option for all three:
#
#   full-sha  (22 of 32 codebases): fetch that one commit. Measured 252 KB.
#     git init -q "$d" && git -C "$d" remote add origin "https://github.com/$repo"
#     git -C "$d" fetch --depth 1 origin "$hint"
#     git -C "$d" checkout -q FETCH_HEAD        # <- makes git rev-parse HEAD work
#
#   mutable-ref (5): no clone needed to READ the pin:
#     git ls-remote "https://github.com/$repo" "$hint"     # e.g. main -> SHA
#     then fetch --depth 1 that SHA as above.
#
#   short-sha (3): the ref is not fetchable by name (measured: `git fetch
#     --depth 1 origin 9e31b40` fails with "couldn't find remote ref"), so:
#     git clone -q --depth 50 "https://github.com/$repo" "$d"
#     git -C "$d" rev-parse "$hint^{commit}"
#     # Idle Finance's b6e5813 is NOT in a depth-50 clone: `git fetch --unshallow`
#     # first (measured: 11 MB for Idle-Labs/idle-tranches).
#
#   unknown / empty (2): the dataset states nothing. Resolve the repo's default
#     branch HEAD and record it as `unknown` — and say in the gate record that
#     the pin is OUR choice, not the dataset's.
for repo in <org>/<repo-a> <org>/<repo-b> ...; do
  name="${repo//\//__}"
  d="$WEBV2_P0_DIR/mirror/$name.git"
  # ... the kind-appropriate recipe above, ending in:
  git -C "$d" rev-parse HEAD        # <- the resolved SHA recorded by `target pin`
  # a bundle is the portable form; keep one if the mirror must move
  git -C "$d" bundle create "$WEBV2_P0_DIR/mirror/$name.bundle" --all
  sha256sum "$WEBV2_P0_DIR/mirror/$name.bundle"
done
# then, per target:
webv2 --root "$WEBV2_P0_DIR/root" regress <cid> target mirror <T-id> \
    --mirror-kind git-bundle --mirror-path "$WEBV2_P0_DIR/mirror/$name.bundle" \
    --mirror-sha256 '<64-hex>' --mirror-bytes <bytes>
```

**Tarball or clone — the decision, and why.** Every codebase carries `tarball_url`, and it is genuinely cheaper for a one-shot tree: one `curl -L` with no history, and it is mechanically `<repo_url>/archive/<commit>.tar.gz` (verified: 0 exceptions across 32 codebases; 29 of 32 have one — the two empty-commit codebases and `Liquid Ron_main` do not). **This plan still mirrors with git**, for three measured reasons: (1) the pin binds to `snapshot.source.git_commit`, which comes from `git rev-parse HEAD` and is `null` for a tarball tree, so a tarball-only checkout cannot produce the snapshot `PinTarget` requires; (2) the tarball URL is not an independent pin — it re-encodes the same `commit` field, so `/archive/main.tar.gz` is exactly as mutable as `main`, and for the three short SHAs it is a short-SHA URL; (3) it is not actually cheaper *for the pinning job* once you skip `--mirror`: a depth-1 fetch by SHA measured 252 KB, and `git ls-remote` resolves a ref with no download at all. Keep the tarball as a **secondary corroboration** (fetch it, hash it, record it as `--mirror-kind tarball` if you want a second copy of the bytes) — never as the source of the resolved SHA.

Write the same rows into the committed index `eval/regression/mirrors.json` (`{target_id, repo, resolved_sha, mirror_kind, mirror_path, mirror_sha256}`), so the mirrors can be re-verified later without the campaign. **Record** in `docs/gates/v16-P0.md`: the per-target `hint_kind`, the resolved SHA, the mirror sha256, and the count of hints that were **not** full SHAs — report it twice, because §3a's Fenix Finance claim is a measurement: **snapshot-wide, 10 of 32 codebases** (5 mutable-ref, 3 short-sha, 2 empty), and among the six selected targets, the actual count. Do not report only the second and let it read as "one project".

- [ ] **Step 6: Commit**

```bash
git add assets/schema/regression_target.schema.json assets/testdata/asset_manifest.json \
        internal/regression/pin.go internal/regression/pin_test.go \
        internal/regression/target.go internal/regression/target_test.go \
        internal/cli/cmd_regress.go internal/audit/sections/regressionsuite.go
git commit -m "feat(v16-p0): commit-hint classification and local mirror bookkeeping"
```

---

### Task 6: The snap-time contamination grep

§3a, verbatim:

> **Fresh-target controls.** Each fresh target needs (a) the snap-time grep for finding titles/IDs across the pinned tree, plus verifying the committed tree contains no fix commits; (b) our own answer key from the report, and (c) a strip of any file mentioning the vulnerability — the same hygiene the ScaBench path needs. Double-transcribe every fresh key and record the disagreement rate; key errors are otherwise undetectable. The snap-time grep is the only thing that catches a leak that got through at ingestion.

The exit criterion is *"every fresh-target snapshot passes the contamination grep"* — so the grep is a gate, and it fails closed: any hit is a refusal, and a grep that could not run is a refusal too (an unmeasured grep is not a pass, the same rule `scripts/verify-full.sh` step 14 applies to the entropy ratchet).

**Offline vs operator, in this task.**
- **Built and tested offline (Steps 1–4):** the walker, the needle matching, the fix-commit history check, the fail-closed refusal, the record and the audit problem line — all over `t.TempDir()` trees and a throwaway git repo.
- **Operator step (Step 5, needs the checkout):** run the grep against each real pinned tree, strip what it finds, re-run until clean.

**Files:**
- Create: `internal/regression/contamination.go`
- Create: `internal/regression/contamination_test.go`
- Modify: `assets/schema/regression_target.schema.json` (add `contamination`)
- Modify: `internal/cli/cmd_regress.go` (`target grep`)
- Modify: `internal/audit/sections/regressionsuite.go` (the fresh-target problem line)
- Modify: `assets/testdata/asset_manifest.json` (regenerated)

**Interfaces:**
- Consumes: `regression.{Target,TargetsDir,writeThenLog,copyTargetWithKeys,hasKey}`, `snapshot.Git(path string, args ...string) string`, `validation.{Sha256Hex,ObjStr,VStr,VInt,VArr}`.
- Produces: `regression.ContaminationSpec{TargetID, Tree, NeedlesPath, FixCommitSHA string, MaxBytesPerFile int64}`, `regression.GrepTree(tree string, needles []string, maxFileBytes int64) (GrepResult, error)`, `regression.GrepResult{FilesScanned int, Hits []GrepHit}`, `regression.GrepHit{Path string, Line int, Needle string}`, `regression.FixCommitAbsent(tree, sha string) (bool, error)`, `regression.RecordContamination(c, spec ContaminationSpec) (validation.Value, error)`; ledger event `regression.contamination.recorded`. Task 9 refuses a fresh target without a clean grep.

- [ ] **Step 1: Extend the schema**

Add to `assets/schema/regression_target.schema.json`:

```json
    "contamination": {
      "type": "object",
      "additionalProperties": false,
      "required": ["clean", "files_scanned", "needles", "hits", "fix_commit_absent"],
      "description": "the snap-time contamination grep (§3a: 'the only thing that catches a leak that got through at ingestion'). clean=false is a refusal, not a warning; a grep that could not run is never recorded as clean — the writer refuses instead, because an unmeasured grep is not a pass",
      "properties": {
        "clean": { "type": "boolean" },
        "files_scanned": { "type": "integer", "minimum": 0 },
        "needles": { "type": "integer", "minimum": 1 },
        "hits": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["path", "line", "needle"],
            "properties": {
              "path": { "type": "string", "minLength": 1 },
              "line": { "type": "integer", "minimum": 1 },
              "needle": { "type": "string", "minLength": 1 }
            }
          }
        },
        "fix_commit_absent": {
          "type": "boolean",
          "description": "true only when the pinned tree's history does NOT contain the fix commit — §3a's 'verifying the committed tree contains no fix commits'"
        },
        "scanned_at": { "type": "string", "minLength": 20 },
        "notes": { "type": "string", "maxLength": 2000 }
      }
    },
```

- [ ] **Step 2: Write the failing tests**

Create `internal/regression/contamination_test.go`:

```go
package regression

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestGrepTreeFindsTitlesAndIDsAcrossTextFiles(t *testing.T) {
	tree := writeTree(t, map[string]string{
		"src/Vault.sol":              "contract Vault { /* reentrancy in withdraw */ }",
		"docs/CHANGELOG.md":          "fixed: REC-2024-113 reentrancy in withdraw",
		"assets/logo.bin":            "\x00\x01REC-2024-113\x02",
		".git/objects/pack/pack-1":   "REC-2024-113",
	})
	res, err := GrepTree(tree, []string{"reentrancy in withdraw", "REC-2024-113"}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, h := range res.Hits {
		paths[h.Path] = true
		if h.Line < 1 {
			t.Errorf("hit %+v has no line number", h)
		}
	}
	if !paths["src/Vault.sol"] || !paths["docs/CHANGELOG.md"] {
		t.Fatalf("hits = %v, want both the source and the changelog", paths)
	}
	if paths[".git/objects/pack/pack-1"] {
		t.Fatal("the grep walked .git — the tree's own history is checked by " +
			"FixCommitAbsent, and scanning packfiles reports noise as a leak")
	}
	if res.FilesScanned == 0 {
		t.Fatal("FilesScanned = 0 — an unmeasured grep must not look like a pass")
	}
}

func TestRecordContaminationFailsClosed(t *testing.T) {
	c := regressionCampaign(t, "C-regcontam001")
	target, err := AddTarget(c, TargetSpec{
		Kind: "fresh", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: shaPre, Repo: "org/acme",
	})
	if err != nil {
		t.Fatal(err)
	}
	tid := validation.ObjStr(target, "target_id")
	needles := filepath.Join(t.TempDir(), "needles.json")
	if err := os.WriteFile(needles, []byte(
		`["reentrancy in withdraw","REC-2024-113"]`), 0o644); err != nil {
		t.Fatal(err)
	}
	dirty := writeTree(t, map[string]string{
		"docs/CHANGELOG.md": "fixed: REC-2024-113",
	})
	// A hit is a refusal, not a record with clean=false: the tree must be
	// stripped and re-grepped, and a recorded dirty tree would be a suite that
	// ships knowing it is contaminated.
	if _, err := RecordContamination(c, ContaminationSpec{
		TargetID: tid, Tree: dirty, NeedlesPath: needles,
	}); err == nil || !strings.Contains(err.Error(), "REC-2024-113") {
		t.Fatalf("err = %v, want a refusal naming the hit", err)
	}
	// A tree that does not exist is a refusal too — never a clean result.
	if _, err := RecordContamination(c, ContaminationSpec{
		TargetID: tid, Tree: filepath.Join(t.TempDir(), "nope"), NeedlesPath: needles,
	}); err == nil {
		t.Fatal("RecordContamination accepted a missing tree")
	}
	clean := writeTree(t, map[string]string{
		"src/Vault.sol": "contract Vault {}",
	})
	doc, err := RecordContamination(c, ContaminationSpec{
		TargetID: tid, Tree: clean, NeedlesPath: needles,
	})
	if err != nil {
		t.Fatal(err)
	}
	con := validation.ObjAt(doc, "contamination")
	if !validation.ObjAt(con, "clean").B {
		t.Fatal("clean = false for a clean tree")
	}
	if got := validation.ObjAt(con, "needles").I; got != 2 {
		t.Fatalf("needles = %d, want 2", got)
	}
	if !hasKey(doc, "contamination") {
		t.Fatal("the contamination block is not on the target record")
	}
}

func TestFixCommitAbsentDetectsTheFixInHistory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitRun(t, dir, "init", "-q")
	write("Vault.sol", "contract Vault {}\n")
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "init")
	pre := gitRun(t, dir, "rev-parse", "HEAD")
	write("Vault.sol", "contract Vault { bool fixed; }\n")
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "fix")
	post := gitRun(t, dir, "rev-parse", "HEAD")

	// Pinned at the PRE-patch commit: the fix is not in history — clean.
	gitRun(t, dir, "checkout", "-q", pre)
	absent, err := FixCommitAbsent(dir, post)
	if err != nil {
		t.Fatal(err)
	}
	if !absent {
		t.Fatal("FixCommitAbsent = false for a tree checked out before the fix")
	}
	// Pinned at the fix: the tree contains the fix commit — refused.
	gitRun(t, dir, "checkout", "-q", post)
	absent, err = FixCommitAbsent(dir, post)
	if err != nil {
		t.Fatal(err)
	}
	if absent {
		t.Fatal("FixCommitAbsent = true for a tree that IS the fix commit")
	}
}

// gitRun is the test-local git runner (duplicated from target_test.go's
// gitTarget on purpose — small helpers are not exported).
func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	cmd := exec.Command("git", args...)
	cmd.Dir, cmd.Env = dir, env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}
```

- [ ] **Step 3: Implement the grep, the history check and the record**

Create `internal/regression/contamination.go`:

```go
package regression

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"websec/internal/snapshot"
	"websec/internal/state"
	"websec/internal/validation"
)

// GrepHit is one needle found in one file, at one line.
type GrepHit struct {
	Path   string
	Line   int
	Needle string
}

// GrepResult is one tree scan.
type GrepResult struct {
	FilesScanned int
	Hits         []GrepHit
}

// GrepTree walks tree and reports every line containing any needle, matched
// case-insensitively. It skips .git (the history check is FixCommitAbsent, and
// a packfile match is noise) and skips files larger than maxFileBytes and
// files that are not valid UTF-8 (a binary blob cannot leak a title, and
// scanning it costs a decode failure per file). FilesScanned is returned
// separately so a caller can tell "no hits in 4,000 files" from "no hits in 0
// files" — the whole point of the grep is that an unmeasured scan is not a
// pass.
func GrepTree(tree string, needles []string, maxFileBytes int64) (GrepResult, error) {
	if maxFileBytes <= 0 {
		maxFileBytes = 1 << 20
	}
	lower := make([]string, 0, len(needles))
	for _, n := range needles {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" {
			lower = append(lower, n)
		}
	}
	if len(lower) == 0 {
		return GrepResult{}, fmt.Errorf(
			"the contamination grep needs at least one needle — a grep with no " +
				"needles always reports clean, which is the failure mode §3a " +
				"warns about")
	}
	res := GrepResult{}
	err := filepath.WalkDir(tree, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxFileBytes {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !utf8Valid(raw) {
			return nil
		}
		res.FilesScanned++
		rel, err := filepath.Rel(tree, path)
		if err != nil {
			rel = path
		}
		sc := bufio.NewScanner(strings.NewReader(string(raw)))
		sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
		line := 0
		for sc.Scan() {
			line++
			text := strings.ToLower(sc.Text())
			for _, n := range lower {
				if strings.Contains(text, n) {
					res.Hits = append(res.Hits, GrepHit{
						Path: filepath.ToSlash(rel), Line: line, Needle: n,
					})
					break
				}
			}
		}
		return sc.Err()
	})
	if err != nil {
		return GrepResult{}, err
	}
	return res, nil
}

// utf8Valid is utf8.Valid without importing unicode/utf8 twice in a doc
// comment (kept local so the file's imports stay minimal).
func utf8Valid(b []byte) bool { return utf8.Valid(b) }

// FixCommitAbsent reports whether tree's history does NOT contain sha — §3a's
// "verifying the committed tree contains no fix commits". A tree that is not a
// git checkout at all returns false with an error: an unverifiable tree is not
// a clean tree.
func FixCommitAbsent(tree, sha string) (bool, error) {
	if strings.TrimSpace(sha) == "" {
		return false, fmt.Errorf(
			"FixCommitAbsent needs the fix commit's SHA — the check exists to " +
				"prove the pinned tree predates the fix, and a blank SHA proves " +
				"nothing")
	}
	log := snapshot.Git(tree, "rev-list", "HEAD")
	if strings.TrimSpace(log) == "" {
		return false, fmt.Errorf(
			"%s is not a git checkout (rev-list HEAD returned nothing) — the " +
				"fix-commit check cannot run, and an unmeasured check is not a pass",
			tree)
	}
	for _, line := range strings.Split(log, "\n") {
		if strings.TrimSpace(line) == sha {
			return false, nil
		}
	}
	return true, nil
}

// ContaminationSpec is one snap-time grep over one pinned tree.
type ContaminationSpec struct {
	TargetID       string
	Tree           string
	NeedlesPath    string
	FixCommitSHA   string
	MaxBytesPerFile int64
	Notes          string
}

// RecordContamination runs the grep and the history check and records both on
// the target. It REFUSES on any hit and on any check it could not run: the
// exit criterion is "every fresh-target snapshot passes the contamination
// grep", and a record saying clean=false would be a suite that ships knowing
// it is contaminated.
func RecordContamination(c *state.Campaign, spec ContaminationSpec) (validation.Value, error) {
	target, ok, err := Target(c, spec.TargetID)
	if err != nil {
		return validation.VNull(), err
	}
	if !ok {
		return validation.VNull(), fmt.Errorf("no target %s in campaign %s",
			spec.TargetID, c.CampaignID)
	}
	if info, err := os.Stat(spec.Tree); err != nil || !info.IsDir() {
		return validation.VNull(), fmt.Errorf(
			"the pinned tree %s is not a directory (%v) — there is nothing to "+
				"grep, and a missing tree is not a clean tree", spec.Tree, err)
	}
	needles, err := readNeedles(spec.NeedlesPath)
	if err != nil {
		return validation.VNull(), err
	}
	res, err := GrepTree(spec.Tree, needles, spec.MaxBytesPerFile)
	if err != nil {
		return validation.VNull(), err
	}
	if len(res.Hits) > 0 {
		first := res.Hits[0]
		return validation.VNull(), fmt.Errorf(
			"the pinned tree is contaminated: %d hit(s), first at %s:%d (%q) — "+
				"strip the file, re-snapshot, and grep again; §3a's fresh-target "+
				"controls make a dirty tree unshippable", len(res.Hits), first.Path,
			first.Line, first.Needle)
	}
	absent := true
	if spec.FixCommitSHA != "" {
		absent, err = FixCommitAbsent(spec.Tree, spec.FixCommitSHA)
		if err != nil {
			return validation.VNull(), err
		}
		if !absent {
			return validation.VNull(), fmt.Errorf(
				"the pinned tree's history contains the fix commit %s — the tree is "+
					"not pre-patch, so it cannot exercise the vulnerable revision",
				spec.FixCommitSHA)
		}
	}
	hits := make([]validation.Value, 0, len(res.Hits))
	for _, h := range res.Hits {
		hits = append(hits, validation.VObj(
			kv("path", validation.VStr(h.Path)),
			kv("line", validation.VInt(int64(h.Line))),
			kv("needle", validation.VStr(h.Needle)),
		))
	}
	con := validation.VObj(
		kv("clean", validation.VBool(true)),
		kv("files_scanned", validation.VInt(int64(res.FilesScanned))),
		kv("needles", validation.VInt(int64(len(needles)))),
		kv("hits", validation.VArr(hits...)),
		kv("fix_commit_absent", validation.VBool(absent)),
		kv("scanned_at", validation.VStr(state.NowIso())),
	)
	if spec.Notes != "" {
		con.O = validation.SetOrAppend(con.O, "notes", validation.VStr(spec.Notes))
	}
	doc := copyTargetWithKeys(target, []validation.KV{kv("contamination", con)})
	data := validation.VObj(
		kv("target_id", validation.VStr(spec.TargetID)),
		kv("files_scanned", validation.VInt(int64(res.FilesScanned))),
		kv("needles", validation.VInt(int64(len(needles)))),
		kv("fix_commit_absent", validation.VBool(absent)),
		kv("tree_sha256", validation.VStr(validation.Sha256Hex([]byte(spec.Tree)))),
	)
	tid := spec.TargetID
	return writeThenLog(c, targetPath(c, tid), doc, "regression_target",
		"regression.contamination.recorded", &tid, data)
}

// readNeedles reads the needle list: a JSON array of strings, or a text file
// with one needle per line. Both are accepted because the operator's needle
// list comes from the report they are reading.
func readNeedles(path string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "[") {
		doc, err := validation.ParseOrdered(raw)
		if err != nil {
			return nil, err
		}
		if doc.Kind != validation.Arr {
			return nil, fmt.Errorf("%s must be a JSON array of needles", path)
		}
		out := make([]string, 0, len(doc.A))
		for _, v := range doc.A {
			if v.Kind != validation.Str || strings.TrimSpace(v.S) == "" {
				return nil, fmt.Errorf("%s carries a non-string or empty needle", path)
			}
			out = append(out, v.S)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("%s carries no needles — a grep with no needles "+
				"always reports clean", path)
		}
		return out, nil
	}
	out := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s carries no needles", path)
	}
	return out, nil
}
```

Add `"unicode/utf8"` to the imports and drop the `utf8Valid` wrapper (call `utf8.Valid` directly) — the wrapper exists only to keep the doc comment honest.

- [ ] **Step 4: CLI + audit + run everything**

`cmd_regress.go`: add `target grep <T-id>` with `--tree`, `--needles`, `--fix-commit`, `--notes` (add them to `valueFlags`), dispatching to `RecordContamination` and printing `clean: N file(s) scanned, M needle(s), 0 hit(s)`. In `regressionsuite.go`, add to the per-target loop:

```go
		if validation.ObjStr(t, "kind") == "fresh" && !hasKeyS(t, "contamination") {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"fresh target %s has no contamination grep — Phase 0 exits only when "+
					"every fresh-target snapshot passes the grep (§3a: \"the only "+
					"thing that catches a leak that got through at ingestion\")", tid)))
		}
```

and add `KV("contamination_clean", ...)` / `KV("contamination_files_scanned", ...)` to the target row (empty string when absent).

```bash
GOCACHE=$PWD/.scratch/gocache go test ./internal/regression ./internal/audit/... ./internal/cli -count=1
```

Expected: PASS.

- [ ] **Step 5: Operator step — grep the real trees (needs the checkouts)**

```bash
# needles: every gold finding's title, every finding_id, and the fix commit's
# subject line — from the report, before you look at the tree's history.
cat > "$WEBV2_P0_DIR/needles.json" <<'JSON'
["<finding title 1>", "<finding title 2>", "<REC-id>", "<fix commit subject>"]
JSON
for t in <T-id>...; do
  webv2 --root "$WEBV2_P0_DIR/root" regress <cid> target grep "$t" \
      --tree "$WEBV2_P0_DIR/target/<repo>" \
      --needles "$WEBV2_P0_DIR/needles.json" \
      --fix-commit '<patch sha>'
done
```

On a hit: delete or strip the offending file (`docs/CHANGELOG.md` and `.github/` are the usual carriers), re-run `snap` to get a fresh pinned tree, and grep again. **Record** in `docs/gates/v16-P0.md`: per target, `files_scanned`, `needles`, `hits` (zero), `fix_commit_absent`, and every file the strip removed.

- [ ] **Step 6: Commit**

```bash
git add assets/schema/regression_target.schema.json assets/testdata/asset_manifest.json \
        internal/regression/contamination.go internal/regression/contamination_test.go \
        internal/cli/cmd_regress.go internal/audit/sections/regressionsuite.go
git commit -m "feat(v16-p0): snap-time contamination grep and fix-commit history check"
```

---

### Task 7: Double-transcription key quality

§3a, verbatim:

> Double-transcribe every fresh key and record the disagreement rate; key errors are otherwise undetectable.

and, from Part 10's residual list:

> **Fresh-target keys and contamination controls are new and self-measured.** Double-transcription disagreement rates and the snap-time grep are themselves unvalidated instruments.

The exit criterion is *"every key carries a recorded double-transcription disagreement rate"*. Note what it does **not** say: it does not say zero. A disagreement rate is a measurement of our own instrument, so recording `0.0` from two transcriptions that were never compared would be exactly the dishonesty this task exists to prevent. So the writer refuses a single transcription, refuses an unresolved disagreement, and records the arithmetic either way.

**Offline vs operator, in this task.**
- **Built and tested offline (Steps 1–4):** the row/field diff, the rate arithmetic (including Python-rounding, so the number matches the repo's other floats), the unresolved-disagreement refusal, the audit problem line.
- **Operator step (Step 5):** transcribe each fresh key twice, by hand, from the report — the second transcription done without looking at the first — then resolve the disagreements.

**Files:**
- Create: `internal/regression/keyquality.go`
- Create: `internal/regression/keyquality_test.go`
- Modify: `assets/schema/regression_target.schema.json` (add `key`)
- Modify: `internal/cli/cmd_regress.go` (`target key`)
- Modify: `internal/audit/sections/regressionsuite.go` (the fresh-target key problem line)
- Modify: `assets/testdata/asset_manifest.json` (regenerated)

**Interfaces:**
- Consumes: `regression.{Target,writeThenLog,copyTargetWithKeys,hasKey}`, `validation.{PyRound,ReadJson,VFloat,VInt,VStr,VArr,ObjStr,ObjAt}`.
- Produces: `regression.KeyFieldNames []string`, `regression.KeyDiff(a, b validation.Value) (validation.Value, error)`, `regression.KeyQualitySpec{TargetID, KeyA, KeyB, ResolutionsPath, ResolvedBy string}`, `regression.RecordKeyQuality(c, spec KeyQualitySpec) (validation.Value, error)`; ledger event `regression.key.recorded`. Task 9 refuses a fresh target whose key has no recorded rate.

- [ ] **Step 1: Extend the schema**

Add to `assets/schema/regression_target.schema.json`:

```json
    "key": {
      "type": "object",
      "additionalProperties": false,
      "required": ["a_path", "b_path", "rows", "agreeing", "disagreement_rate", "disagreements"],
      "description": "the answer key's provenance (§3a: 'Double-transcribe every fresh key and record the disagreement rate; key errors are otherwise undetectable'). The rate is the count of disagreeing (finding, field) pairs over all compared pairs; it is a measurement of OUR instrument, not a property of the target, so 0.0 must mean 'two transcriptions were compared and agreed everywhere', never 'nobody checked'",
      "properties": {
        "a_path": { "type": "string", "minLength": 1 },
        "b_path": { "type": "string", "minLength": 1 },
        "rows": { "type": "integer", "minimum": 1 },
        "agreeing": { "type": "integer", "minimum": 0 },
        "disagreement_rate": { "type": "number", "minimum": 0, "maximum": 1 },
        "disagreements": {
          "type": "array",
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["finding_id", "field", "a", "b"],
            "properties": {
              "finding_id": { "type": "string", "minLength": 1 },
              "field": { "type": "string", "minLength": 1 },
              "a": { "type": "string" },
              "b": { "type": "string" }
            }
          }
        },
        "resolved_by": { "type": "string", "minLength": 1 },
        "recorded_at": { "type": "string", "minLength": 20 }
      }
    },
```

- [ ] **Step 2: Write the failing tests**

Create `internal/regression/keyquality_test.go`:

```go
package regression

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

func keyDoc(t *testing.T, rows ...validation.Value) validation.Value {
	t.Helper()
	return validation.VObj(kv("rows", validation.VArr(rows...)))
}

func keyRow(fid, class, severity string) validation.Value {
	return validation.VObj(
		kv("finding_id", validation.VStr(fid)),
		kv("class", validation.VStr(class)),
		kv("severity", validation.VStr(severity)),
	)
}

func TestKeyDiffCountsPairsAndRoundsLikePython(t *testing.T) {
	a := keyDoc(t, keyRow("S-1", "reentrancy", "high"), keyRow("S-2", "oracle-manipulation", "high"),
		keyRow("S-3", "access-control", "medium"))
	b := keyDoc(t, keyRow("S-1", "reentrancy", "high"), keyRow("S-2", "oracle-manipulation", "medium"),
		keyRow("S-3", "access-control", "medium"))
	diff, err := KeyDiff(a, b)
	if err != nil {
		t.Fatal(err)
	}
	// 3 rows x 2 compared fields (class, severity) = 6 pairs, 1 disagreement.
	if got := validation.ObjAt(diff, "rows").I; got != 3 {
		t.Fatalf("rows = %d, want 3", got)
	}
	if got := validation.ObjAt(diff, "agreeing").I; got != 5 {
		t.Fatalf("agreeing = %d, want 5", got)
	}
	rate := validation.ObjAt(diff, "disagreement_rate")
	if rate.Kind != validation.Flt || rate.F != validation.PyRound(1.0/6.0, 6) {
		t.Fatalf("disagreement_rate = %v, want %v (Python rounding)",
			rate, validation.PyRound(1.0/6.0, 6))
	}
	d := validation.ObjAt(diff, "disagreements").A
	if len(d) != 1 || validation.ObjStr(d[0], "field") != "severity" {
		t.Fatalf("disagreements = %v, want the S-2 severity pair", d)
	}
}

func TestKeyDiffRefusesAMismatchedOrDuplicateRowSet(t *testing.T) {
	a := keyDoc(t, keyRow("S-1", "reentrancy", "high"), keyRow("S-2", "liveness", "high"))
	missing := keyDoc(t, keyRow("S-1", "reentrancy", "high"))
	if _, err := KeyDiff(a, missing); err == nil ||
		!strings.Contains(err.Error(), "S-2") {
		t.Fatalf("err = %v, want a refusal naming the row only one side has", err)
	}
	dup := keyDoc(t, keyRow("S-1", "reentrancy", "high"), keyRow("S-1", "liveness", "high"))
	if _, err := KeyDiff(a, dup); err == nil ||
		!strings.Contains(err.Error(), "twice") {
		t.Fatalf("err = %v, want a refusal naming the duplicate row", err)
	}
}

func TestRecordKeyQualityRefusesOneTranscriptionAndUnresolvedDisagreements(t *testing.T) {
	c := regressionCampaign(t, "C-regkey000001")
	target, err := AddTarget(c, TargetSpec{
		Kind: "fresh", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: shaPre, Repo: "org/acme",
	})
	if err != nil {
		t.Fatal(err)
	}
	tid := validation.ObjStr(target, "target_id")
	dir := t.TempDir()
	aPath := filepath.Join(dir, "a.json")
	bPath := filepath.Join(dir, "b.json")
	if err := os.WriteFile(aPath, []byte(
		`{"rows":[{"finding_id":"S-1","class":"reentrancy","severity":"high"}]}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bPath, []byte(
		`{"rows":[{"finding_id":"S-1","class":"reentrancy","severity":"medium"}]}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	// One transcription is not a disagreement rate.
	if _, err := RecordKeyQuality(c, KeyQualitySpec{
		TargetID: tid, KeyA: aPath,
	}); err == nil || !strings.Contains(err.Error(), "two transcriptions") {
		t.Fatalf("err = %v, want a refusal naming the second transcription", err)
	}
	// A real disagreement with no resolution is refused: the key is ambiguous.
	if _, err := RecordKeyQuality(c, KeyQualitySpec{
		TargetID: tid, KeyA: aPath, KeyB: bPath,
	}); err == nil || !strings.Contains(err.Error(), "unresolved") {
		t.Fatalf("err = %v, want a refusal naming the unresolved disagreement", err)
	}
	res := filepath.Join(dir, "resolve.json")
	if err := os.WriteFile(res, []byte(`{"S-1":"a"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := RecordKeyQuality(c, KeyQualitySpec{
		TargetID: tid, KeyA: aPath, KeyB: bPath, ResolutionsPath: res,
		ResolvedBy: "operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	key := validation.ObjAt(doc, "key")
	if got := validation.ObjAt(key, "disagreement_rate").F; got != validation.PyRound(0.5, 6) {
		t.Fatalf("disagreement_rate = %v, want 0.5 (1 of 2 pairs)", got)
	}
	if len(validation.ObjAt(key, "disagreements").A) != 1 {
		t.Fatal("the disagreement was resolved away instead of recorded — §3a " +
			"says record the rate, and a resolved disagreement is still a datum")
	}
	// A resolution naming a side that does not exist is refused.
	if err := os.WriteFile(res, []byte(`{"S-1":"c"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RecordKeyQuality(c, KeyQualitySpec{
		TargetID: tid, KeyA: aPath, KeyB: bPath, ResolutionsPath: res,
	}); err == nil {
		t.Fatal("RecordKeyQuality accepted a resolution of 'c'")
	}
}
```

- [ ] **Step 3: Implement the diff and the record**

Create `internal/regression/keyquality.go`:

```go
package regression

import (
	"fmt"
	"os"

	"websec/internal/state"
	"websec/internal/validation"
)

// KeyFieldNames are the compared fields of one answer-key row. It is the whole
// comparison: a field that is not here is not double-transcribed, and adding
// one is a deliberate act with a test.
var KeyFieldNames = []string{"class", "severity"}

// KeyDiff compares two transcriptions of the same key and returns
// {rows, agreeing, disagreement_rate, disagreements[]}. Both sides must cover
// the same finding ids exactly once — a key with a row only one transcription
// saw is a key nobody transcribed twice.
func KeyDiff(a, b validation.Value) (validation.Value, error) {
	rowsA, err := keyRows(a)
	if err != nil {
		return validation.VNull(), fmt.Errorf("transcription A: %w", err)
	}
	rowsB, err := keyRows(b)
	if err != nil {
		return validation.VNull(), fmt.Errorf("transcription B: %w", err)
	}
	for id := range rowsA {
		if _, ok := rowsB[id]; !ok {
			return validation.VNull(), fmt.Errorf(
				"finding %s appears in transcription A but not B — the two "+
					"transcriptions must cover the same rows, or the disagreement "+
					"rate is computed over a set nobody agreed on", id)
		}
	}
	for id := range rowsB {
		if _, ok := rowsA[id]; !ok {
			return validation.VNull(), fmt.Errorf(
				"finding %s appears in transcription B but not A", id)
		}
	}
	ids := make([]string, 0, len(rowsA))
	for id := range rowsA {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	disagreements := []validation.Value{}
	agreeing := 0
	pairs := 0
	for _, id := range ids {
		for _, field := range KeyFieldNames {
			pairs++
			va := validation.ObjStr(rowsA[id], field)
			vb := validation.ObjStr(rowsB[id], field)
			if va == vb {
				agreeing++
				continue
			}
			disagreements = append(disagreements, validation.VObj(
				kv("finding_id", validation.VStr(id)),
				kv("field", validation.VStr(field)),
				kv("a", validation.VStr(va)),
				kv("b", validation.VStr(vb)),
			))
		}
	}
	rate := 0.0
	if pairs > 0 {
		rate = validation.PyRound(float64(pairs-agreeing)/float64(pairs), 6)
	}
	return validation.VObj(
		kv("rows", validation.VInt(int64(len(ids)))),
		kv("agreeing", validation.VInt(int64(agreeing))),
		kv("disagreement_rate", validation.VFloat(rate)),
		kv("disagreements", validation.VArr(disagreements...)),
	), nil
}

// keyRows indexes a transcription by finding_id, refusing a duplicate.
func keyRows(doc validation.Value) (map[string]validation.Value, error) {
	out := map[string]validation.Value{}
	for _, row := range validation.ObjAt(doc, "rows").A {
		id := validation.ObjStr(row, "finding_id")
		if id == "" {
			return nil, fmt.Errorf("a row carries no finding_id")
		}
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf(
				"finding %s appears twice — a row transcribed twice cannot be "+
					"compared against anything", id)
		}
		out[id] = row
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("the transcription carries no rows")
	}
	return out, nil
}

// KeyQualitySpec is one double-transcription record.
type KeyQualitySpec struct {
	TargetID        string
	KeyA            string
	KeyB            string
	ResolutionsPath string
	ResolvedBy      string
}

// RecordKeyQuality diffs the two transcriptions and records the rate on the
// target. Two refusals: one transcription is not a rate (§3a asks for
// double-transcription), and an unresolved disagreement means the key is
// ambiguous — resolve it explicitly (a JSON {"finding_id": "a"|"b"}) and the
// disagreement is still recorded, because a resolved disagreement is a datum
// about the instrument, not a mistake to erase.
func RecordKeyQuality(c *state.Campaign, spec KeyQualitySpec) (validation.Value, error) {
	target, ok, err := Target(c, spec.TargetID)
	if err != nil {
		return validation.VNull(), err
	}
	if !ok {
		return validation.VNull(), fmt.Errorf("no target %s in campaign %s",
			spec.TargetID, c.CampaignID)
	}
	if spec.KeyA == "" || spec.KeyB == "" {
		return validation.VNull(), fmt.Errorf(
			"a disagreement rate needs two transcriptions (--key-a and --key-b); "+
				"one transcription produces no rate, and recording 0.0 from it "+
				"would be a number nobody measured")
	}
	docA, err := validation.ReadJson(spec.KeyA)
	if err != nil {
		return validation.VNull(), err
	}
	docB, err := validation.ReadJson(spec.KeyB)
	if err != nil {
		return validation.VNull(), err
	}
	diff, err := KeyDiff(docA, docB)
	if err != nil {
		return validation.VNull(), err
	}
	disagreements := validation.ObjAt(diff, "disagreements").A
	if len(disagreements) > 0 {
		resolutions := map[string]string{}
		if spec.ResolutionsPath != "" {
			res, err := validation.ReadJson(spec.ResolutionsPath)
			if err != nil {
				return validation.VNull(), err
			}
			for _, kvp := range res.O {
				if kvp.V.Kind != validation.Str ||
					(kvp.V.S != "a" && kvp.V.S != "b") {
					return validation.VNull(), fmt.Errorf(
						"resolution for %s is %v, want \"a\" or \"b\"", kvp.K, kvp.V)
				}
				resolutions[kvp.K] = kvp.V.S
			}
		}
		unresolved := []string{}
		for _, d := range disagreements {
			if resolutions[validation.ObjStr(d, "finding_id")] == "" {
				unresolved = append(unresolved, validation.ObjStr(d, "finding_id")+
					"."+validation.ObjStr(d, "field"))
			}
		}
		if len(unresolved) > 0 {
			return validation.VNull(), fmt.Errorf(
				"%d unresolved disagreement(s) between the two transcriptions "+
					"(%v) — the key is ambiguous until a human picks a side; pass "+
					"--resolutions {\"<finding_id>\":\"a\"|\"b\"}",
				len(unresolved), unresolved)
		}
	}
	key := validation.VObj(
		kv("a_path", validation.VStr(spec.KeyA)),
		kv("b_path", validation.VStr(spec.KeyB)),
		kv("rows", validation.ObjAt(diff, "rows")),
		kv("agreeing", validation.ObjAt(diff, "agreeing")),
		kv("disagreement_rate", validation.ObjAt(diff, "disagreement_rate")),
		kv("disagreements", validation.ObjAt(diff, "disagreements")),
		kv("recorded_at", validation.VStr(state.NowIso())),
	)
	if spec.ResolvedBy != "" {
		key.O = validation.SetOrAppend(key.O, "resolved_by",
			validation.VStr(spec.ResolvedBy))
	}
	doc := copyTargetWithKeys(target, []validation.KV{kv("key", key)})
	data := validation.VObj(
		kv("target_id", validation.VStr(spec.TargetID)),
		kv("rows", validation.ObjAt(diff, "rows")),
		kv("disagreement_rate", validation.ObjAt(diff, "disagreement_rate")),
		kv("disagreements", validation.VInt(int64(len(disagreements)))),
	)
	tid := spec.TargetID
	return writeThenLog(c, targetPath(c, tid), doc, "regression_target",
		"regression.key.recorded", &tid, data)
}
```

Add `"sort"` to the imports and `os` only if used (it is not — drop it).

- [ ] **Step 4: CLI + audit + run everything**

`cmd_regress.go`: add `target key <T-id>` with `--key-a`, `--key-b`, `--resolutions` (add all three to `valueFlags`; `--actor` is already there), printing `key: N row(s), M agreeing pair(s), disagreement_rate=R`. In `regressionsuite.go`:

```go
		if validation.ObjStr(t, "kind") == "fresh" && !hasKeyS(t, "key") {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"fresh target %s carries no double-transcription disagreement rate — "+
					"Phase 0 exits only when every key carries a recorded rate, and "+
					"key errors are otherwise undetectable (§3a)", tid)))
		}
```

plus `KV("key_disagreement_rate", ...)` on the target row (empty string when absent).

```bash
GOCACHE=$PWD/.scratch/gocache go test ./internal/regression ./internal/audit/... ./internal/cli -count=1
```

Expected: PASS.

- [ ] **Step 5: Operator step — transcribe twice, resolve, record**

```bash
# 1. transcribe the key from the contest report, by hand, into key A.
# 2. transcribe it AGAIN, from the report, without looking at A — into key B.
#    (Do this in one sitting but in two passes: the whole value of the control
#    is that the second pass does not inherit the first's reading.)
# 3. record the rate. The command refuses an unresolved disagreement, so the
#    operator's job is to look at each one and say which side the report
#    supports.
webv2 --root "$WEBV2_P0_DIR/root" regress <cid> target key <T-id> \
    --key-a eval/scabench/keys/<target>/a.json \
    --key-b eval/scabench/keys/<target>/b.json \
    --resolutions "$WEBV2_P0_DIR/resolutions.json" --actor "$(whoami)"
```

**Record** in `docs/gates/v16-P0.md`, per fresh target: `rows`, `agreeing`, `disagreement_rate`, the disagreements themselves (field + both readings), and how each was resolved. Part 10 calls this instrument unvalidated — the recorded rate is the first datum about it, so it belongs in the gate record even when it is zero.

- [ ] **Step 6: Commit**

```bash
git add assets/schema/regression_target.schema.json assets/testdata/asset_manifest.json \
        internal/regression/keyquality.go internal/regression/keyquality_test.go \
        internal/cli/cmd_regress.go internal/audit/sections/regressionsuite.go
git commit -m "feat(v16-p0): double-transcription key quality and its disagreement rate"
```

---

### Task 8: Commit-before-reveal, and never diagnose on held-out projects

§3a, verbatim:

> 1. **Hold out by project within the single snapshot.** Never diagnose on held-out projects. Commit-before-reveal — ledger hash committed and recorded before consulting the answer key — applies to *every* use of the current snapshot, not only reserved runs.

and the exit criterion's last clause: *"fresh targets carry our own answer keys with the ledger hash committed before any diagnostic use"*.

The enforcement is three ordered facts in the ledger: the key's hash is **committed**, the key is **revealed** only against a still-matching commitment, and a **diagnostic** run is refused unless a reveal precedes it. A commitment whose key file changed afterwards is void — that is the one failure mode a hash alone would miss.

**Offline vs operator, in this task.**
- **Built and tested offline (Steps 1–4):** the commit/reveal records, the key-change voiding, the diagnostic gate, the held-out refusal, the audit problem line — all as ordinary Go tests over `t.TempDir()` campaigns.
- **Operator step (Step 5):** commit each fresh key's hash *before* reading the report's key section, then reveal. Nothing about this needs the network; it needs discipline, and the record is what makes the discipline checkable.

**Files:**
- Create: `internal/regression/goldcommit.go`
- Create: `internal/regression/goldcommit_test.go`
- Modify: `assets/schema/regression_target.schema.json` (add `partition`)
- Modify: `assets/schema/regression_run.schema.json` (add `run_kind`)
- Modify: `internal/regression/target.go` (`TargetSpec.Partition`)
- Modify: `internal/regression/run.go` (`RunSpec.Kind` + the gate)
- Modify: `internal/cli/cmd_regress.go` (`target commit`, `target reveal`, `run --kind`)
- Modify: `internal/audit/sections/regressionsuite.go` (the held-out problem line)
- Modify: `assets/testdata/asset_manifest.json` (regenerated)

**Interfaces:**
- Consumes: `regression.{Target,TargetsDir,writeThenLog,copyTargetWithKeys,hasKey}`, `(*state.Campaign).Events() ([]validation.Value, error)`, `(*state.Campaign).NextSeq() (int, error)`, `validation.Sha256File`.
- Produces: `regression.Partitions []string`, `regression.GoldCommitSpec{TargetID, KeyPath, CommittedBy string}`, `regression.CommitKey(c, spec GoldCommitSpec) (validation.Value, error)`, `regression.RevealSpec{TargetID, KeyPath, RevealedBy string}`, `regression.RevealKey(c, spec RevealSpec) (validation.Value, error)`, `regression.AssertDiagnosticAllowed(c *state.Campaign, targetID string) error`, `regression.CommittedKeySHA(c, targetID) (string, bool, error)`; ledger events `regression.gold.committed`, `regression.gold.revealed`. Task 9 refuses a fresh target that never committed its key.

- [ ] **Step 1: Extend both schemas**

`assets/schema/regression_target.schema.json` — add:

```json
    "partition": {
      "enum": ["dev", "held-out", "training"],
      "description": "the leakage partition of this target, in the eval store's own vocabulary (internal/evalstore.Partitions). 'held-out' targets are never diagnosed on (§3a rule 1); the diagnosed campaign is 'training' — retained, relabeled, never eval"
    },
```

and add `"partition"` to the `required` list (a target with no partition is a target whose role nobody decided).

`assets/schema/regression_run.schema.json` — add `"run_kind"` to `required` and to `properties`:

```json
    "run_kind": {
      "enum": ["eval", "diagnostic"],
      "description": "'eval' is a measurement run — allowed on any target including held-out ones. 'diagnostic' is a run whose output a human reads to change the framework — refused on a held-out target (§3a: 'Never diagnose on held-out projects') and refused on a fresh target whose key was never committed and revealed"
    },
```

- [ ] **Step 2: Write the failing tests**

Create `internal/regression/goldcommit_test.go`:

```go
package regression

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

func freshTarget(t *testing.T, c *state.Campaign, partition string) string {
	t.Helper()
	target, err := AddTarget(c, TargetSpec{
		Kind: "fresh", Program: "Acme Fresh", Shape: "vault-erc4626",
		CommitHint: shaPre, Repo: "org/acme", Partition: partition,
	})
	if err != nil {
		t.Fatal(err)
	}
	return validation.ObjStr(target, "target_id")
}

func writeKey(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const keyBody = `{"rows":[{"finding_id":"S-1","class":"reentrancy","severity":"high"}]}`

func TestCommitBeforeRevealGate(t *testing.T) {
	c := regressionCampaign(t, "C-reggold000001")
	tid := freshTarget(t, c, "dev")
	key := writeKey(t, keyBody)

	// No commitment yet: a reveal is refused.
	if _, err := RevealKey(c, RevealSpec{TargetID: tid, KeyPath: key}); err == nil ||
		!strings.Contains(err.Error(), "committed") {
		t.Fatalf("err = %v, want a refusal naming the missing commitment", err)
	}
	commit, err := CommitKey(c, GoldCommitSpec{
		TargetID: tid, KeyPath: key, CommittedBy: "operator",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(commit, "key_sha256"); len(got) != 64 {
		t.Fatalf("key_sha256 = %q, want 64 hex", got)
	}
	// The key changes after commitment: the reveal is refused, because the
	// hash committed is no longer the hash of the key being revealed.
	other := writeKey(t, strings.Replace(keyBody, "high", "medium", 1))
	if _, err := RevealKey(c, RevealSpec{TargetID: tid, KeyPath: other}); err == nil ||
		!strings.Contains(err.Error(), "changed") {
		t.Fatalf("err = %v, want a refusal naming the changed key", err)
	}
	// The right key reveals.
	if _, err := RevealKey(c, RevealSpec{TargetID: tid, KeyPath: key}); err != nil {
		t.Fatal(err)
	}
	// The commitment survives on the target record with its ledger sequence —
	// and the sequence is the one the ledger actually assigned, read back from
	// the event whose type is "type" (sequences start at 0, so "not found" is
	// -1, never 0).
	target, _, err := Target(c, tid)
	if err != nil {
		t.Fatal(err)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	want := int64(-1)
	for _, e := range events {
		if validation.ObjStr(e, "type") == "regression.gold.committed" &&
			validation.ObjStr(e, "ref") == tid {
			want = validation.ObjAt(e, "seq").I
		}
	}
	if want < 0 {
		t.Fatal("no regression.gold.committed event for the target in the ledger")
	}
	if got := validation.ObjAt(validation.ObjAt(target, "gold"), "commit_seq").I; got != want {
		t.Fatalf("commit_seq = %d, want the ledger's own sequence %d", got, want)
	}
}

func TestDiagnosticIsRefusedOnHeldOutAndUnrevealedTargets(t *testing.T) {
	c := regressionCampaign(t, "C-reggold000002")
	heldOut := freshTarget(t, c, "held-out")
	key := writeKey(t, keyBody)
	if _, err := CommitKey(c, GoldCommitSpec{TargetID: heldOut, KeyPath: key}); err != nil {
		t.Fatal(err)
	}
	if _, err := RevealKey(c, RevealSpec{TargetID: heldOut, KeyPath: key}); err != nil {
		t.Fatal(err)
	}
	// §3a rule 1, as a refusal.
	if err := AssertDiagnosticAllowed(c, heldOut); err == nil ||
		!strings.Contains(err.Error(), "held-out") {
		t.Fatalf("err = %v, want a refusal naming the held-out partition", err)
	}
	// A dev fresh target that never revealed is refused too.
	dev := freshTarget(t, c, "dev")
	if err := AssertDiagnosticAllowed(c, dev); err == nil ||
		!strings.Contains(err.Error(), "revealed") {
		t.Fatalf("err = %v, want a refusal naming the missing reveal", err)
	}
	if _, err := CommitKey(c, GoldCommitSpec{TargetID: dev, KeyPath: key}); err != nil {
		t.Fatal(err)
	}
	if _, err := RevealKey(c, RevealSpec{TargetID: dev, KeyPath: key}); err != nil {
		t.Fatal(err)
	}
	if err := AssertDiagnosticAllowed(c, dev); err != nil {
		t.Fatalf("a revealed dev fresh target must allow a diagnostic: %v", err)
	}
	// A scabench target has ScaBench's own key: the reveal rule is about OUR
	// keys, and a scabench target is diagnosed freely.
	sb, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: "main", Partition: "dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := AssertDiagnosticAllowed(c, validation.ObjStr(sb, "target_id")); err != nil {
		t.Fatalf("a scabench target must allow a diagnostic: %v", err)
	}
}

func TestRecordRunRefusesADiagnosticOnAHeldOutTarget(t *testing.T) {
	c := regressionCampaign(t, "C-reggold000003")
	tid := freshTarget(t, c, "held-out")
	score := writeKey(t, evalGoldFixture)
	if _, err := RecordRun(c, RunSpec{
		TargetID: tid, Scorer: "eval-gold", ScoreFile: score, Kind: "diagnostic",
	}); err == nil || !strings.Contains(err.Error(), "held-out") {
		t.Fatalf("err = %v, want the held-out refusal from the run path", err)
	}
	// An eval run on the same held-out target is allowed: the point of holding
	// out is that it is measured, not that it is never run.
	if _, err := RecordRun(c, RunSpec{
		TargetID: tid, Scorer: "eval-gold", ScoreFile: score, Kind: "eval",
	}); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 3: Implement the commitment, the reveal and the gate**

Create `internal/regression/goldcommit.go`:

```go
package regression

import (
	"fmt"

	"websec/internal/state"
	"websec/internal/validation"
)

// Partitions is the eval store's leakage vocabulary, reused verbatim
// (internal/evalstore.Partitions) so a regression target's partition joins to
// the eval store's rows without a translation table.
var Partitions = []string{"dev", "held-out", "training"}

// GoldCommitSpec is one key-hash commitment.
type GoldCommitSpec struct {
	TargetID    string
	KeyPath     string
	CommittedBy string
}

// CommitKey records the sha256 of a fresh target's answer key in the ledger
// BEFORE the key is read. The sequence the event lands at is stored on the
// target, so "committed before any diagnostic use" is an ordering fact in the
// ledger rather than a claim about the operator's habits.
func CommitKey(c *state.Campaign, spec GoldCommitSpec) (validation.Value, error) {
	target, ok, err := Target(c, spec.TargetID)
	if err != nil {
		return validation.VNull(), err
	}
	if !ok {
		return validation.VNull(), fmt.Errorf("no target %s in campaign %s",
			spec.TargetID, c.CampaignID)
	}
	if spec.KeyPath == "" {
		return validation.VNull(), fmt.Errorf("a commitment needs --key (the key file)")
	}
	sha, err := validation.Sha256File(spec.KeyPath)
	if err != nil {
		return validation.VNull(), err
	}
	gold := validation.VObj(
		kv("key_path", validation.VStr(spec.KeyPath)),
		kv("key_sha256", validation.VStr(sha)),
		kv("committed_at", validation.VStr(state.NowIso())),
	)
	if spec.CommittedBy != "" {
		gold.O = validation.SetOrAppend(gold.O, "committed_by",
			validation.VStr(spec.CommittedBy))
	}
	doc := copyTargetWithKeys(target, []validation.KV{kv("gold", gold)})
	data := validation.VObj(
		kv("target_id", validation.VStr(spec.TargetID)),
		kv("key_sha256", validation.VStr(sha)),
		kv("key_path", validation.VStr(spec.KeyPath)),
	)
	tid := spec.TargetID
	written, err := writeThenLog(c, targetPath(c, tid), doc, "regression_target",
		"regression.gold.committed", &tid, data)
	if err != nil {
		return validation.VNull(), err
	}
	// The sequence the commitment landed at is itself part of the record: read
	// it back from the ledger, never from a counter the writer kept.
	seq, err := lastSeqFor(c, "regression.gold.committed", tid)
	if err != nil {
		return validation.VNull(), err
	}
	gold.O = validation.SetOrAppend(gold.O, "commit_seq", validation.VInt(int64(seq)))
	final := copyTargetWithKeys(written, []validation.KV{kv("gold", gold)})
	if err := validation.WriteJson(targetPath(c, tid), final, "regression_target"); err != nil {
		return validation.VNull(), err
	}
	return final, nil
}

// lastSeqFor is the sequence of the newest event of one type for one ref. The
// type key is "type" (internal/state/eventlog.go:364 builds {seq, at, type,
// ref, data, prev_hash, event_hash}) — not "event", and not "event_type".
// Sequences start at 0, so a caller must test "found" separately from ">= 0".
func lastSeqFor(c *state.Campaign, eventType, ref string) (int, error) {
	events, err := c.Events()
	if err != nil {
		return 0, err
	}
	seq := -1
	for _, e := range events {
		if validation.ObjStr(e, "type") != eventType {
			continue
		}
		if r := validation.ObjStr(e, "ref"); r != "" && r != ref {
			continue
		}
		if s := validation.ObjAt(e, "seq"); s.Kind == validation.Int && int(s.I) > seq {
			seq = int(s.I)
		}
	}
	return seq, nil
}

// RevealSpec is one key reveal.
type RevealSpec struct {
	TargetID   string
	KeyPath    string
	RevealedBy string
}

// RevealKey records that the key was read, and refuses when the key is not the
// one that was committed. A commitment whose file changed afterwards is void —
// that is the failure a bare hash would miss.
func RevealKey(c *state.Campaign, spec RevealSpec) (validation.Value, error) {
	target, ok, err := Target(c, spec.TargetID)
	if err != nil {
		return validation.VNull(), err
	}
	if !ok {
		return validation.VNull(), fmt.Errorf("no target %s in campaign %s",
			spec.TargetID, c.CampaignID)
	}
	if !hasKey(target, "gold") {
		return validation.VNull(), fmt.Errorf(
			"target %s has no committed key hash — commit the key's sha256 BEFORE "+
				"reading it (§3a: commit-before-reveal applies to every use of the "+
				"snapshot)", spec.TargetID)
	}
	want := validation.ObjStr(validation.ObjAt(target, "gold"), "key_sha256")
	got, err := validation.Sha256File(spec.KeyPath)
	if err != nil {
		return validation.VNull(), err
	}
	if want != got {
		return validation.VNull(), fmt.Errorf(
			"the key at %s has changed since it was committed (committed %s, now "+
				"%s) — the commitment is void; commit the new hash before revealing",
			spec.KeyPath, want, got)
	}
	reveal := validation.VObj(
		kv("key_path", validation.VStr(spec.KeyPath)),
		kv("key_sha256", validation.VStr(got)),
		kv("revealed_at", validation.VStr(state.NowIso())),
	)
	if spec.RevealedBy != "" {
		reveal.O = validation.SetOrAppend(reveal.O, "revealed_by",
			validation.VStr(spec.RevealedBy))
	}
	doc := copyTargetWithKeys(target, []validation.KV{kv("reveal", reveal)})
	data := validation.VObj(
		kv("target_id", validation.VStr(spec.TargetID)),
		kv("key_sha256", validation.VStr(got)),
	)
	tid := spec.TargetID
	return writeThenLog(c, targetPath(c, tid), doc, "regression_target",
		"regression.gold.revealed", &tid, data)
}

// AssertDiagnosticAllowed is the gate §3a's rule 1 and the exit criterion's
// last clause both describe. It refuses a diagnostic on a held-out target, and
// a diagnostic on a fresh target whose own key was never committed and
// revealed. A scabench target uses ScaBench's key, so it is diagnosed freely.
func AssertDiagnosticAllowed(c *state.Campaign, targetID string) error {
	target, ok, err := Target(c, targetID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no target %s in campaign %s", targetID, c.CampaignID)
	}
	if validation.ObjStr(target, "partition") == "held-out" {
		return fmt.Errorf(
			"target %s is held out — §3a rule 1: never diagnose on held-out "+
				"projects; run it as --kind eval instead", targetID)
	}
	if validation.ObjStr(target, "kind") != "fresh" {
		return nil
	}
	if !hasKey(target, "gold") || !hasKey(target, "reveal") {
		return fmt.Errorf(
			"fresh target %s has no committed-and-revealed key — a diagnostic on "+
				"it would be a diagnostic on a key nobody committed; run `regress "+
				"target commit` then `target reveal` first", targetID)
	}
	return nil
}

// CommittedKeySHA is the committed key hash for a target, when it has one.
func CommittedKeySHA(c *state.Campaign, targetID string) (string, bool, error) {
	target, ok, err := Target(c, targetID)
	if err != nil || !ok {
		return "", false, err
	}
	if !hasKey(target, "gold") {
		return "", false, nil
	}
	return validation.ObjStr(validation.ObjAt(target, "gold"), "key_sha256"), true, nil
}
```

Then in `target.go` add `Partition string` to `TargetSpec` (default `"dev"`, refused if not in `Partitions`) and write the key; in `run.go` add `Kind string` to `RunSpec` (default `"eval"`, refused if not in `{"eval","diagnostic"}`), write `run_kind`, and gate the diagnostic path:

```go
	if spec.Kind == "" {
		spec.Kind = "eval"
	}
	if spec.Kind != "eval" && spec.Kind != "diagnostic" {
		return validation.VNull(), fmt.Errorf(
			"unknown run kind %q (known: eval, diagnostic)", spec.Kind)
	}
	if spec.Kind == "diagnostic" {
		if err := AssertDiagnosticAllowed(c, spec.TargetID); err != nil {
			return validation.VNull(), err
		}
	}
```

- [ ] **Step 4: CLI, audit, run everything**

`cmd_regress.go`: `target commit <T-id> --key <path> --actor`, `target reveal <T-id> --key <path> --actor`, `run --kind eval|diagnostic` (default `eval`) — add `--key` to `valueFlags` (`--kind` and `--actor` are already there). In `regressionsuite.go`, add to the run loop:

```go
		if validation.ObjStr(run, "run_kind") == "diagnostic" {
			if t, ok := byID[tid]; ok && validation.ObjStr(t, "partition") == "held-out" {
				problems = append(problems, validation.VStr(fmt.Sprintf(
					"run %s is a DIAGNOSTIC on held-out target %s — §3a rule 1: "+
						"never diagnose on held-out projects",
					validation.ObjStr(run, "run_id"), tid)))
			}
		}
```

plus `KV("partition", ...)`, `KV("gold_committed", ...)`, `KV("gold_revealed", ...)` on the target row.

```bash
python3 scripts/sync-asset-manifest.py
GOCACHE=$PWD/.scratch/gocache go test ./internal/regression ./internal/audit/... ./internal/cli ./assets -count=1
```

Expected: PASS. Task 1's and Task 2's `AddTarget` calls now need `Partition`; they default to `dev`, so nothing breaks — but `partition` is now *required in the schema*, so the writer must always set it. Confirm with `GOCACHE=$PWD/.scratch/gocache go test ./internal/regression -run TestAddTarget -count=1`.

- [ ] **Step 5: Operator step — commit before reading the key**

```bash
# BEFORE opening the report's answer-key section:
sha256sum eval/scabench/keys/<target>/a.json     # the hash you are about to commit
webv2 --root "$WEBV2_P0_DIR/root" regress <cid> target commit <T-id> \
    --key eval/scabench/keys/<target>/a.json --actor "$(whoami)"
# now read the report, finish both transcriptions, then:
webv2 --root "$WEBV2_P0_DIR/root" regress <cid> target reveal <T-id> \
    --key eval/scabench/keys/<target>/a.json --actor "$(whoami)"
```

**Record** in `docs/gates/v16-P0.md`, per fresh target: the committed `key_sha256`, the `commit_seq`, the reveal, and — the part that matters — **whether the commit really preceded the reveal in the ledger**, which the audit's `gold_committed`/`gold_revealed` flags and the two sequence numbers show. A commitment made after the fact is not a control; if that happened for a target, say so and treat the target as contaminated rather than re-recording it.

- [ ] **Step 6: Commit**

```bash
git add assets/schema/regression_target.schema.json assets/schema/regression_run.schema.json \
        assets/testdata/asset_manifest.json internal/regression/goldcommit.go \
        internal/regression/goldcommit_test.go internal/regression/target.go \
        internal/regression/run.go internal/cli/cmd_regress.go \
        internal/audit/sections/regressionsuite.go
git commit -m "feat(v16-p0): commit-before-reveal and the held-out diagnostic gate"
```

---

### Task 9: Fresh targets from post-window contest reports

§3a, verbatim:

> 2. **Build fresh targets ourselves from published contest reports in the window ScaBench doesn't cover.**

with the fresh-target controls from the same section:

> Each fresh target needs (a) the snap-time grep for finding titles/IDs across the pinned tree, plus verifying the committed tree contains no fix commits; (b) our own answer key from the report, and (c) a strip of any file mentioning the vulnerability — the same hygiene the ScaBench path needs. Double-transcribe every fresh key and record the disagreement rate; key errors are otherwise undetectable.

Tasks 6, 7 and 8 built the three controls. This task is the **registration gate** that makes them a precondition rather than a good intention: a fresh target cannot be *created* without a cited report published after ScaBench's window, and cannot enter the suite until all three controls are present. The second half is `AssertFreshControls`, which Task 10's suite writer calls and `regress target check` exposes to the operator.

**Offline vs operator, in this task.**
- **Built and tested offline (Steps 1–4):** the window arithmetic, the provenance refusals, the composed control check, the CLI, the tests that build a complete fresh target through the real writers and then break each control in turn.
- **Operator step (Step 5, needs network):** find the reports, mirror the repos, strip, transcribe twice, commit/reveal, check.

**Files:**
- Create: `internal/regression/fresh.go`
- Create: `internal/regression/fresh_test.go`
- Modify: `internal/cli/cmd_regress.go` (`target add-fresh`, `target check`)
- Modify: `internal/audit/sections/regressionsuite.go` (report the control-completeness flag per fresh target)

**Interfaces:**
- Consumes: `regression.{AddTarget,Target,AssertDiagnosticAllowed,CommittedKeySHA,hasKey,contains,Partitions,TargetShapes}`, `validation.{ObjStr,ObjAt}`.
- Produces: `regression.ScabenchSnapshotDate = "2025-08-18"`, `regression.FreshSpec{Program, RecordID, Repo, ReportURL, ReportDate, CommitHint, Shape, Partition string}`, `regression.AddFreshTarget(c *state.Campaign, spec FreshSpec) (validation.Value, error)`, `regression.AssertFreshControls(c *state.Campaign, targetID string) error`. Task 10 calls `AssertFreshControls` for every fresh target in the suite.

- [ ] **Step 1: Write the failing tests**

Create `internal/regression/fresh_test.go`:

```go
package regression

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

func freshSpec() FreshSpec {
	return FreshSpec{
		Program: "Post Window", RecordID: "post-window-2026-01",
		Repo: "org/post-window", ReportURL: "https://example.test/report/2026-01",
		ReportDate: "2026-01-15", CommitHint: shaPre,
		Shape: "bridge-messaging", Partition: "dev",
	}
}

func TestAddFreshTargetRefusesAReportInsideTheScabenchWindow(t *testing.T) {
	c := regressionCampaign(t, "C-regfresh00001")
	for _, date := range []string{"2025-08-18", "2025-01-01", ""} {
		spec := freshSpec()
		spec.ReportDate = date
		if _, err := AddFreshTarget(c, spec); err == nil ||
			!strings.Contains(err.Error(), ScabenchSnapshotDate) {
			t.Errorf("ReportDate %q: err = %v, want a refusal naming %s",
				date, err, ScabenchSnapshotDate)
		}
	}
	spec := freshSpec()
	spec.ReportURL = ""
	if _, err := AddFreshTarget(c, spec); err == nil ||
		!strings.Contains(err.Error(), "report") {
		t.Fatalf("err = %v, want a refusal naming the missing report", err)
	}
	spec = freshSpec()
	spec.Partition = "training"
	if _, err := AddFreshTarget(c, spec); err == nil ||
		!strings.Contains(err.Error(), "training") {
		t.Fatalf("err = %v, want a refusal explaining that training is not a "+
			"fresh target's partition", err)
	}
	spec = freshSpec()
	spec.Shape = "diagnosed-campaign"
	if _, err := AddFreshTarget(c, spec); err == nil {
		t.Fatal("AddFreshTarget accepted a non-ScaBench shape")
	}
	target, err := AddFreshTarget(c, freshSpec())
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(target, "kind"); got != "fresh" {
		t.Fatalf("kind = %q, want fresh", got)
	}
	if got := validation.ObjStr(target, "report_date"); got != "2026-01-15" {
		t.Fatalf("report_date = %q", got)
	}
}

// TestAssertFreshControlsNamesEveryMissingControl builds a complete fresh
// target through the REAL writers, then removes one control at a time by
// building a second target without it — the composed check must name exactly
// what is missing, because "controls incomplete" is not actionable.
func TestAssertFreshControlsNamesEveryMissingControl(t *testing.T) {
	c := regressionCampaign(t, "C-regfresh00002")
	needles := filepath.Join(t.TempDir(), "needles.json")
	if err := os.WriteFile(needles, []byte(`["reentrancy in withdraw"]`), 0o644); err != nil {
		t.Fatal(err)
	}
	cleanTree := writeTree(t, map[string]string{"src/V.sol": "contract V {}"})
	keyA := writeKey(t, keyBody)
	keyB := writeKey(t, keyBody)

	// 1. nothing recorded yet: the first missing control is named.
	bare, err := AddFreshTarget(c, freshSpec())
	if err != nil {
		t.Fatal(err)
	}
	bareID := validation.ObjStr(bare, "target_id")
	if err := AssertFreshControls(c, bareID); err == nil ||
		!strings.Contains(err.Error(), "contamination") {
		t.Fatalf("err = %v, want a refusal naming the missing contamination grep", err)
	}
	// 2. grep only: the key is named next.
	if _, err := RecordContamination(c, ContaminationSpec{
		TargetID: bareID, Tree: cleanTree, NeedlesPath: needles,
	}); err != nil {
		t.Fatal(err)
	}
	if err := AssertFreshControls(c, bareID); err == nil ||
		!strings.Contains(err.Error(), "key") {
		t.Fatalf("err = %v, want a refusal naming the missing key rate", err)
	}
	// 3. key only: the commitment is named next.
	if _, err := RecordKeyQuality(c, KeyQualitySpec{
		TargetID: bareID, KeyA: keyA, KeyB: keyB,
	}); err != nil {
		t.Fatal(err)
	}
	if err := AssertFreshControls(c, bareID); err == nil ||
		!strings.Contains(err.Error(), "commit") {
		t.Fatalf("err = %v, want a refusal naming the missing commitment", err)
	}
	// 4. committed but not revealed: the reveal is named.
	if _, err := CommitKey(c, GoldCommitSpec{TargetID: bareID, KeyPath: keyA}); err != nil {
		t.Fatal(err)
	}
	if err := AssertFreshControls(c, bareID); err == nil ||
		!strings.Contains(err.Error(), "reveal") {
		t.Fatalf("err = %v, want a refusal naming the missing reveal", err)
	}
	// 5. all four controls present: it passes, and only then.
	if _, err := RevealKey(c, RevealSpec{TargetID: bareID, KeyPath: keyA}); err != nil {
		t.Fatal(err)
	}
	if err := AssertFreshControls(c, bareID); err != nil {
		t.Fatalf("a fresh target with all three controls must pass: %v", err)
	}
}

func TestAssertFreshControlsRefusesNonFreshTargets(t *testing.T) {
	c := regressionCampaign(t, "C-regfresh00003")
	sb, err := AddTarget(c, TargetSpec{
		Kind: "scabench", Program: "Acme", Shape: "vault-erc4626",
		CommitHint: "main",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := AssertFreshControls(c, validation.ObjStr(sb, "target_id")); err == nil ||
		!strings.Contains(err.Error(), "fresh") {
		t.Fatalf("err = %v, want a refusal explaining the check is for fresh targets", err)
	}
}
```

- [ ] **Step 2: Run them to verify they fail**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/regression -run 'Fresh' -count=1`

Expected: FAIL to compile — `undefined: FreshSpec`, `undefined: AddFreshTarget`, `undefined: AssertFreshControls`, `undefined: ScabenchSnapshotDate`.

- [ ] **Step 3: Implement the registration gate**

Create `internal/regression/fresh.go`:

```go
package regression

import (
	"fmt"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// ScabenchSnapshotDate is the one ScaBench snapshot's cutoff (§3a: "There is
// exactly ONE ScaBench snapshot — curated-2025-08-18; no releases, no tags").
// Verified 2026-09-21 against the checkout: datasets/ holds one directory, and
// the upstream repo has no releases and no tags. A fresh target exists to cover
// the window that snapshot does not, so a report inside the window is a
// ScaBench target wearing a different name.
const ScabenchSnapshotDate = "2025-08-18"

// FreshSpec is one fresh target's provenance.
type FreshSpec struct {
	Program    string
	RecordID   string
	Repo       string
	ReportURL  string
	ReportDate string
	CommitHint string
	Shape      string
	Partition  string
}

// AddFreshTarget registers a fresh target. Two refusals at registration, and
// both are about the target's REASON to exist: the report must be published
// after ScaBench's snapshot (otherwise the snapshot already covers it, and
// §3a's fallback rule would treat it as held-out ScaBench data instead), and
// the partition must be dev or held-out — "training" is the diagnosed
// campaign's relabel, not a fresh target's role.
func AddFreshTarget(c *state.Campaign, spec FreshSpec) (validation.Value, error) {
	if strings.TrimSpace(spec.ReportURL) == "" {
		return validation.VNull(), fmt.Errorf(
			"a fresh target needs --report-url: §3a builds them \"from published "+
				"contest reports\", and an unsourced target is not one")
	}
	if spec.ReportDate <= ScabenchSnapshotDate {
		return validation.VNull(), fmt.Errorf(
			"report date %q is inside ScaBench's window (the snapshot is %s) — a "+
				"fresh target must cover the window the snapshot does not; use a "+
				"ScaBench target or cite a later report",
			spec.ReportDate, ScabenchSnapshotDate)
	}
	if spec.Partition == "training" {
		return validation.VNull(), fmt.Errorf(
			"a fresh target is dev or held-out, never training — §3a's training "+
				"row is the diagnosed campaign, retained but relabeled")
	}
	if !contains(ScaBenchShapes, spec.Shape) {
		return validation.VNull(), fmt.Errorf(
			"a fresh target takes one of §3a's four shapes %v, not %q",
			ScaBenchShapes, spec.Shape)
	}
	doc, err := AddTarget(c, TargetSpec{
		Kind: "fresh", Program: spec.Program, RecordID: spec.RecordID,
		Repo: spec.Repo, Shape: spec.Shape, CommitHint: spec.CommitHint,
		Partition: spec.Partition,
	})
	if err != nil {
		return validation.VNull(), err
	}
	doc.O = validation.SetOrAppend(doc.O, "report_url", validation.VStr(spec.ReportURL))
	doc.O = validation.SetOrAppend(doc.O, "report_date", validation.VStr(spec.ReportDate))
	tid := validation.ObjStr(doc, "target_id")
	if err := validation.Validate(doc, "regression_target", 1); err != nil {
		return validation.VNull(), err
	}
	if err := validation.WriteJson(targetPath(c, tid), doc, ""); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		kv("target_id", validation.VStr(tid)),
		kv("report_url", validation.VStr(spec.ReportURL)),
		kv("report_date", validation.VStr(spec.ReportDate)),
	)
	if _, err := c.Log("regression.fresh.registered", &tid, &data); err != nil {
		return validation.VNull(), err
	}
	return doc, nil
}

// AssertFreshControls is the gate: a fresh target enters the suite only when
// all three §3a controls are recorded — a clean snap-time contamination grep,
// a key with a recorded double-transcription disagreement rate, and a key hash
// committed before its reveal. It names the FIRST missing control, in the
// order the operator would fix them, because "controls incomplete" is not an
// actionable message.
func AssertFreshControls(c *state.Campaign, targetID string) error {
	target, ok, err := Target(c, targetID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("no target %s in campaign %s", targetID, c.CampaignID)
	}
	if got := validation.ObjStr(target, "kind"); got != "fresh" {
		return fmt.Errorf(
			"target %s is kind %q — the fresh-target controls apply to fresh "+
				"targets; a scabench target uses ScaBench's own key", targetID, got)
	}
	if !hasKey(target, "contamination") {
		return fmt.Errorf(
			"fresh target %s has no contamination grep — run `regress <campaign> "+
				"target grep %s --tree <pinned tree> --needles <needles.json>`",
			targetID, targetID)
	}
	if !validation.ObjAt(validation.ObjAt(target, "contamination"), "clean").B {
		return fmt.Errorf(
			"fresh target %s has a contamination record that is not clean", targetID)
	}
	if !hasKey(target, "key") {
		return fmt.Errorf(
			"fresh target %s has no double-transcription disagreement rate — run "+
				"`regress <campaign> target key %s --key-a ... --key-b ...` (§3a: "+
				"key errors are otherwise undetectable)", targetID, targetID)
	}
	if !hasKey(target, "gold") {
		return fmt.Errorf(
			"fresh target %s has no committed key hash — run `regress <campaign> "+
				"target commit %s --key ...` BEFORE reading the key", targetID, targetID)
	}
	if !hasKey(target, "reveal") {
		return fmt.Errorf(
			"fresh target %s committed its key but never revealed it — run "+
				"`regress <campaign> target reveal %s --key ...`", targetID, targetID)
	}
	commit := validation.ObjAt(validation.ObjAt(target, "gold"), "key_sha256")
	reveal := validation.ObjAt(validation.ObjAt(target, "reveal"), "key_sha256")
	if validation.ObjStr(commit, "x") != validation.ObjStr(reveal, "x") {
		return fmt.Errorf(
			"fresh target %s committed key %s but revealed key %s — the reveal did "+
				"not use the committed key, so the commitment proves nothing",
			targetID, commit.S, reveal.S)
	}
	return nil
}
```

The two `ObjStr(commit, "x")` calls in the last check are a bug — comparing a value to itself. The real check compares the two SHA strings directly:

```go
	commitSHA := validation.ObjStr(validation.ObjAt(target, "gold"), "key_sha256")
	revealSHA := validation.ObjStr(validation.ObjAt(target, "reveal"), "key_sha256")
	if commitSHA != revealSHA {
		return fmt.Errorf(
			"fresh target %s committed key %s but revealed key %s — the reveal did "+
				"not use the committed key, so the commitment proves nothing",
			targetID, commitSHA, revealSHA)
	}
```

- [ ] **Step 4: CLI, audit, run everything**

`cmd_regress.go`: add `target add-fresh` (`--program`, `--record-id`, `--repo`, `--report-url`, `--report-date`, `--commit-hint`, `--shape`, `--partition` — `--report-date` and `--partition` are the two new names for `valueFlags`; the rest are already there) and `target check <T-id>` (prints `fresh target T-… controls: OK` or returns the refusal as exit 1). In `regressionsuite.go`, add a per-fresh-target completeness flag to the row (`KV("fresh_controls_complete", validation.VBool(err == nil))` from a call to `AssertFreshControls`) and keep the existing per-control problems (do not duplicate them — the problems come from the individual checks, the flag is the summary).

```bash
GOCACHE=$PWD/.scratch/gocache go test ./internal/regression ./internal/audit/... ./internal/cli -count=1
```

Expected: PASS.

- [ ] **Step 5: Operator step — build the fresh targets (needs network)**

```bash
# 1. find contest reports published AFTER 2025-08-18 (Code4rena / Sherlock /
#    Cantina public reports; Part 4 cuts live platform support but the reports
#    are published documents).
# 2. register the target — the window and the provenance are checked here.
webv2 --root "$WEBV2_P0_DIR/root" regress <cid> target add-fresh \
    --program '<project>' --record-id '<contest slug>' --repo '<org>/<repo>' \
    --report-url '<url>' --report-date '<YYYY-MM-DD>' \
    --commit-hint '<dataset-style hint>' --shape '<one of the four>' \
    --partition dev          # or held-out
# 3. mirror, pin and snap exactly as in Task 1 Step 21 / Task 5 Step 5.
# 4. strip: remove any file the grep flags, re-snap, grep again.
webv2 --root "$WEBV2_P0_DIR/root" regress <cid> target grep <T-id> \
    --tree "$WEBV2_P0_DIR/target/<repo>" --needles "$WEBV2_P0_DIR/needles.json"
# 5. transcribe the key twice (Task 7 Step 5), record the rate, commit, reveal.
# 6. the composed check, which is what Task 10's suite writer will call.
webv2 --root "$WEBV2_P0_DIR/root" regress <cid> target check <T-id>
```

**Record** in `docs/gates/v16-P0.md`, per fresh target: the report URL and date, the pinned SHA, `files_scanned`/`hits`/`fix_commit_absent`, the disagreement rate, the committed and revealed key hashes with their sequences, and the `target check` output. If no suitable report could be sourced, record the fresh-target row of §3a's composition as `NOT SOURCED — <reason>` and say what that costs: §3a's Part 10 item 5 — *"a slipped fresh-target set silently degrades the suite back toward ScaBench-only rediscovery"*.

- [ ] **Step 6: Commit**

```bash
git add internal/regression/fresh.go internal/regression/fresh_test.go \
        internal/cli/cmd_regress.go internal/audit/sections/regressionsuite.go
git commit -m "feat(v16-p0): fresh-target registration gate and composed control check"
```

---

### Task 10: The suite composition — one file that says which six, and refuses a broken six

Tasks 1–9 produce the parts. This task is the join: one repo-level, schema-validated, sidecar-verified composition that names each pick's campaign, checks every pick against the campaign's own target record, refuses a fresh target whose controls are incomplete, refuses a partition that disagrees with the selection, and refuses a suite with no control target or no training row. It is also the plan's second end-to-end branch test: it drives the real writers in five campaigns and reads the result back through the audit of one of them.

§3a's composition, verbatim:

> Constrained to the four target shapes below plus the diagnosed campaign:
> - One vault/ERC-4626-style target (share-inflation, rounding)
> - One lending/liquidation market (insolvency, bad-debt dynamics)
> - One bridge/cross-chain messaging target (verification config, replay)
> - One non-rollup L2 or oracle-driven protocol
> - The diagnosed campaign itself, retained but relabeled as training data, not eval
> - One already-publicly-exploited target, to exercise §C7.2's PATCHED-KNOWN path before it ships

and the D8 rule this file carries into every downstream report:

> 3. **Label what the suite measures (D8).** ... A suite that quietly switches from rediscovery to fresh-target measurement is worse than no suite, because the number looks like the thing it isn't.

**Offline vs operator, in this task.**
- **Built and tested offline (Steps 1–5):** the composition schema, the writer with all seven refusals, the CLI, the cross-campaign consistency test, the audit read-back.
- **Operator step (Step 6):** write the real composition once every target's controls are recorded, then run the suite and record the numbers with their label.

**Files:**
- Create: `assets/schema/regression_suite.schema.json`
- Create: `internal/regression/suite.go`
- Create: `internal/regression/suite_test.go`
- Modify: `internal/cli/cmd_regress.go` (repo-level `suite` action)
- Modify: `internal/audit/sections/regressionsuite.go` (the suite-level row)
- Modify: `internal/validation/schema.go` (append `"regression_suite"`)
- Modify: `assets/testdata/asset_manifest.json` (regenerated)

**Interfaces:**
- Consumes: `regression.{ReadRepoRecord,WriteRepoRecord,Select,ScaBenchShapes,AssertFreshControls,LoadTargets,Target,hasKey}`, `state.Open(root, cid string) (*state.Campaign, error)`.
- Produces: `regression.SuiteSpec{Root, SelectionPath string, Bindings map[string]string, DiagnosedProgram, ControlProgram string}`, `regression.WriteSuite(c, spec SuiteSpec) (validation.Value, error)`, `regression.SuiteComposition` keys `{selection_path, selection_sha256, bindings[], diagnosed, control, coverage, created_at, schema_version}` with `bindings[].{project, target_id, campaign_id, kind, shape, partition, run_count}`; ledger event `regression.suite.written`.

- [ ] **Step 1: Write the composition schema**

Create `assets/schema/regression_suite.schema.json`:

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://web3sec.local/schema/regression_suite.schema.json",
  "title": "WebSec Regression Suite Composition",
  "description": "The frozen Phase 0 suite (§3a): which targets, which campaign audits each one, and what the suite as a whole is composed of. This is the file a later phase cites when it says 'the regression suite' — it is not a plan, it is the composition that ran, with each pick checked against its own campaign's target record (shape, partition, kind) so a renamed or re-shaped target cannot silently invalidate the suite. The D8 label is carried here too: every number this suite produces is rediscovery, never a detection rate.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "selection_path", "selection_sha256", "bindings", "coverage",
    "measurement", "is_detection_rate", "created_at", "schema_version"
  ],
  "properties": {
    "selection_path": { "type": "string", "minLength": 1 },
    "selection_sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "bindings": {
      "type": "array",
      "minItems": 4,
      "maxItems": 6,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["project", "target_id", "campaign_id", "kind", "shape", "partition", "run_count"],
        "properties": {
          "project": { "type": "string", "minLength": 1 },
          "target_id": { "type": "string", "pattern": "^T-[a-f0-9]{12}$" },
          "campaign_id": { "type": "string", "minLength": 3 },
          "kind": { "enum": ["scabench", "fresh", "control", "diagnosed"] },
          "shape": { "type": "string", "minLength": 1 },
          "partition": { "enum": ["dev", "held-out", "training"] },
          "run_count": { "type": "integer", "minimum": 0 },
          "fresh_controls_complete": { "type": "boolean" }
        }
      }
    },
    "coverage": {
      "type": "object",
      "additionalProperties": false,
      "required": ["covered_findings", "total_findings", "covered_classes", "total_classes"],
      "properties": {
        "covered_findings": { "type": "integer", "minimum": 0 },
        "total_findings": { "type": "integer", "minimum": 0 },
        "covered_classes": { "type": "integer", "minimum": 0 },
        "total_classes": { "type": "integer", "minimum": 0 },
        "uncovered_classes": { "type": "array", "items": { "type": "string" } }
      }
    },
    "diagnosed": {
      "type": "object",
      "additionalProperties": false,
      "required": ["program", "campaign_id"],
      "properties": {
        "program": { "type": "string", "minLength": 1 },
        "campaign_id": { "type": "string", "minLength": 3 }
      }
    },
    "control": {
      "type": "object",
      "additionalProperties": false,
      "required": ["program", "campaign_id", "target_id"],
      "properties": {
        "program": { "type": "string", "minLength": 1 },
        "campaign_id": { "type": "string", "minLength": 3 },
        "target_id": { "type": "string", "pattern": "^T-[a-f0-9]{12}$" }
      }
    },
    "measurement": { "const": "rediscovery" },
    "is_detection_rate": { "const": false },
    "created_at": { "type": "string", "minLength": 20 },
    "schema_version": { "const": 1 }
  }
}
```

- [ ] **Step 2: Write the failing test**

Create `internal/regression/suite_test.go`. It builds five campaigns under one root and drives the real writers:

```go
package regression

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func campaignIn(t *testing.T, root, id string) *state.Campaign {
	t.Helper()
	c, err := state.Open(root, id)
	if err != nil {
		// state.Init takes the root and the id; the campaign must be created
		// before Open can see it.
		c, err = state.Init(root, "Suite "+id, state.InitOpts{CampaignID: id})
		if err != nil {
			t.Fatal(err)
		}
	}
	return c
}

// suiteFixture builds a root with one campaign per pick plus the diagnosed and
// control campaigns, and returns the selection + bindings.
func suiteFixture(t *testing.T) (root string, sel validation.Value, bindings map[string]string) {
	t.Helper()
	root = t.TempDir()
	projects := []struct {
		name      string
		shape     string
		partition string
	}{
		{"vault-p", "vault-erc4626", "dev"},
		{"lend-p", "lending-liquidation", "dev"},
		{"bridge-p", "bridge-messaging", "held-out"},
		{"oracle-p", "non-rollup-l2-or-oracle", "held-out"},
	}
	labels := validation.VObj(kv("rows", validation.VArr()), kv("dataset", validation.VStr("scabench")),
		kv("snapshot_date", validation.VStr("2025-08-18")),
		kv("unmapped_reviewed", validation.VBool(true)))
	rows := []validation.Value{}
	shapes := map[string]string{}
	for i, p := range projects {
		shapes[p.name] = p.shape
		for j := 0; j < i+1; j++ {
			rows = append(rows, validation.VObj(
				kv("finding_id", validation.VStr(p.name+"-"+string(rune('a'+j)))),
				kv("project", validation.VStr(p.name)),
				kv("severity", validation.VStr("high")),
				kv("class", validation.VStr([]string{"reentrancy", "liquidation-logic",
					"bridge-message", "oracle-manipulation"}[i])),
				kv("rule", validation.VStr("test")),
			))
		}
	}
	labels.O = validation.SetOrAppend(labels.O, "rows", validation.VArr(rows...))
	sel, err := Select(SelectSpec{
		Labels: labels, Shapes: shapes, Picks: 4,
		HeldOut: []string{"bridge-p", "oracle-p"},
		DiagnosedProgram: "diagnosed-l2", ControlProgram: "exploited",
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings = map[string]string{}
	for i, p := range projects {
		cid := "C-suite" + string(rune('a'+i)) + "0000001"
		c := campaignIn(t, root, cid)
		if _, err := AddTarget(c, TargetSpec{
			Kind: "scabench", Program: p.name, RecordID: p.name,
			Repo: "org/" + p.name, Shape: p.shape, CommitHint: "main",
			Partition: p.partition,
		}); err != nil {
			t.Fatal(err)
		}
		bindings[p.name] = cid
	}
	// the diagnosed campaign: kind diagnosed, partition training
	dc := campaignIn(t, root, "C-suitetraining01")
	if _, err := AddTarget(dc, TargetSpec{
		Kind: "diagnosed", Program: "diagnosed-l2", Shape: "diagnosed-campaign",
		Partition: "training",
	}); err != nil {
		t.Fatal(err)
	}
	// the control campaign: kind control with its control block
	cc := campaignIn(t, root, "C-suitecontrol01")
	ctl, err := AddTarget(cc, TargetSpec{
		Kind: "control", Program: "exploited", Shape: "already-exploited",
		CommitHint: shaPre, Partition: "dev",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RecordControl(cc, ControlSpec{
		TargetID: validation.ObjStr(ctl, "target_id"),
		IncidentURL: "https://example.test/incident", IncidentDate: "2025-09-01",
		LossUSD: 1000, LossSource: "post-mortem",
		PrePatchSHA: shaPre, PatchSHA: shaPost, HarnessRunner: "foundry",
	}); err != nil {
		t.Fatal(err)
	}
	bindings["diagnosed-l2"] = dc.CampaignID
	bindings["exploited"] = cc.CampaignID
	return root, sel, bindings
}

func TestWriteSuiteChecksEveryPickAgainstItsCampaign(t *testing.T) {
	root, sel, bindings := suiteFixture(t)
	selPath := filepath.Join(t.TempDir(), "selection.json")
	if err := WriteRepoRecord(selPath, sel, "regression_selection"); err != nil {
		t.Fatal(err)
	}
	spec := SuiteSpec{
		Root: root, SelectionPath: selPath, Bindings: bindings,
		DiagnosedProgram: "diagnosed-l2", ControlProgram: "exploited",
	}
	// A pick with no binding is refused, and the refusal names the project.
	missing := map[string]string{}
	for k, v := range bindings {
		missing[k] = v
	}
	delete(missing, "bridge-p")
	if _, err := WriteSuite(campaignIn(t, root, "C-suitea0000001"), SuiteSpec{
		Root: root, SelectionPath: selPath, Bindings: missing,
		DiagnosedProgram: "diagnosed-l2", ControlProgram: "exploited",
	}); err == nil || !strings.Contains(err.Error(), "bridge-p") {
		t.Fatalf("err = %v, want a refusal naming the unbound pick", err)
	}
	// A binding whose campaign has no target for that project is refused.
	wrong := map[string]string{}
	for k, v := range bindings {
		wrong[k] = v
	}
	wrong["bridge-p"] = "C-suitea0000001" // the vault campaign
	if _, err := WriteSuite(campaignIn(t, root, "C-suitea0000001"), SuiteSpec{
		Root: root, SelectionPath: selPath, Bindings: wrong,
		DiagnosedProgram: "diagnosed-l2", ControlProgram: "exploited",
	}); err == nil {
		t.Fatal("WriteSuite accepted a binding to a campaign with no such target")
	}
	// A partition that disagrees with the selection is refused.
	_ = spec
	doc, err := WriteSuite(campaignIn(t, root, "C-suitea0000001"), spec)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(doc, "measurement"); got != "rediscovery" {
		t.Fatalf("measurement = %q, want rediscovery (D8)", got)
	}
	if got := validation.ObjAt(doc, "is_detection_rate"); got.Kind != validation.Bool || got.B {
		t.Fatalf("is_detection_rate = %v, want false", got)
	}
	if len(validation.ObjAt(doc, "bindings").A) != 6 {
		t.Fatalf("%d bindings, want 6 (four picks + diagnosed + control)",
			len(validation.ObjAt(doc, "bindings").A))
	}
	if !hasKey(doc, "control") || !hasKey(doc, "diagnosed") {
		t.Fatal("the composition must name both the control target and the training row")
	}
}

func TestWriteSuiteRefusesAFreshTargetWithIncompleteControls(t *testing.T) {
	root, sel, bindings := suiteFixture(t)
	selPath := filepath.Join(t.TempDir(), "selection.json")
	if err := WriteRepoRecord(selPath, sel, "regression_selection"); err != nil {
		t.Fatal(err)
	}
	// Swap the vault pick's campaign for one holding an uncontrolled FRESH
	// target: the suite must refuse to include it.
	freshRoot := filepath.Join(root)
	fc := campaignIn(t, freshRoot, "C-suitefresh0001")
	if _, err := AddFreshTarget(fc, FreshSpec{
		Program: "vault-p", RecordID: "vault-p", Repo: "org/vault-p",
		ReportURL: "https://example.test/r", ReportDate: "2026-01-01",
		CommitHint: shaPre, Shape: "vault-erc4626", Partition: "dev",
	}); err != nil {
		t.Fatal(err)
	}
	bindings["vault-p"] = fc.CampaignID
	if _, err := WriteSuite(fc, SuiteSpec{
		Root: root, SelectionPath: selPath, Bindings: bindings,
		DiagnosedProgram: "diagnosed-l2", ControlProgram: "exploited",
	}); err == nil || !strings.Contains(err.Error(), "contamination") {
		t.Fatalf("err = %v, want the fresh-controls refusal", err)
	}
}

func TestWriteSuiteRefusesAMissingTrainingRowOrControlTarget(t *testing.T) {
	root, sel, bindings := suiteFixture(t)
	selPath := filepath.Join(t.TempDir(), "selection.json")
	if err := WriteRepoRecord(selPath, sel, "regression_selection"); err != nil {
		t.Fatal(err)
	}
	noTraining := map[string]string{}
	for k, v := range bindings {
		noTraining[k] = v
	}
	delete(noTraining, "diagnosed-l2")
	if _, err := WriteSuite(campaignIn(t, root, "C-suitea0000001"), SuiteSpec{
		Root: root, SelectionPath: selPath, Bindings: noTraining,
		DiagnosedProgram: "diagnosed-l2", ControlProgram: "exploited",
	}); err == nil || !strings.Contains(err.Error(), "training") {
		t.Fatalf("err = %v, want a refusal naming the missing training row", err)
	}
	noControl := map[string]string{}
	for k, v := range bindings {
		noControl[k] = v
	}
	delete(noControl, "exploited")
	if _, err := WriteSuite(campaignIn(t, root, "C-suitea0000001"), SuiteSpec{
		Root: root, SelectionPath: selPath, Bindings: noControl,
		DiagnosedProgram: "diagnosed-l2", ControlProgram: "exploited",
	}); err == nil || !strings.Contains(err.Error(), "control") {
		t.Fatalf("err = %v, want a refusal naming the missing control target", err)
	}
}
```

Delete the `_ = spec` line (a draft artefact) and use `spec` directly in the first acceptance call.

- [ ] **Step 3: Run it to verify it fails**

Run: `GOCACHE=$PWD/.scratch/gocache go test ./internal/regression -run TestWriteSuite -count=1`

Expected: FAIL to compile — `undefined: SuiteSpec`, `undefined: WriteSuite`.

- [ ] **Step 4: Implement the composition writer**

Create `internal/regression/suite.go`:

```go
package regression

import (
	"fmt"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// SuiteSpec is one composition write. Bindings maps a selection project (or
// the diagnosed/control program name) to the campaign that audits it.
type SuiteSpec struct {
	Root             string
	SelectionPath    string
	Bindings         map[string]string
	DiagnosedProgram string
	ControlProgram   string
}

// WriteSuite assembles the frozen composition. It reads the selection and the
// bound campaigns' own target records and refuses every inconsistency:
//
//   - a selection pick with no binding, or a binding to a campaign that has no
//     target for that project (a renamed or re-shaped target invalidates the
//     suite silently otherwise);
//   - a target whose shape or partition disagrees with the selection;
//   - a fresh target whose §3a controls are incomplete;
//   - no diagnosed row (kind "diagnosed", partition "training") and no control
//     target (kind "control" with its control block).
func WriteSuite(c *state.Campaign, spec SuiteSpec) (validation.Value, error) {
	sel, err := ReadRepoRecord(spec.SelectionPath)
	if err != nil {
		return validation.VNull(), err
	}
	if spec.Root == "" {
		return validation.VNull(), fmt.Errorf(
			"the composition needs --root: the bound campaigns live under it, and " +
				"a composition nobody can resolve is a list of names")
	}
	selSHA, err := validation.Sha256File(spec.SelectionPath)
	if err != nil {
		return validation.VNull(), err
	}
	bindings := []validation.Value{}
	bound := 0
	for _, pick := range validation.ObjAt(sel, "picks").A {
		project := validation.ObjStr(pick, "project")
		cid := spec.Bindings[project]
		if cid == "" {
			return validation.VNull(), fmt.Errorf(
				"selection pick %q has no campaign binding — the suite cannot name "+
					"a target it never audited", project)
		}
		row, err := bindingRow(spec.Root, project, cid, pick)
		if err != nil {
			return validation.VNull(), err
		}
		bindings = append(bindings, row)
		bound++
	}
	// The diagnosed row: retained, relabeled training, never eval.
	diagnosed, err := namedRow(spec.Root, spec.Bindings[spec.DiagnosedProgram],
		spec.DiagnosedProgram, "diagnosed", "training")
	if err != nil {
		return validation.VNull(), fmt.Errorf(
			"the diagnosed campaign (program %q) is not bound to a campaign holding "+
				"a target of kind diagnosed and partition training: %w — §3a keeps "+
				"it \"retained but relabeled as training data, not eval\"",
			spec.DiagnosedProgram, err)
	}
	control, err := namedRow(spec.Root, spec.Bindings[spec.ControlProgram],
		spec.ControlProgram, "control", "")
	if err != nil {
		return validation.VNull(), fmt.Errorf(
			"the control target (program %q) is not bound to a campaign holding a "+
				"control target with its control block: %w — §3a budgets for it "+
				"separately and Phase 0 is not done without it",
			spec.ControlProgram, err)
	}
	controlTarget, _, err := Target(campaignAt(spec.Root, spec.Bindings[spec.ControlProgram]),
		validation.ObjStr(control, "target_id"))
	if err != nil {
		return validation.VNull(), err
	}
	if !hasKey(controlTarget, "control") {
		return validation.VNull(), fmt.Errorf(
			"control target %s has no control block (incident, pre-patch pin, "+
				"harness)", validation.ObjStr(control, "target_id"))
	}
	bindings = append(bindings, diagnosed, control)
	doc := validation.VObj(
		kv("selection_path", validation.VStr(spec.SelectionPath)),
		kv("selection_sha256", validation.VStr(selSHA)),
		kv("bindings", validation.VArr(bindings...)),
		kv("coverage", validation.ObjAt(sel, "coverage")),
		kv("measurement", validation.VStr("rediscovery")),
		kv("is_detection_rate", validation.VBool(false)),
		kv("created_at", validation.VStr(state.NowIso())),
		kv("schema_version", validation.VInt(1)),
	)
	doc.O = validation.SetOrAppend(doc.O, "diagnosed", validation.VObj(
		kv("program", validation.VStr(spec.DiagnosedProgram)),
		kv("campaign_id", validation.VStr(spec.Bindings[spec.DiagnosedProgram])),
	))
	doc.O = validation.SetOrAppend(doc.O, "control", validation.VObj(
		kv("program", validation.VStr(spec.ControlProgram)),
		kv("campaign_id", validation.VStr(spec.Bindings[spec.ControlProgram])),
		kv("target_id", validation.VStr(validation.ObjStr(control, "target_id"))),
	))
	// The composition is repo-level, so it is written like the selection: file
	// + sidecar, no campaign ledger (there is no single campaign to log to).
	if err := validation.Validate(doc, "regression_suite", 1); err != nil {
		return validation.VNull(), err
	}
	if err := WriteRepoRecord(spec.Bindings["__out__"], doc, "regression_suite"); err != nil {
		return validation.VNull(), err
	}
	return doc, nil
}

// campaignAt opens a campaign by id under root.
func campaignAt(root, cid string) *state.Campaign {
	c, err := state.Open(root, cid)
	if err != nil {
		return nil
	}
	return c
}

// bindingRow checks one selection pick against the bound campaign's own target
// record and returns the composition row.
func bindingRow(root, project, cid string, pick validation.Value) (validation.Value, error) {
	c, err := state.Open(root, cid)
	if err != nil {
		return validation.VNull(), fmt.Errorf(
			"pick %q is bound to campaign %s, which does not open: %w",
			project, cid, err)
	}
	targets, err := LoadTargets(c)
	if err != nil {
		return validation.VNull(), err
	}
	for _, t := range targets {
		if validation.ObjStr(t, "program") != project &&
			validation.ObjStr(t, "record_id") != project {
			continue
		}
		if got, want := validation.ObjStr(t, "shape"), validation.ObjStr(pick, "shape"); got != want {
			return validation.VNull(), fmt.Errorf(
				"pick %q is %s in the selection but the campaign's target says %s — "+
					"a re-shaped target invalidates the suite", project, want, got)
		}
		if got, want := validation.ObjStr(t, "partition"), validation.ObjStr(pick, "partition"); got != want {
			return validation.VNull(), fmt.Errorf(
				"pick %q is partition %s in the selection but %s in the campaign",
				project, want, got)
		}
		if validation.ObjStr(t, "kind") == "fresh" {
			if err := AssertFreshControls(c, validation.ObjStr(t, "target_id")); err != nil {
				return validation.VNull(), fmt.Errorf(
					"pick %q is a fresh target with incomplete controls: %w",
					project, err)
			}
		}
		runs, err := LoadRuns(c)
		if err != nil {
			return validation.VNull(), err
		}
		n := 0
		for _, r := range runs {
			if validation.ObjStr(r, "target_id") == validation.ObjStr(t, "target_id") {
				n++
			}
		}
		row := validation.VObj(
			kv("project", validation.VStr(project)),
			kv("target_id", validation.VStr(validation.ObjStr(t, "target_id"))),
			kv("campaign_id", validation.VStr(cid)),
			kv("kind", validation.VStr(validation.ObjStr(t, "kind"))),
			kv("shape", validation.VStr(validation.ObjStr(t, "shape"))),
			kv("partition", validation.VStr(validation.ObjStr(t, "partition"))),
			kv("run_count", validation.VInt(int64(n))),
		)
		if validation.ObjStr(t, "kind") == "fresh" {
			row.O = validation.SetOrAppend(row.O, "fresh_controls_complete",
				validation.VBool(true))
		}
		return row, nil
	}
	return validation.VNull(), fmt.Errorf(
		"pick %q is bound to campaign %s, which has no target whose program or "+
			"record_id is %q", project, cid, project)
}

// namedRow finds the campaign bound to a named program and the target of the
// expected kind under it (partition, when non-empty, must match too).
func namedRow(root, cid, program, kind, partition string) (validation.Value, error) {
	if cid == "" {
		return validation.VNull(), fmt.Errorf("program %q has no campaign binding",
			program)
	}
	c, err := state.Open(root, cid)
	if err != nil {
		return validation.VNull(), err
	}
	targets, err := LoadTargets(c)
	if err != nil {
		return validation.VNull(), err
	}
	for _, t := range targets {
		if validation.ObjStr(t, "kind") != kind {
			continue
		}
		if partition != "" && validation.ObjStr(t, "partition") != partition {
			return validation.VNull(), fmt.Errorf(
				"target %s is kind %s but partition %q, want %q",
				validation.ObjStr(t, "target_id"), kind,
				validation.ObjStr(t, "partition"), partition)
		}
		runs, err := LoadRuns(c)
		if err != nil {
			return validation.VNull(), err
		}
		n := 0
		for _, r := range runs {
			if validation.ObjStr(r, "target_id") == validation.ObjStr(t, "target_id") {
				n++
			}
		}
		return validation.VObj(
			kv("project", validation.VStr(program)),
			kv("target_id", validation.VStr(validation.ObjStr(t, "target_id"))),
			kv("campaign_id", validation.VStr(cid)),
			kv("kind", validation.VStr(kind)),
			kv("shape", validation.VStr(validation.ObjStr(t, "shape"))),
			kv("partition", validation.VStr(validation.ObjStr(t, "partition"))),
			kv("run_count", validation.VInt(int64(n))),
		), nil
	}
	return validation.VNull(), fmt.Errorf("campaign %s has no target of kind %s",
		cid, kind)
}
```

Two things to fix in that draft before running it: the `spec.Bindings["__out__"]` hack for the output path is not an interface — add an `Out string` field to `SuiteSpec` and use `spec.Out`; and `campaignAt` returning nil on error will panic — make the control check open the campaign properly and return the error. Also `WriteSuite` takes `c *state.Campaign` but never uses it; drop the parameter and take only `spec`, so the signature is `WriteSuite(spec SuiteSpec) (validation.Value, error)` (and update the tests' calls). The composition is repo-level: there is no campaign to log to, which is why it is written through `WriteRepoRecord` and not `writeThenLog` — say so in the doc comment.

- [ ] **Step 5: CLI + audit + run everything**

`cmd_regress.go`: the repo-level `suite` action takes `--selection`, `--bindings` (a JSON object `{project: campaign_id}`, including the diagnosed and control program names), `--root` (default the CLI's root), `--out`, `--diagnosed`, `--control`. This is the `regressSuite` arm Task 3's switch already dispatches to, so declare it here:

```go
// regressSuite writes the frozen composition (repo-level: no campaign).
func regressSuite(vals map[string]string, r *Runner) error {
	sel := vals["--selection"]
	if sel == "" {
		return t14ArgparseErr(regressUsage, "regress",
			"the following arguments are required: --selection")
	}
	bindingsPath := vals["--bindings"]
	if bindingsPath == "" {
		return t14ArgparseErr(regressUsage, "regress",
			"the following arguments are required: --bindings")
	}
	doc, err := validation.ReadJson(bindingsPath)
	if err != nil {
		return err
	}
	bindings := map[string]string{}
	for _, kvp := range doc.O {
		if kvp.V.Kind != validation.Str {
			return fmt.Errorf("binding %s is not a campaign id", kvp.K)
		}
		bindings[kvp.K] = kvp.V.S
	}
	out := vals["--out"]
	if out == "" {
		return t14ArgparseErr(regressUsage, "regress",
			"the following arguments are required: --out")
	}
	composition, err := regression.WriteSuite(regression.SuiteSpec{
		Root: vals["--root"], SelectionPath: sel, Bindings: bindings,
		DiagnosedProgram: vals["--diagnosed"], ControlProgram: vals["--control"],
		Out: out,
	})
	if err != nil {
		return err
	}
	rows := validation.ObjAt(composition, "bindings").A
	fmt.Fprintf(r.Out, "suite %s written: %d binding(s), measurement %s\n",
		out, len(rows), validation.ObjStr(composition, "measurement"))
	for _, row := range rows {
		fmt.Fprintf(r.Out, "  %-24s %s -> %s (%s, %s, %d run(s))\n",
			validation.ObjStr(row, "project"), validation.ObjStr(row, "target_id"),
			validation.ObjStr(row, "campaign_id"), validation.ObjStr(row, "kind"),
			validation.ObjStr(row, "partition"), validation.ObjAt(row, "run_count").I)
	}
	return nil
}
```

Add `--selection`, `--bindings`, `--diagnosed`, `--control` to `valueFlags` (Task 1 Step 15's convention) along with the other tasks' flags. `vals["--root"]` is injected by the dispatcher (Task 3 Step 6), so the repo-level actions never have to reach for a root they cannot see.

In `regressionsuite.go`, add a suite-level row when a composition is present: read `$WEBV2_EVAL_DIR/regression/suite.json` (via `regression.ReadRepoRecord`), report `suite_measurement` and the binding count, and add a problem when a composition exists but a binding's campaign is missing — the composition is repo-level, so this is the only place the audit can notice that the suite file and the campaigns have drifted apart.

```bash
python3 scripts/sync-asset-manifest.py
GOCACHE=$PWD/.scratch/gocache go test ./internal/regression ./internal/audit/... ./internal/cli ./internal/validation ./assets -count=1
GOCACHE=$PWD/.scratch/gocache go test ./... -count=1
```

Expected: PASS. This task's test is the plan's second end-to-end branch test — if it passes while the per-task tests pass, the suite composition is joined up.

- [ ] **Step 6: Operator step — write the real composition and run the suite**

```bash
# 1. one campaign per target has already been created and audited (Tasks 1-9).
#    Write the binding map. The keys are the selection's `picks[].project`, i.e.
#    the dataset's project_id. A project with TWO codebases (Starknet Perpetual)
#    still gets ONE pick and ONE campaign — bind the campaign whose target
#    carries the codebase you actually pinned, and record the codebase_id in the
#    gate record so the choice is not implicit.
cat > "$WEBV2_P0_DIR/bindings.json" <<'JSON'
{"<project-a>": "C-...", "<project-b>": "C-...", "<project-c>": "C-...",
 "<project-d>": "C-...", "<diagnosed program>": "C-...",
 "<control program>": "C-..."}
JSON
webv2 --root "$WEBV2_P0_DIR/root" regress suite \
    --selection eval/regression/selection-2025-08-18.json \
    --bindings "$WEBV2_P0_DIR/bindings.json" \
    --root "$WEBV2_P0_DIR/root" \
    --diagnosed '<diagnosed program>' --control '<control program>' \
    --out eval/regression/suite.json
# 2. the full run: for each bound campaign, run the ordinary stages against the
#    pinned tree and record the coarse score, exactly as Task 1 Step 21 does.
# 3. read the whole thing back
webv2 --root "$WEBV2_P0_DIR/root" audit <cid> --json
```

**Record** in `docs/gates/v16-P0.md`: the composition file with its sidecar, the six bindings, each target's run count, and — with the D8 label spelled out — the coarse numbers per target and for the suite. State plainly that these are **rediscovery** numbers: §3a Part 10 item 4 — *"No number before then is a detection rate, and none should be quoted as one."*

- [ ] **Step 7: Commit**

```bash
git add assets/schema/regression_suite.schema.json assets/testdata/asset_manifest.json \
        internal/regression/suite.go internal/regression/suite_test.go \
        internal/cli/cmd_regress.go internal/audit/sections/regressionsuite.go \
        internal/validation/schema.go eval/regression/suite.json \
        eval/regression/suite.json.sha256
git commit -m "feat(v16-p0): the frozen regression suite composition"
```

---

### Task 11: The Phase 0 gate record

`docs/gates/v16-P1.md` is the house style: a verdict line, "Method, and what this record is not", one section per exit criterion, a "what this record could NOT verify" section, and a "post-record corrections" section. Phase 0 needs the same document, and it must be written **without** waiting on the network — every offline criterion is already green in CI, and saying so is the whole point.

**Files:**
- Create: `docs/gates/v16-P0.md`

**Interfaces:**
- Consumes: the test names from Tasks 1–10, the operator records from `docs/gates/v16-P0-control-target.md`, the `regression_suite` audit section, `eval/regression/*.json`.
- Produces: nothing downstream; this is the record Phase 3–4 cite.

- [ ] **Step 1: Write the record**

Create `docs/gates/v16-P0.md`:

````markdown
# v1.6 Phase 0 Gate Record — the regression suite

**Verdict: <n> of the 8 exit criteria TEST-PROVEN; <m> OPERATOR-RUN; <k> NOT RUN — offline
(<date>, HEAD `<sha>`).**

Plan: `docs/superpowers/plans/2026-09-21-v16-p0-regression-suite.md`.
Companion: `docs/gates/v16-P0-control-target.md` (the already-exploited control target and
its P1 handoff).

## Method, and what this record is not

Every command below was run in this checkout at HEAD `<sha>` with the mandated prefix
`GOCACHE=$PWD/.scratch/gocache`, and the output pasted is what it actually printed.

**This machine has no network.** `github.com`, `api.github.com` and `pypi.org` all fail to
connect (`http_code 000`), and no ScaBench snapshot exists locally. Phase 0 is operator
tooling over external data, so this record separates, per criterion, what is **built and
tested offline** (the machinery: selection arithmetic, set-cover, the contamination grep,
the disagreement arithmetic, the SHA bookkeeping, the ledger hash, the record shapes) from
what is an **operator step requiring the network and the dataset**. The offline half is
ordinary TDD with tests named below; the operator half is named with the command that would
produce it. A criterion that could not run is recorded `NOT RUN — offline`, never as passed.

## 1. The Phase 0 exit criteria, verbatim (framework-plan-v1.6.md Part 7, line 427)

> Suite runnable end-to-end on one ScaBench target via ScaBench's own baseline runner;
> control target runs under its own harness; every snapshot carries a resolved SHA; every
> fresh-target snapshot passes the contamination grep; every key carries a recorded
> double-transcription disagreement rate; fresh targets carry our own answer keys with the
> ledger hash committed before any diagnostic use

Split into the eight claims the table below judges, one per clause.

## 2. Criterion by criterion

| # | Criterion (the spec's words) | Status | Evidence |
|---|---|---|---|
| 1 | "Suite runnable end-to-end on one ScaBench target" | TEST-PROVEN (machinery) / OPERATOR-RUN or NOT RUN (the real runner) | `TestRegressOneTargetEndToEnd`; the operator's `regress_suite` section, pasted in §3 |
| 2 | "via ScaBench's own baseline runner" | OPERATOR-RUN or NOT RUN — offline | the runner command and its output in §4 |
| 3 | "control target runs under its own harness" | OPERATOR-RUN or NOT RUN — offline | `docs/gates/v16-P0-control-target.md` §3 |
| 4 | "every snapshot carries a resolved SHA" | TEST-PROVEN | `TestPinTargetBindsTheSnapshotToTheResolvedSHA`, `TestPinTargetRefusesAHintInsteadOfASHA`, `TestPinTargetRefusesASnapshotThatDisagreesWithTheSHA`; the audit's `problems` line for an unpinned target |
| 5 | "every fresh-target snapshot passes the contamination grep" | TEST-PROVEN (the grep and its refusals) / OPERATOR-RUN (the real trees) | `TestGrepTreeFindsTitlesAndIDsAcrossTextFiles`, `TestRecordContaminationFailsClosed`, `TestFixCommitAbsentDetectsTheFixInHistory`; per-tree `files_scanned` in §4 |
| 6 | "every key carries a recorded double-transcription disagreement rate" | TEST-PROVEN (the arithmetic) / OPERATOR-RUN (the real keys) | `TestKeyDiffCountsPairsAndRoundsLikePython`, `TestRecordKeyQualityRefusesOneTranscriptionAndUnresolvedDisagreements`; the rates in §4 |
| 7 | "fresh targets carry our own answer keys with the ledger hash committed before any diagnostic use" | TEST-PROVEN (the gate) / OPERATOR-RUN (the commitments) | `TestCommitBeforeRevealGate`, `TestDiagnosticIsRefusedOnHeldOutAndUnrevealedTargets`; the `commit_seq`/reveal pairs in §4 |
| 8 | (composition, from §3a) "six targets … constrained to the four target shapes plus the diagnosed campaign … 2 held out by project" | TEST-PROVEN (the picker and the composition writer) / OPERATOR-RUN (the real picks) | `TestSelectCoversTheRareClassAndAllFourShapes`, `TestWriteSuiteChecksEveryPickAgainstItsCampaign`, `TestWriteSuiteRefusesAMissingTrainingRowOrControlTarget`; the selection's `coverage` object and the composition in §4 |

## 3. The offline half, as run

Paste, in this order: `go test ./... -count=1` (tail), `scripts/verify-full.sh` (the final
`VERIFY-FULL GREEN` line and its 14 steps), then the focused invocations this plan added —
`go test ./internal/regression -count=1`, `go test ./internal/cli -run TestRegress -count=1`,
`go test ./internal/audit/... -count=1` — with their output.

State explicitly which pinned surfaces did **not** move: `git diff --stat` for
`scripts/verify-full.sh`, `scripts/check-golden.py` and
`internal/cli/testdata/p3_args_golden.json` must be empty, and that emptiness is the evidence
that the new audit section is presence-gated and the new verb took a fresh `ord`.

## 4. The operator half

Per criterion 2, 3, 5, 6, 7 and 8, the artefact and the command that produced it — or
`NOT RUN — offline` with the exact command the operator would run. Include:

- the selection's `coverage` object, and the same figure for an unweighted pick (§3a claims
  weighting matters; this is the measurement) — and say which reading of "unweighted" you
  used, because a random six and the six biggest differ by ~2.5× on this snapshot;
- the number of codebases whose dataset commit field was NOT a full SHA — report it
  snapshot-wide (**10 of 32**: 5 `mutable-ref`, 3 `short-sha`, 2 empty/`unknown`) as well as
  among the selected targets (the Fenix Finance claim, as a count);
- the row count and `counts` object from the label file, plus how many rows stayed
  `unmapped` and why;
- each fresh target's `files_scanned` / `hits` / `fix_commit_absent` / disagreement rate /
  committed-and-revealed key hashes;
- the composition, with the D8 label spelled out: these are **rediscovery** numbers;
- the tarball-vs-git decision as executed: the mirror kind actually recorded per target, and
  the measured bytes, so Task 5's choice is a datum rather than a preference.

## 5. What this record could NOT verify

Name every one. At minimum:

- anything behind the network (the mirrors, the real checkouts, the baseline runner, the
  contest reports) if it did not run. The dataset download is no longer on this list: the
  checkout is on disk and every count in *Operator prerequisites §7* was measured from it;
- the class-count discrepancy: §3a says "ARGUS's 23-class taxonomy", the live
  `taxonomy.CanonicalClasses()` holds **25** classes (verified 2026-09-21 by reading
  `CLASS_CONFIRM_FLOOR` ∪ the dedup compat vocabulary — both the built-in default and the
  `dedup` seam yield 25; Task 3 Step 2's `go run` is the executable confirmation). The
  plan pins the labels to the LIVE set; the spec's "23" is recorded here as stale rather
  than edited (D9: a spec change cites a measurement);
- that the disagreement rate is a measurement of an instrument Part 10 calls *unvalidated* —
  one rate is a datum, not a validation;
- whether all 32 codebases actually clone: only 3 repositories were fetched by hand while
  correcting this plan (`Liquid Ron`, `oku-custom-order-types`, `idle-tranches`) plus two
  `ls-remote` lookups. The other 27 are unverified, and the six selected targets are the
  ones that matter;
- ScaBench's own README claims a "2024-08 to 2025-08" range; the `project_id` suffixes run
  `2024_09` … `2025_08`. Which is right depends on whether the suffix is the contest date or
  the curation date, and nothing in this plan depends on it.

**Closed by this correction (do not re-open them as unknowns):** the snapshot contains
exactly **114** `high` findings, 555 findings in total, 31 projects and 32 codebases, one
snapshot directory, and no releases or tags. Each of those now carries the command that
produced it in *Operator prerequisites §7*.

## 6. Post-record corrections and open questions

The P1 record has this section because it found two real defects after the fact. Leave the
heading here even if it is empty at first: the next executor appends to it.

---

````

## Self-review

Run this before declaring the plan executed; it is the same checklist the plan was written against.

**1. Spec coverage (Phase 0 only).**

| Spec item (§3a / Part 7 Phase 0) | Task |
|---|---|
| "Suite runnable end-to-end on one ScaBench target" | 1 |
| "control target runs under its own harness" + the already-exploited control target | 2 |
| "Class labels are derived by bucketing the 114 high findings … from title plus description" | 3 |
| "picking six targets by greedy set-cover … weighted by gold-finding count" + the four shapes + "2 held out by project" | 4 |
| "resolves every commit to a concrete SHA … mirrors the repos locally … ScaBench's commit field is a hint, not a pin" | 5 |
| "the snap-time grep for finding titles/IDs across the pinned tree, plus verifying the committed tree contains no fix commits" | 6 |
| "Double-transcribe every fresh key and record the disagreement rate" | 7 |
| "Never diagnose on held-out projects. Commit-before-reveal … applies to every use of the current snapshot" | 8 |
| "Build fresh targets ourselves from published contest reports in the window ScaBench doesn't cover" | 9 |
| The six-row composition; the D8 label carried into every number | 10 |
| The Phase 0 exit criteria, recorded per clause | 11 |
| The P1 Task 10 dependency (the confirmed finding) | 2, recorded in `docs/gates/v16-P0-control-target.md` |

**Deliberately not in this plan** (they belong to later phases or to other plans): the
closure tier and `closed-by-failed-construction` (P2); the dual-arm critic and the
cross-family adjudicator (roadmap); the excluded-disclosure duplicate-risk probe (§C7.2 —
it runs *from* Phase 4, and the control target only exercises its PATCHED-KNOWN path);
target scoring (`target-score`, C6); acceptance telemetry (C8); the severity engine and the
rubric (P4). Do not smuggle them in — Phase 4's duplicate-risk rate and Phase 5's policy
translation depend on how this suite behaves first.

**1b. The plan's own sequencing ruling, checked.** The user's ruling — *"Sequence it so 'one
ScaBench target end-to-end' lands first"* — is Task 1, and the control target is Task 2
rather than a late "sourcing" task, because its second payoff is the P1 handoff. The
cross-plan dependency is written down twice on purpose: in Task 2's header (quoting
`docs/gates/v16-P1.md` §7b's "what unblocks it, precisely") and in Task 2's gate-record
template, which states that `FORK_RPC_URL` still blocks P1 Task 10 Step 3. If Task 2's
operator step is `NOT RUN — offline`, then P1's Task 10 remains blocked on **both** halves
and this plan says so; it must never be read as having unblocked it.

**1c. Offline vs operator, per task.** Tasks 3–10 all follow the same shape: the machinery
is a TDD task with a focused `go test` invocation, and the operator step is an explicit
block with the exact commands and the exact recording location. No test in this plan needs
the network, a dataset, Docker or a model. Two tests shell out to `git` (`target_test.go`,
`contamination_test.go`) and skip when it is absent, and one (`run_test.go`'s
`TestEvalGoldKeysMatchTheRealScorer`) shells out to `python3` and skips likewise — a skipped
test is recorded as skipped in the gate record, never counted as a pass.

**2. Placeholder scan.** Every code step carries runnable Go; every run step carries an exact
command and its expected result; every operator step carries the exact shell and the exact
file to write the result into. Three deliberate deferrals, each named in place rather than
left implicit: Task 3 Step 6 says which switch arms land in which task (so the package
compiles between tasks), Task 10 Step 4 lists the three draft artefacts to remove before
running (`spec.Bindings["__out__"]`, `campaignAt`'s nil return, the unused `c` parameter),
and Tasks 3/4/5/6/7 say explicitly which helper is *duplicated on purpose* rather than
exported. No step says "similar to Task N" — each task's code is written out in full, because
the implementer of Task 7 may never have read Task 3.

**3. Type consistency.** The names later tasks call are fixed in Task 1's Interfaces block and
never renamed: `AddTarget`/`PinTarget`/`LoadTargets`/`Target`, `RecordRun`/`LoadRuns`/
`NormalizeScore`, `TargetKinds`/`TargetShapes`, `writeThenLog`, `copyTargetWithKeys`,
`hasKey`, `sha40Re`, `kv`, `contains`. Task 2 adds `RecordControl`/`RecordHandoff` and the
`incident`/`control`/`handoff` keys; Task 3 adds `Classify`/`DeriveLabels`/`WriteRepoRecord`/
`ReadRepoRecord`; Task 4 adds `Select`/`SelectSpec`/`ScaBenchShapes`; Task 5 adds
`HintKind`/`RecordMirror`; Task 6 adds `GrepTree`/`FixCommitAbsent`/`RecordContamination`;
Task 7 adds `KeyDiff`/`RecordKeyQuality`; Task 8 adds `CommitKey`/`RevealKey`/
`AssertDiagnosticAllowed` and the `partition`/`run_kind` keys; Task 9 adds `AddFreshTarget`/
`AssertFreshControls`/`ScabenchSnapshotDate`; Task 10 adds `WriteSuite`/`SuiteSpec`. Two
`TargetSpec` fields are added after Task 1 (`Partition` in Task 8) and one `RunSpec` field
(`Kind`, also Task 8) — both default to a value that keeps every earlier task's call sites
compiling, and Task 8 Step 4 says to confirm that with a focused run.

**3b. The ledger law has a test in this plan.** `TestWriteThenLogUnwindsTheRecordWhenTheLedgerWriteFails`
(Task 1 Step 4) is the test P1's self-review found missing: it makes the event-log append
fail and asserts the projection file does not survive. Every writer in `internal/regression`
goes through `writeThenLog`, so one test covers all of them; the repo-level files (Tasks 3,
4, 10) deliberately do not — they are not campaign-scoped, there is no ledger to join them
to, and their integrity is the sidecar's job (`TestRepoRecordRoundTripsWithItsSidecar`).

**3c. The refusals have accept-cases.** Every task that adds a refusal also adds a test that a
*valid* record is accepted, because a refusal test alone passes trivially if the code refuses
everything: Task 1 (`TestRegressOneTargetEndToEnd`'s green audit), Task 2 (the handoff's
positive case), Task 3 (a clean label file), Task 4 (a valid selection), Task 5 (a full-sha
pin with no mirror), Task 6 (a clean tree), Task 7 (a resolved disagreement), Task 8 (a
revealed dev target and a scabench target), Task 9 (`AssertFreshControls` passing on a
complete target), Task 10 (the accepted composition).

**4. Exit criteria this plan does *not* satisfy.** Criteria 2 and 3 are operator-only
(the real baseline runner, the control target's harness) and criteria 5, 6, 7, 8 have an
operator half. `scripts/verify-full.sh` and `scripts/p2-docker-e2e.sh` are pre-existing gates:
run them, do not re-implement them. Phase 0's two-week budget assumes both the ScaBench path
and the control-target path get real operator time — a plan that lands only the machinery has
landed the cheap half, and Task 11's per-criterion table is where that must be visible.

**4b. Report the two halves separately.** Exactly as `docs/gates/v16-P1.md` §7 records the
Phase 2 criterion in two halves, this plan's record separates "the machinery is green in CI"
from "the operator ran it against the real data". Do not report Phase 0 as blocked while ten
tasks are green in CI, and do not report it as done while the operator half is `NOT RUN`.

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-09-21-v16-p0-regression-suite.md`, with the phase map in `docs/superpowers/plans/2026-09-21-v16-roadmap.md`.

Two execution options:

1. **Subagent-driven (recommended)** — one fresh subagent per task, review between tasks, fast iteration. Task 1 must be reviewed before Task 2 starts: it is the sequencing ruling, and every later task extends the record shapes it defines.
2. **Inline execution** — execute tasks in this plan in this session, with checkpoints for review.

**Before Task 1, run Step 0's premise block** and record its output in the ledger the execution skill uses. **Before Task 11, read `docs/gates/v16-P1.md`** — Task 11 copies its structure, and its §7b is the sentence Task 2 exists to answer.

**What this plan unblocks, and what it does not.** Task 2 supplies the confirmed finding P1 Task 10 was missing; `FORK_RPC_URL` is still unset, so P1 Task 10 Step 3 remains blocked. P2 (the closure tier) and P4 (severity) both wait on Phase 0's held-out targets — and if the fresh-target set slips, §3a's own fallback applies: *"a ScaBench held-out project satisfies the gate, substitution recorded"*, which is a substitution to record in `docs/gates/v16-P0.md`, not a quiet downgrade.


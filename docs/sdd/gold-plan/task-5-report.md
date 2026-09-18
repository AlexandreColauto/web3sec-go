# Task 5 report — Morph gold re-run protocol (the measurement loop)

**STATUS: COMPLETE** — commit `99e7e906` on `production-readiness` (BASE `8b2886ec`).

**Deliverable:** `docs/eval/morph-rerun-protocol.md` — 240 lines, six mandatory sections, no
placeholders (scanned for `TODO`/`TBD`/`FIXME`/`XXX`/`<name>`: none). Committed by exact path; the
commit contains that one file and nothing else (`git show --stat`: 1 file changed, 240 insertions).

**Step 2 evidence:** `.superpowers/sdd/2026-09-18-gold-findings-closure.md/task-5-logs/command-resolution.log`
(the whole resolution run, one file, 60 lines). Nothing was ever run against the pinned target.

## Step 2 — command resolution (every command the doc names)

| doc command | form verified | result |
|---|---|---|
| `git -C $WEB3SEC2/morph rev-parse HEAD` | ran | `8e8b6c5…` — the fixture checkout is **not** on `22ca805e`; the commit object is present (`git cat-file -t 22ca805e` → `commit`) |
| `git -C $WEB3SEC2/morph worktree add … 22ca805e` | **not executed** (it writes into the fixture repo's admin dir); read-only `worktree list` resolves, commit object confirmed | form OK, see concern 2 |
| `bash scripts/release.sh` | `-rwxr-xr-x`, `bash -n` clean | prints `RELEASE OK: static single binary, embedded assets served, standalone walkthrough clean` (release.sh:164) |
| archived `docs/sdd/release-final.log` | `git log -1 -- docs/sdd/release-final.log` → `10182b5c`; log line 36 has the same `RELEASE OK` | cited in the doc as script-works evidence only, never a substitute |
| `webv2 shared --verify` | ran | exit 0, `integrity: PASS — 0 problem(s)`, 766 approved rows |
| `rg -i -c '<keyword list>' ~/.webv2/shared-memory/memory.json` | ran | exit 1, no matching row → **CLEAN** today |
| `webv2 init --program "Morph L2"` | ran in a scratch temp workspace | created `C-386d8b3bf7` |
| `webv2 probes <C-id> run --emit` | ran against the scratch campaign | exit 2, `probes: no structural index for C-386d8b3bf7 — run 'webv2 index …' first` → command **and** `--emit` resolve; the refusal is the expected fresh-campaign state |
| `webv2 snap` / `index` / `model` / `invariant-verify` `--help` | ran | all exit 0 |
| `python3 scripts/eval-gold.py --gold <benchmark> --campaign <archived>` | ran | exit 0, the 0/2 baseline JSON (`missed: [G-01, G-02]`, `false_positives: 0`, `verdict: FAIL`) |
| same `--confirm G-01` | ran | exit 0, verdict unchanged, `operator_confirmed: {"G-01": true}` |
| `python3 -m unittest scripts.eval_gold_test` | ran from the repo root, no path hacks | 25 tests, OK, exit 0 |
| `python3 scripts/eval_gold_test.py` | ran | 25 tests, OK, exit 0 |

### Drift found and fixed in the doc before commit

1. **The plan's pinned `--gold` spelling does not resolve from the repo root.** `--gold
   web3sec-final/targets/gold-findings.json` is relative to the directory holding the sibling
   checkouts, not to `web3sec-go/`; tried as `../web3sec-final/…` from the repo root the scorer exits 2
   (`eval-gold: ../web3sec-final/targets/gold-findings.json not found`). Fix: the doc defines
   `WEB3SEC2` (the directory the spelling is relative to) in its preamble and uses
   `$WEB3SEC2/web3sec-final/targets/gold-findings.json` — same read-only file, same invocation shape,
   and it states the path base explicitly in §4. The `--campaign <dir>` half was already
   workspace-relative and is unchanged.
2. **`probes run --emit` needs an index first.** The doc names `webv2 index <C-id> --src <target>`
   before the emit (matches the release.sh mini walkthrough and the real campaign lifecycle).
3. **Real CLI signatures, not the brief's shorthand.** The campaign is positional *before* the
   subcommand: `webv2 probes <C-id> run --emit` (likewise `snap`, `model`, `index`).
4. **The contamination check must grep the rows file, not the store directory.** A directory-wide
   search hits `manifest.json`, whose provenance note literally contains "ScaBench" (a
   pre-v2-reingestion migration note) — a false positive that is not a corpus row. The doc pins
   `memory.json` and says why.

## Doc section map

| § | content |
|---|---|
| preamble | 0/2 baseline + archived campaign; `WEB3SEC2`/`WS`/`SCRATCH` paths; what "record" means (campaign dir + write-up beside the 0/2 eval) |
| 1. Pinned target | Morph L2 @ `22ca805e`; verify + record the checkout hash; scratch worktree instead of moving the fixture; **fresh `bash scripts/release.sh` required, must end in `RELEASE OK`**; archived log @ `10182b5c` demoted to script-works evidence |
| 2. Contamination re-check (FIRST) | machine-global `~/.webv2/shared-memory` caveat; `webv2 shared --verify`; the benchmark's keyword list quoted verbatim + a runnable `rg`; strict A/B arm (`WEBV2_GLOBAL_MEMORY_DIR`); record date + result + row count; CI persistent-home note |
| 3. Campaign protocol | fresh campaign (`init`/`snap`/`index`); **3.1** `rollup_finalization` modeled as a state machine (minimal schema-valid shape, name is the stable handle); **3.2** the three expected gate firings, quoted verbatim from source: per-machine liveness refusal, cold-probe nag + `probes run --emit`, exec-relevance refusal |
| 4. Scoring | the pinned `eval-gold.py` invocation (path base stated), `--confirm G-01`, record verdict + FP count, the benchmark's `pass`/`bonus`/`false_positive_budget` verbatim, the scorer's own gate (both invocations) |
| 5. Honesty rules | no score pressure; a miss is a miss with the 0/2 eval as the template; re-run numbers enter framework DATA only through the `docs/eval-methodology.md` provenance rubric; record what actually happened |
| 6. Out of scope | no exploit-development automation; no CI execution; no benchmark edits (and the target fixture frozen); no release substitution |

Gate-firing wording is verified against source, not paraphrased: liveness refusal
`protocol model: state machine(s) <names> have no liveness invariant (one per machine — stage 37)`
(`internal/invariants/invariants.go:499-502`, pinned by `TestPartialLivenessCoverageRefused`,
`internal/invariants/invariants_test.go:913`); cold-probe line
(`internal/briefing/briefing.go:2201-2215`); exec-relevance refusal and its three reasons
(`internal/cli/cmd_invariant_verify.go:97-105`, `invariants.ExecTouchesInvariant`). The benchmark's
`pass`/`bonus`/`false_positive_budget` strings were re-checked programmatically as verbatim
(whitespace-normalized) after writing.

## Concerns / deliberate decisions

1. **The doc is operator-local by design.** It names `$WEB3SEC2`/`$WS` instead of inventing a
   portable path for a benchmark that lives in a sibling checkout. That is the only honest way to
   keep the plan's pinned invocation resolvable; a fully portable form would require a path base the
   repo does not have.
2. **`git worktree add` for `22ca805e` was not executed** — it writes into the fixture repo's admin
   directory, and the brief forbids touching the pinned target. The commit object exists and the
   form is stock git; the operator's first run should sanity-check the path it picks.
3. **The "verify the checkout hash" step will fail today by design**: the fixture checkout is at
   `8e8b6c5`, not `22ca805e`. The doc records that actual hash and tells the operator to take a
   scratch worktree rather than move the fixture.
4. **No fresh release was run by Task 5** (per the brief). The `RELEASE OK` line is quoted from
   `scripts/release.sh:164` and the archived log; §1 still requires the operator's own fresh run
   before discovery starts.
5. **The report and the resolution log are not committed** — `.superpowers/` is untracked in this
   worktree (`git ls-files .superpowers` → 0 files), and the brief pins the commit to the doc path
   only. The commit holds exactly `docs/eval/morph-rerun-protocol.md`.
6. **No CI wiring and no `verify-full.sh` change** — the protocol is explicitly out of CI (§6), and
   the 13-step release pin stays.
7. **One nuance the doc carries deliberately**: `webv2 probes <C> run --emit` exits 2 on a fresh
   campaign until the index exists. That is the correct refusal, not drift — the doc orders `index`
   before `emit`.

## Fix round 1 (review `task-5-review.md`, findings F-1, F-2, F-3)

Doc-only changes to `docs/eval/morph-rerun-protocol.md`. No source, test, or fixture touched.

### What changed

- **F-1 (major).** §3.1 no longer presents a bare `{"state_machines": …}` as the minimal
  `model.json`. It now gives a **schema-valid skeleton** (the six required keys — `protocol_id`,
  `name`, `contracts`, `actors`, `assets`, `relations`, empty arrays — with the
  `rollup_finalization` fragment embedded), quotes the skeleton's **real** load output, and keeps
  the bare fragment only as a negative example whose **real** schema error is quoted. The operator
  is told plainly that a bare fragment dies in `validation.Validate` before the liveness gate ever
  runs.
- **F-2 (minor).** §3.1 now states the distinction the review asked for: one machine with **zero**
  liveness coverage takes the **zero-coverage synthesis** path (a `liveness-template` invariant is
  minted, the model **loads, exit 0**); the per-machine refusal is a **partial-coverage** gate.
  §3.2-1 carries a complete, pasteable **partial-coverage variant** (second machine
  `message_queue` + a `kind: "liveness"` invariant covering it, `rollup_finalization` left bare)
  with its verbatim refusal output, so the operator actually sees the gate fire.
- **F-3 (note).** §4 "25 tests" → "26 tests" (`e28efeed` added one). Re-counted at HEAD: both
  `python3 -m unittest scripts.eval_gold_test` and `python3 scripts/eval_gold_test.py` report
  `Ran 26 tests … OK`.

### Evidence (scratch campaigns only — the pinned target was never touched)

A binary was built from this worktree's HEAD (`CGO_ENABLED=0 go build -trimpath -ldflags '-s -w'
-o .scratch/task5-fix1/webv2 ./cmd/webv2`, with a workspace-local `GOMODCACHE` because the shared
`~/go/pkg/mod` is outside the sandbox's write scope; the module graph is four modules, x/text
v0.39.0 fetched from `proxy.golang.org`). Every command below ran against it, in throwaway
campaigns under `.scratch/task5-fix1/ws`:

| input | exit | real output (quoted in the doc) |
|---|---|---|
| bare fragment (the old §3.1 snippet) | 2 | `model load failed: protocol_model validation failed at <root>: 'protocol_id' is a required property` + the five `also at <root>` lines |
| §3.1 skeleton | 0 | `model loaded: 0 actors, 0 assets, 0 invariants` / `reconciliation: …` (stdout) + `WARNING: … seeded with NOTHING …` (stderr) |
| §3.2-1 partial-coverage variant | 2 | `model load failed: protocol model: state machine(s) rollup_finalization have no liveness invariant (one per machine — stage 37)` |

Verification was mechanical, not eyeballed: the two ```json blocks were **extracted from the
committed doc text**, `json.loads`-parsed, and fed to `webv2 model` in fresh campaigns (block 0 →
exit 0, block 1 → exit 2), and each quoted output block was **byte-compared** against the captured
stdout+stderr of the corresponding run — all three comparisons `True`, exit codes as documented.
The pre-fix text was checked the same way: the old snippet reproduces the schema error exactly as
the review's F-1 states.

### Deliberate decisions

1. The partial-coverage variant is a **complete file**, not a diff with `…`: it is the one snippet
   whose job is to make the gate fire, so a partial paste would be the same class of trap F-1 was.
2. The skeleton keeps **empty arrays** (verified schema-valid, and the review confirmed it): the
   point of §3.1 is the state machine, not a filled-in model. The operator fills it during recon.
3. The doc records that the `WARNING` goes to **stderr** while the load lines go to stdout, because
   the quoted block mixes the two streams and an operator capturing only stdout would otherwise
   think the line is missing.
4. Nothing else in the doc was reworded; §1/§2/§4 invocations, the three gate quotes, the honesty
   rules, and §6 are untouched. No re-verification of unchanged commands was warranted beyond the
   test-count re-run.

# Task 7 fix round 1 review — scoped re-review

**Reviewer:** independent, read-only. **Commits:** ac11de2c..b77eb7fa (single commit
`b77eb7fa` "next-actions close their proofs (review round 1)").
**Verified by running, not by reading** (repo-cache convention `GOCACHE=.scratch/gocache`,
`GOPATH=.scratch/gomod`): `go test ./internal/orchestrator ./internal/briefing -count=1` →
ok ×2; `go test ./internal/cli -count=1` → ok; `go vet` on the three touched packages →
clean; `scripts/golden.sh` → GOLDEN GREEN; `scripts/runbook-walkthrough.sh` → 150 passed /
0 failed; `git status --porcelain` empty afterwards. `git diff ac11de2c..b77eb7fa --
internal/orchestrator/testdata/oracles.json` examined mechanically: 18 changed lines, all
`"oracle"` values (9 next_actions re-records × 2), no state/event/seam oracle moved.

---

## VERDICTS

**Spec compliance: YES.** **Task quality: CLEAN** — 0 new Critical, 0 new Important,
3 deferred minors (out-of-scope observations, listed at the end). All six open findings
ADDRESSED; all three fixer round-2 concerns adjudicated in the fix's favor.

---

## A. Verdicts on the open findings

### C-1 (RISK_CALIBRATION dead-end) — ADDRESSED

`status.go` RISK_CALIBRATION now mints `[webv2 run <C>, webv2 rank <C>]` — the
proof-closing command first, `rank` retained as the informational view (the review's fix
text explicitly allowed "keep or drop"). The in-code comment cites the proof field
(`risk.validated.band` per CONFIRMED finding, `completion/proofs2.go:109-131`) and rank's
read-only contract (`cmd_rank.go:8-9`, verified verbatim). Closure is enforced three ways:

1. `TestNextActionsConcreteFixtures` gained the RISK_CALIBRATION case — the §B blind-spot
   remedy the review asked for, delivered.
2. New property `TestNextActionsLeadWithTheProofClosingCommand` over all 13 proof-bearing
   phases, with the phase→stage mapping cross-checked against `pipeline.Stages`.
3. `TestNextActionsProofClosingPinIsNotVacuous` seeds a CONFIRMED finding lacking the
   proof's field and asserts the proof is genuinely OPEN (done=false AND missing non-empty)
   before asserting the lead verb — the vacuous-pin guard is itself tested.

Both affected oracles re-recorded (deduped, phases/risk-calibration step). Deliberate,
reasoned, confined to `"oracle"` lines.

### I-1 (INDEPENDENT_VERIFICATION mints a proof-blind `mint` lead) — ADDRESSED

IV now leads with `webv2 verify <C> --finding <finding> --exec <EXEC-id> --verifier
<verifier> --description <description>`. Verified against the parser, not the report:
`cmd_verify.go:194-196` rejects `--exec` without `--verifier` and `--description`, so the
minted flags match exactly what the review demanded ("match verify's actual required
flags"). The lead's effect is the proof's input field
(`verification.independent_reproduction{status=="matches",verifier}`, proofs2.go:79-101;
the proof's own missing-item text says "mint with webv2 verify --exec ..."), reached only
via `verify --exec` → `orchestrator.VerifyIndependently`. `mint` is demoted (not deleted)
with a correct rationale — it records the FORGE evidence but cannot set the proof's field,
so it must not lead — and `run` drives the stage. Phase pinned in the concrete fixtures;
oracle re-recorded; `<verifier>` added to the metavariable substitution table so the parse
check stays total.

### I-2 (briefing.go's own mint violates the law) — ADDRESSED

The §A ruling is implemented at the mint: `webv2Action(command, reason)` renders
`webv2 …  # reason`, `noParens` maps `(`→`[`/`)`→`]` for interpolated data, and every
previously-prose-first block was converted — all five lines cited in the review (2064 FIX
INTEGRITY, 2142 work probe row, 2152 emit probe row, lens routing, 2479 batting average)
plus the rest of the report's conversion table, open and closed branches. The law is now
enforced by a new dedicated test (`brief_next_actions_law_test.go`): every minted line
must start `webv2 ` and contain NO parenthesis anywhere in the line (the plan's `\(` regex
reads the whole line — the test correctly does not exempt the comment), over a hand-built
brief exercising every block plus a real completed campaign, with block-silence guards so
a conversion cannot silently drop a line. The nil-campaign panic at the old emit-probe-row
branch (pre-fix briefing.go:2147) is a genuine latent bug, correctly fixed via
`lensActionCampaign`. The T35 parity re-pins are deliberate with inline reasons on every
changed assertion, and I checked the substance: the re-pinned tests still assert the same
behavior (rank order, contiguity, lead precedence, suppression semantics — the
fallback-suppression filter now classifies by reason suffix and by identity for attention
lines, same semantics as the old prefix list). `cmd_t31_test.go` recallRe covers both the
backticked gate-message form and the command-first form. This satisfies the §A remedy as
written.

### M-1 (DISCOVERY omits `run`) — ADDRESSED. Leads `webv2 run <C>`; fixture + oracle
re-recorded. ### M-2 (MAINNET_FORK_POC mint line) — ADDRESSED. Gains
`webv2 mint <C> <finding> --exec <EXEC-id> --description <description> --type fork-test`;
verified `--type` choices include `fork-test` (cmd_mint.go). Fixture + oracle re-recorded.
### M-3 (`<same|distinct>` shell hazard) — ADDRESSED. `<same-or-distinct>`; the
metavariable table was updated with it, so the parse check stays blind nowhere.

M-4/M-5 correctly untouched (the review assigned them no action / follow-up).

---

## B. Adjudication of the fixer's round-2 concerns

### (1) Bare-command attention lines vs reason-inline — UPHOLD BARE. No change required.

The law requires a runnable command; a bare ledger command satisfies it, and the attention
block renders the action prose beside the command (the ledger's own `line`/`action`
fields — verified in briefing.go's ledger mint). Inlining a reason would force either
editing the ledger mint (a broader blast radius than this finding) or appending the reason
at the render site — which the plan's law explicitly forbids ("the code that MINTS those
strings is the fix site, not the renderer"). Bare commands also keep the T35 lead-equality
pins honest (`acts[i] == ranked[i].command` is an exact behavioral claim). The
identity-based exclusion from the generic filter is exact (string equality on the minted
command), unlike the old prefix heuristics. The offered two-line change is a style
preference, not a law violation — defer.

### (2) Commandless-advisory carriers — UPHOLD ALL THREE (and the fourth).

- **deficit → `webv2 run <C>`:** no per-deficit verb exists; run drives the specialist
  stage that works the deficit, and the reason names the E-level gap. This is the same
  sibling-model-stage pattern the round-1 review itself prescribed for C-1.
- **submission-ready → `webv2 report <C>`:** submission happens off-CLI (a human act);
  report is the deterministic step that precedes it and the reason says "submit F-x".
  Slightly indirect but honest. Acceptable.
- **terminals → `webv2 exploit <C> <last-path-member> --paid`:** verified against the
  parser — `exploit` requires exactly one of `--paid|--unpaid` plus campaign+finding
  positionals (cmd_exploit.go), so the minted shape is real and runnable. The empty-path
  fallback `webv2 terminals <C>` is a read-only view, but with no path member there is no
  finding to work, and none of these lines is a phase's only line — C-1's dead-end
  objection does not reach them (the fixer's own analysis, confirmed).
- (Same family, checked unprompted: cost-ceiling → `webv2 budget <C> --set <max-usd>
  --actor <actor>` matches the budget parser exactly.)

### (3) REPRODUCTION mint-first reorder — UPHOLD. Do not rescope the property.

The reorder follows from C-1's rationale generalized, and it is *correct on the proof's
own terms*: `proofReproduction` (proofs.go:411-441) reads
`verification.reproduction.status/attempts`, written by the mint path
(cmd_mint.go → `reproduction.AttemptAndMint`); `repro-queue` is the read-only view of the
same queue. Leading with a view and following with the closer is exactly the shape C-1
condemned. Scoping `TestNextActionsLeadWithTheProofClosingCommand` to the two flagged
phases would leave the identical dead-end shape in the other 11 phases unpinned. The
reorder is reasoned in the status.go comment, the golden_test.go provenance note, and the
re-pinned fixtures — deliberate per the Global Constraint.

---

## C. Re-pin scrutiny (9 oracles + T35 parity)

**Deliberate, reasoned, confined — accepted.** The 9-oracle re-record is mechanically
verified confined to 18 `"oracle"` lines in oracles.json; the golden_test.go provenance
note names the round, the reason (C-1/I-1 lead corrections, M-1/M-2 additions, M-3
metavariable, REPRODUCTION reorder), and the Go-authored status of the snapshots, matching
the Task-7 precedent. Every changed test line in the 10 T35/parity files carries an inline
reason naming I-2 and what moved where; the behavioral claims survived the re-pin (checked
individually, see §A I-2). The rerecord tooling was deleted before commit (consistent with
the diff; same cannot-fully-verify caveat as round 1).

---

## D. New breakage in the fix diff

**None at Critical/Important.** What I checked and cleared:

- Every verb the diff newly mints was verified against its parser usage block: `doctor
  <C>`, `budget <C> --set --actor`, `answered <C> <pid> answered --reason --actor`
  (positionals + flags match t14AnsweredUsage), `invariant-verify`, `probes <C> run
  --emit`, `chain <C> <members…>` (parser needs ≥1 member, the code guards ≥2), `verify
  --finding --exec --verifier --description`, `recall --finding`, `floors <C> set --actor
  --reason <class_> <floor>` (shape matches t14FloorsSetUsage, including the `<E4-E7>`
  fallback metavar), `report`, `run`, `memory --approve`, `exploit --paid`, `terminals`,
  `snap`, `status`, `prove --stage`, `mint --type fork-test`.
- Closed-branch `cid := campaign.CampaignID` introduces no new nil risk — the closed
  branch already dereferenced `campaign` pre-fix via `campaign.State()`.
- The law test's whole-line paren ban matches the plan's `\(` regex; `noParens` covers the
  interpolated reasons; the wilson CI brackets render paren-free (pinned exactly).
- Green evidence reproduced independently (see header), including golden and the runbook
  walkthrough, which the orchestrator+briefing output changes could have broken.

### Deferred minors (out-of-scope observations — for the ledger, not this task)

- **D-1 (minor, cosmetic):** for IV and RISK_CALIBRATION the catalog emits both a bare
  `webv2 run <C>` (from phaseActions) and the trailing `webv2 run <C>  # <stage> proof
  holds; the stage auto-completes` — two adjacent run lines with the same effect. Pre
  existing shape (the old IV list had it too), not introduced by this diff; deduping the
  bare run when the proof-holds line is present would read cleaner.
- **D-2 (minor, latent):** the briefing corpus line falls back to `--finding ?` when the
  findings list is empty while `irrelevant_checks != 0` — unreachable in practice, but if
  it ever fired the mint would be a non-substitutable command. Shape carried over from the
  pre-fix line, not new.
- **D-3 (observation, pre-existing):** attention-ledger queue commands still carry literal
  `--reason R --actor A` placeholders (ledger mint, briefing.go ~1066), inconsistent with
  the `<reason>`/`<actor>` metavariable convention used by the new mints. The ledger mint
  is untouched by this diff; note for a future pass.

## E. Cannot-verify items

- Authorship order of the inherited red logs (`red-orchestrator-inherited.txt`,
  `red-brief-law.txt`): consistent with the claims and with the green-first-run/rerun pair
  honestly preserved in `green-focused.txt`, but not independently confirmable.
- The Python twin's behavior for the re-recorded oracles: assumed from the recorded bytes;
  no twin run (same caveat as round 1, unchanged).

## F. Bottom line

The fix closes all six findings at the mint, with the proof-closing property enforced
generally rather than spot-fixed, the parse oracle's blind spot documented at the test and
compensated by a non-vacuous pin, and every re-pin deliberate and reasoned. All three
round-2 concerns are adjudicated in the fix's favor; no new Critical/Important breakage.
Task 7 is spec-compliant and clean at b77eb7fa.

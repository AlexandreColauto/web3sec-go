#!/usr/bin/env bash
#
# runbook-walkthrough.sh — T37 deliverable 2 / spec 1.5 DoD item 4:
# "RUNBOOK.md commands run verbatim against the Go binary with the
# documented exit codes."
#
# The runbook is this repo's embedded copy (assets/runbook/RUNBOOK.md; the
# D7 registry<->document test keeps it honest). This script executes its
# command sequence against the Go binary in a fresh scratch root and asserts
# the documented exit code (and the documented output markers the runbook
# calls out) for every command.
#
# ── SUBSTITUTIONS (every one, and why) ───────────────────────────────────
#
#  S1  `python3 -m webv2.cli`  ->  $WEBV2 (the Go binary)
#      The runbook's module form; the Go twin is one file. Everything after
#      the interpreter is verbatim.
#  S2  `python3 verify.py`     ->  `webv2 selftest`
#      RUNBOOK §0. Fast self-check (spec 1.5 item 1).
#  S3  `PYTHONPATH=src python3 -m pytest tests/ -q`
#                              ->  `webv2 selftest --full`
#      RUNBOOK §0. The ported suite instead of pytest (never run pytest:
#      user directive). Documented contract is identical: all green.
#  S4  `PYTHONPATH=src python3 examples/example_campaign/walkthrough.py`
#                              ->  the walkthrough check inside `webv2
#      selftest` (RUNBOOK §0). The Go port of the deterministic walkthrough
#      is a subcommand check, not a script.
#  S5  `python3 -m venv .venv && pip install ...` (RUNBOOK §0)
#                              ->  no equivalent needed: the release is a
#      static binary (scripts/release.sh). Not a command under test.
#  S6  Python-API snippets (the API blocks in RUNBOOK §1, §2, §3, §5, §6,
#      §7, §9)
#                              ->  the CLI form the runbook itself documents
#      for the same operation (RUNBOOK §cheat). Where the runbook gives
#      no CLI form (pure API calls), the row is listed as API-only and is
#      covered by the ported suite, not invoked here.
#  S7  `--root ROOT` in the cheat sheet
#                              ->  `--root .` in a fresh scratch root; the
#      runbook's own convention is "run from the workspace, --root defaults
#      to cwd" (RUNBOOK §top).
#  S8  fixtures: `policy.json`/`model.json`/`deployment.json`/`chain.json`/
#      finding payloads are copied from scripts/golden/ (the golden v4
#      fixtures) into the scratch root; the SFT example is the committed
#      extract scripts/golden/sft-example.json (sft store, first example).
#  S9  docker-dependent commands: RUNBOOK §0 documents docker as
#      expected-but-degrading. This script detects a running daemon:
#        * daemon present -> `exec` runs for real (asserting the runbook's
#          EXEC record + mint path);
#        * daemon absent  -> the same commands are asserted for the
#          DOCUMENTED preflight refusal instead (exit != 0 with the named
#          fix), which is the behavior the runbook describes for a missing
#          daemon.
#      `sequence run` (RUNBOOK §6a) needs a fork-runner RPC on top of
#      docker; the script exercises `sequence verify` (§6a) and records
#      `sequence run` as covered by the ported suite + scripts/p2-docker-e2e.sh.
#  S10 `WEBV2_GLOBAL_MEMORY_DIR` is pointed at the scratch root so the
#      walkthrough never touches the operator's real shared store and works
#      where $HOME is read-only (the runbook's §publish/globalize/shared
#      rows). The variable is honored (the retired reference read the same
#      env var; the row is a divergence record, D15 — see docs/archive).
#
# ── DOCUMENTED EXPECTATIONS ──────────────────────────────────────────────
# The runbook states exit codes for: `run` (2 = stage failed, 3 = halted at
# a model stage, §1), the CLI contract 0 ok / 1 handled error / 2 usage
# (§top, "the real signature"), `gate <c> <f>` (exit 1 while checks fail,
# §6), `probes blank` on a non-blind axis (refused, §4a), `env doctor`
# (exit 1 while it cannot, §0), `invariant-verify` (passing both or
# neither exits 2, §cheat), `move DISPROVED` without --adjacent on a
# lifecycle finding (§6). Every row below asserts its documented code; rows with no
# documented code assert 0 (success) or the handled-error contract.
#
# Two rows are RECORDED DISCREPANCIES (the runbook's literal text is refused
# by the binary — see docs/runbook-go-notes.md and docs/gates/P4-gate.md):
#   * §6a moves HYPOTHESIS -> CONFIRMED without the POSSIBLE step the §6
#     API block performs first; refused (exit 2).
#   * §7p `immunize ... --mutations "M1;M2;M3"` fails its own >=5-char
#     mutation-description validation (exit 2).
# Both are run VERBATIM here and asserted for the refusal, so the walkthrough
# proves the discrepancy instead of hiding it.
#
# Idempotent: wipes and rebuilds .scratch/t37/runbook-walkthrough. Exits 1
# if any row fails; prints the per-command table either way.

set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$GO_ROOT"

export GOCACHE="${GOCACHE:-$GO_ROOT/.scratch/gocache}"
export GOPATH="${GOPATH:-$GO_ROOT/.scratch/gomod}"
export GOMODCACHE="${GOMODCACHE:-$GOPATH/pkg/mod}"
export GOFLAGS="${GOFLAGS:--mod=mod}"

RB="$GO_ROOT/.scratch/t37/runbook-walkthrough"
WEBV2="$RB/webv2"
rm -rf "$RB"
mkdir -p "$RB/target/src" "$RB/target/bulk" "$RB/gm"
export WEBV2_GLOBAL_MEMORY_DIR="$RB/gm"

# --- build the binary under test ----------------------------------------
go build -o "$WEBV2" ./cmd/webv2 || { echo "FAIL: go build"; exit 1; }
WEBV2="$(cd "$(dirname "$WEBV2")" && pwd)/$(basename "$WEBV2")"

# --- fixtures -----------------------------------------------------------
cp "$GO_ROOT"/scripts/golden/{model.json,policy.json,deployment.json,chain.json} "$RB/"
cp "$GO_ROOT"/scripts/golden/h1-withdraw-double-count.json "$RB/"
cp "$GO_ROOT"/scripts/golden/h2-deposit-double-mint.json "$RB/"
cp "$GO_ROOT"/scripts/golden/sft-example.json "$RB/" 
cat > "$RB/target/src/MiniVault.sol" <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MiniVault {
    uint256 public totalDeposited;
    uint256 public rewardRate;
    mapping(address => uint256) public deposits;

    constructor() { rewardRate = 1e18; }

    function deposit() external payable {
        totalDeposited += msg.value;
        deposits[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "balance");
        (void) msg.sender.call{value: amount}("");
        deposits[msg.sender] -= amount;
        totalDeposited -= amount;
    }

    function rescue(address token, address to) external {
        (bool ok, ) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, 0));
        require(ok, "rescue failed");
    }
}
SOL
# The runbook (§cheat) promises "a foundry.toml is read
# automatically (toolchain line + config recorded)". Both twins read
# profile.default.sol, not the real Foundry key `solc` (twin quirk, see
# docs/python-twin-issues.md); the fixture therefore uses `sol` so the
# documented toolchain line is exercised, and a later row proves the quirk.
printf '[profile.default]\nsol = "0.8.24"\n' > "$RB/target/foundry.toml"
echo "generated fixture, not in scope" > "$RB/target/bulk/generated.txt"
# snap() pins through git: it walks UP to the enclosing repo, and the
# scratch root lives inside THIS repository — without its own git repo the
# toy target would pin the whole web3sec-go tree (472 nodes) and `run`'s
# snapshot re-index would stale the probe surface the final audit re-checks.
# A real audit target is a checkout; the fixture must be one too.
( cd "$RB/target" && git init -q && git add -A && \
  git -c user.email=walkthrough@web3sec -c user.name=walkthrough commit -qm "toy vault fixture" )

cd "$RB"

# --- the runner ---------------------------------------------------------
PASS=0
FAIL=0
TABLE="$RB/table.txt"
: > "$TABLE"

# check NAME EXPECT MARKER RUNBOOK_LINE -- cmd args...
#   EXPECT: a number, `ok` (exit 0), `nonzero`, or `0or1`.
#   MARKER: required substring of combined stdout+stderr ("" = none).
check() {
  local name="$1" expect="$2" marker="$3" line="$4"; shift 4
  [ "${1:-}" = "--" ] && shift
  local out code ok=1 why=""
  out="$("$@" 2>&1)"; code=$?
  case "$expect" in
    ok)      [ "$code" -eq 0 ] || { ok=0; why="exit $code, want 0"; } ;;
    nonzero) [ "$code" -ne 0 ] || { ok=0; why="exit 0, want nonzero"; } ;;
    0or1)    { [ "$code" -eq 0 ] || [ "$code" -eq 1 ]; } || { ok=0; why="exit $code, want 0/1"; } ;;
    *)       [ "$code" -eq "$expect" ] || { ok=0; why="exit $code, want $expect"; } ;;
  esac
  if [ "$ok" -eq 1 ] && [ -n "$marker" ]; then
    # MARKER may be a pipe-separated list; every part must appear.
    local part
    while IFS= read -r part; do
      if ! grep -qF -- "$part" <<<"$out"; then
        ok=0; why="marker not found: $part"
      fi
    done < <(tr '|' '\n' <<<"$marker")
  fi
  if [ "$ok" -eq 1 ]; then
    PASS=$((PASS+1))
    printf '[PASS] %-7s %-30s exit=%-2s %s\n' "$line" "$name" "$code" "" >> "$TABLE"
    printf '[PASS] %-7s %-30s exit=%-2s\n' "$line" "$name" "$code"
  else
    FAIL=$((FAIL+1))
    printf '[FAIL] %-7s %-30s exit=%-2s %s\n' "$line" "$name" "$code" "$why" >> "$TABLE"
    printf '[FAIL] %-7s %-30s exit=%-2s %s\n' "$line" "$name" "$code" "$why"
    printf '       cmd: %s\n' "$*" >> "$TABLE"
    printf '       out: %s\n' "$(head -2 <<<"$out" | tr '\n' ' ')" >> "$TABLE"
  fi
}

# q CMD... — run for side effects (builders), fail hard on error.
q() {
  local out
  out="$("$@" 2>&1)" || { echo "SETUP FAIL: $*"; echo "$out" | head -5; exit 1; }
  printf '%s' "$out"
}

# --- 0. setup (RUNBOOK §0) ----------------------------------------------
check selftest-fast ok "ALL PASS" §0 -- "$WEBV2" selftest
check selftest-full ok "ALL PASS" §0 -- "$WEBV2" selftest --full

# --- 2/3. campaign, policy, pin (RUNBOOK §2, §3; §cheat) ----------------
CID="$(q "$WEBV2" --root . init --program "Runbook walkthrough" \
  | grep -oE 'C-[0-9a-f]+' | head -1)"
[ -n "$CID" ] || { echo "FAIL: init produced no campaign id"; exit 1; }
check scope ok "policy loaded" §2 -- "$WEBV2" --root . scope "$CID" --policy policy.json
check snap ok "toolchain:|EXCLUDED from the pin" §3 -- "$WEBV2" --root . snap "$CID" target \
  --deployment deployment.json --chain chain.json --exclude bulk
check model ok "model loaded" §4 -- "$WEBV2" --root . model "$CID" model.json

# --- 4. structural index + plan (RUNBOOK §4, §4a, §5) -------------------
check index ok "index:" §4 -- "$WEBV2" --root . index "$CID" --src target
check plan ok "plan:" §5 -- "$WEBV2" --root . plan "$CID"
check plan-rebuild ok "plan:" §5 -- "$WEBV2" --root . plan "$CID" --rebuild
check probes-run ok "probe surface:" §4a -- "$WEBV2" --root . probes "$CID" run
check probes-emit ok "probe surface:" §4a -- "$WEBV2" --root . probes "$CID" run --emit
check probes-list ok "probe surface:" §4a -- "$WEBV2" --root . probes "$CID" list
check probes-list-all ok "probe surface:" §4a -- "$WEBV2" --root . probes "$CID" list --all
check probes-list-axis ok "probe surface:" §4a -- "$WEBV2" --root . probes "$CID" list --axis L-01
check probes-list-json ok '"rows"' §4a -- "$WEBV2" --root . probes "$CID" list --json
check probes-blank-refused 2 "is not blind" §4a -- "$WEBV2" --root . probes "$CID" blank \
  --axis incentive-inversion --anchor-blind user --reason "rejected every site" --actor operator

# the emitted surface row's plan priority, for the runbook's --anchor form.
PRIO="$("$WEBV2" --root . probes "$CID" list --json \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["surface_rows"][0]["priority_id"])')"
[ -n "$PRIO" ] || { echo "FAIL: no emitted probe row priority"; exit 1; }
check answered-anchor ok "not-applicable" §4a -- "$WEBV2" --root . answered "$CID" \
  "$PRIO" not-applicable --anchor actor --reason "the actor is trusted by the model" --actor operator

# --- 4b. derived surfaces (RUNBOOK §4b; §cheat for the verbs) -----------
check sinks ok "sinks:" §cheat -- "$WEBV2" --root . sinks "$CID" --src target
check prescreen ok "[no]" §cheat -- "$WEBV2" --root . prescreen "$CID" --src target
check forkdiff ok "fork-diff:" §cheat -- "$WEBV2" --root . forkdiff "$CID" --src target
check recency ok "recency:" §cheat -- "$WEBV2" --root . recency "$CID" --target target --src target
check baseline-list ok "" §cheat -- "$WEBV2" --root . baseline list
check baseline-add ok "baseline" §cheat -- "$WEBV2" --root . baseline add walkthrough --path target
check baseline-remove ok "removed" §cheat -- "$WEBV2" --root . baseline remove walkthrough
check corpus-surface ok "corpus surface" §cheat -- "$WEBV2" --root . corpus-surface "$CID"

# --- Wave G/I flags the walkthrough never exercised (Wave J Task 5) -----
# `--backtest --baseline`, `ingest --from aderyn` and `model --facts` each
# need state the walkthrough's own campaign does not have:
#   * `--backtest` scores against the eval-suite store, and the campaign's
#     program ("Runbook walkthrough") matches no suite case;
#   * `--facts` merges onto model.components[], which the committed golden
#     model.json does not carry — and the join is fail-closed (a fact
#     matching ZERO components is an error, never a dropped row).
# So they run on their OWN scratch campaign in this root, which leaves the
# main campaign — and every row that depends on it — byte-untouched.
WT_CID="$(q "$WEBV2" --root . init --program "SummerFi" \
  | grep -oE 'C-[0-9a-f]+' | head -1)"
[ -n "$WT_CID" ] || { echo "FAIL: flag-row campaign not created"; exit 1; }
# The committed P4 eval store (4 adjudicated cases, one sharing the
# campaign's program). The seam is empty-string-safe: evalstore reads
# WEBV2_EVAL_DIR only when it is non-empty, so restoring "" restores the
# default. It is restored immediately, before any other row runs.
WT_EVAL_DIR="${WEBV2_EVAL_DIR:-}"
export WEBV2_EVAL_DIR="$GO_ROOT/scripts/golden/p4/eval"
check backtest-baselines ok "baseline always:|baseline never:|precision: 0/0" §5 -- \
  "$WEBV2" --root . corpus-surface "$WT_CID" --backtest --baseline always --baseline never
# BINARY-GATED: the tool baselines run the real slither/aderyn binaries. A
# row that fails on a box without them is worse than no row, so it is
# skipped unless both are present (mirrors the optional-tool idiom used
# elsewhere in this repo — e.g. internal/harness's forge/libs probe).
if command -v slither >/dev/null 2>&1 && command -v aderyn >/dev/null 2>&1; then
  check backtest-tool-baselines ok "baseline slither:|baseline aderyn:|no local checkout" §5 -- \
    "$WEBV2" --root . corpus-surface "$WT_CID" --backtest \
    --baseline slither --baseline aderyn
else
  echo "[SKIP] §5      backtest-tool-baselines        slither/aderyn not on PATH"
fi
export WEBV2_EVAL_DIR="$WT_EVAL_DIR"
# I2a: the detector lane over the committed Aderyn sample (pure JSON, no
# binary at run time — `--from aderyn` parses a saved report).
check ingest-aderyn ok "hypotheses created" §5 -- "$WEBV2" --root . ingest "$WT_CID" \
  --from aderyn --json-file "$GO_ROOT/internal/datasets/aderyn/testdata/aderyn_sample.json"
# I4: the checked-in operator-facts example. The model is generated inline
# (the walkthrough already builds its fixtures this way) because a facts
# document must name components the model actually declares.
cat > "$RB/facts-model.json" <<'FACTSMODEL'
{"protocol_id":"factsdemo","name":"Facts Demo",
 "components":[
  {"kind":"frontend","url":"https://app.example","trust":"semi-trusted",
   "in_scope":true,"paid_for":true},
  {"kind":"keeper-service","path":"apps/keeper","trust":"semi-trusted",
   "in_scope":true,"paid_for":false}],
 "contracts":[{"name":"Vault","path":"src/Vault.sol"}],
 "actors":[{"id":"user","kind":"EOA"}],
 "assets":[{"id":"share","kind":"share"}],
 "relations":[]}
FACTSMODEL
check model-facts ok "facts: 2 applied (1 dns, 1 dependency) onto 2 components" §5 -- \
  "$WEBV2" --root . model "$WT_CID" facts-model.json \
  --facts "$GO_ROOT/assets/protocol/example_facts.json"

# --- 5. floors + budget (RUNBOOK §5a; §cheat) ---------------------------
check floors ok "floors" §5a -- "$WEBV2" --root . floors "$CID"
check floors-set ok "floor policy set" §5a -- "$WEBV2" --root . floors "$CID" set reentrancy E5 \
  --actor operator --reason "mainnet fork reachable"
check floors-unset ok "cleared" §5a -- "$WEBV2" --root . floors "$CID" unset reentrancy \
  --actor operator --reason "fork infra gone"
check floors-json ok '"' §5a -- "$WEBV2" --root . floors "$CID" --json
check budget ok "spent" §5a -- "$WEBV2" --root . budget "$CID"
check budget-set ok "limit" §5a -- "$WEBV2" --root . budget "$CID" --set 5000 --actor operator
check budget-clear ok "NO CEILING SET" §5a -- "$WEBV2" --root . budget "$CID" --clear --actor operator
check budget-discovery ok "max_discovery_findings" §5a -- "$WEBV2" --root . budget "$CID" \
  --set-discovery 50 --actor operator
check budget-json ok '"' §5a -- "$WEBV2" --root . budget "$CID" --json
check index-json ok '"' §4 -- "$WEBV2" --root . index "$CID" --src target --json
check sinks-json ok '"' §cheat -- "$WEBV2" --root . sinks "$CID" --src target --json
check prescreen-json ok '"' §cheat -- "$WEBV2" --root . prescreen "$CID" --src target --json
check forkdiff-json ok '"' §cheat -- "$WEBV2" --root . forkdiff "$CID" --src target --json
check recency-json ok '"' §cheat -- "$WEBV2" --root . recency "$CID" --target target --src target --json
check ingest-example ok '"' §5 -- "$WEBV2" --root . ingest --example
check run-max-stages nonzero '"ran"' §1 -- "$WEBV2" --root . run "$CID" --max-stages 1

# --- 6. finding lifecycle (RUNBOOK §6, §6a; §cheat) ---------------------
check ingest ok "ingested" §5 -- "$WEBV2" --root . ingest "$CID" \
  --json-file h1-withdraw-double-count.json --trajectory code --stage selftest
FID="$(ls campaigns/"$CID"/findings | head -1 | sed 's/\.json$//')"
check ingest-second ok "ingested" §5 -- "$WEBV2" --root . ingest "$CID" \
  --json-file h2-deposit-double-mint.json --trajectory code --stage selftest
F2="$(ls campaigns/"$CID"/findings | grep -v "$FID" | head -1 | sed 's/\.json$//')"
[ -n "$FID" ] && [ -n "$F2" ] || { echo "FAIL: findings not created"; exit 1; }

check exec-dry ok "exec preview" §6a -- "$WEBV2" --root . exec "$CID" \
  --profile docker-networkless --command "forge test --match-test test_poc" --workdir poc --dry-run
if docker info >/dev/null 2>&1; then
  check exec-ok ok "EXEC-" §6a -- "$WEBV2" --root . exec "$CID" \
    --profile docker-networkless --command "echo walkthrough" --finding "$FID"
  check exec-env ok "EXEC-" §6a -- "$WEBV2" --root . exec "$CID" \
    --profile docker-networkless --command "echo \$WALKTHROUGH" --finding "$FID" --env WALKTHROUGH=ok
  check exec-fail ok "EXEC-" §6a -- "$WEBV2" --root . exec "$CID" \
    --profile docker-networkless --command "exit 7" --finding "$FID"
else
  # S9: the documented preflight refusal (daemon absent).
  check exec-ok nonzero "docker" §6a -- "$WEBV2" --root . exec "$CID" \
    --profile docker-networkless --command "echo walkthrough" --finding "$FID"
  check exec-fail nonzero "docker" §6a -- "$WEBV2" --root . exec "$CID" \
    --profile docker-networkless --command "exit 7" --finding "$FID"
fi
# Pick the successful exec for mint/verify and the failed one for classify:
# `ls` order is not the ledger order.
EXID="$("$WEBV2" --root . execs "$CID" --json | python3 -c '
import json,sys
rows=json.load(sys.stdin)
print(next(r["exec_id"] for r in rows if r.get("exit_status") == 0))')"
EXFAIL="$("$WEBV2" --root . execs "$CID" --json | python3 -c '
import json,sys
rows=json.load(sys.stdin)
print(next(r["exec_id"] for r in rows if r.get("exit_status") not in (0, None)))')"
EXID2="$("$WEBV2" --root . execs "$CID" --json | python3 -c '
import json,sys
rows=[r for r in json.load(sys.stdin) if r.get("exit_status") == 0]
print(rows[-1]["exec_id"])')"
check execs ok "EXEC-" §cheat -- "$WEBV2" --root . execs "$CID"
check execs-json ok '"exec_id"' §cheat -- "$WEBV2" --root . execs "$CID" --json
check execs-id ok '"' §cheat -- "$WEBV2" --root . execs "$CID" --id "$EXID"

check mint ok "minted" §6a -- "$WEBV2" --root . mint "$CID" "$FID" --exec "$EXID" \
  --description "the unit PoC drains the vault" --tier T2 --type foundry-test
check recall ok "recorded: mode=" §6 -- "$WEBV2" --root . recall "$CID" --finding "$FID" --mode negative
check verdict ok "critic verdict" §6 -- "$WEBV2" --root . verdict "$CID" "$FID" \
  --verdict confirmed --reason "no compensating control on the withdraw path"
# The runbook's §6a block omits the POSSIBLE step its own §6 API block performs
# (§6a); executed verbatim first to PROVE the refusal, then with the step.
check move-confirmed-verbatim 2 "not a legal transition" §6 -- "$WEBV2" --root . move \
  "$CID" "$FID" CONFIRMED --reason "gates passed"
check move-possible ok "POSSIBLE" §6 -- "$WEBV2" --root . move "$CID" "$FID" POSSIBLE \
  --reason "triage: the mechanism is falsifiable"
check move-confirmed ok "CONFIRMED" §6 -- "$WEBV2" --root . move "$CID" "$FID" CONFIRMED \
  --reason "gates passed"
check gate-finding ok "CONFIRMED gate" §6 -- "$WEBV2" --root . gate "$CID" "$FID"
check gate-failing 1 "✗" §6 -- "$WEBV2" --root . gate "$CID" "$F2"
check gate-all ok "submission_ready" §6 -- "$WEBV2" --root . gate "$CID"
check gate-explain ok "evidence-floor" §6 -- "$WEBV2" --root . gate --explain evidence-floor
check classify ok "exec EXEC-" §6a -- "$WEBV2" --root . classify "$CID" "$EXFAIL"
check shield ok "shield" §cheat -- "$WEBV2" --root . shield "$CID" "$FID" \
  --reason "the docs call the mechanism intentional; the effect is still extraction"
check precondition ok "precondition" §cheat -- "$WEBV2" --root . precondition "$CID" "$FID" \
  "the attacker holds any positive share balance" --enforced
check sequence-verify ok "sequence" §6a -- "$WEBV2" --root . sequence verify "$CID" "$FID"
check impact ok "impact recorded" §7u -- "$WEBV2" --root . impact "$CID" "$FID" \
  --extractable 1200000 --description "1.2M at fork depth, protocol liquidity only"
check impact-unpriceable ok "UNPRICEABLE" §7u -- "$WEBV2" --root . impact "$CID" "$F2" \
  --unpriceable --ceiling "liquidity in the pool at fork block" \
  --reason "only a test constant is defensible" --actor operator
check verify-exec-independence 2 "independent" §7 -- "$WEBV2" --root . verify "$CID" \
  --exec "$EXID" --finding "$FID" --verifier verifier-b --description "same block, same drain"
check verify-exec ok "independently verified" §7 -- "$WEBV2" --root . verify "$CID" \
  --exec "$EXID2" --finding "$FID" --verifier verifier-b --description "same block, same drain"
check verify-queue ok "" §7 -- "$WEBV2" --root . verify "$CID" --queue
check verify-log ok '"ok": true' §7 -- "$WEBV2" --root . verify "$CID"

# --- 7/9. views, memory, ladder (RUNBOOK §7, §9, §6a; §cheat) -----------
check report ok "report.md" §9 -- "$WEBV2" --root . report "$CID"
check brief ok "campaign" §cheat -- "$WEBV2" --root . brief "$CID"
check brief-json ok '"' §cheat -- "$WEBV2" --root . brief "$CID" --json
check brief-deep ok "campaign" §cheat -- "$WEBV2" --root . brief "$CID" --deep
check memory-empty ok "memory" §9 -- "$WEBV2" --root . memory "$CID"
check ladder-start ok "ladder" §6a -- "$WEBV2" --root . ladder "$CID" start "$FID"
check ladder-add ok "rung" §6a -- "$WEBV2" --root . ladder "$CID" add "$FID" \
  --name "dust the pool" --description "donate one wei before the victim deposits" \
  --axes capital-minimization --capital 1 --ratio 1 --removes "victim stakes first"
RUNG="$("$WEBV2" --root . ladder "$CID" show "$FID" \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["variants"][-1]["rung_id"])')"
check ladder-show ok "rung_id" §6a -- "$WEBV2" --root . ladder "$CID" show "$FID"
# §cheat writes `explore F-xxx [RUNG|AXIS]`. The reference parsed
# the 4th positional as RUNG and refused the literal form (twin-issues P3);
# Go follows the runbook — explore takes no rung, so the verbatim command
# works and reports the axis explored. The next row keeps the legacy
# rung-placeholder form green for anyone holding old scripts.
check ladder-explore-verbatim ok "axis capital-minimization" §6a -- "$WEBV2" --root . ladder \
  "$CID" explore "$FID" capital-minimization --note "already the cheapest variant"
check ladder-explore ok "axis capital-minimization" §6a -- "$WEBV2" --root . ladder \
  "$CID" explore "$FID" R-any capital-minimization --note "already the cheapest variant"
check ladder-disprove ok "negative memory queued" §6a -- "$WEBV2" --root . ladder "$CID" \
  disprove "$FID" "$RUNG" --reason "the pool already holds one wei, so the variant is free"
check ladder-report ok '"' §6a -- "$WEBV2" --root . ladder "$CID" report "$FID"
check ladder-complete 2 "unexplored axes" §6a -- "$WEBV2" --root . ladder "$CID" complete "$FID" \
  --actor operator
check memory-list ok "MEM-" §9 -- "$WEBV2" --root . memory "$CID"
MEM="$("$WEBV2" --root . memory "$CID" | grep -oE 'MEM-[0-9a-f]+' | head -1)"
check memory-approve ok "approved" §9 -- "$WEBV2" --root . memory "$CID" --approve "$MEM" --by operator
# §7p verbatim: the runbook's own 2-char mutation names are refused.
check immunize-verbatim 2 "written description" §7p -- "$WEBV2" --root . immunize "$CID" "$FID" \
  --poc-exec "$EXID" --patch h1-withdraw-double-count.json --mutations "M1;M2;M3" --actor operator
check immunize-unit-poc-refused nonzero "fork" §7p -- "$WEBV2" --root . immunize "$CID" "$FID" \
  --poc-exec "$EXID" --patch h1-withdraw-double-count.json \
  --mutations "M1 dust one wei;M2 adjacent path via rescue;M3 boundary amount zero" --actor operator
check hint ok "HINT-" §cheat -- "$WEBV2" --root . hint "$CID" --kind note \
  --content "check the accumulator basis before the next pass" --actor operator

# --- artifacts / invariants / shared store (RUNBOOK §7, §9; §cheat) -----
check artifact-register ok "kind=report" §7 -- "$WEBV2" --root . artifact-register "$CID" \
  h1-withdraw-double-count.json --kind report
ART="$(q "$WEBV2" --root . artifact-list "$CID" | grep -oE 'REP-[0-9a-f]+' | head -1)"
check artifact-list ok "REP-" §cheat -- "$WEBV2" --root . artifact-list "$CID"
check invariant-verify ok "INV-1" §cheat -- "$WEBV2" --root . invariant-verify "$CID" INV-1 --artifact "$ART"
check invariant-contradict ok "INV-2" §cheat -- "$WEBV2" --root . invariant-contradict "$CID" INV-2 \
  --evidence "target/src/MiniVault.sol#L20"
check publish ok "published" §9 -- "$WEBV2" --root . publish "$CID" --actor operator
check globalize ok "scope=global" §9 -- "$WEBV2" --root . globalize --actor operator
check publish-global ok "global tier" §9 -- "$WEBV2" --root . publish "$CID" --actor operator --global
check shared ok "shared" §9 -- "$WEBV2" --root . shared
check shared-verify ok "shared" §9 -- "$WEBV2" --root . shared --verify
# I6: `publish --disclosure` — the bundle is generated inline from the
# CONFIRMED finding FID (the disclosure rule is fail-closed: an unknown or
# unconfirmed id is refused). Its prose stays campaign-local; the publish
# record carries only its sha256 and embargo date, and the extra output line
# ends "recorded, not enforced" so an embargo is never read as a guarantee.
cat > "$RB/disclosure.json" <<DISCLOSURE
{
  "schema_version": "1",
  "finding_ids": ["$FID"],
  "summary": "the vault releases collateral before the debt is burned",
  "impact": "the attacker drains the pool at no cost",
  "affected": [{"contract": "MiniVault", "chain": "ethereum", "path": "target/src/MiniVault.sol"}],
  "embargo_until": "2026-10-01",
  "contact": "security@example.invalid",
  "reporter_credit": "walkthrough"
}
DISCLOSURE
check publish-disclosure ok "recorded, not enforced" §9 -- "$WEBV2" --root . publish "$CID" \
  --actor walkthrough --disclosure disclosure.json

# --- money / economics / graph views (RUNBOOK §7u, §8; §cheat) ----------
check cost ok "recorded COST-" §cheat -- "$WEBV2" --root . cost "$CID" --kind model --amount 12.50 \
  --trajectory code --actor harness
check yields ok "yield=" §cheat -- "$WEBV2" --root . yields "$CID"
check price-table ok "price" §cheat -- "$WEBV2" --root . price "$CID" table
check price-set ok "price row" §cheat -- "$WEBV2" --root . price "$CID" set WETH 3000 --source coinbase --actor operator
PRICE="$("$WEBV2" --root . price "$CID" table | grep -oE 'PRC-[0-9a-f]+' | head -1)"
check price-basis ok "PRC-|price" §cheat -- "$WEBV2" --root . price-basis "$CID" "$FID" "$PRICE"
check relations ok "edges:" §cheat -- "$WEBV2" --root . relations "$CID"
check relations-rebuild ok "re-derived" §cheat -- "$WEBV2" --root . relations "$CID" --rebuild
check resemble ok "candidate" §cheat -- "$WEBV2" --root . resemble "$CID" "$FID"
check chains ok "capability links:" §8 -- "$WEBV2" --root . chains "$CID"
check terminals ok "terminal" §8 -- "$WEBV2" --root . terminals "$CID"
check privileged ok "privileged track" §cheat -- "$WEBV2" --root . privileged "$CID"
check dedup ok "tier1_merges" §6 -- "$WEBV2" --root . dedup "$CID"
check prioritize ok "prior=" §cheat -- "$WEBV2" --root . prioritize "$CID"
check repro-queue ok "" §cheat -- "$WEBV2" --root . repro-queue "$CID"
check answered-priority ok "answered" §5 -- "$WEBV2" --root . answered "$CID" Q-001 answered \
  --reason "the model covers this in the scope entry" --ref "$FID"
check waive ok "waived" §cheat -- "$WEBV2" --root . waive "$CID" discovery \
  --reason "walkthrough waiver: the diversity floor is advisory" --actor operator
# Round-3 walkthrough coverage: the §4b enforcement table, the §5 reverse
# sweep and the §8 adversarial-game setter — Go-only verbs the reviewer named
# as unwalked. All three have clean happy paths on this campaign (the plan,
# index and CONFIRMED finding already exist); no verb was skipped for
# exotic fixtures — the docker/fork-dependent verbs stay covered by S9 and
# scripts/p2-docker-e2e.sh as before.
check enforce ok "enforce: totalDeposited" §4b -- "$WEBV2" --root . enforce "$CID" totalDeposited
check enforce-json ok "sites" §4b -- "$WEBV2" --root . enforce "$CID" totalDeposited --json
check deferred ok "deferred:" §5 -- "$WEBV2" --root . deferred "$CID"
check deferred-json ok "skipped" §5 -- "$WEBV2" --root . deferred "$CID" --json
check adversarial-game ok "adversarial-game clause recorded" §8 -- "$WEBV2" --root . adversarial-game \
  "$CID" "$FID" \
  --who-profit "the operator who reopened the withdrawals window" \
  --mechanism "sealing a stale state root lets them collect exit fees" \
  --interplay "the challenge path cannot unseal the batch once it is final"
check doctor ok "state:" §0 -- "$WEBV2" --root . doctor "$CID"
check doctor-json ok '"' §0 -- "$WEBV2" --root . doctor "$CID" --json
check env-doctor 0or1 "docker:" §0 -- "$WEBV2" --root . env doctor
check env-doctor-json ok '"' §0 -- "$WEBV2" --root . env doctor --json
check status ok '"' §cheat -- "$WEBV2" --root . status "$CID"
check status-verbose ok '"' §cheat -- "$WEBV2" --root . status "$CID" --verbose

# --- SFT dataset tooling (RUNBOOK §cheat) -------------------------------
check sft-lint ok "PASS" §cheat -- "$WEBV2" --root . sft lint sft-example.json
check sft-add ok "SFT-" §cheat -- "$WEBV2" --root . sft add sft-example.json --status draft
check sft-list ok "SFT-" §cheat -- "$WEBV2" --root . sft list
check sft-split ok "split:" §cheat -- "$WEBV2" --root . sft split --seed 7
check sft-report ok "taxonomy mix" §cheat -- "$WEBV2" --root . sft report
check sft-export ok "" §cheat -- "$WEBV2" --root . sft export --partition training
check sft-backfill ok "backfill" §cheat -- "$WEBV2" --root . sft backfill "$CID" "$FID"

# --- completion + the final audit (RUNBOOK §10) -------------------------
# prove renders one human line per stage: "<stage> DONE|open [authoritative]"
# (exit 1 while open — the runbook's documented code).
check prove-incomplete 1 "open|hostile-review" §10 -- "$WEBV2" --root . prove "$CID" --stage hostile-review
check prove-done ok "DONE|discovery" §10 -- "$WEBV2" --root . prove "$CID" --stage discovery
check doctor-state-only ok "state:" §0 -- "$WEBV2" --root . doctor "$CID" --state-only
check doctor-snapshot-only ok "snapshot" §0 -- "$WEBV2" --root . doctor "$CID" --snapshot-only
check env-doctor-campaign 0or1 "docker:" §0 -- "$WEBV2" --root . env doctor "$CID"
check answered-lens ok "not-applicable" §5 -- "$WEBV2" --root . answered "$CID" L-01 \
  not-applicable --reason "the lens is not seeded in this model" --families protocol
# The reference crashed on --note (dedup_meta typed; twin-issues P2 / D14);
# Go records the verdict and stamps the note on BOTH findings.
check resolve-candidate ok "candidate pair" §6 -- "$WEBV2" --root . resolve-candidate \
  "$CID" "$FID" "$F2" --verdict distinct --note "different root cause" --actor operator
check run-halt 3 "HALTED at model stage" §1 -- "$WEBV2" --root . run "$CID"
check complete ok "COMPLETE" §10 -- "$WEBV2" --root . complete "$CID" \
  --actor operator --reason "walkthrough pass finished"
check prove ok "DONE" §10 -- "$WEBV2" --root . prove "$CID"
check log ok "" §cheat -- "$WEBV2" --root . log "$CID" --tail 50
check audit ok "audit PASS" §10 -- "$WEBV2" --root . audit "$CID"
check audit-json ok '"ok": true' §10 -- "$WEBV2" --root . audit "$CID" --json
check verify-final ok '"ok": true' §7 -- "$WEBV2" --root . verify "$CID"
check selftest-final ok "ALL PASS" §0 -- "$WEBV2" selftest

# --- table + verdict ----------------------------------------------------
echo
echo "=== RUNBOOK walkthrough: per-command results ($((PASS+FAIL)) commands) ==="
cat "$TABLE"
echo
echo "walkthrough: $PASS passed, $FAIL failed (runbook assets/runbook/RUNBOOK.md, binary $WEBV2)"
if [ "$FAIL" -eq 0 ]; then
  echo "WALKTHROUGH GREEN: every RUNBOOK command matched its documented behavior"
  exit 0
fi
echo "WALKTHROUGH RED: $FAIL command(s) did not match the runbook"
exit 1

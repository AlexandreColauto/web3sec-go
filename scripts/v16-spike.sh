#!/usr/bin/env bash
# v16-spike.sh — the Phase 2 maximization spike driver (v1.6 plan, Task 10).
#
#   scripts/v16-spike.sh [--dry-run] <campaign> <finding> <fork-rpc> <block>
#
# Drives the whole Phase 2 loop on ONE already-CONFIRMED finding against a
# pinned fork: existence exec -> mint (existence tier) -> ladder start/add/repro
# of the amplified variant -> amplified exec -> mint (maximized tier) -> ladder
# complete -> impact --replayable -> audit -> machine-readable summary.
#
# EVERY webv2 call goes through run() below. That is load-bearing, not style:
# internal/cli/spike_driver_test.go reads this file's `run <verb>` lines and
# asserts offline that every flag the driver emits is one the CLI really
# declares — a typo would otherwise surface mid-spike, with Docker up and a
# fork pinned. A bare `webv2 ...` call anywhere would escape that check.
#
# DRY_RUN=1 (or --dry-run) makes run() echo each command and return 0, so the
# whole driver walks with no Docker, no RPC and no campaign.
#
# Operator inputs beyond the four arguments (environment, with defaults):
#   TEST_NAME       the existence forge test (default test_exploit)
#   AMP_TEST        the amplified forge test, same pin (default test_exploit_amplified)
#   AMP_NAME/AMP_DESC/AMP_AXES/AMP_RATIO   the amplification rung
#   REPLAYABLE=0    skip step 4 (a finding with no replay)
#   X_PER_ROUND / POOL_USD / GAS_USD / FREQ_PER_DAY   the replay's figures
#   REPLAY_ASSUMPTION / REPLAY_BLOCKER                the replay's two prose fields
set -euo pipefail

DRY_RUN="${DRY_RUN:-0}"
if [ "${1:-}" = "--dry-run" ]; then
  DRY_RUN=1
  shift
fi

if [ "$#" -ne 4 ]; then
  printf 'usage: scripts/v16-spike.sh [--dry-run] <campaign> <finding> <fork-rpc> <block>\n' >&2
  exit 2
fi

C="$1"
FID="$2"
RPC="$3"
BLOCK="$4"

TEST_NAME="${TEST_NAME:-test_exploit}"
AMP_TEST="${AMP_TEST:-test_exploit_amplified}"
AMP_NAME="${AMP_NAME:-amplified}"
AMP_DESC="${AMP_DESC:-amplification of the base variant at the same pin}"
AMP_AXES="${AMP_AXES:-capital-minimization}"
AMP_RATIO="${AMP_RATIO:-1}"
REPLAYABLE="${REPLAYABLE:-1}"
X_PER_ROUND="${X_PER_ROUND:-0}"
POOL_USD="${POOL_USD:-0}"
GAS_USD="${GAS_USD:-0}"
FREQ_PER_DAY="${FREQ_PER_DAY:-1}"
REPLAY_ASSUMPTION="${REPLAY_ASSUMPTION:-replayed against the pinned fork state}"
REPLAY_BLOCKER="${REPLAY_BLOCKER:-none identified at the pinned block}"

# FORGE_CMD / FORGE_CMD_AMP are the container commands handed to `exec
# --command`; the flags inside them are foundry's, not webv2's.
FORGE_CMD="forge test --fork-url $RPC --fork-block-number $BLOCK --match-test $TEST_NAME"
FORGE_CMD_AMP="forge test --fork-url $RPC --fork-block-number $BLOCK --match-test $AMP_TEST"

# run is the single door to webv2. The flag-name test reads these lines.
run() {
  if [ "${DRY_RUN:-0}" = 1 ]; then
    echo "webv2 $*"
    return 0
  fi
  webv2 "$@"
}

# nth_id prints field $2 of a captured webv2 transcript's first line — the id
# webv2 minted (field 1 of `exec`, field 2 of `ladder add`). Under --dry-run
# nothing ran, so it prints the placeholder in $3 instead.
nth_id() {
  if [ "${DRY_RUN:-0}" = 1 ]; then
    printf '%s\n' "$3"
    return 0
  fi
  printf '%s\n' "$1" | awk -v n="$2" 'NR == 1 { print $n }'
}

# replay_summary turns `webv2 impact --replayable`'s computed line
# ("computed:     N rounds to exhaustion, ceiling $C, attack cost $A") into the
# summary block's three replay keys, so the block is machine-readable.
replay_summary() {
  if [ "${DRY_RUN:-0}" = 1 ]; then
    printf 'rounds_to_exhaustion: (dry-run)\nceiling_usd: (dry-run)\n'
    printf 'cumulative_attack_cost_usd: (dry-run)\n'
    return 0
  fi
  printf '%s\n' "$1" | awk '
    /^computed:/ { gsub(/[$,]/, "", $7); gsub(/[$,]/, "", $10)
      printf "rounds_to_exhaustion: %s\nceiling_usd: %s\ncumulative_attack_cost_usd: %s\n", $2, $7, $10
      found = 1 }
    END { if (!found)
      printf "rounds_to_exhaustion: (unparsed)\nceiling_usd: (unparsed)\ncumulative_attack_cost_usd: (unparsed)\n" }'
}

echo "== step 1: existence exec on the pinned fork =="
EXEC_OUT="$(
  run exec --profile fork-runner --command "$FORGE_CMD" --finding "$FID"
)"
printf '%s\n' "$EXEC_OUT"
EXEC="$(nth_id "$EXEC_OUT" 1 "EXEC-DRYRUN-1")"

echo "== step 2: mint the existence tier =="
run mint "$C" "$FID" --exec "$EXEC" --type fork-test --poc-tier existence \
  --description "state break on the pinned fork"

echo "== step 3: amplify at the same pin, then mint the maximized tier =="
run ladder "$C" start "$FID"
ADD_OUT="$(
  run ladder "$C" add "$FID" --name "$AMP_NAME" --description "$AMP_DESC" \
    --axes "$AMP_AXES" --ratio "$AMP_RATIO"
)"
printf '%s\n' "$ADD_OUT"
RUNG="$(nth_id "$ADD_OUT" 2 "RUNG-DRYRUN-1")"
EXEC_AMP_OUT="$(
  run exec --profile fork-runner --command "$FORGE_CMD_AMP" --finding "$FID"
)"
printf '%s\n' "$EXEC_AMP_OUT"
EXEC_AMP="$(nth_id "$EXEC_AMP_OUT" 1 "EXEC-DRYRUN-2")"
run ladder "$C" repro "$FID" "$RUNG" --exec "$EXEC_AMP"
run mint "$C" "$FID" --exec "$EXEC_AMP" --type fork-test --poc-tier maximized \
  --description "amplified state break at the same pin"
run ladder "$C" complete "$FID"

REPLAY_KEYS="replayable: no"
if [ "$REPLAYABLE" = 1 ]; then
  echo "== step 4: the replay arithmetic =="
  IMPACT_OUT="$(
    run impact "$C" "$FID" --replayable \
      --extractable-per-round "$X_PER_ROUND" --max-loss "$POOL_USD" \
      --gas-cost "$GAS_USD" --frequency "$FREQ_PER_DAY" --rounds-run 2 \
      --replay-assumption "$REPLAY_ASSUMPTION" --replay-blocker "$REPLAY_BLOCKER"
  )"
  printf '%s\n' "$IMPACT_OUT"
  REPLAY_KEYS="$(replay_summary "$IMPACT_OUT")"
fi

echo "== step 5: audit =="
AUDIT_EXIT=0
if [ "$DRY_RUN" = 1 ]; then
  run audit "$C"
else
  run audit "$C" || AUDIT_EXIT=$?
fi

echo "== step 6: machine-readable summary =="
RPC_HOST="${RPC#*://}"
RPC_HOST="${RPC_HOST%%/*}"
echo "--- v16-spike summary ---"
echo "campaign: $C"
echo "finding: $FID"
echo "pinned_block: $BLOCK"
echo "fork_rpc_host: $RPC_HOST"
echo "tiers_reached: existence,maximized"
echo "exec_existence: $EXEC"
echo "exec_maximized: $EXEC_AMP"
echo "maximal_rung: $RUNG"
echo "extractable_per_round_usd: $X_PER_ROUND"
printf '%s\n' "$REPLAY_KEYS"
echo "audit_exit: $AUDIT_EXIT"
echo "--- end v16-spike summary ---"

exit "$AUDIT_EXIT"

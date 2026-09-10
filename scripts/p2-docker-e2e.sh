#!/usr/bin/env bash
# P2 DOCKER e2e — the real-container leg of the verification suite.
#
# The golden suite (scripts/golden.sh) is deliberately docker-FREE: its E4
# exec records are harness-seeded. This script closes that gap by running
# the P2 command sequence against a REAL docker daemon and a REAL anvil
# fork endpoint, then asserting the resulting campaign tree and every CLI
# capture. (Historical: until the 2026-09-09 twin retirement this script
# byte-diffed the same sequence between the twins.)
#
#   (a) exec / classify / mint
#       a real `forge test` inside foundry-solc-0824:latest under the
#       docker-networkless profile — one passing run (exit 0, minted as E4
#       foundry-test evidence) and one failing run (exit 1, fed to
#       `classify`) — so the exec_record.json, the stdout/stderr logs, the
#       ATT-/EV- attempt+evidence records and events.jsonl are compared as
#       real container artifacts.
#
#   (b) sequence run / sequence verify / audit
#       a 2-step sequence PoC spec executed by the generated POSIX-sh
#       driver under the fork-runner profile against an anvil container
#       (FORK_RPC_URL=...:8545, actors resolved through eth_accounts), so
#       sequence_result.json + spec_hash + the sequence_coverage audit
#       section are compared from a real multi-tx run.
#
# DETERMINISM.  Everything that would otherwise differ run-to-run is
# pinned, and every remaining nondeterminism is documented here:
#
#   * clock        WEBV2_NOW (base + step seconds)
#   * id stream    WEBV2_UUID=<seed>:<step> per command, so EXEC-/ATT-/EV-
#                  ids cannot collide across the two `exec` invocations
#                  (each CLI process restarts its new_id counter at 0)
#   * finding ids  WEBV2_FINDING_IDS=pin (+ WEBV2_FINDING_ID_SEQ)
#   * chain state  a fresh anvil container with anvil_setCode: the setup
#                  transactions are signed by the same anvil account at the
#                  same nonces, so artifacts reproduce run-to-run
#   * forge output the container command filters forge's own wall-clock
#                  timing fields (`finished in <T>`, ` in <T> (<T> CPU
#                  time)`) with sed, because those vary per run in the same
#                  image; the filtered text is what the exec record hashes,
#                  so stdout_hash matches byte-exactly
#   * generated_at the generated sequence_result.json carries
#                  `date -u` from INSIDE the container, which cannot be
#                  pinned from outside; that single field is normalized
#
# What is NOT normalized: root paths (<ROOT>) and environment_hash
# (<ENVHASH>) only — the same two normalizations the golden checker
# documents (KNOWN_DIVERGENCES D3). The exec record's environment block
# needs no extra normalization: the probe always targets this host, so
# tool_versions is byte-identical (see docs/gates/golden-v3.md).
#
# Exit 0 = GREEN, exit 1 = divergence, exit 0 with SKIP when docker or the
# images are unavailable (the suite is opt-in infrastructure).
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

WORK="$ROOT/.scratch/p2-docker"
IMG="${WEBV2_DOCKER_IMAGE:-foundry-solc-0824:latest}"
ANVIL_NAME="p2-docker-anvil"
PORT="${P2_DOCKER_ANVIL_PORT:-8545}"
SEED="p2-docker"
GOBIN="$WORK/webv2"
TGT_ADDR="0x0000000000000000000000000000000000001234"
# deployedBytecode of src/Box.sol (below) compiled with solc 0.8.24 in
# foundry-solc-0824:latest; installed with anvil_setCode so the sequence
# needs no deploy transaction (and therefore no deployer nonce in the
# determinism budget). Source:
#   contract Box { uint256 public v;
#       function set(uint256 x) external { v = x; }
#       function get() external view returns (uint256) { return v; } }
BOX_RUNTIME="0x608060405234801561000f575f80fd5b506004361061003f575f3560e01c806360fe47b1146100435780636d4ce63c1461005f5780637c2efcba1461007d575b5f80fd5b61005d600480360381019061005891906100e8565b61009b565b005b6100676100a4565b6040516100749190610122565b60405180910390f35b6100856100ac565b6040516100929190610122565b60405180910390f35b805f8190555050565b5f8054905090565b5f5481565b5f80fd5b5f819050919050565b6100c7816100b5565b81146100d1575f80fd5b50565b5f813590506100e2816100be565b92915050565b5f602082840312156100fd576100fc6100b1565b5b5f61010a848285016100d4565b91505092915050565b61011c816100b5565b82525050565b5f6020820190506101355f830184610113565b9291505056fea2646970667358221220078b2af93b6ad99e9ed04e78d913e4fe012248b16b328dfc2c697cd7426a29f064736f6c63430008180033"

log()  { printf '[p2-docker] %s\n' "$*"; }
fail() { printf '[p2-docker] FAIL: %s\n' "$*" >&2; exit 1; }
skip() { printf '[p2-docker] SKIP: %s\n' "$*"; exit 0; }

# --- preflight ------------------------------------------------------------
command -v docker >/dev/null 2>&1 || skip "docker not on PATH"
docker info >/dev/null 2>&1 || skip "docker daemon not reachable"
docker image inspect "$IMG" >/dev/null 2>&1 || skip "image $IMG not present"

rm -rf "$WORK"
mkdir -p "$WORK/captures/py" "$WORK/captures/go" "$WORK/shared-memory"

log "building the Go binary"
GOCACHE="$ROOT/.scratch/gocache" GOPATH="$ROOT/.scratch/gopath" \
GOMODCACHE="$ROOT/.scratch/gomodcache" GOFLAGS=-mod=mod \
  go build -o "$GOBIN" ./cmd/webv2 || fail "go build failed"

# --- shared target (OUTSIDE the repo: a git target would pin a worktree
# whose .git file embeds a per-process gitdir) ------------------------------
TARGET="$(mktemp -d "${TMPDIR:-/tmp}/p2-docker-target-XXXXXX")"
cleanup() {
  docker rm -f "$ANVIL_NAME" >/dev/null 2>&1
  rm -rf "$TARGET"
}
trap cleanup EXIT
mkdir -p "$TARGET/src" "$TARGET/docs"
cat > "$TARGET/foundry.toml" <<'EOF'
[profile.default]
solc = "0.8.24"
EOF
cat > "$TARGET/src/Vault.sol" <<'EOF'
// P2 docker e2e vault
contract Vault { uint256 public total; }
EOF
cat > "$TARGET/docs/INVARIANTS.md" <<'EOF'
# P2 docker e2e invariants

INV-1: only the admin role may withdraw assets from the vault.
INV-2: the total assets must always cover the sum of all user claims.
EOF

# --- deterministic container fixtures -------------------------------------
# A tar of the fixture (pinned mtime/owner/order) base64'd into the command
# line: the CLI never pipes stdin into `docker run`, and the DSH file
# sandbox makes host temp dirs invisible to the daemon, so the fixture
# travels in the command string itself.
fixture_b64() {  # $1 = source dir
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
      -cf - -C "$1" . | base64 -w0
}

FX="$WORK/fixture"; FXF="$WORK/fixture-fail"
mkdir -p "$FX" "$FXF"
cp -r internal/reproduction/testdata/foundry-mini/. "$FX/"
cp -r internal/reproduction/testdata/foundry-mini/. "$FXF/"
# the failing variant flips the assertion the passing test makes
sed -i 's/t.two() == 2/t.two() == 3/; s/two() must be 2/two() must be 3/' \
    "$FXF/test/Tiny.t.sol"

B64_PASS="$(fixture_b64 "$FX")"
B64_FAIL="$(fixture_b64 "$FXF")"

# forge prints its own wall-clock timings; the sed filter is the documented
# normalization (see the header) and runs INSIDE the container, so the
# filtered text is what the exec record hashes.
FILTER='sed -E -e "s/ *finished in.*$//" -e "s/ in [0-9.]+m?s \([^)]*CPU time\):/:/"'
forge_cmd() {  # $1 = fixture b64
  printf 'mkdir -p /tmp/w && echo %s | base64 -d | tar -x -C /tmp/w && ' \
      "$1"
  printf 'cd /tmp/w && out=$(forge test 2>&1); rc=$?; '
  printf 'printf "%%s\\n" "$out" | %s; exit $rc' "$FILTER"
}
CMD_PASS="$(forge_cmd "$B64_PASS")"
CMD_FAIL="$(forge_cmd "$B64_FAIL")"

# --- anvil fork endpoint --------------------------------------------------
# anvil runs in its OWN container: the host's 8545 is unreachable from the
# bridge on this box (host-gateway resolves, the port does not answer), but
# container-to-container traffic on the default bridge does. The leg gets
# a FRESH container: `anvil_reset` does NOT restore a byte-identical first
# transaction (its base-fee state carries over from the pre-reset chain —
# measured 2026-09-09), while a fresh container starts from the same
# genesis, so the same unlocked account signs the same nonce-0 transaction
# with the same gas parameters. The container IP varies run to run but is
# never recorded (the exec record stores env KEYS, not the URL).
start_anvil() {
  docker rm -f "$ANVIL_NAME" >/dev/null 2>&1
  log "starting a fresh anvil container ($IMG)"
  docker run -d --name "$ANVIL_NAME" --entrypoint anvil "$IMG" \
      --host 0.0.0.0 --port "$PORT" >/dev/null \
      || fail "anvil container start failed"
  RPC_IP="$(docker inspect -f \
      '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
      "$ANVIL_NAME")"
  [ -n "$RPC_IP" ] || fail "cannot read the anvil container IP"
  RPC="http://$RPC_IP:$PORT"
  for _ in $(seq 1 30); do
    if docker run --rm --entrypoint cast "$IMG" rpc --rpc-url "$RPC" \
         eth_chainId >/dev/null 2>&1; then break; fi
    sleep 1
  done
  docker run --rm --entrypoint cast "$IMG" rpc --rpc-url "$RPC" eth_chainId \
      >/dev/null 2>&1 || fail "anvil never became ready at $RPC"
  # install the Box runtime code (no deploy tx, no deployer nonce)
  docker run --rm --entrypoint /bin/sh "$IMG" -c \
      "cast rpc --rpc-url $RPC anvil_setCode $TGT_ADDR $BOX_RUNTIME \
         >/dev/null" >/dev/null 2>&1 || fail "anvil_setCode failed"
  log "anvil ready at $RPC"
}
RPC=""

# --- the run ---------------------------------------------------------
NOW_EPOCH=1788900000
run_cli() {  # run_cli <step> <name> <argv...>
  local step="$1" name="$2"; shift 2
  local base now rc
  base="$WORK/captures/go/$(printf '%02d' "$step")-$name"
  now="$(date -u -d "@$((NOW_EPOCH + step))" \
      +'%Y-%m-%dT%H:%M:%S.000000+00:00')"
  env WEBV2_NOW="$now" WEBV2_UUID="$SEED:$step" WEBV2_FINDING_IDS=pin \
      WEBV2_FINDING_ID_SEQ=0 WEBV2_GLOBAL_MEMORY_DIR="$WORK/shared-memory" \
      WEBV2_DOCKER_IMAGE="$IMG" FORK_RPC_URL="$RPC" \
      "$GOBIN" --root "$WORK/go" "$@" >"$base.out" 2>"$base.err"
  rc=$?
  printf '%s' "$rc" >"$base.exit"
  printf '%s' "$base"
}

first_id() {  # first_id <file> <ERE>
  grep -oE "$2" "$1" | head -n1
}

run_campaign() {
  local root="$WORK/go"
  mkdir -p "$root"
  log "--- go campaign ---"

  # deterministic genesis: a fresh anvil container (see the start_anvil
  # comment on why anvil_reset is not enough)
  start_anvil

  local b cid fid ex_pass ex_fail
  b="$(run_cli 0 init init --program P2Docker)"
  cid="$(first_id "$b.out" 'C-[0-9a-f]+')"
  [ -n "$cid" ] || fail "init minted no campaign id"
  log "go campaign $cid"

  # NOTE: `snap --chain/--deployment` is NOT used here. The Go CLI parses
  # those flags and drops the fork pin (docs/archive/KNOWN_DIVERGENCES.md
  # D19), so sequence_coverage stays VACUOUS (required=0) — the final
  # assertion pins that, and a future chain-pin wiring must flip it.
  b="$(run_cli 1 snap snap "$cid" "$TARGET")"
  b="$(run_cli 2 ingest ingest "$cid" --json-file \
      "scripts/golden/h1-withdraw-double-count.json" \
      --stage docker-e2e --trajectory code)"
  fid="$(first_id "$b.out" 'F-[0-9a-f]+')"
  [ -n "$fid" ] || fail "ingest minted no finding id"
  log "go finding $fid"

  # (a) exec / classify / mint — real containerized forge runs
  b="$(run_cli 3 exec-pass exec "$cid" --command "$CMD_PASS" \
      --profile docker-networkless --finding "$fid")"
  ex_pass="$(first_id "$b.out" 'EXEC-[0-9a-f]+')"
  [ -n "$ex_pass" ] || fail "exec-pass minted no exec id"

  b="$(run_cli 4 exec-fail exec "$cid" --command "$CMD_FAIL" \
      --profile docker-networkless --finding "$fid")"
  ex_fail="$(first_id "$b.out" 'EXEC-[0-9a-f]+')"
  [ -n "$ex_fail" ] || fail "exec-fail minted no exec id"

  b="$(run_cli 5 execs-json execs "$cid" --json)"
  b="$(run_cli 6 classify classify "$cid" "$ex_fail")"
  b="$(run_cli 7 mint mint "$cid" "$fid" --exec "$ex_pass" \
      --description "containerized forge test proves the two() invariant" \
      --tier T2 --type foundry-test)"

  # (b) sequence run/verify — the generated POSIX-sh driver under
  # fork-runner against the anvil container
  cat > "$WORK/spec.json" <<SPECEOF
{"actors": {"attacker": "anvil:0"},
 "final_assertions": [{"function": "get()", "id": "A1", "kind": "call",
                       "op": "==", "target": "$TGT_ADDR", "value": "9"}],
 "finding_id": "$fid",
 "spec_id": "SEQ-P2D-01",
 "steps": [{"actor": "attacker", "args": ["7"], "expect_revert": false,
            "function": "set(uint256)", "step": 1, "target": "$TGT_ADDR"},
           {"actor": "attacker", "args": ["9"], "expect_revert": false,
            "function": "set(uint256)", "mine_blocks": 1, "step": 2,
            "target": "$TGT_ADDR"}]}
SPECEOF
  b="$(run_cli 8 sequence-run sequence run "$cid" "$WORK/spec.json" \
      --finding "$fid")"
  b="$(run_cli 9 sequence-verify sequence verify "$cid" "$fid")"
  b="$(run_cli 10 audit-json audit "$cid" --json)"
  b="$(run_cli 11 verify verify "$cid")"
  log "go campaign done"
}

run_campaign

# --- assertions -----------------------------------------------------------
log "asserting the campaign tree and every CLI capture"
python3 - "$WORK" <<'PYEOF'
import json, re, sys
from pathlib import Path

work = Path(sys.argv[1])
fails = []

# 1. every captured CLI invocation must exit 0 (documented behavior)
caps = sorted(pp.name[:-5] for pp in (work / "captures" / "go").glob("*.exit"))
if len(caps) != 12:
    fails.append(f"{len(caps)} captures, want 12")
for stem in caps:
    rc = (work / "captures" / "go" / f"{stem}.exit").read_text().strip()
    if rc != "0":
        tailtxt = (work / "captures" / "go" / f"{stem}.err").read_text()[-2000:]
        fails.append(f"capture {stem} exited {rc}: {tailtxt}")

# 2. the exec ledger: two REAL container runs, one pass + one exit-1
ledger = json.loads((work / "captures" / "go" / "05-execs-json.out").read_text())
statuses = sorted(int(r["exit_status"]) for r in ledger)
if statuses != [0, 1]:
    fails.append(f"exec exit statuses {statuses}, want [0, 1] (forge pass+fail)")
if not all(r["profile"] == "docker-networkless" for r in ledger):
    fails.append("an exec did not run under docker-networkless")
if not all(isinstance(r.get("container"), dict) and r["container"] for r in ledger):
    fails.append("an exec record carries no container block (not a real run?)")

# 3. the staged sequence_result.json: exactly one, and it passed
hits = [pp for pp in (work / "go").rglob("sequence_result.json")
        if "/EXEC-" in pp.as_posix()]
if len(hits) != 1:
    fails.append(f"expected 1 staged sequence_result.json, got {len(hits)}")
else:
    d = json.loads(hits[0].read_text())
    if d.get("overall") != "pass":
        fails.append(f"sequence overall={d.get('overall')!r}, want pass")
    if len(d.get("steps", [])) != 2:
        fails.append(f"{len(d.get('steps', []))} steps, want 2")
    for a in d.get("final_assertions", []):
        if not a.get("passed"):
            fails.append(f"assertion {a.get('id')} did not pass")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(d.get("spec_hash"))):
        fails.append(f"bad spec_hash {d.get('spec_hash')!r}")

# 4. the audit: ok + all 14 sections + the VACUOUS sequence_coverage pin
#    (no fork pin is attachable through the Go CLI, D19; a future chain-pin
#    wiring must FLIP this assertion, not delete it)
rep = json.loads((work / "captures" / "go" / "10-audit-json.out").read_text())
if rep.get("ok") is not True:
    fails.append(f"audit ok={rep.get('ok')!r}, want true")
secs = rep.get("sections") or {}
if len(secs) != 14:
    fails.append(f"{len(secs)} audit sections, want 14")
sec = secs.get("sequence_coverage")
if sec is None:
    fails.append("audit report has no sequence_coverage section")
elif not sec.get("ok"):
    fails.append(f"sequence_coverage problems {sec.get('problems')}")
elif sec.get("required", 0) != 0 or sec.get("covered", 0) != 0:
    fails.append(f"sequence_coverage required={sec.get('required')} "
                 f"covered={sec.get('covered')} — chain-pin wiring landed: "
                 f"update this assertion to demand required>0 covered>0")

# 5. the event chain: verify --json says ok
v = json.loads((work / "captures" / "go" / "11-verify.out").read_text())
if v.get("ok") is not True:
    fails.append(f"event-log verify ok={v.get('ok')!r}, want true")

# 6. campaign tree shape
groot = work / "go"
cdirs = list((groot / "campaigns").glob("C-*"))
if len(cdirs) != 1:
    fails.append(f"{len(cdirs)} campaign dirs, want 1")
else:
    c = cdirs[0]
    if len(list((c / "findings").glob("F-*.json"))) != 1:
        fails.append("findings dir lacks exactly 1 F-*.json")
    # (a) contributes two exec records; `sequence run` records its driver
    # exec too — require at least the three
    if len([d for d in (c / "execs").iterdir() if d.is_dir()]) < 3:
        fails.append("execs dir lacks pass+fail+sequence-driver records")
    if not (c / "campaign_state.json").is_file():
        fails.append("no campaign_state.json")

if fails:
    print("P2 DOCKER E2E RED:")
    for f in fails:
        print(f"  - {f}")
    sys.exit(1)
nfiles = sum(1 for pp in (work / "go").rglob("*") if pp.is_file())
print(f"P2 DOCKER E2E GREEN: {len(caps)} commands, {nfiles} tree files, "
      "real docker exec (pass+fail) + real anvil sequence, all assertions hold")
PYEOF
rc=$?
if [ "$rc" -ne 0 ]; then exit 1; fi
log "done"

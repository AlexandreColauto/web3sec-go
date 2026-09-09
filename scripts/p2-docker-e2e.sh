#!/usr/bin/env bash
# P2 cross-twin DOCKER e2e (Task 24, deliverable 3).
#
# The golden suite (scripts/golden.sh) is deliberately docker-FREE: its E4
# exec records are harness-seeded. This script closes that gap by running
# the SAME P2 command sequence through BOTH twins against a REAL docker
# daemon and a REAL anvil fork endpoint, then byte-diffing the resulting
# campaign trees:
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
#   * clock        WEBV2_NOW (base + step seconds, identical for both twins)
#   * id stream    WEBV2_UUID=<seed>:<step> per command, so EXEC-/ATT-/EV-
#                  ids cannot collide across the two `exec` invocations
#                  (each CLI process restarts its new_id counter at 0)
#   * finding ids  WEBV2_FINDING_IDS=pin (+ WEBV2_FINDING_ID_SEQ)
#   * chain state  anvil_reset + anvil_setCode before EACH twin, so both
#                  runs start from the same genesis: the two `cast send`
#                  transactions are signed by the same anvil account at the
#                  same nonces, hence have the same tx hashes
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
# needs no extra normalization: both twins probe the SAME host, so
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
PY_ROOT="$ROOT/../web3sec-final"
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

log "building the Go twin"
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
# container-to-container traffic on the default bridge does. Each twin gets
# a FRESH container: `anvil_reset` does NOT restore a byte-identical first
# transaction (its base-fee state carries over from the pre-reset chain —
# measured 2026-09-09), while a fresh container starts from the same
# genesis, so the same unlocked account signs the same nonce-0 transaction
# with the same gas parameters. The container IP differs per twin but is
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

# --- per-twin run ---------------------------------------------------------
NOW_EPOCH=1788900000
run_cli() {  # run_cli <twin> <step> <name> <argv...>
  local twin="$1" step="$2" name="$3"; shift 3
  local base now rc
  base="$WORK/captures/$twin/$(printf '%02d' "$step")-$name"
  now="$(date -u -d "@$((NOW_EPOCH + step))" \
      +'%Y-%m-%dT%H:%M:%S.000000+00:00')"
  if [ "$twin" = py ]; then
    env WEBV2_NOW="$now" WEBV2_UUID="$SEED:$step" WEBV2_FINDING_IDS=pin \
        WEBV2_FINDING_ID_SEQ=0 WEBV2_GLOBAL_MEMORY_DIR="$WORK/shared-memory" \
        WEBV2_DOCKER_IMAGE="$IMG" FORK_RPC_URL="$RPC" \
        PYTHONPATH="$ROOT/scripts/golden:$PY_ROOT/src" \
        python3 -m webv2.cli --root "$WORK/py" "$@" \
        >"$base.out" 2>"$base.err"
  else
    env WEBV2_NOW="$now" WEBV2_UUID="$SEED:$step" WEBV2_FINDING_IDS=pin \
        WEBV2_FINDING_ID_SEQ=0 WEBV2_GLOBAL_MEMORY_DIR="$WORK/shared-memory" \
        WEBV2_DOCKER_IMAGE="$IMG" FORK_RPC_URL="$RPC" \
        "$GOBIN" --root "$WORK/go" "$@" >"$base.out" 2>"$base.err"
  fi
  rc=$?
  printf '%s' "$rc" >"$base.exit"
  printf '%s' "$base"
}

first_id() {  # first_id <file> <ERE>
  grep -oE "$2" "$1" | head -n1
}

run_twin() {
  local twin="$1"
  local root="$WORK/$twin"
  mkdir -p "$root"
  log "--- twin $twin ---"

  # identical genesis for both twins: a fresh anvil container (see the
  # start_anvil comment on why anvil_reset is not enough)
  start_anvil

  local b cid fid ex_pass ex_fail
  b="$(run_cli "$twin" 0 init init --program P2Docker)"
  cid="$(first_id "$b.out" 'C-[0-9a-f]+')"
  [ -n "$cid" ] || fail "$twin: init minted no campaign id"
  log "$twin campaign $cid"

  # NOTE: `snap --chain/--deployment` is NOT used here. The Python CLI
  # attaches a fork pin; the Go CLI parses the flags and drops them
  # (KNOWN_DIVERGENCES D19), so a chain pin would diverge the trees. The
  # consequence is that sequence_coverage is compared but VACUOUS
  # (required=0) — see docs/gates/P2-gate.md.
  b="$(run_cli "$twin" 1 snap snap "$cid" "$TARGET")"
  b="$(run_cli "$twin" 2 ingest ingest "$cid" --json-file \
      "scripts/golden/h1-withdraw-double-count.json" \
      --stage docker-e2e --trajectory code)"
  fid="$(first_id "$b.out" 'F-[0-9a-f]+')"
  [ -n "$fid" ] || fail "$twin: ingest minted no finding id"
  log "$twin finding $fid"

  # (a) exec / classify / mint — real containerized forge runs
  b="$(run_cli "$twin" 3 exec-pass exec "$cid" --command "$CMD_PASS" \
      --profile docker-networkless --finding "$fid")"
  ex_pass="$(first_id "$b.out" 'EXEC-[0-9a-f]+')"
  [ -n "$ex_pass" ] || fail "$twin: exec-pass minted no exec id"

  b="$(run_cli "$twin" 4 exec-fail exec "$cid" --command "$CMD_FAIL" \
      --profile docker-networkless --finding "$fid")"
  ex_fail="$(first_id "$b.out" 'EXEC-[0-9a-f]+')"
  [ -n "$ex_fail" ] || fail "$twin: exec-fail minted no exec id"

  b="$(run_cli "$twin" 5 execs-json execs "$cid" --json)"
  b="$(run_cli "$twin" 6 classify classify "$cid" "$ex_fail")"
  b="$(run_cli "$twin" 7 mint mint "$cid" "$fid" --exec "$ex_pass" \
      --description "containerized forge test proves the two() invariant" \
      --tier T2 --type foundry-test)"

  # (b) sequence run/verify — the generated POSIX-sh driver under
  # fork-runner against the anvil container
  cat > "$WORK/spec.json" <<EOF
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
EOF
  b="$(run_cli "$twin" 8 sequence-run sequence run "$cid" "$WORK/spec.json" \
      --finding "$fid")"
  b="$(run_cli "$twin" 9 sequence-verify sequence verify "$cid" "$fid")"
  b="$(run_cli "$twin" 10 audit-json audit "$cid" --json)"
  log "$twin done"
}

run_twin py
run_twin go

# --- comparison -----------------------------------------------------------
log "comparing the two twin trees"
python3 - "$WORK" "$TARGET" <<'PY'
import json, re, sys
from pathlib import Path

work, target = Path(sys.argv[1]), Path(sys.argv[2])
fails = []

# environment_hash (and the manifest_hash derived from it) hashes the
# RUNTIME — python X vs the Go binary — so it can never match across twins
# (KNOWN_DIVERGENCES D3). Normalize by VALUE, discovered from each twin's
# own snapshot manifests, exactly like scripts/check-golden.py does.
def env_hashes(root: Path) -> list[str]:
    vals = []
    for p in root.rglob("snapshot.json"):
        try:
            doc = json.loads(p.read_text())
        except Exception:                                   # noqa: BLE001
            continue
        man = doc.get("manifest") or {}
        for key in ("environment_hash", "manifest_hash"):
            if man.get(key):
                vals.append(man[key])
    return vals


def norm(text: str, root: str) -> str:
    text = text.replace(root, "<ROOT>")
    for val in env_hashes(Path(root)):
        text = text.replace(val, "<ENVHASH>")
    text = re.sub(r'"environment_hash": "[0-9a-f]+"',
                  '"environment_hash": "<ENVHASH>"', text)
    # the sequence driver stamps `date -u` from inside the container; that
    # single field cannot be pinned from outside (see the script header)
    text = re.sub(r'"generated_at": "[^"]*"',
                  '"generated_at": "<GENAT>"', text)
    return text


# 1. captured CLI stdout/stderr/exit, step by step
caps = sorted(p.name[:-4] for p in (work / "captures" / "py").glob("*.out"))
if not caps:
    fails.append("no captures were produced")
for stem in caps:
    for ext in ("out", "err", "exit"):
        a = (work / "captures" / "py" / f"{stem}.{ext}").read_text()
        b = (work / "captures" / "go" / f"{stem}.{ext}").read_text()
        if norm(a, str(work / "py")) != norm(b, str(work / "go")):
            fails.append(f"capture {stem}.{ext} differs\n"
                         f"--- py ---\n{a[:2000]}\n--- go ---\n{b[:2000]}")

# 2. every file of the campaign tree, byte-for-byte after normalization
py_root, go_root = work / "py", work / "go"
for p in sorted(py_root.rglob("*")):
    if not p.is_file():
        continue
    rel = p.relative_to(py_root)
    q = go_root / rel
    if not q.is_file():
        fails.append(f"missing in go tree: {rel}")
        continue
    a, b = p.read_text(errors="replace"), q.read_text(errors="replace")
    if norm(a, str(py_root)) != norm(b, str(go_root)):
        fails.append(f"tree file differs: {rel}")
for q in sorted(go_root.rglob("*")):
    if q.is_file() and not (py_root / q.relative_to(go_root)).is_file():
        fails.append(f"extra in go tree: {q.relative_to(go_root)}")

# 3. the sequence result itself: spec_hash + overall, on BOTH twins. The
# staged copy lives in the exec output dir; the workdir keeps a second one.
for twin in ("py", "go"):
    hits = [p for p in (work / twin).rglob("sequence_result.json")
            if "/EXEC-" in p.as_posix()]
    if len(hits) != 1:
        fails.append(f"{twin}: expected 1 staged sequence_result.json, "
                     f"got {len(hits)}")
        continue
    d = json.loads(hits[0].read_text())
    if d.get("overall") != "pass":
        fails.append(f"{twin}: sequence overall={d.get('overall')!r}, want pass")
    if len(d.get("steps", [])) != 2:
        fails.append(f"{twin}: {len(d.get('steps', []))} steps, want 2")
    for a in d.get("final_assertions", []):
        if not a.get("passed"):
            fails.append(f"{twin}: assertion {a.get('id')} did not pass")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(d.get("spec_hash"))):
        fails.append(f"{twin}: bad spec_hash {d.get('spec_hash')!r}")

# 4. the audit's sequence_coverage section must be present and identical
for twin in ("py", "go"):
    hit = work / "captures" / twin / "10-audit-json.out"
    try:
        rep = json.loads(hit.read_text())
    except Exception as e:                                  # noqa: BLE001
        fails.append(f"{twin}: audit --json unreadable: {e}")
        continue
    sec = (rep.get("sections") or {}).get("sequence_coverage")
    if sec is None:
        fails.append(f"{twin}: audit report has no sequence_coverage section")
    elif not sec.get("ok"):
        fails.append(f"{twin}: sequence_coverage problems {sec.get('problems')}")
    elif sec.get("required", 0) != 0 or sec.get("covered", 0) != 0:
        # no fork pin is attachable through the Go CLI (D19), so the
        # finding cannot be coverage-required: both twins must agree on the
        # vacuous verdict, and a future chain-pin wiring flips this check
        fails.append(f"{twin}: sequence_coverage required="
                     f"{sec.get('required')} covered={sec.get('covered')}")

if fails:
    print("P2 DOCKER E2E RED — divergences:")
    for f in fails:
        print(f"  - {f}")
    sys.exit(1)
print(f"P2 DOCKER E2E GREEN: {len(caps)} commands x 2 twins, "
      f"{sum(1 for p in py_root.rglob('*') if p.is_file())} tree files, "
      "real docker exec + real anvil sequence, byte-identical")
PY
rc=$?
if [ "$rc" -ne 0 ]; then exit 1; fi
log "done"

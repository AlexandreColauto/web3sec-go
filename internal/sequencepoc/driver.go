package sequencepoc

import (
	"fmt"
	"regexp"
	"strings"

	"websec/internal/validation"
)

// shHelpers is _SH_HELPERS, transcribed verbatim: the POSIX-sh helpers
// embedded in every generated command. NOTE the deliberate avoidance of
// shell arithmetic on VALUE data — storage slots and wei balances are up to
// 256 bits, far beyond any sh integer. dec_cmp is length + lexicographic
// (LC_ALL=C); hex2dec builds decimal strings digit-wise.
const shHelpers = `
add_step() {
  if [ -z "$STEPS" ]; then printf '%s' "$1"; else printf '%s,%s' "$STEPS" "$1"; fi
}
add_assert() {
  if [ -z "$ASSERTS" ]; then printf '%s' "$1"; else printf '%s,%s' "$ASSERTS" "$1"; fi
}
emit_result() {
  printf '{"spec_hash": "%s", "steps": [%s], "final_assertions": [%s], "overall": "%s", "generated_at": "%s"}\n' \
    "$SPEC_HASH" "$STEPS" "$ASSERTS" "$1" "$GENAT" > "$WD/sequence_result.json"
}
dec_mul16_add() {
  s=$1; d=$2; out=""; carry=$d; i=${#s}
  while [ "$i" -gt 0 ]; do
    i=$((i - 1))
    c=$(expr substr "$s" $((i + 1)) 1)
    prod=$((c * 16 + carry))
    out=$(printf '%d%s' "$((prod % 10))" "$out")
    carry=$((prod / 10))
  done
  while [ "$carry" -gt 0 ]; do
    out=$(printf '%d%s' "$((carry % 10))" "$out")
    carry=$((carry / 10))
  done
  [ -z "$out" ] && out=0
  printf '%s' "$out"
}
hex2dec() {
  h=${1#0x}; d=0; i=1
  while [ "$i" -le "${#h}" ]; do
    c=$(expr substr "$h" "$i" 1)
    case $c in
      [0-9]) n=$c ;;
      a|A) n=10 ;; b|B) n=11 ;; c|C) n=12 ;; d|D) n=13 ;; e|E) n=14 ;; f|F) n=15 ;;
      *) return 1 ;;
    esac
    d=$(dec_mul16_add "$d" "$n") || return 1
    i=$((i + 1))
  done
  printf '%s' "$d"
}
dec_cmp() {
  a=$1; b=$2
  while [ "${a#0}" != "$a" ]; do a=${a#0}; done
  while [ "${b#0}" != "$b" ]; do b=${b#0}; done
  [ -z "$a" ] && a=0
  [ -z "$b" ] && b=0
  if [ "${#a}" -lt "${#b}" ]; then echo -1; return; fi
  if [ "${#a}" -gt "${#b}" ]; then echo 1; return; fi
  if [ "$a" = "$b" ]; then echo 0; return; fi
  if [ "$a" \< "$b" ]; then echo -1; else echo 1; fi
}
anvil_addr() {
  n=$1
  while [ "${n#0}" != "$n" ]; do
    n=${n#0}
    [ -z "$n" ] && { n=0; break; }
  done
  [ -z "$n" ] && n=0
  printf '%s\n' "$UNLOCKED" | sed -n "$((n + 1))p"
}
sanitize_reason() {
  head -n1 "$WD/seq_err.txt" | tr '"\\' '  ' | cut -c1-200
}
sanitize_field() {
  printf '%s\n' "$1" | head -n1 | tr '"\\' '  ' | cut -c1-200
}
`

// shlexUnsafe is shlex._find_unsafe (re.ASCII): a character outside
// [a-zA-Z0-9_@%+=:,./-] needs quoting.
var shlexUnsafe = regexp.MustCompile(`[^A-Za-z0-9_@%+=:,./-]`)

// shlexQuote is shlex.quote: the bare string when every character is safe,
// else single quotes with the classic '\” escape.
func shlexQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !shlexUnsafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// checkAnvilIndex is _check_anvil_index: defense in depth — build_command
// never embeds raw indices. Digits only (leading zeros allowed — anvil_addr
// strips them so the shell never hits the $((08)) octal trap).
func checkAnvilIndex(n string) error {
	if !anvilIndexRe.MatchString(n) {
		return specErrf("sequence spec field 'actors': anvil index %s must "+
			"be decimal digits", validation.PyReprStr(n))
	}
	return nil
}

// shellJSON is _shell_json: a shell double-quoted string from a JSON
// template — inner quotes escaped, `$var` references left to expand at run
// time.
func shellJSON(tmpl string) string {
	return `"` + strings.ReplaceAll(tmpl, `"`, `\"`) + `"`
}

// actorFragments is _actor_fragments: (setup_lines, flag_string) for one
// actor. anvil:N roles resolve to their address at run time via
// eth_accounts (mnemonic-independent); 0x actors require the operator's key
// in env as FORK_KEY_<ROLE> (upper).
func actorFragments(spec validation.Value, role string) ([]string, string,
	error) {
	if !roleKeyRe.MatchString(role) {
		return nil, "", specErrf("sequence spec field 'actors': role key %s "+
			"is not a shell-safe identifier", validation.PyReprStr(role))
	}
	addr := validation.ObjStr(validation.ObjAt(spec, "actors"), role)
	if strings.HasPrefix(addr, "anvil:") {
		n := strings.SplitN(addr, ":", 2)[1]
		if err := checkAnvilIndex(n); err != nil {
			return nil, "", err
		}
		v := "A_" + role
		setup := []string{
			fmt.Sprintf("%s=$(anvil_addr %s) || "+
				`{ echo "seq: cannot resolve anvil:%s" >&2; exit 1; }`,
				v, n, n),
			fmt.Sprintf(`[ -n "${%s}" ] || `+
				`{ echo "seq: empty address for anvil:%s" >&2; exit 1; }`,
				v, n),
		}
		return setup, fmt.Sprintf(`--from "${%s}" --unlocked`, v), nil
	}
	// ${VAR:-} (not $VAR): the driver runs under `set -u`, so a missing
	// operator key must degrade to an empty arg that cast rejects with a
	// recorded reason — not an unbound-variable abort before cast runs.
	return nil, fmt.Sprintf(`--private-key "${FORK_KEY_%s:-}"`,
		strings.ToUpper(role)), nil
}

// resolveAddr is _resolve_addr: a shell fragment resolving an account
// reference at run time.
func resolveAddr(spec validation.Value, ref string) (string, error) {
	actors := validation.ObjAt(spec, "actors")
	if hasObjKey(actors, ref) {
		val := validation.ObjStr(actors, ref)
		if strings.HasPrefix(val, "anvil:") {
			n := strings.SplitN(val, ":", 2)[1]
			if err := checkAnvilIndex(n); err != nil {
				return "", err
			}
			return "$(anvil_addr " + n + ")", nil
		}
		return shlexQuote(val), nil
	}
	return shlexQuote(ref), nil
}

// hasObjKey is Python's `key in dict`.
func hasObjKey(v validation.Value, key string) bool {
	for _, kv := range v.O {
		if kv.K == key {
			return true
		}
	}
	return false
}

// BuildCommand is build_command: the full POSIX-sh driver for a validated
// spec. PURE in the spec — replayable from the EXEC ledger's recorded
// command string. A step's optional `value` (wei, decimal or 0x-hex)
// becomes `cast send --value <literal>`; a step without the key emits no
// flag, so the pre-value driver text is unchanged (see valueFragment).
func BuildCommand(spec validation.Value, workdir string) (string, error) {
	wd := strings.TrimRight(workdir, "/")
	if wd == "" {
		wd = "/"
	}
	parts := []string{
		"set -u",
		"LC_ALL=C",
		"WD=" + shlexQuote(wd),
		`cd "$WD" || exit 1`,
		"rm -f seq_err.txt sequence_result.json .sent_once",
		shHelpers,
		"SPEC_HASH=" + shlexQuote(SpecHash(spec)),
		"GENAT=$(date -u +%Y-%m-%dT%H:%M:%SZ)",
		`STEPS=""; ASSERTS=""; ASSERTFAIL=0; STEPFAIL=0`,
		// one address per line — anvil_addr selects by line number
		`UNLOCKED=$(cast rpc --rpc-url "$FORK_RPC_URL" eth_accounts ` +
			`2>/dev/null | grep -o '0x[0-9a-fA-F]\{40\}')`,
	}
	steps := listOf(validation.ObjAt(spec, "steps"))
	for _, s := range steps {
		lines, err := buildStep(spec, s)
		if err != nil {
			return "", err
		}
		parts = append(parts, lines...)
	}
	for _, a := range listOf(validation.ObjAt(spec, "final_assertions")) {
		lines, err := buildAssertion(spec, a)
		if err != nil {
			return "", err
		}
		parts = append(parts, lines...)
	}
	parts = append(parts,
		`if [ "$STEPFAIL" = "0" ] && [ "$ASSERTFAIL" = "0" ]; then `+
			`OVERALL=pass; else OVERALL=fail; fi`,
		`emit_result "$OVERALL"`,
		// C1 (final pass 1+2): the pass path must print to stdout. Every
		// cast invocation is captured in $(...) and only failure branches
		// echo to stderr, so a passing run was byte-silent — and
		// mint_repro_evidence refuses exit-0 execs with EMPTY captured
		// output, making E5 unmintable on the happy path.
		`if [ "$OVERALL" = "pass" ]; then `+
			fmt.Sprintf(`echo "seq: PASS spec=$SPEC_HASH steps=%d `+
				`overall=pass"; exit 0; else `, len(steps))+
			`echo "seq: overall fail (stepfail=$STEPFAIL `+
			`assertfail=$ASSERTFAIL)" >&2; exit 1; fi`,
	)
	return strings.Join(parts, "\n"), nil
}

// buildStep is build_command's per-step block (mine_blocks, actor setup,
// cast send, result fragment).
func buildStep(spec, s validation.Value) ([]string, error) {
	n := intOf(validation.ObjAt(s, "step"))
	var out []string
	if mine := intOf(validation.ObjAt(s, "mine_blocks")); mine > 0 {
		// anvil reads evm_mine's param as a timestamp, not a block count —
		// block advancement is `anvil_mine <decimal N>`.
		out = append(out, fmt.Sprintf(
			`cast rpc --rpc-url "$FORK_RPC_URL" anvil_mine %d `+
				`>/dev/null 2>&1 || { echo "seq: anvil_mine before step `+
				`%d failed" >&2; exit 1; }`, mine, n))
	}
	setup, flag, err := actorFragments(spec, validation.ObjStr(s, "actor"))
	if err != nil {
		return nil, err
	}
	out = append(out, setup...)
	args := joinArgs(validation.ObjAt(s, "args"))
	send := `out=$(cast send --rpc-url "$FORK_RPC_URL" ` +
		shlexQuote(validation.ObjStr(s, "target")) + " " +
		shlexQuote(validation.ObjStr(s, "function")) + args + valueFragment(s) + " " +
		flag + ` 2>"$WD/seq_err.txt")`
	out = append(out, send, "rc=$?")
	// s["actor"] is a shell-safe identifier (the field rule above), so it
	// is safe to embed verbatim in the JSON template.
	role := validation.CanonCompact(validation.ObjAt(s, "actor"))
	if validation.PyTruthy(validation.ObjAt(s, "expect_revert")) {
		j := `{"step": ` + validation.IntText(validation.ObjAt(s, "step")) +
			`, "actor": ` + role + `, "tx_hash": null, "status": "revert",` +
			` "revert_reason": "$reason"}`
		out = append(out,
			fmt.Sprintf(`if [ $rc -eq 0 ]; then echo "seq: step %d `+
				`expected revert but succeeded" >&2; emit_result fail; `+
				`exit 1; fi`, n),
			"reason=$(sanitize_reason)",
			"STEPS=$(add_step "+shellJSON(j)+")")
		return out, nil
	}
	j := `{"step": ` + validation.IntText(validation.ObjAt(s, "step")) +
		`, "actor": ` + role + `, "tx_hash": "$tx", "status": "success",` +
		` "revert_reason": null}`
	out = append(out,
		fmt.Sprintf(`if [ $rc -ne 0 ]; then reason=$(sanitize_reason); `+
			`echo "seq: step %d failed (rc=$rc): $reason" >&2; `+
			`STEPFAIL=1; emit_result fail; exit 1; fi`, n),
		`tx=$(printf '%s\n' "$out" | grep -oi `+
			`'transaction[- ]*hash[: ]*0x[0-9a-fA-F]*' | head -n1 | `+
			`grep -o '0x[0-9a-fA-F]*')`,
		"STEPS=$(add_step "+shellJSON(j)+")")
	return out, nil
}

// joinArgs is `" ".join(shlex.quote(a) for a in args or [])` with the
// leading space the driver's f-strings add.
func joinArgs(v validation.Value) string {
	args := listOf(v)
	if len(args) == 0 {
		return ""
	}
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = shlexQuote(pyStr(a))
	}
	return " " + strings.Join(parts, " ")
}

// valueFragment is the step's optional wei `value` as a `cast send
// --value` fragment, "" when the step carries none — so every spec
// written before the key existed produces byte-identical driver text.
// The literal is passed through VERBATIM (cast parses a decimal wei
// integer, and the schema's other admitted spelling, hex): the loader's
// schema check is the gate that refuses anything human-formatted, and
// this builder never reinterprets a number — a driver that "helpfully"
// converted "1 ether" would replay a transaction the witness never ran.
// The fragment rides before the actor flag, right after the calldata it
// pays for, because the value is a field of the CALL, not of the sender.
func valueFragment(s validation.Value) string {
	v := validation.ObjAt(s, "value")
	if v.Kind != validation.Str || v.S == "" {
		return ""
	}
	return " --value " + shlexQuote(v.S)
}

// buildAssertion is build_command's per-assertion block.
func buildAssertion(spec, a validation.Value) ([]string, error) {
	kind := validation.ObjStr(a, "kind")
	var readCmd string
	switch kind {
	case "balance":
		addr, err := resolveAddr(spec, validation.ObjStr(a, "account"))
		if err != nil {
			return nil, err
		}
		readCmd = `raw=$(cast balance --rpc-url "$FORK_RPC_URL" ` + addr +
			` 2>"$WD/seq_err.txt") || raw=""`
	case "storage":
		readCmd = `raw=$(cast storage --rpc-url "$FORK_RPC_URL" ` +
			shlexQuote(validation.ObjStr(a, "target")) + " " +
			shlexQuote(validation.ObjStr(a, "slot")) + ` 2>"$WD/seq_err.txt") || raw=""`
	default: // call
		readCmd = `raw=$(cast call --rpc-url "$FORK_RPC_URL" ` +
			shlexQuote(validation.ObjStr(a, "target")) + " " +
			shlexQuote(validation.ObjStr(a, "function")) + joinArgs(validation.ObjAt(a, "args")) +
			` 2>"$WD/seq_err.txt") || raw=""`
	}
	op, value := validation.ObjStr(a, "op"), validation.ObjStr(a, "value")
	j := `{"id": "` + validation.ObjStr(a, "id") + `", "kind": "` + kind +
		`", "observed": "$obs", "expected": "` + op + " " + value +
		`", "passed": $passed}`
	return []string{
		readCmd,
		`obs=$(sanitize_field "$raw")`,
		"case $raw in",
		`  0x*|0X*) norm=$(hex2dec "$raw") || norm="" ;;`,
		`  "") norm="" ;;`,
		`  *[!0-9]*) norm="" ;;`,
		`  *) norm=$raw ;;`,
		"esac",
		`if [ -z "$norm" ]; then passed=false; else`,
		`c=$(dec_cmp "$norm" ` + shlexQuote(value) + `)`,
		"case " + shlexQuote(op) + " in",
		`  ">=") if [ "$c" != "-1" ]; then passed=true; else ` +
			`passed=false; fi ;;`,
		`  "<=") if [ "$c" != "1" ]; then passed=true; else ` +
			`passed=false; fi ;;`,
		`  "==") if [ "$c" = "0" ]; then passed=true; else ` +
			`passed=false; fi ;;`,
		`  "!=") if [ "$c" != "0" ]; then passed=true; else ` +
			`passed=false; fi ;;`,
		"esac",
		"fi",
		`if [ "$passed" = "false" ]; then ASSERTFAIL=1; fi`,
		"ASSERTS=$(add_assert " + shellJSON(j) + ")",
	}, nil
}

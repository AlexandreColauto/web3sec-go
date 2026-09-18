// Package sequencepoc ports webv2.sequence_poc: the T4 rung of the
// reproduction ladder — multi-transaction sequence PoCs.
//
//   - LoadSequenceSpec: schema + field-rule validation of the spec artifact
//     (fail-loud, naming the offending field);
//   - BuildCommand / RunSequence: a deterministic POSIX-sh driver for the
//     fork-runner profile, executed through foundry's `cast` CLI; the driver
//     writes sequence_result.json binding itself to the executed spec via
//     sha256 (the ledger-anchored philosophy of E4+ mints);
//   - VerifySequenceCoverage: a pure function of (finding, exec record) —
//     did the executed result cover the finding's declared exploit_sequence?
//
// No model calls, no new dependencies (stdlib host-side; sh + cast +
// coreutils in the container). The gate changes built on this are
// structural: they fire solely when the finding declares a multi-step or
// multi-actor exploit_sequence — never from scores or tags.
package sequencepoc

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// SpecError is Python's ValueError: every fail-loud path in this module.
type SpecError struct{ Msg string }

func (e *SpecError) Error() string { return e.Msg }

func specErrf(format string, a ...any) error {
	return &SpecError{Msg: fmt.Sprintf(format, a...)}
}

// addrRe is _ADDR; roleKeyRe is _ROLE_KEY ([A-Za-z][A-Za-z0-9_]*\Z);
// anvilIndexRe is _ANVIL_INDEX ([0-9]+\Z).
var (
	addrRe       = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
	roleKeyRe    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)
	anvilIndexRe = regexp.MustCompile(`^[0-9]+$`)
)

// CanonicalJSON is canonical_json: the canonical serialization used for
// spec_hash (sorted keys, compact).
func CanonicalJSON(spec validation.Value) []byte {
	return []byte(validation.CanonCompact(spec))
}

// SpecHash is spec_hash: sha256 of the canonical JSON — binds a result to
// the exact spec.
func SpecHash(spec validation.Value) string {
	sum := sha256.Sum256(CanonicalJSON(spec))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// IsSequenceRequired is is_sequence_required: true iff the finding's
// declared exploit_sequence is MULTI-STEP or MULTI-ACTOR in shape — >= 2
// steps, or >= 2 distinct non-empty actors among its steps. A PURE predicate
// about the finding's declared shape, and the total guard (malformed input
// -> false).
func IsSequenceRequired(finding validation.Value) bool {
	if finding.Kind != validation.Obj {
		return false
	}
	seq := validation.ObjAt(finding, "exploit_sequence")
	if seq.Kind != validation.Arr {
		return false
	}
	steps := seq.A
	if len(steps) >= 2 {
		return true
	}
	actors := map[string]struct{}{}
	for _, s := range steps {
		if s.Kind != validation.Obj {
			continue
		}
		if actor := validation.ObjAt(s, "actor"); validation.PyTruthy(actor) {
			actors[valueKey(actor)] = struct{}{}
		}
	}
	return len(actors) >= 2
}

// SnapshotHasForkTarget is snapshot_has_fork_target: true iff the ACTIVE
// snapshot pins a fork target — a deployment or a chain. Reads the pin FILE
// in the immutable tree, not the state mirror.
//
// The pair is (has, err). (false, nil) is the FACT that there is no active
// snapshot or no pin manifest at all (ENOENT). Every other stat/read failure
// is a REFUSAL naming the path and the errno: a pin the tool could not read
// is not a pin that does not exist, and r45b closed the older "any error ->
// false" fold that let EACCES be answered as "no fork target".
func SnapshotHasForkTarget(campaign *state.Campaign) (bool, error) {
	sid, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil {
		return false, err
	}
	if sid == nil || *sid == "" {
		return false, nil
	}
	pinPath := filepath.Join(campaign.Dir, "snapshots", *sid, "snapshot.json")
	if st, serr := os.Stat(pinPath); serr != nil {
		if os.IsNotExist(serr) {
			return false, nil // genuinely no fork target
		}
		return false, fmt.Errorf("the active snapshot's pin manifest %s "+
			"cannot be read: %v", pinPath, serr)
	} else if st.IsDir() {
		return false, fmt.Errorf("the active snapshot's pin manifest %s is a "+
			"directory", pinPath)
	}
	pin, err := validation.ReadJson(pinPath)
	if err != nil {
		return false, fmt.Errorf("the active snapshot's pin manifest %s "+
			"cannot be read: %v", pinPath, err)
	}
	return validation.PyTruthy(validation.ObjAt(pin, "deployment")) ||
		validation.PyTruthy(validation.ObjAt(pin, "chain")), nil
}

// OnchainSequenceRequiredErr is onchain_sequence_required with the refusal
// carried: a pin the tool could not read is returned as an error naming the
// path and the errno — never as "not required". Error-aware callers (the
// CONFIRMED gate) use this form.
func OnchainSequenceRequiredErr(campaign *state.Campaign,
	finding validation.Value) (bool, error) {
	if !IsSequenceRequired(finding) {
		return false, nil
	}
	return SnapshotHasForkTarget(campaign)
}

// OnchainSequenceRequired is onchain_sequence_required: the ON-CHAIN-shaped
// requirement — a multi-step/multi-actor finding in a campaign whose active
// snapshot has a fork target MUST be proven with a multi-tx fork PoC. The
// gate keys off the deployment pin, not the step count, because steps in a
// logic bug are not transactions.
//
// The wired seam contract (findings/forkpoc SetOnchainSequenceRequired) is a
// bare bool and cannot carry an error, so this form is FAIL-CLOSED: a
// sequenced finding whose pin could not be read keeps the requirement — it
// never answers false ("not required") for a pin the tool failed to read, and
// therefore never discharges the audit row, the CONFIRMED-gate clause or the
// fork-PoC evidence floor. Callers that can carry an error use
// OnchainSequenceRequiredErr for the named refusal.
func OnchainSequenceRequired(campaign *state.Campaign,
	finding validation.Value) bool {
	required, err := OnchainSequenceRequiredErr(campaign, finding)
	if err != nil {
		return true
	}
	return required
}

// fail is _fail: the ValueError text naming the offending field.
func fail(field, problem string) error {
	return specErrf("sequence spec field %s: %s",
		validation.PyReprStr(field), problem)
}

// LoadSequenceSpec is load_sequence_spec: load + validate a sequence PoC
// spec. Returns a *SpecError naming the offending field for anything
// malformed (schema OR field rules).
func LoadSequenceSpec(path string) (validation.Value, error) {
	data, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), specErrf(
			"sequence spec unreadable at %s: %s", path, err)
	}
	if data.Kind != validation.Obj {
		return validation.VNull(), fail("spec", "top level must be an object")
	}
	if err := validation.Validate(data, "sequence_poc", 1); err != nil {
		return validation.VNull(), specErrf(
			"sequence spec schema violation: %s", err)
	}
	actors := validation.ObjAt(data, "actors")
	steps := listOf(validation.ObjAt(data, "steps"))
	if err := checkRoleKeys(actors); err != nil {
		return validation.VNull(), err
	}
	if err := checkSteps(data, actors, steps); err != nil {
		return validation.VNull(), err
	}
	if err := checkAssertions(data, actors); err != nil {
		return validation.VNull(), err
	}
	return data, nil
}

// checkRoleKeys applies the actor-key field rules: shell-safe identifiers
// and no case-insensitive collisions on FORK_KEY_<ROLE>.
func checkRoleKeys(actors validation.Value) error {
	seenUpper := map[string]string{}
	for _, kv := range actors.O {
		if !roleKeyRe.MatchString(kv.K) {
			return fail("actors", fmt.Sprintf(
				"role key %s is not a shell-safe identifier "+
					"[A-Za-z][A-Za-z0-9_]* (actor keys become shell "+
					"variable names and FORK_KEY_<ROLE> env vars)",
				validation.PyReprStr(kv.K)))
		}
		up := strings.ToUpper(kv.K)
		if first, ok := seenUpper[up]; ok {
			return fail("actors", fmt.Sprintf(
				"role keys %s and %s collide on FORK_KEY_%s (role lookup "+
					"is case-insensitive)", validation.PyReprStr(first),
				validation.PyReprStr(kv.K), up))
		}
		seenUpper[up] = kv.K
	}
	return nil
}

// checkSteps materializes expect_revert, validates actor membership, and
// requires step numbers to be exactly 1..n.
func checkSteps(data, actors validation.Value,
	steps []validation.Value) error {
	seen := map[int64]struct{}{}
	known := pyListReprStrings(objKeys(actors))
	for i := range steps {
		s := &steps[i]
		if s.Kind != validation.Obj {
			continue
		}
		s.O = validation.SetDefault(s.O, "expect_revert", validation.VBool(false))
		actor := validation.ObjAt(*s, "actor")
		if _, ok := actorKey(actors, actor); !ok {
			return fail(fmt.Sprintf("steps[%d].actor", i), fmt.Sprintf(
				"%s is not a key of 'actors' (known: %s)",
				pyStr(actor), known))
		}
		n := intOf(validation.ObjAt(*s, "step"))
		if _, dup := seen[n]; dup {
			return fail(fmt.Sprintf("steps[%d].step", i), fmt.Sprintf(
				"duplicate step number %s — steps must be strictly "+
					"increasing by 1", validation.IntText(
					validation.ObjAt(*s, "step"))))
		}
		seen[n] = struct{}{}
	}
	for n := int64(1); n <= int64(len(steps)); n++ {
		if _, ok := seen[n]; !ok {
			return fail("steps[].step", fmt.Sprintf(
				"step numbers must be exactly 1..%d (missing %d) — "+
					"ordering is the whole point", len(steps), n))
		}
	}
	return nil
}

// checkAssertions validates the final_assertions field rules.
func checkAssertions(data, actors validation.Value) error {
	assertions := listOf(validation.ObjAt(data, "final_assertions"))
	known := pyListReprStrings(objKeys(actors))
	seenIDs := map[string]struct{}{}
	for i, a := range assertions {
		id := validation.ObjAt(a, "id")
		idKey := pyStr(id)
		if _, dup := seenIDs[idKey]; dup {
			return fail(fmt.Sprintf("final_assertions[%d].id", i),
				fmt.Sprintf("duplicate assertion id %s — ids must be "+
					"unique (coverage matches results by id)",
					pyStr(id)))
		}
		seenIDs[idKey] = struct{}{}
		if err := checkAssertionFields(i, a, actors, known); err != nil {
			return err
		}
	}
	return nil
}

// checkAssertionFields is the per-assertion kind/account rule block.
func checkAssertionFields(i int, a, actors validation.Value,
	known string) error {
	kind := validation.ObjStr(a, "kind")
	switch kind {
	case "balance":
		if !validation.PyTruthy(validation.ObjAt(a, "account")) {
			return fail(fmt.Sprintf("final_assertions[%d].account", i),
				"required for kind 'balance' (native ETH balance)")
		}
	case "storage":
		if !validation.PyTruthy(validation.ObjAt(a, "target")) || !validation.PyTruthy(validation.ObjAt(a, "slot")) {
			return fail(fmt.Sprintf("final_assertions[%d]", i),
				"kind 'storage' requires both 'target' and 'slot'")
		}
	case "call":
		if !validation.PyTruthy(validation.ObjAt(a, "target")) || !validation.PyTruthy(validation.ObjAt(a, "function")) {
			return fail(fmt.Sprintf("final_assertions[%d]", i),
				"kind 'call' requires both 'target' and 'function'")
		}
	}
	acct := validation.ObjAt(a, "account")
	if !validation.PyTruthy(acct) {
		return nil
	}
	if acct.Kind == validation.Str && addrRe.MatchString(acct.S) {
		return nil
	}
	if _, ok := actorKey(actors, acct); ok {
		return nil
	}
	return fail(fmt.Sprintf("final_assertions[%d].account", i), fmt.Sprintf(
		"%s is neither a 0x address nor a key of 'actors' (known: %s)",
		pyStr(acct), known))
}

// --- small value helpers ---------------------------------------------------

// listOf is Python `x or []` for list-shaped fields.
func listOf(v validation.Value) []validation.Value {
	if v.Kind != validation.Arr {
		return nil
	}
	return v.A
}

// objKeys lists an object's keys in insertion order.
func objKeys(v validation.Value) []string {
	out := make([]string, 0, len(v.O))
	for _, kv := range v.O {
		out = append(out, kv.K)
	}
	return out
}

// actorKey is Python's `x in actors` for the shapes a JSON key can take: a
// string actor is the common case; every other scalar is compared by its
// rendered form (Python would hash the scalar itself).
func actorKey(actors, actor validation.Value) (string, bool) {
	key := valueKey(actor)
	for _, kv := range actors.O {
		if valueKey(validation.VStr(kv.K)) == key {
			return kv.K, true
		}
	}
	return "", false
}

// valueKey renders a scalar for set/dict membership; container values use
// their Python repr (Python would raise on an unhashable element — this
// module's total-guard contract wins).
func valueKey(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return "s:" + v.S
	case validation.Int:
		return "i:" + validation.IntText(v)
	case validation.Bool:
		if v.B {
			return "b:True"
		}
		return "b:False"
	case validation.Null:
		return "n:None"
	}
	return "r:" + validation.PyRepr(v)
}

// pyStr is Python str(v) for a JSON scalar (str and repr agree outside str).
func pyStr(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return validation.PyRepr(v)
}

// pyListReprStrings renders Python repr(list-of-str): ['a', 'b'].
func pyListReprStrings(items []string) string {
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	parts := make([]string, len(sorted))
	for i, s := range sorted {
		parts[i] = validation.PyReprStr(s)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// intOf is Python int() for the JSON integer shapes (floats truncate).
func intOf(v validation.Value) int64 {
	switch v.Kind {
	case validation.Int:
		if v.Big != "" {
			n, _ := strconv.ParseInt(v.Big, 10, 64)
			return n
		}
		return v.I
	case validation.Flt:
		return int64(v.F)
	}
	return 0
}

// Package immunize ports webv2.immunize: proving the PATCH blocks the PoC.
//
// The basis is the mainnet FORK PoC, never a unit test. A patch that blocks
// a unit test but not the fork is not a patch — it is a coincidence of the
// harness. So immunization verifies the fix against the exact fork-runner
// exec that proved the exploit works on mainnet: the PoC must FAIL under the
// patch, and THREE boundary mutations must also be blocked.
package immunize

import (
	"fmt"
	"os"
	"path/filepath"

	"websec/internal/findings"
	"websec/internal/forkpoc"
	"websec/internal/state"
	"websec/internal/validation"
)

// MIN_MUTATIONS / MAX_MUTATIONS (both 3: exactly three, no more, no less).
const (
	MinMutations = 3
	MaxMutations = 3
)

// InputError is Python's (ValueError, KeyError) family: the CLI maps it to
// exit 2 with `immunize failed: {e}`. A KeyError renders as repr(message),
// so those messages already carry their own quotes.
type InputError struct{ Msg string }

func (e *InputError) Error() string { return e.Msg }

// Options are immunize()'s keyword-only arguments.
type Options struct {
	Patch     string
	POCExecID string
	Mutations []string
	Actor     string
	Bypass    *string
}

// --- seam: sandbox.load_exec ----------------------------------------------

// loadExecFunc is sandbox.load_exec: (record, found, error). The default
// reads <execs_dir>/<exec_id>/exec_record.json and reports found=false for a
// missing file — Python's FileNotFoundError, which immunize turns into a
// KeyError. A ported sandbox package installs its own reader.
var loadExecFunc = defaultLoadExec

func defaultLoadExec(campaign *state.Campaign,
	execID string) (validation.Value, bool, error) {
	path := filepath.Join(campaign.ExecsDir, execID, "exec_record.json")
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return validation.VNull(), false, nil
		}
		return validation.VNull(), false, err
	}
	rec, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), false, err
	}
	return rec, true, nil
}

// SetLoadExec wires sandbox.load_exec; nil restores the default reader.
func SetLoadExec(f func(*state.Campaign, string) (validation.Value, bool, error)) {
	if f == nil {
		f = defaultLoadExec
	}
	loadExecFunc = f
}

// validateInputs is _validate_inputs.
func validateInputs(patch string, mutations []string, actor string) error {
	if patch == "" || len(strip(patch)) < 10 {
		return &InputError{Msg: "immunization needs a written patch description " +
			"(>=10 chars): what the fix changes and why it blocks the exploit"}
	}
	if actor == "" {
		return &InputError{Msg: "immunization needs a named actor"}
	}
	if len(mutations) != MinMutations {
		return &InputError{Msg: fmt.Sprintf("immunization requires exactly %d "+
			"boundary mutations — a patch tested against the PoC alone may "+
			"block one path and leave its neighbors open", MinMutations)}
	}
	for _, m := range mutations {
		if len(strip(m)) < 5 {
			return &InputError{Msg: "each boundary mutation needs a written " +
				"description (>=5 chars): what input/path variant was tested"}
		}
	}
	return nil
}

// requireForkBasis is _require_fork_basis: the exec must be THIS finding's
// proven fork PoC — a fork-runner run that succeeded and is minted on the
// finding as E5/E6 fork evidence. A unit-test exec is refused with the exact
// replacement command.
func requireForkBasis(campaign *state.Campaign, f validation.Value,
	pocExecID string) (validation.Value, error) {
	rec, found, err := loadExecFunc(campaign, pocExecID)
	if err != nil {
		return validation.VNull(), err
	}
	if !found {
		// str(KeyError(msg)) is repr(msg): the quotes are part of the text.
		return validation.VNull(), &InputError{Msg: validation.PyReprStr(
			"exec " + pocExecID + " not found in the campaign's exec ledger")}
	}
	if validation.ObjStr(rec, "profile") != forkpoc.ForkProfile {
		return validation.VNull(), &InputError{Msg: "immunization is based on " +
			"the mainnet FORK PoC, not a unit test: " + pocExecID +
			" ran under profile " + validation.PyRepr(validation.ObjAt(rec, "profile")) +
			". Re-run the PoC on the pinned fork (webv2 exec --profile " +
			"fork-runner --command 'forge test --fork-url ...') and " +
			"re-verify against that exec"}
	}
	if !exitIsZero(rec) {
		return validation.VNull(), &InputError{Msg: pocExecID + " exited " +
			validation.PyRepr(validation.ObjAt(rec, "exit_status")) + " — the PoC must " +
			"have SUCCEEDED on the unpatched fork for the verification to " +
			"mean anything"}
	}
	if !mintedOn(f, pocExecID) {
		return validation.VNull(), &InputError{Msg: pocExecID + " is not " +
			"minted on " + validation.ObjStr(f, "finding_id") + " as E5/E6 fork " +
			"evidence — mint it first: webv2 mint " + validation.ObjStr(f, "finding_id") +
			" --exec " + pocExecID + " --type fork-test"}
	}
	return rec, nil
}

// mintedOn is the `any(...)` over the finding's evidence: an E5/E6 item that
// cites this exec under the fork-runner profile.
func mintedOn(f validation.Value, pocExecID string) bool {
	for _, e := range listAt(f, "evidence") {
		if e.Kind != validation.Obj {
			continue
		}
		if validation.ObjStr(e, "artifact_id") != pocExecID {
			continue
		}
		if !isForkLevel(validation.ObjStr(e, "level")) {
			continue
		}
		if validation.ObjStr(e, "sandbox_profile") == forkpoc.ForkProfile {
			return true
		}
	}
	return false
}

// Immunize is immunize: record that the patch blocks the finding's mainnet
// fork PoC plus its 3 boundary mutations. Pass a non-nil Bypass to record
// that a mutation slipped through: the block is still written (the record is
// the artifact), but boundary_bypass_found=True. Returns the updated finding.
func Immunize(campaign *state.Campaign, findingID string,
	o Options) (validation.Value, error) {
	if err := validateInputs(o.Patch, o.Mutations, o.Actor); err != nil {
		return validation.VNull(), err
	}
	f, err := findings.LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := requireForkBasis(campaign, f, o.POCExecID); err != nil {
		return validation.VNull(), err
	}
	if o.Bypass != nil && len(strip(*o.Bypass)) < 5 {
		return validation.VNull(), &InputError{Msg: "a recorded bypass needs " +
			"a written description (>=5 chars): which mutation, what it " +
			"extracted"}
	}
	verification := validation.ObjAt(f, "verification")
	if verification.Kind != validation.Obj {
		verification = validation.VObj()
	}
	pairs := []validation.KV{
		kv("patch_blocks_poc", validation.VBool(o.Bypass == nil)),
		kv("boundary_mutations_tested", validation.VInt(MinMutations)),
		kv("boundary_bypass_found", validation.VBool(o.Bypass != nil)),
		kv("artifact_id", validation.VStr(o.POCExecID)),
		kv("patch", validation.VStr(strip(o.Patch))),
		kv("mutations", mutationsValue(o.Mutations)),
		kv("actor", validation.VStr(o.Actor)),
		kv("at", validation.VStr(state.NowIso())),
	}
	if o.Bypass != nil {
		pairs = append(pairs, kv("bypass", validation.VStr(strip(*o.Bypass))))
	}
	verification.O = validation.SetOrAppend(verification.O, "patch_verified",
		validation.VObj(pairs...))
	f.O = validation.SetOrAppend(f.O, "verification", verification)
	if err := findings.SaveFinding(campaign, &f); err != nil {
		return validation.VNull(), err
	}
	event := "finding.immunized"
	if o.Bypass != nil {
		event = "finding.immunize_bypass"
	}
	data := validation.VObj(
		kv("poc_exec", validation.VStr(o.POCExecID)),
		kv("actor", validation.VStr(o.Actor)),
		kv("bypass_found", validation.VBool(o.Bypass != nil)),
	)
	if _, err := campaign.Log(event, &findingID, &data); err != nil {
		return validation.VNull(), err
	}
	return f, nil
}

// IsImmunized is is_immunized: True when verification.patch_verified says
// the patch blocks the fork PoC and all 3 boundary mutations, with no bypass
// on the record.
func IsImmunized(f validation.Value) bool {
	pv := patchVerified(f)
	if pv.Kind != validation.Obj {
		return false
	}
	return isTrue(validation.ObjAt(pv, "patch_blocks_poc")) &&
		intEq(validation.ObjAt(pv, "boundary_mutations_tested"), MinMutations) &&
		isFalse(validation.ObjAt(pv, "boundary_bypass_found")) &&
		pyTruthyLenientContainers(validation.ObjAt(pv, "artifact_id"))
}

// ImmunizationDetail is immunization_detail: (state, detail) for gate/report
// rendering: immunized / bypass / partial / missing.
func ImmunizationDetail(f validation.Value) (string, string) {
	pv := patchVerified(f)
	if pv.Kind != validation.Obj || len(pv.O) == 0 {
		return "missing", "no patch verification recorded (webv2 " +
			"immunize ... against the FORK PoC)"
	}
	if pyTruthyLenientContainers(validation.ObjAt(pv, "boundary_bypass_found")) {
		return "bypass", "boundary bypass found: " +
			truncate(pyStr(validation.ObjAt(pv, "bypass")), 60) +
			" — the patch does not hold"
	}
	if !isTrue(validation.ObjAt(pv, "patch_blocks_poc")) {
		return "partial", "patch_blocks_poc is not confirmed"
	}
	if !intEq(validation.ObjAt(pv, "boundary_mutations_tested"), MinMutations) {
		return "partial", "only " + pyStr(validation.ObjAt(pv,
			"boundary_mutations_tested")) + "/" +
			fmt.Sprintf("%d", MinMutations) + " boundary mutations tested"
	}
	return "immunized", "patch blocks the fork PoC and all " +
		fmt.Sprintf("%d", MinMutations) + " boundary mutations (basis: " +
		pyStr(validation.ObjAt(pv, "artifact_id")) + ")"
}

// patchVerified is (f.get("verification") or {}).get("patch_verified") or {}.
func patchVerified(f validation.Value) validation.Value {
	verification := validation.ObjAt(f, "verification")
	if verification.Kind != validation.Obj {
		verification = validation.VObj()
	}
	pv := validation.ObjAt(verification, "patch_verified")
	if pv.Kind != validation.Obj {
		return validation.VObj()
	}
	return pv
}

// mutationsValue is [m.strip() for m in mutations].
func mutationsValue(mutations []string) validation.Value {
	out := make([]validation.Value, 0, len(mutations))
	for _, m := range mutations {
		out = append(out, validation.VStr(strip(m)))
	}
	return validation.VArr(out...)
}

// listAt is `v.get(key) or []` for list-shaped fields.
func listAt(v validation.Value, key string) []validation.Value {
	if got := validation.ObjAt(v, key); got.Kind == validation.Arr {
		return got.A
	}
	return nil
}

// pyStr is Python's str() of a JSON scalar (f-string interpolation).
func pyStr(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return validation.PyRepr(v)
}

// pyTruthyLenientContainers is a DIVERGENT pyTruthy variant (Wave J Task 7),
// NOT the canonical form; it is named so the divergence is visible.
// Rule: exactly validation.PyTruthy, except (a) empty arrays and objects read
// TRUTHY (CPython and validation.PyTruthy read them falsy) and (b) an Int with
// any non-empty Big text is truthy (Big == "0" included).
func pyTruthyLenientContainers(v validation.Value) bool {
	switch v.Kind {
	case validation.Null:
		return false
	case validation.Bool:
		return v.B
	case validation.Int:
		return !(v.Big == "" && v.I == 0)
	case validation.Flt:
		return v.F != 0
	case validation.Str:
		return v.S != ""
	case validation.Arr, validation.Obj:
		return true
	}
	return false
}

// isTrue / isFalse are Python's `is True` / `is False` identity tests.
func isTrue(v validation.Value) bool  { return v.Kind == validation.Bool && v.B }
func isFalse(v validation.Value) bool { return v.Kind == validation.Bool && !v.B }

// intEq is Python's `== n` for an int field (False for every other kind,
// including a bool: True == 1 in Python, but the schema stores ints here).
func intEq(v validation.Value, n int64) bool {
	return v.Kind == validation.Int && v.Big == "" && v.I == n
}

// isForkLevel is `level in FORK_LEVELS`.
func isForkLevel(level string) bool {
	for _, l := range forkpoc.ForkLevels {
		if l == level {
			return true
		}
	}
	return false
}

// exitIsZero is `rec.get("exit_status") != 0` negated (Python's None/False
// semantics: None != 0 is True, False == 0 is True).
func exitIsZero(rec validation.Value) bool {
	v := validation.ObjAt(rec, "exit_status")
	switch v.Kind {
	case validation.Int:
		return v.Big == "" && v.I == 0
	case validation.Flt:
		return v.F == 0
	case validation.Bool:
		return !v.B
	}
	return false
}

// strip is Python's str.strip() for the ASCII whitespace this module sees.
func strip(s string) string {
	start, end := 0, len(s)
	for start < end && isSpace(s[start]) {
		start++
	}
	for end > start && isSpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

// isSpace is Python's str.strip() whitespace set (ASCII; the module's inputs
// are operator-typed descriptions).
func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

// truncate is Python's s[:n].
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// kv is the vet-clean keyed KV constructor.
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

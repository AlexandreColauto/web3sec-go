// patch_clause.go (IMPROVEMENTS D8): the patch clause follows the target
// program, not the framework. `poc_requirements.patch_clause` is the policy's
// answer to "does this program want a tested patch, a written recommendation,
// or nothing at all?" — and check12 reads it instead of applying one hard-coded
// strictness to every program.
//
//	verification (default when the key is absent) — today's bar: a recorded
//	    patch that blocks the fork PoC and all 3 boundary mutations
//	prose — a written recommendation on the finding clears the clause;
//	    the boundary-mutation record becomes an advisory line
//	none — the program does not ask for a fix; nothing is required
//
// The absent key means `verification`, so every campaign that predates this
// field (and the golden fixture, and the pinned gate vectors) behaves
// byte-for-byte as before. An unknown value is a loud error, never a silent
// default; the policy schema's enum refuses it at load time too.
package bounty

import (
	"strconv"
	"strings"

	"websec/internal/validation"
)

// minRecommendationRunes is the length floor for a `prose` recommendation:
// "use a mutex" is not a recommendation, a function + change + snippet is.
// The floor counts runes, not bytes, so a non-English recommendation is not
// penalised for its encoding.
const minRecommendationRunes = 40

// patchClause is the program's fix requirement: verification | prose | none.
func patchClause(policy validation.Value) (string, error) {
	req := validation.ObjAt(policy, "poc_requirements")
	mode := validation.ObjStr(req, "patch_clause")
	switch mode {
	case "":
		return "verification", nil
	case "verification", "prose", "none":
		return mode, nil
	default:
		return "", &UnknownPatchClauseError{Value: mode,
			Program: validation.ObjStr(policy, "program")}
	}
}

// UnknownPatchClauseError is the load-style refusal for a mode the framework
// does not implement (never a silent fallback to the framework's own bar).
type UnknownPatchClauseError struct {
	Value   string
	Program string
}

func (e *UnknownPatchClauseError) Error() string {
	where := ""
	if e.Program != "" {
		where = " for program " + validation.PyReprStr(e.Program)
	}
	return "unknown poc_requirements.patch_clause " +
		validation.PyReprStr(e.Value) + where +
		": expected verification, prose or none"
}

// recommendation is the finding's written fix (verification.recommendation),
// trimmed. A missing or null field is "".
func recommendation(f validation.Value) string {
	v := validation.ObjAt(validation.ObjAt(f, "verification"), "recommendation")
	if v.Kind != validation.Str {
		return ""
	}
	return strings.TrimSpace(v.S)
}

// recommendationOK is the `prose` clause's pass condition.
func recommendationOK(f validation.Value) bool {
	return len([]rune(recommendation(f))) >= minRecommendationRunes
}

// patchVerified is the finding's recorded immunization record
// (verification.patch_verified), or Null when the finding has none.
func patchVerified(f validation.Value) validation.Value {
	v := validation.ObjAt(validation.ObjAt(f, "verification"), "patch_verified")
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	return v
}

// boundaryAdvisory is the prose/none mode's advisory line for a recorded
// patch ("" when there is nothing to say). The boundary-mutation test stays
// in the record in every mode: a mutation that still extracts under the patch
// means a misdiagnosed root cause, which is duplicate risk regardless of what
// the program asks for. Only its gate authority changes.
func boundaryAdvisory(f validation.Value) string {
	pv := patchVerified(f)
	if pv.Kind != validation.Obj {
		return ""
	}
	if b := validation.ObjAt(pv, "boundary_bypass_found"); b.Kind == validation.Bool && b.B {
		return "boundary mutation still extracts under the recorded patch — " +
			"re-check the root cause before submitting"
	}
	tested := 0
	if t := validation.ObjAt(pv, "boundary_mutations_tested"); t.Kind == validation.Int {
		tested, _ = strconv.Atoi(validation.IntText(t))
	}
	if tested < 3 {
		return "recorded patch tested " + itoa(tested) + "/3 boundary " +
			"mutations — the program does not gate on it, but a missed " +
			"mutation is duplicate risk"
	}
	return ""
}

// itoa is str(int) without pulling fmt into this file's call sites.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

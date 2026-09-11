package structidx

// GuardForm classifies a guard condition by WHAT IT CAN EXPRESS:
//
//	"sentinel"    — the condition only rules out the zero value (or an empty
//	                collection): != 0, != bytes32(0), != address(0), > 0,
//	                .length > 0. A sentinel check cannot assert the truth of
//	                a value — any non-zero lie passes it.
//	"substantive" — everything else: equality to persisted state, ownership,
//	                membership, inequality between two named values.
//
// The sentinel set is exactly guardStrength's class-1 set (the same two
// matchers guardStrength uses), so the two never disagree about what a
// sentinel is.
func GuardForm(cond string) string {
	if _, ok := pyGuard1.search(cond, 0); ok {
		return "sentinel"
	}
	if reGuard1.MatchString(cond) {
		return "sentinel"
	}
	return "substantive"
}

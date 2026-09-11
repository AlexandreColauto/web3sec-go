package structidx

import "testing"

// TestGuardForm pins the sentinel/substantive split. The sentinel set is
// exactly guardStrength's class-1 set (pyGuard1/reGuard1): zero-checks,
// length checks. Everything else — equality to persisted state, ownership,
// membership, inequality of two names — is substantive.
func TestGuardForm(t *testing.T) {
	cases := map[string]string{
		"prevStateRoot != bytes32(0)":            "sentinel",
		"amount > 0":                             "sentinel",
		"inputs.length > 0":                      "sentinel",
		"token != address(0)":                    "sentinel",
		"x != 0":                                 "sentinel",
		"prevStateRoot[batchIndex] == stateRoot": "substantive",
		"msg.sender == owner":                    "substantive",
		"balanceOf(user) >= amount":              "substantive",
		"root == keccak256(data)":                "substantive",
		"":                                       "substantive",
	}
	for cond, want := range cases {
		if got := GuardForm(cond); got != want {
			t.Errorf("GuardForm(%q) = %q, want %q", cond, got, want)
		}
	}
}

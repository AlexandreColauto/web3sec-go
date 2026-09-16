// symmetry_testdouble_test.go — a test harness is not a custody member: its
// mint/burn cells are fixture noise that outranks real pairings in the
// per-axis quota (C-12f17fd555: 8 of 12 custody slots were MockTree/test_*
// rows, and the true-positive onDropMessage rows sat in the cut tail).
package probes

import (
	"testing"

	"websec/internal/validation"
)

func TestSymMemberIsTestDouble(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"contracts/contracts/test/MorphTokenTest.sol", true},
		{"contracts/contracts/mocks/MockRollup.sol", true},
		{"contracts/contracts/l1/gateways/L1ERC20Gateway.sol", false},
		{"contracts/contracts/l2/Staking.sol", false},
	}
	for _, tc := range cases {
		node := validation.VObj(validation.KV{K: "path", V: validation.VStr(tc.path)})
		if got := symMemberIsTestDouble(node); got != tc.want {
			t.Errorf("symMemberIsTestDouble(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

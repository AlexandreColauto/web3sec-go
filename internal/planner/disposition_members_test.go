// disposition_members_test.go — the reconcile gate demands cites for the
// members it lists; RowSymbols (the cite validator's vocabulary) must
// therefore read the row's members field too. C-12f17fd555 §8a: row
// b6c0484194 demanded 34 members and refused every one of them.
package planner

import (
	"testing"

	"websec/internal/validation"
)

func TestRowSymbolsIncludeMembers(t *testing.T) {
	row := validation.VObj(
		validation.KV{K: "contract", V: validation.VStr("L1ReverseCustomGateway")},
		validation.KV{K: "members", V: validation.VArr(
			validation.VStr("IL1ERC20Gateway"),
			validation.VStr("L1ERC721Gateway"),
		)},
	)
	got := RowSymbols(row)
	for _, want := range []string{"L1ReverseCustomGateway", "IL1ERC20Gateway", "L1ERC721Gateway"} {
		found := false
		for _, s := range got {
			if s == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("RowSymbols missing member %q; got %v", want, got)
		}
	}
}

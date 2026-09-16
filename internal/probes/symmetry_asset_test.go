package probes

// symmetry_asset_test.go — the verb table collapses every token call to
// "erc20", so an ERC-1155/721 gateway "disagrees" with an ERC-20 gateway over
// the same verb. A member-disagreement across token standards is noise.
//
// C-12f17fd555: rows b6c0484194, be5532323d, 135acfc612, 4badf2ba8a,
// a836f14fd6 — the review's "top-ranked noise".

import (
	"testing"

	"websec/internal/validation"
)

func nodeWith(calls ...string) validation.Value {
	arr := make([]validation.Value, 0, len(calls))
	for _, c := range calls {
		arr = append(arr, validation.VStr(c))
	}
	return validation.VObj(validation.KV{K: "calls_external", V: validation.VArr(arr...)})
}

func TestSymmetryCellsAssetStandard(t *testing.T) {
	cases := []struct {
		call string
		want string
	}{
		{"IERC20Upgradeable.safeTransfer", "erc20"},
		{"IMorphERC20Upgradeable.burn", "erc20"},
		{"IERC1155Upgradeable.safeTransferFrom", "erc1155"},
		{"IERC721Upgradeable.safeTransferFrom", "erc721"},
	}
	for _, tc := range cases {
		cells := symmetryCells("C", "deposit", 1, nodeWith(tc.call))
		if len(cells) != 1 {
			t.Fatalf("%s: expected 1 cell, got %d", tc.call, len(cells))
		}
		if cells[0].Asset != tc.want {
			t.Errorf("%s: asset = %q, want %q", tc.call, cells[0].Asset, tc.want)
		}
	}
}

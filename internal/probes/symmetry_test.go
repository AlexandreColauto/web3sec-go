package probes

// symmetry_test.go — IMPROVEMENTS C2. The morph G-02 shape (the custody
// fixture: a base recovery path paying out of its own balance while the
// derived forward path burns) is a FAMILY divergence, not a per-contract
// quirk: the matrix must see both ends, name both members and ask who funds
// the difference.

import (
	"path/filepath"
	"testing"

	"websec/internal/validation"
)

func symFixture(t *testing.T, kind string) validation.Value {
	t.Helper()
	return t29Index(t, filepath.Join(t29ProbesDir, "custody", kind))
}

func TestPrimitiveMatrixSeesTheGatewayFamilyDivergence(t *testing.T) {
	idx := symFixture(t, "buggy")
	m := PrimitiveMatrix(idx)
	stats := vGet(m, "stats")
	if vInt(stats, "families") != 1 {
		t.Fatalf("families = %s (want the one gateway family: %s)",
			t29JSON(stats), t29JSON(vGet(m, "families")))
	}
	fam := vList(m, "families")[0]
	if vStr(fam, "name") != "L1ERC20Gateway" {
		t.Errorf("family = %q", vStr(fam, "name"))
	}
	if got, want := t29StrJSON(vStrList(fam, "members")),
		t29StrJSON([]string{"L1ERC20Gateway", "L1ReverseCustomGateway"}); got != want {
		t.Errorf("members = %s, want %s", got, want)
	}
	// The cells carry the direction/asset split the per-contract probe cannot.
	directions := map[string]string{}
	for _, c := range vObjList(fam, "cells") {
		directions[vStr(c, "contract")+"/"+vStr(c, "direction")+"/"+vStr(c, "asset")] =
			vStr(c, "primitive")
	}
	if got := directions["L1ERC20Gateway/drop/erc20"]; got != "transfer-out" {
		t.Errorf("drop cell = %q, want transfer-out", got)
	}
	if got := directions["L1ReverseCustomGateway/deposit/erc20"]; got != "transfer-in" {
		t.Errorf("deposit cell = %q, want transfer-in", got)
	}
	if got := directions["L1ReverseCustomGateway/deposit/share"]; got != "burn" {
		t.Errorf("burn cell = %q", got)
	}
}

func TestPrimitiveMatrixFundingMismatchNamesBothEnds(t *testing.T) {
	m := PrimitiveMatrix(symFixture(t, "buggy"))
	divs := vList(m, "divergences")
	if len(divs) != 1 {
		t.Fatalf("divergences = %s", t29JSON(validation.VArr(divs...)))
	}
	d := divs[0]
	if vStr(d, "kind") != SymFundingMismatch {
		t.Errorf("kind = %q", vStr(d, "kind"))
	}
	if vStr(d, "family") != "L1ERC20Gateway" || vStr(d, "asset") != "erc20" {
		t.Errorf("family/asset = %q/%q", vStr(d, "family"), vStr(d, "asset"))
	}
	exp := vGet(d, "expected_site")
	obs := vGet(d, "observed_site")
	if vStr(exp, "contract") != "L1ReverseCustomGateway" ||
		vStr(exp, "function") != "_deposit" || vStr(d, "expected") != "burn" {
		t.Errorf("expected end = %s (%s)", t29JSON(exp), vStr(d, "expected"))
	}
	if vStr(obs, "contract") != "L1ERC20Gateway" ||
		vStr(obs, "function") != "onDropMessage" || vStr(d, "observed") != "transfer-out" {
		t.Errorf("observed end = %s (%s)", t29JSON(obs), vStr(d, "observed"))
	}
	q := vStr(d, "question")
	for _, want := range []string{"L1ERC20Gateway", "onDropMessage", "transfer-out",
		"who funds the difference?"} {
		if !containsSub(q, want) {
			t.Errorf("question %q lacks %q", q, want)
		}
	}
}

func TestPrimitiveMatrixIsDeterministicAndCleanStaysSilent(t *testing.T) {
	idx := symFixture(t, "buggy")
	a := validation.Canon(PrimitiveMatrix(idx), true)
	b := validation.Canon(PrimitiveMatrix(idx), true)
	if a != b {
		t.Error("PrimitiveMatrix is not byte-stable on the same index")
	}
	clean := PrimitiveMatrix(symFixture(t, "clean"))
	if n := vInt(vGet(clean, "stats"), "divergences"); n != 0 {
		t.Errorf("clean divergences = %d (%s)", n, t29JSON(vGet(clean, "divergences")))
	}
}

func TestSymmetrySurfaceRowsRideTheCustodyAxis(t *testing.T) {
	idx := symFixture(t, "buggy")
	spec := probesTable["custody-primitive"]
	paths := contractPaths(idx)
	raw, extras := symmetryRawRows(idx, validation.VNull())
	if len(raw) != 1 {
		t.Fatalf("symmetry rows = %d", len(raw))
	}
	rows := rankRows(collapse(raw, "custody-primitive", spec, paths), spec)
	final := make([]validation.Value, len(rows))
	for i, r := range rows {
		final[i] = finalize(r, "custody-primitive", spec)
	}
	final = attachSymmetry(final, extras)
	row := final[0]
	if vStr(row, "family") != "L1ERC20Gateway" ||
		vStr(row, "divergence") != SymFundingMismatch ||
		vStr(row, "direction") != "drop" || vStr(row, "asset") != "erc20" {
		t.Errorf("row = %s", t29JSON(row))
	}
	if vStr(row, "contract") != "L1ERC20Gateway" ||
		vStr(row, "consumer") != "onDropMessage" {
		t.Errorf("row site = %s", t29JSON(row))
	}
	if len(vStr(row, "row_id")) != 10 {
		t.Errorf("row_id = %q", vStr(row, "row_id"))
	}
	if vInt(row, "assertion_gap") != 4 || vInt(row, "tier") != 0 {
		t.Errorf("gap=%d tier=%d", vInt(row, "assertion_gap"), vInt(row, "tier"))
	}
	if !containsSub(vStr(row, "why"), "who funds the difference?") {
		t.Errorf("why = %q", vStr(row, "why"))
	}
	// The row is anchored on the family: its siblings carry the other member.
	if len(vList(row, "siblings")) == 0 {
		t.Errorf("siblings = %s", t29JSON(vGet(row, "siblings")))
	}
}

// containsSub is a tiny substring helper (strings.Contains, spelled out so the
// test file imports nothing extra).
func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestSymmetrySurfaceIsOptIn is the parity claim: the reference surface (zero
// ProbeOpts) carries no family divergence row, while the shipped options add
// exactly one on the custody axis — and the enriched surface still validates
// against probe_surface.schema.json.
func TestSymmetrySurfaceIsOptIn(t *testing.T) {
	idx := symFixture(t, "buggy")
	plain, err := BuildSurfaceOpts(idx, validation.VNull(), 12, 40, 3,
		"2026-01-01T00:00:00Z", ProbeOpts{})
	if err != nil {
		t.Fatalf("plain build: %v", err)
	}
	for _, row := range vList(plain, "rows") {
		if _, ok := vGetPresent(row, "family"); ok {
			t.Fatalf("row %s carries the C2 enrichment without opting in",
				vStr(row, "row_id"))
		}
	}
	prod, err := BuildSurfaceOpts(idx, validation.VNull(), 12, 40, 3,
		"2026-01-01T00:00:00Z", ProbeOpts{Symmetry: true})
	if err != nil {
		t.Fatalf("prod build: %v", err)
	}
	found := []validation.Value{}
	for _, row := range vList(prod, "rows") {
		if vStr(row, "divergence") != "" {
			found = append(found, row)
		}
	}
	if len(found) != 1 {
		t.Fatalf("divergence rows = %d (%s)", len(found), t29JSON(prod))
	}
	row := found[0]
	if vStr(row, "probe") != "custody-primitive" ||
		vStr(row, "family") != "L1ERC20Gateway" ||
		vStr(row, "custody") != "burns" {
		t.Errorf("row = %s", t29JSON(row))
	}
	if err := validation.Validate(prod, "probe_surface", 1); err != nil {
		t.Fatalf("enriched surface fails its own schema: %v", err)
	}
}

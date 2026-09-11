package probes

// symmetry_test.go — IMPROVEMENTS C2. The morph G-02 shape (the custody
// fixture: a base recovery path paying out of its own balance while the
// derived forward path burns) is a FAMILY divergence, not a per-contract
// quirk: the matrix must see both ends, name both members and ask who funds
// the difference.

import (
	"path/filepath"
	"strings"
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

// noncreditSurface builds the production-option surface over the NONCREDIT
// custody fixture: a family whose (deposit, erc20) column disagrees on
// transfer-in vs transfer-out, so the divergence's expected/observed primitive
// has no value in the schema's custody enum (mints|burns).
func noncreditSurface(t *testing.T) validation.Value {
	t.Helper()
	idx := t29Index(t, filepath.Join(t29ProbesDir, "custody", "noncredit"))
	surface, err := BuildSurfaceOpts(idx, validation.VNull(), 12, 40, 3,
		"2026-01-01T00:00:00Z", ProdProbeOpts())
	if err != nil {
		t.Fatalf("BuildSurfaceOpts: %v", err)
	}
	return surface
}

// TestCustodyPrimitiveOmitsCustodyForNonCreditDivergences is D1: the schema
// declares rows[].custody enum ["burns","mints"], so a divergence whose
// expected primitive is neither must omit the key — and the surface the emit
// path validates must then still pass that same validator end to end.
func TestCustodyPrimitiveOmitsCustodyForNonCreditDivergences(t *testing.T) {
	surface := noncreditSurface(t)
	rows := t29Rows(surface, "custody-primitive")
	cases := []struct {
		consumer string
		observed string
	}{
		{"_depositByTransfer", "transfer-out"},
		{"depositViaVault", "transfer-out"},
	}
	if len(rows) != len(cases) {
		t.Fatalf("divergence rows = %d, want %d (%s)", len(rows), len(cases),
			t29JSON(surface))
	}
	seen := map[string]struct{}{}
	for _, row := range rows {
		consumer := vStr(row, "consumer")
		seen[consumer] = struct{}{}
		if _, present := vGetPresent(row, "custody"); present {
			t.Errorf("%s: custody = %q, want the key omitted — the schema "+
				"enum is mints|burns and the expected primitive is %q",
				consumer, vStr(row, "custody"), vStr(row, "expected"))
		}
		if vStr(row, "expected") != "transfer-in" {
			t.Errorf("%s: expected = %q, want transfer-in", consumer,
				vStr(row, "expected"))
		}
		if !containsSub(vStr(row, "why"), "which of them is the custody model?") {
			t.Errorf("%s: why = %q", consumer, vStr(row, "why"))
		}
		for _, c := range cases {
			if c.consumer != consumer {
				continue
			}
			if got := vStr(row, "observed"); got != c.observed {
				t.Errorf("%s: observed = %q, want %q", consumer, got, c.observed)
			}
		}
	}
	for _, c := range cases {
		if _, ok := seen[c.consumer]; !ok {
			t.Errorf("no divergence row anchored on L1ReverseCustomGateway::%s",
				c.consumer)
		}
	}
	// The real entry point the emit path uses: `probes run --emit` writes the
	// surface through validation.WriteJson(out, surface, "probe_surface"), and
	// this is the validator underneath it.
	if err := validation.Validate(surface, "probe_surface", 1); err != nil {
		t.Fatalf("emit path surface fails its own schema: %v", err)
	}
}

// TestCustodyPrimitiveIdentitySurvivesOmittedCustody is D1's identity half:
// with `custody` omitted the fourth identity slot falls back to `observed`, so
// one (direction, asset) column with two different non-credit primitives still
// yields two different row_ids, and the observed primitive is what separates
// them (an empty slot would not).
func TestCustodyPrimitiveIdentitySurvivesOmittedCustody(t *testing.T) {
	rows := t29Rows(noncreditSurface(t), "custody-primitive")
	if len(rows) != 2 {
		t.Fatalf("divergence rows = %d, want 2 (%s)", len(rows),
			t29JSON(validation.VArr(rows...)))
	}
	ids := map[string]struct{}{}
	for _, row := range rows {
		rid := vStr(row, "row_id")
		if len(rid) != 10 {
			t.Errorf("row_id = %q, want 10 hex chars", rid)
		}
		if _, dup := ids[rid]; dup {
			t.Errorf("two divergence rows share row_id %q", rid)
		}
		ids[rid] = struct{}{}
		if _, present := vGetPresent(row, "custody"); present {
			t.Errorf("row %s still carries custody = %q", rid, vStr(row, "custody"))
		}
		if got := RowIDFor(row); got != rid {
			t.Errorf("RowIDFor(row) = %q, row_id = %q — the emitted id is not "+
				"content-derived from the finalized row", got, rid)
		}
	}
	// The fourth slot must be the observed primitive, not "" — otherwise
	// renaming it would leave the id untouched.
	first := rows[0]
	moved := t29Clone(t, first)
	vSet(&moved, "observed", validation.VStr("transfer-in"))
	if RowIDFor(moved) == vStr(first, "row_id") {
		t.Errorf("row %s ignores observed with custody omitted: the fourth "+
			"identity slot is empty, so distinct divergences can collide",
			vStr(first, "row_id"))
	}
}

// TestMintAndBurnCustodyLabelsSurviveTheOmission: only primitives the schema
// cannot name lose the key — mint/burn rows keep carrying "mints"/"burns".
func TestMintAndBurnCustodyLabelsSurviveTheOmission(t *testing.T) {
	for _, tc := range []struct {
		primitive string
		label     string
	}{
		{"mint", "mints"},
		{"burn", "burns"},
		{"transfer-in", ""},
		{"transfer-out", ""},
		{"send-native", ""},
	} {
		if got := symCustodyLabel(tc.primitive); got != tc.label {
			t.Errorf("symCustodyLabel(%q) = %q, want %q", tc.primitive, got,
				tc.label)
		}
	}
	surface, err := BuildSurfaceOpts(t29Index(t,
		filepath.Join(t29ProbesDir, "custody", "buggy")), validation.VNull(),
		12, 40, 3, "2026-01-01T00:00:00Z", ProdProbeOpts())
	if err != nil {
		t.Fatalf("BuildSurfaceOpts: %v", err)
	}
	rows := t29Rows(surface, "custody-primitive")
	if len(rows) != 2 {
		t.Fatalf("custody rows = %d, want the 1 burn row + its divergence (%s)",
			len(rows), t29JSON(surface))
	}
	for _, row := range rows {
		if got := vStr(row, "custody"); got != "burns" {
			t.Errorf("row %s custody = %q, want \"burns\"", vStr(row, "row_id"),
				got)
		}
	}
	if err := validation.Validate(surface, "probe_surface", 1); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// TestFinalizeKeepsAbsentDeclaredFieldsExceptCustody pins the narrowed rule:
// `custody` is the only declared field a row may lose. Every other declared
// field the row does not carry is still copied as null — and because the
// schema types those fields non-nullably, a null keeps emit validation loud.
// A generic "omit what the row lacks" rule would silently ship the key-less
// row instead.
func TestFinalizeKeepsAbsentDeclaredFieldsExceptCustody(t *testing.T) {
	// A custody row with no custody (the D1 case) and no forward (an
	// unexpected omission that must stay visible).
	row := validation.VObj(
		kv("row_id", validation.VStr("0123456789")),
		kv("tier", validation.VInt(0)),
		kv("rank", validation.VInt(1)),
		kv("assertion_gap", validation.VInt(0)),
		kv("gate", validation.VStr("gate")),
		kv("siblings", validation.VArr(validation.VObj(
			kv("contract", validation.VStr("C")),
			kv("line", validation.VInt(1))))),
		kv("contract", validation.VStr("C")),
		kv("consumer", validation.VStr("f")),
		kv("consumer_line", validation.VInt(1)),
		kv("base", validation.VStr("B")),
		kv("base_line", validation.VInt(2)),
		kv("inherited", validation.VBool(true)),
	)
	spec := probesTable["custody-primitive"]
	out := finalize(row, "custody-primitive", spec)

	if _, present := vGetPresent(out, "custody"); present {
		t.Errorf("custody absent from the row reached the surface: the D1 "+
			"exception must omit it (%s)", t29JSON(out))
	}
	got, present := vGetPresent(out, "forward")
	if !present {
		t.Fatalf("forward absent from the row was dropped, not copied as "+
			"null: an unexpected omission must still fail emit validation (%s)",
			t29JSON(out))
	}
	if got.Kind != validation.Null {
		t.Errorf("forward = %s, want null so the schema rejects it", t29JSON(got))
	}
	if !vBool(out, "inherited") {
		t.Errorf("inherited = %s, want true", t29JSON(vGet(out, "inherited")))
	}

	// The loud signal itself: a declared field nulled on a real surface is
	// rejected by the same validator the emit path calls.
	surface := noncreditSurface(t)
	rows := vObjList(surface, "rows")
	nulled := false
	for i := range rows {
		if vStr(rows[i], "probe") != "custody-primitive" {
			continue
		}
		if _, ok := vGetPresent(rows[i], "forward"); ok {
			vSet(&rows[i], "forward", validation.VNull())
			nulled = true
			break
		}
	}
	if !nulled {
		t.Fatalf("noncredit surface has no custody row carrying forward (%s)",
			t29JSON(surface))
	}
	vSet(&surface, "rows", validation.VArr(rows...))
	if err := validation.Validate(surface, "probe_surface", 1); err == nil {
		t.Error("a nulled declared field validated: the fail-loud path was " +
			"weakened")
	}
}

// TestFundingMismatchCarriesPayoutQuestion: the funding-mismatch question
// ends with the payout-funding sub-question, so dismissing the row requires
// naming the crediting primitive (or recording that none exists).
func TestFundingMismatchCarriesPayoutQuestion(t *testing.T) {
	rows := fundingMismatchRows(t) // the existing fixture builder
	if len(rows) == 0 {
		t.Fatal("fixture lost its funding-mismatch row")
	}
	const suffix = " Who funds the observed payout — name the primitive that " +
		"credits the paying balance for this asset; if none exists, the payout " +
		"draws from an unfunded balance."
	if !strings.HasSuffix(vStr(rows[0], "question"), suffix) {
		t.Errorf("question = %q\nwant suffix %q", vStr(rows[0], "question"), suffix)
	}
	// Non-mismatch divergences stay unchanged.
	for _, r := range nonMismatchDivergenceRows(t) {
		if strings.Contains(vStr(r, "question"), "Who funds the observed payout") {
			t.Errorf("sub-question leaked into a %q row", vStr(r, "divergence"))
		}
	}
}

// divergenceRows runs the shipped surface pipeline over one custody fixture
// and returns only the rows carrying a divergence. The row's operator-visible
// `why` IS the divergence's question (symmetryRawRows copies it into the
// extras and attachSymmetry stamps it), so each returned row also exposes it
// under the divergence's own field name `question`: the same string the
// `symmetry` CLI prints and the matrix renders.
func divergenceRows(t *testing.T, root string) []validation.Value {
	t.Helper()
	surface, err := BuildSurfaceOpts(t29Index(t, root), validation.VNull(),
		12, 40, 3, "2026-01-01T00:00:00Z", ProdProbeOpts())
	if err != nil {
		t.Fatalf("BuildSurfaceOpts(%s): %v", root, err)
	}
	out := []validation.Value{}
	for _, row := range t29Rows(surface, "custody-primitive") {
		if vStr(row, "divergence") == "" {
			continue
		}
		view := copyObj(row)
		vSet(&view, "question", validation.VStr(vStr(row, "why")))
		out = append(out, view)
	}
	return out
}

// fundingMismatchRows is the G-02 fixture (custody/buggy): the derived forward
// path burns while the inherited recovery path pays out of its own balance.
func fundingMismatchRows(t *testing.T) []validation.Value {
	t.Helper()
	out := []validation.Value{}
	for _, r := range divergenceRows(t, filepath.Join(t29ProbesDir, "custody", "buggy")) {
		if vStr(r, "divergence") == SymFundingMismatch {
			out = append(out, r)
		}
	}
	return out
}

// nonMismatchDivergenceRows is the NONCREDIT fixture: two sibling members
// disagree on the (deposit, erc20) primitive, so the family carries
// member-disagreement divergences and no funding mismatch.
func nonMismatchDivergenceRows(t *testing.T) []validation.Value {
	t.Helper()
	out := []validation.Value{}
	for _, r := range divergenceRows(t, filepath.Join(t29ProbesDir, "custody", "noncredit")) {
		if vStr(r, "divergence") != SymFundingMismatch {
			out = append(out, r)
		}
	}
	return out
}

package probes

// absence_test.go — IMPROVEMENTS C3: the never-asserted-consumption rows.
//
// C3 is NOT shipped (see ProbeOpts.AbsenceRows for the Morph measurements
// that retired it). These tests pin the two facts that matter while it sits
// behind the flag: ProdProbeOpts leaves it off, and when it is switched on
// it fires only on a real lifecycle hand-off — a concept written by one
// stage, read by another, asserted nowhere — never on a lone unguarded
// setter.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// absenceHandoffSrc is the positive fixture: submitRoot writes the pending
// root the later-declared executeRoot reads back, and nothing asserts the
// concept at any class — the reference probe's skip drops the key before a
// row or a blind entry. A mapping (not a plain state variable) because the
// index only records a `read` use for the forms it can see through:
// `executedRoot = pendingRoot` yields no read use at all, while
// `executedRoot = pendingRoots[i]` does. The index parameter is a bare `i`
// so its concept key carries no ":" and the parameter noise the rule
// deliberately ignores cannot show up here.
const absenceHandoffSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Bridge {
    mapping(uint256 => bytes32) private pendingRoots;
    bytes32 private executedRoot;

    function submitRoot(uint256 i, bytes32 root) external {
        pendingRoots[i] = root;
    }

    function executeRoot(uint256 i) external {
        executedRoot = pendingRoots[i];
    }
}
`

// absenceLoneSrc is the negative fixture: one unguarded setter, no second
// stage reading what it wrote. An unguarded setter with no reader is not an
// enforcement-timing question, and the hand-off gate must not oblige it.
const absenceLoneSrc = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    mapping(uint256 => bytes32) private roots;

    function setRoot(uint256 i, bytes32 r) external {
        roots[i] = r;
    }
}
`

func absenceFixture(t *testing.T, kind string) validation.Value {
	t.Helper()
	return t29Index(t, filepath.Join(t29ProbesDir, "assertion_strength", kind))
}

func absenceTree(t *testing.T, name, src string) validation.Value {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, name), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return t29Index(t, root)
}

func absenceSurface(t *testing.T, idx validation.Value, opts ProbeOpts) validation.Value {
	t.Helper()
	surface, err := BuildSurfaceOpts(idx, validation.VNull(), 12, 40, 3,
		"2026-01-01T00:00:00Z", opts)
	if err != nil {
		t.Fatalf("BuildSurfaceOpts: %v", err)
	}
	if err := validation.Validate(surface, "probe_surface", 1); err != nil {
		t.Fatalf("surface fails its own schema: %v", err)
	}
	return surface
}

// TestAbsenceRowsAreNotShipped: the shipped options must not carry C3. The
// Morph measurement is the reason — 421 rows whose top ranks were
// constructors, pure computations and msg:sender — so switching it back on
// has to be a deliberate edit that updates this test.
func TestAbsenceRowsAreNotShipped(t *testing.T) {
	if ProdProbeOpts().AbsenceRows {
		t.Fatal("ProdProbeOpts enables AbsenceRows again — read the Morph " +
			"measurements in ProbeOpts.AbsenceRows before shipping it")
	}
	shipped := absenceSurface(t, absenceTree(t, "Bridge.sol", absenceHandoffSrc),
		ProdProbeOpts())
	for _, row := range t29Rows(shipped, "assertion-strength") {
		if vStr(row, "asserter") == "" {
			t.Fatalf("shipped surface carries an absence row: %s",
				t29JSON(row))
		}
	}
}

// TestAbsenceRowsFireOnALifecycleHandoff: with the flag on, the hand-off
// fixture obliges exactly one row — empty asserter, gap 4, and a why that
// names the downstream reader the missing check would have protected.
func TestAbsenceRowsFireOnALifecycleHandoff(t *testing.T) {
	idx := absenceTree(t, "Bridge.sol", absenceHandoffSrc)
	plain := absenceSurface(t, idx, ProbeOpts{})
	if rows := t29Rows(plain, "assertion-strength"); len(rows) != 0 {
		t.Fatalf("reference rows = %d, want 0 (%s)",
			len(rows), t29JSON(validation.VArr(rows...)))
	}
	on := absenceSurface(t, idx, ProbeOpts{AbsenceRows: true})
	rows := t29Rows(on, "assertion-strength")
	if len(rows) != 1 {
		t.Fatalf("C3 rows = %d, want 1 (%s)", len(rows),
			t29JSON(validation.VArr(rows...)))
	}
	row := rows[0]
	if vStr(row, "asserter") != "" || vInt(row, "assert_class") != 0 ||
		vInt(row, "own_class") != 0 || vInt(row, "assertion_gap") != 4 {
		t.Fatalf("row is not an absence row: %s", t29JSON(row))
	}
	if vStr(row, "contract") != "Bridge" || vStr(row, "consumer") != "submitRoot" {
		t.Fatalf("row site = %s", t29JSON(row))
	}
	for _, want := range []string{"submitRoot", "at any class",
		"which stage should check it", "executeRoot"} {
		if !strings.Contains(vStr(row, "why"), want) {
			t.Fatalf("why %q lacks %q", vStr(row, "why"), want)
		}
	}
}

// TestAbsenceRowsSkipLoneUncheckedSetters: the noise the hand-off gate
// exists to stop. A single function writing storage nobody reads back is
// not an enforcement-timing obligation, and neither is a key that only ever
// arrives as a parameter.
func TestAbsenceRowsSkipLoneUncheckedSetters(t *testing.T) {
	on := absenceSurface(t, absenceTree(t, "Vault.sol", absenceLoneSrc),
		ProbeOpts{AbsenceRows: true})
	if rows := t29Rows(on, "assertion-strength"); len(rows) != 0 {
		t.Fatalf("lone setter fired %d absence rows (%s)", len(rows),
			t29JSON(validation.VArr(rows...)))
	}
}

// TestAbsenceLeavesJoinedRowsAlone: on the G-01 buggy fixture the joined
// row (asserted class-4 in finalizeBatch, consumed class-0 in commitBatch)
// keeps its asserter and template-rendered why — the post-pass rewrites
// only rows no asserter joined.
func TestAbsenceLeavesJoinedRowsAlone(t *testing.T) {
	prod := absenceSurface(t, absenceFixture(t, "buggy"),
		ProbeOpts{AbsenceRows: true})
	rows := t29Rows(prod, "assertion-strength")
	if len(rows) == 0 {
		t.Fatal("C3 surface lost the joined row")
	}
	joined := false
	for _, row := range rows {
		if vStr(row, "asserter") == "" {
			continue
		}
		joined = true
		if vStr(row, "asserter") != "finalizeBatch" {
			t.Errorf("asserter = %q, want finalizeBatch (%s)",
				vStr(row, "asserter"), t29JSON(row))
		}
		if strings.Contains(vStr(row, "why"), "which stage should check it") {
			t.Errorf("joined row carries the absence question: %s",
				t29JSON(row))
		}
	}
	if !joined {
		t.Fatalf("no joined row among %d C3 rows (%s)", len(rows),
			t29JSON(validation.VArr(rows...)))
	}
}

// TestAbsenceSurfaceIsOptIn is the parity claim: the reference surface
// (zero ProbeOpts) carries no absence row, while the flag adds them on the
// assertion axis — and both validate.
func TestAbsenceSurfaceIsOptIn(t *testing.T) {
	idx := absenceTree(t, "Bridge.sol", absenceHandoffSrc)
	plain := absenceSurface(t, idx, ProbeOpts{})
	for _, row := range t29Rows(plain, "assertion-strength") {
		if vStr(row, "asserter") == "" {
			t.Fatalf("row %s carries the C3 enrichment without opting in",
				vStr(row, "row_id"))
		}
	}
}

// TestCollapseNearKeysDedupesTokenPermutations: near values carrying the
// same token set collapse to one entry; other blind kinds pass through;
// each (contract, key) group is capped.
func TestCollapseNearKeysDedupesTokenPermutations(t *testing.T) {
	near := func(key, near, contract string) validation.Value {
		return blindEntry("near-key", key, validation.VStr(near),
			kv("contract", validation.VStr(contract)),
			kv("function", validation.VStr("f")),
			kv("line", validation.VInt(1)),
			kv("reason", validation.VStr("r")))
	}
	other := blindEntry("rejected-site", "k", validation.VNull(),
		kv("contract", validation.VStr("C")),
		kv("function", validation.VStr("f")),
		kv("line", validation.VInt(1)),
		kv("reason", validation.VStr("r")))
	in := []validation.Value{
		near("k", "batch:header:parent", "C"),
		near("k", "header:parent:batch", "C"),
		near("k", "batch:parent", "C"),
		other,
	}
	got := collapseNearKeys(in)
	if len(got) != 3 {
		t.Fatalf("collapsed = %d entries, want 2 near + 1 other (%s)",
			len(got), t29JSON(validation.VArr(got...)))
	}
	if vStr(got[0], "near") != "batch:header:parent" ||
		vStr(got[1], "near") != "batch:parent" {
		t.Fatalf("kept the wrong representatives: %s",
			t29JSON(validation.VArr(got...)))
	}
	// The cap: 6 distinct near values on one key keep 5.
	many := []validation.Value{}
	for _, n := range []string{"a:b", "a:c", "a:d", "a:e", "a:f", "a:g"} {
		many = append(many, near("k2", n, "C"))
	}
	if got := collapseNearKeys(many); len(got) != nearKeyCap {
		t.Fatalf("capped = %d, want %d", len(got), nearKeyCap)
	}
}

package roles

// T38 (golden v5) regressions, both surfaced end-to-end by the P4 fixture's
// backfilled proposer bundle:
//
//  1. deciding_propositions is passed through VERBATIM for schema_version 2
//     rows — Python's `row.get(...)` yields None when the field is absent, so
//     the JSON must be null, not []. The port emitted [] and diverged from
//     the reference on every campaign negative-memory row.
//  2. pattern/evidence_summary are clipped by CHARACTERS (`[:300]`/`[:200]`),
//     not bytes; the port sliced bytes, so a multi-byte rune straddling the
//     budget shortened the row (and the backfilled bundle) relative to Python.

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

func rowObj(pairs ...validation.KV) validation.Value {
	return validation.VObj(pairs...)
}

func TestSummarizeNonIssueDecidingPropositionsVerbatim(t *testing.T) {
	base := func(over ...validation.KV) validation.Value {
		pairs := []validation.KV{
			{K: "memory_id", V: validation.VStr("MEM-abc")},
			{K: "status", V: validation.VStr("DISPROVED")},
			{K: "schema_version", V: validation.VInt(2)},
		}
		return rowObj(append(pairs, over...)...)
	}

	// v2 with the field ABSENT -> null (Python's dict.get default).
	got := summarizeNonIssue(base(), "")
	if dp := objAt(got, "deciding_propositions"); dp.Kind != validation.Null {
		t.Fatalf("absent deciding_propositions = %v, want null", dp)
	}
	// v2 with an explicit null -> null.
	got = summarizeNonIssue(base(validation.KV{K: "deciding_propositions",
		V: validation.VNull()}), "")
	if dp := objAt(got, "deciding_propositions"); dp.Kind != validation.Null {
		t.Fatalf("null deciding_propositions = %v, want null", dp)
	}
	// v2 with a list -> the list.
	got = summarizeNonIssue(base(validation.KV{K: "deciding_propositions",
		V: validation.VArr(validation.VStr("p1"), validation.VStr("p2"))}), "")
	if dp := objAt(got, "deciding_propositions"); dp.Kind != validation.Arr ||
		len(dp.A) != 2 || dp.A[1].S != "p2" {
		t.Fatalf("list deciding_propositions = %v, want 2 items", dp)
	}
	// v1 rows carry no proposition structure -> [].
	got = summarizeNonIssue(rowObj(
		validation.KV{K: "memory_id", V: validation.VStr("MEM-old")},
		validation.KV{K: "schema_version", V: validation.VInt(1)},
	), "")
	if dp := objAt(got, "deciding_propositions"); dp.Kind != validation.Arr ||
		len(dp.A) != 0 {
		t.Fatalf("v1 deciding_propositions = %v, want []", dp)
	}
}

func TestSummarizeNonIssueClipsByRunes(t *testing.T) {
	// 250 runes / 500 bytes of evidence_summary and 350 runes of pattern: the
	// cuts must be 200/300 CHARACTERS (Python's slice), so the multi-byte
	// em dash every 5th rune must not shorten the result.
	long := strings.Repeat("abcd\u2014", 50) // 250 runes
	row := rowObj(
		validation.KV{K: "memory_id", V: validation.VStr("MEM-runes")},
		validation.KV{K: "schema_version", V: validation.VInt(2)},
		validation.KV{K: "pattern", V: validation.VStr(strings.Repeat("x", 350))},
		validation.KV{K: "evidence_summary", V: validation.VStr(long)},
	)
	got := summarizeNonIssue(row, "")
	if n := len([]rune(objStr(got, "evidence_summary"))); n != 200 {
		t.Fatalf("evidence_summary runes = %d, want 200", n)
	}
	if n := len([]rune(objStr(got, "pattern"))); n != 300 {
		t.Fatalf("pattern runes = %d, want 300", n)
	}
	if !strings.HasSuffix(objStr(got, "evidence_summary"), "\u2014") {
		t.Fatalf("evidence_summary cut mid-rune: %q",
			objStr(got, "evidence_summary"))
	}
}

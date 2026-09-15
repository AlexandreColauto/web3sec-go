package state

// zz_r40c_test.go — r40c P2-3, the AUDIT half of waivers.jsonl framing.
//
// waivers.jsonl is a line-framed projection (row + completion.waived event),
// and readWaiverRowsR12 is the reader verify/audit use. It frames on the
// physical "\n"-delimited line with BlankLine as the blank predicate, and
// this file pins that it keeps answering exactly that — including for a row
// the pre-r40c writer left on disk with a raw U+0085/U+2028/U+2029 inside
// the reason. completion.Waivers used to frame the same bytes with CPython's
// str.splitlines() (whose boundary set contains those three runes), so the
// proof saw two fragments where this reader saw one row: verify green, the
// waiver never consulted. One frame now — the physical line — shared by both
// readers; the r40c writer also escapes the three codepoints so the frame
// can never be broken again by a written row.
//
// This package's own behavior did not change (the split was already "\n");
// these pins exist so the AUDIT side cannot silently drift back to a
// second, exotic-separator framing while the proof side moves.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

func zzR40cAuditCamp(t *testing.T, id string) *Campaign {
	t.Helper()
	c, err := Init(t.TempDir(), "r40c audit framing", InitOpts{CampaignID: id})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	return c
}

// TestR40cAuditReaderFramesPhysicalLines: three rows — one carrying the
// escape the post-r40c writer emits, one carrying the pre-r40c raw
// separator, one plain — are three rows, one per physical line, and the
// row/event pairing over them verifies green.
func TestR40cAuditReaderFramesPhysicalLines(t *testing.T) {
	c := zzR40cAuditCamp(t, "C-r40caudit0001")
	wp := filepath.Join(c.Dir, "waivers.jsonl")
	withEscape := `{"stage": "discovery", "subject": "*", ` +
		`"reason": "escaped \u2028 reason"}`
	withRaw := `{"stage": "dedup", "subject": "*", ` +
		`"reason": "legacy ` + string('\u2028') + ` reason"}`
	plain := `{"stage": "learning", "subject": "*", "reason": "plain"}`
	body := withEscape + "\n" + withRaw + "\n" + plain + "\n"
	if err := os.WriteFile(wp, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, err, line := readWaiverRowsR12(wp)
	if err != nil {
		t.Fatalf("readWaiverRowsR12: %v (line %d)", err, line)
	}
	if len(rows) != 3 {
		t.Fatalf("readWaiverRowsR12 returned %d row(s), want 3 "+
			"(one per physical line)", len(rows))
	}
	if got := objStr(rows[0], "reason"); got != "escaped \u2028 reason" {
		t.Errorf("escaped-form reason = %q", got)
	}
	if got := objStr(rows[1], "reason"); got != "legacy \u2028 reason" {
		t.Errorf("raw-form reason = %q", got)
	}
	// The pairing verify enforces: every row anchored by its event.
	for _, stage := range []string{"discovery", "dedup", "learning"} {
		ref := stage
		data := validation.VObj(
			kv("subject", validation.VStr("*")),
			kv("actor", validation.VStr("tester")),
			kv("reason", validation.VStr("paired")),
		)
		if _, err := c.Log("completion.waived", &ref, &data); err != nil {
			t.Fatal(err)
		}
	}
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK || len(v.Problems) != 0 {
		t.Errorf("the three-row file must verify green: ok=%v problems=%v",
			v.OK, v.Problems)
	}
}

// TestR40cAuditReaderBlankPredicateIsBlankLine: ASCII blanks are blanks; a
// U+00A0-only line is a RECORD (the r38 law), reported at its physical line
// number — the same answer completion.Waivers gives.
func TestR40cAuditReaderBlankPredicateIsBlankLine(t *testing.T) {
	c := zzR40cAuditCamp(t, "C-r40caudit0002")
	wp := filepath.Join(c.Dir, "waivers.jsonl")
	row1 := `{"stage": "discovery", "subject": "*"}`
	row2 := `{"stage": "dedup", "subject": "*"}`
	// ASCII blank lines — including a whitespace-only one — are blanks.
	if err := os.WriteFile(wp,
		[]byte(row1+"\n \t\n"+row2+"\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, err, _ := readWaiverRowsR12(wp)
	if err != nil {
		t.Fatalf("ASCII blanks must not be records: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("readWaiverRowsR12 returned %d row(s), want 2", len(rows))
	}
	if BlankLine("\u00a0") || blankLine("\u00a0") {
		t.Fatal("U+00A0 must not be blank to THE predicate")
	}
	if err := os.WriteFile(wp,
		[]byte(row1+"\n\u00a0\n"+row2+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, err, line := readWaiverRowsR12(wp)
	if err == nil {
		t.Fatal("a U+00A0-only waiver line is a record the decoder cannot " +
			"parse — the audit reader must fail closed")
	}
	if rows != nil || line != 2 {
		t.Errorf("readWaiverRowsR12 = (%d rows, line %d), want (nil, 2)",
			len(rows), line)
	}
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Fatalf("verify must go red over the unparseable row: %v", v.Problems)
	}
	found := false
	for _, p := range v.Problems {
		if strings.Contains(p, "waivers.jsonl line 2") {
			found = true
		}
	}
	if !found {
		t.Errorf("verify must name the file and the physical line: %v",
			v.Problems)
	}
}

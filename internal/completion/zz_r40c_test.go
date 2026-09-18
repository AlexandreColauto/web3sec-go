package completion

// zz_r40c_test.go — r40c P2-3: a waiver reason carrying U+0085 / U+2028 /
// U+2029, the three CPython line boundaries that json.dumps(ensure_ascii=
// False) leaves RAW.
//
// Pre-fix shape (reproduced against the baseline binary): `waive <C>
// discovery --reason $'abcdefghij\u2028klmnopqrst' --actor tester` exited 0
// with "waived discovery/*", waivers.jsonl held the raw rune, `verify` said
// ok:true with no problems — and `prove <C> --stage discovery` answered
// "discovery open [authoritative] — proof error: unexpected EOF" rc 1. One
// recorded disposition, reported as success, green in the audit, and NEVER
// consulted: the writer emitted a row that str.splitlines() frames as two,
// while readWaiverRowsR12 (verify's reader) frames on "\n" and saw one clean
// row. Two readers, one byte string, two answers.
//
// The fix has two halves and these tests pin both:
//
//  1. the writer escapes the three codepoints as \uXXXX (the same string
//     VALUE to every JSON reader), so one row is one physical line under
//     every framing — and the em-dash the golden replay pins stays raw;
//  2. both readers answer the same frame — the physical "\n"-delimited
//     line with state.BlankLine as the blank predicate — so a row the OLD
//     writer left on disk (raw separator, already accepted and reported as
//     success) is now honoured instead of being split in half.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// zzR40cSep is the three-codepoint table the finding names.
var zzR40cSep = []struct {
	name string
	r    rune
	esc  string
}{
	{"U+0085 NEL", '\u0085', `\u0085`},
	{"U+2028 LINE SEPARATOR", '\u2028', `\u2028`},
	{"U+2029 PARAGRAPH SEPARATOR", '\u2029', `\u2029`},
}

func zzR40cCamp(t *testing.T, id string) *state.Campaign {
	t.Helper()
	c, err := state.Init(t.TempDir(), "r40c P2-3 waive program",
		state.InitOpts{CampaignID: id})
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	return c
}

func zzR40cSha(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// zzR40cPhysicalLines counts the file's PHYSICAL records: one row per
// "\n"-delimited line, which is the frame the writer uses and both readers
// now answer.
func zzR40cPhysicalLines(raw []byte) int {
	n := 0
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.TrimRight(ln, " \t\r\v\f") != "" {
			n++
		}
	}
	return n
}

// TestR40cSeparatorReasonIsOneRowAndHonoured is the finding's repro, fixed:
// the row lands as ONE physical line carrying the escape, the reason reads
// back byte-identical through the proof's own reader, the proof is DONE (a
// stage-wide waiver is honoured), and verify is green over the pair.
func TestR40cSeparatorReasonIsOneRowAndHonoured(t *testing.T) {
	for i, tc := range zzR40cSep {
		t.Run(tc.name, func(t *testing.T) {
			c := zzR40cCamp(t, "C-r40csep0000"+string(rune('1'+i)))
			reason := "abcdefghij" + string(tc.r) + "klmnopqrst"
			row, err := Waive(c, "discovery", "", reason, "tester")
			if err != nil {
				t.Fatalf("Waive must accept a %s reason: %v", tc.name, err)
			}
			if got := validation.ObjStr(row, "reason"); got != reason {
				t.Fatalf("returned reason = %q, want %q", got, reason)
			}
			raw, err := os.ReadFile(WaiversPath(c))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), string(tc.r)) {
				t.Errorf("raw %s on disk — the row can split under "+
					"str.splitlines(): %q", tc.name, raw)
			}
			if !strings.Contains(string(raw), tc.esc) {
				t.Errorf("waivers.jsonl must carry the %s escape: %q",
					tc.esc, raw)
			}
			if n := zzR40cPhysicalLines(raw); n != 1 {
				t.Errorf("waivers.jsonl holds %d physical line(s), want 1: %q",
					n, raw)
			}
			// The proof's reader: one row, the reason unchanged.
			rows, err := Waivers(c, "")
			if err != nil {
				t.Fatalf("Waivers: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("Waivers returned %d row(s), want 1", len(rows))
			}
			if got := validation.ObjStr(rows[0], "reason"); got != reason {
				t.Errorf("read-back reason = %q, want %q", got, reason)
			}
			// The proof HONOURS it — the whole point of the finding.
			pr, err := ProofStatus(c, "discovery")
			if err != nil {
				t.Fatal(err)
			}
			if d := validation.ObjAt(pr, "done"); d.Kind != validation.Bool || !d.B {
				t.Errorf("the waiver was not honoured: %s",
					validation.PyRepr(pr))
			}
			if note := validation.ObjStr(pr, "note"); note == "proof raised" {
				t.Errorf("proof raised instead of honouring the waiver: %s",
					validation.PyRepr(pr))
			}
			// verify: the row and its completion.waived event agree.
			v, err := c.VerifyLog()
			if err != nil {
				t.Fatal(err)
			}
			if !v.OK || len(v.Problems) != 0 {
				t.Errorf("verify over the escaped row: ok=%v problems=%v",
					v.OK, v.Problems)
			}
		})
	}
}

// TestR40cLegacyRawSeparatorRowReadsLikeTheAuditReader pins the second
// half: a row the PRE-fix writer left on disk (raw separator, one "\n"-
// terminated physical line) is read identically by the proof's reader and
// by verify's — as the single valid JSON row its bytes are — and the
// disposition is honoured. Pre-fix this file was verify-green and
// prove-red, which is "accepted and silently ignored".
func TestR40cLegacyRawSeparatorRowReadsLikeTheAuditReader(t *testing.T) {
	c := zzR40cCamp(t, "C-r40clegacy001")
	reason := "legacy raw " + string('\u2028') + " separator reason"
	// The old writer's bytes, hand-placed: the rune RAW inside the string.
	line := `{"stage": "discovery", "subject": "*", "reason": "` + reason +
		`", "actor": "tester", "at": "2026-01-02T03:04:05.000006+00:00"}` +
		"\n"
	if err := os.WriteFile(WaiversPath(c), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	ref := "discovery"
	data := validation.VObj(
		kv("subject", validation.VStr("*")),
		kv("actor", validation.VStr("tester")),
		kv("reason", validation.VStr(reason)),
	)
	if _, err := c.Log("completion.waived", &ref, &data); err != nil {
		t.Fatal(err)
	}
	rows, err := Waivers(c, "")
	if err != nil {
		t.Fatalf("the proof's reader must frame a legacy raw row as one "+
			"row, exactly as verify's does: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("Waivers returned %d row(s), want 1", len(rows))
	}
	if got := validation.ObjStr(rows[0], "reason"); got != reason {
		t.Errorf("read-back reason = %q, want %q", got, reason)
	}
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if !v.OK || len(v.Problems) != 0 {
		t.Errorf("verify over the legacy row: ok=%v problems=%v",
			v.OK, v.Problems)
	}
	pr, err := ProofStatus(c, "discovery")
	if err != nil {
		t.Fatal(err)
	}
	if d := validation.ObjAt(pr, "done"); d.Kind != validation.Bool || !d.B {
		t.Errorf("legacy waiver not honoured: %s", validation.PyRepr(pr))
	}
}

// TestR40cFramingPredicateIsStateBlankLine pins the ONE framing predicate:
// ASCII blank lines are blanks (skipped), a Unicode-whitespace-only line is
// a RECORD (the r38 law), and the reader names the file and the physical
// line so the operator is not left diffing bytes by eye.
func TestR40cFramingPredicateIsStateBlankLine(t *testing.T) {
	c := zzR40cCamp(t, "C-r40cblank0001")
	path := WaiversPath(c)
	row1 := `{"stage": "discovery", "subject": "*"}`
	row2 := `{"stage": "dedup", "subject": "*"}`
	// ASCII blanks — including a tab/space-only line — are blanks to both.
	if err := os.WriteFile(path,
		[]byte(row1+"\n  \t\n"+row2+"\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rows, err := Waivers(c, "")
	if err != nil {
		t.Fatalf("ASCII blanks must not be records: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("Waivers returned %d row(s), want 2", len(rows))
	}
	// U+00A0 alone is a RECORD — state.BlankLine is the shared answer, and
	// it says so; the reader fails closed and names the line.
	if state.BlankLine("\u00a0") {
		t.Fatal("state.BlankLine must not call U+00A0 blank")
	}
	if err := os.WriteFile(path,
		[]byte(row1+"\n\u00a0\n"+row2+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = Waivers(c, "")
	if err == nil {
		t.Fatal("a U+00A0-only waiver line is a record the decoder cannot " +
			"parse — the proof's reader must not skip it silently")
	}
	if !strings.Contains(err.Error(), "waivers.jsonl line 2") {
		t.Errorf("the error must name the file and the physical line: %v", err)
	}
	v, err := c.VerifyLog()
	if err != nil {
		t.Fatal(err)
	}
	if v.OK {
		t.Fatalf("verify must go red over the same line: %v", v.Problems)
	}
	found := false
	for _, p := range v.Problems {
		if strings.Contains(p, "waivers.jsonl line 2") {
			found = true
		}
	}
	if !found {
		t.Errorf("verify must name the same file/line: %v", v.Problems)
	}
}

// TestR40cRefusedSeparatorWaiveUnwindsByteExact is the honest refusal shape
// for this finding's payload: with the ledger cut to a prefix of the mirror,
// a waiver whose reason carries a raw line boundary is REFUSED and the
// pre-write bytes come back exactly — no row, no second row on the retry,
// and the surviving row still reads with its separator intact.
func TestR40cRefusedSeparatorWaiveUnwindsByteExact(t *testing.T) {
	c := zzR40cCamp(t, "C-r40crefuse001")
	for i := 0; i < 3; i++ {
		if _, err := c.Log("note.added", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	reason := "abcdefghij" + string('\u2028') + "klmnopqrst"
	if _, err := Waive(c, "discovery", "", reason, "tester"); err != nil {
		t.Fatalf("first waiver: %v", err)
	}
	path := WaiversPath(c)
	pre, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// `head -n 2 events.jsonl`: the mirror is longer than the log, so the
	// next write's c.Log refuses rather than adopting the loss.
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if err := os.WriteFile(c.EventsPath,
		[]byte(strings.Join(lines[:2], "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, werr := Waive(c, "dedup", "", reason, "tester")
	if werr == nil {
		t.Fatal("the write must be REFUSED under a truncated ledger")
	}
	if !strings.Contains(werr.Error(), "events.jsonl holds") ||
		!strings.Contains(werr.Error(), "webv2 doctor") {
		t.Errorf("refusal must be the honest ledger message: %v", werr)
	}
	post, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if zzR40cSha(pre) != zzR40cSha(post) {
		t.Errorf("waivers.jsonl was not restored byte-exact:\n pre %q\npost %q",
			pre, post)
	}
	if n := zzR40cPhysicalLines(post); n != 1 {
		t.Errorf("waivers.jsonl holds %d row(s) after the refusal, want 1: %q",
			n, post)
	}
	rows, err := Waivers(c, "")
	if err != nil {
		t.Fatalf("the surviving row must still read: %v", err)
	}
	if len(rows) != 1 || validation.ObjStr(rows[0], "reason") != reason {
		t.Errorf("surviving row = %s, want the one separator reason",
			validation.PyRepr(validation.VArr(rows...)))
	}
}

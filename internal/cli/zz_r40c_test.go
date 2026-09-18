package cli

// zz_r40c_test.go — r40c, the two verb-level contracts.
//
// P2-3: `waive <C> discovery --reason $'abcdefghij\u2028klmnopqrst' --actor
// tester` used to exit 0 with "waived discovery/*", leave the raw rune in
// waivers.jsonl, and pass `verify` (ok:true, no problems) — while `prove <C>
// --stage discovery` answered "discovery open [authoritative] — proof error:
// unexpected EOF" rc 1. The waiver was recorded, reported as success and
// never consulted. The writer escapes the three codepoints now and both
// readers frame the file on the physical line, so the same three commands
// must answer: one row, verify green, the proof DONE.
//
// P3: doctor's r39 loss sentence said "the projection lost N events that the
// journal records ..." — inverted. In the repro the JOURNAL holds 30 events
// (before and after; doctor never touches the ledger) and the PROJECTION is
// the store that remembered the 970 that doctor.json reports as
// dropped_from_projection. The corrected sentence must say that direction,
// match its own parenthetical, and never contradict the JSON.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"websec/internal/validation"

	"websec/internal/state"
)

var zzR40cCLISep = []struct {
	name string
	r    string
	esc  string
}{
	{"U+0085", "\u0085", `\u0085`},
	{"U+2028", "\u2028", `\u2028`},
	{"U+2029", "\u2029", `\u2029`},
}

// TestR40cWaiveSeparatorReasonEndToEnd is the finding's repro at verb level,
// for each of the three codepoints: waive rc 0, ONE physical row carrying
// the escape, verify green, prove DONE.
func TestR40cWaiveSeparatorReasonEndToEnd(t *testing.T) {
	for _, tc := range zzR40cCLISep {
		t.Run(tc.name, func(t *testing.T) {
			root := mkroot(t)
			cid := initOne(t, root)
			reason := "abcdefghij" + tc.r + "klmnopqrst"
			code, out, errS := run(t, "--root", root, "waive", cid,
				"discovery", "--reason", reason, "--actor", "tester")
			if code != 0 {
				t.Fatalf("waive exit %d: out=%q err=%q", code, out, errS)
			}
			if !strings.Contains(out, "waived discovery/*") {
				t.Fatalf("waive output: %q", out)
			}
			c, err := state.Open(root, cid)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(c.Dir, "waivers.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), tc.r) {
				t.Errorf("raw %s landed in waivers.jsonl: %q", tc.name, raw)
			}
			if !strings.Contains(string(raw), tc.esc) {
				t.Errorf("waivers.jsonl must carry %s: %q", tc.esc, raw)
			}
			n := 0
			for _, ln := range strings.Split(string(raw), "\n") {
				if strings.TrimRight(ln, " \t\r\v\f") != "" {
					n++
				}
			}
			if n != 1 {
				t.Errorf("waivers.jsonl holds %d physical line(s), want 1: %q",
					n, raw)
			}
			code, out, errS = run(t, "--root", root, "verify", cid)
			if code != 0 {
				t.Fatalf("verify exit %d: out=%q err=%q", code, out, errS)
			}
			if !strings.Contains(out, `"ok": true`) ||
				!strings.Contains(out, `"problems": []`) {
				t.Errorf("verify is not green over the escaped row: %q", out)
			}
			code, out, errS = run(t, "--root", root, "prove", cid,
				"--stage", "discovery")
			if code != 0 {
				t.Fatalf("prove exit %d (the waiver was ignored): out=%q err=%q",
					code, out, errS)
			}
			if !strings.Contains(out, "DONE") ||
				strings.Contains(out, "proof error") {
				t.Errorf("prove must honour the waiver: %q", out)
			}
		})
	}
}

// TestR40cRefusedWaiveAtVerbLevel is the honest refusal shape the operator
// can always hit: the ledger grown by a few events, then cut to a shorter
// PREFIX of its own bytes (the mirror is longer), so the write is refused
// with the ledger message — and waivers.jsonl keeps its pre-write bytes.
func TestR40cRefusedWaiveAtVerbLevel(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := c.Log("note.added", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(c.Dir, "waivers.jsonl")
	pre, had := []byte(nil), false
	if b, err := os.ReadFile(path); err == nil {
		pre, had = b, true
	}
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) < 3 {
		t.Fatalf("fixture: ledger holds %d line(s)", len(lines))
	}
	if err := os.WriteFile(c.EventsPath,
		[]byte(strings.Join(lines[:2], "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reason := "abcdefghij" + "\u2028" + "klmnopqrst"
	code, _, errS := run(t, "--root", root, "waive", cid, "discovery",
		"--reason", reason, "--actor", "tester")
	if code != 1 {
		t.Fatalf("refused write must exit 1, got %d (err=%q)", code, errS)
	}
	for _, want := range []string{"events.jsonl holds", "webv2 doctor"} {
		if !strings.Contains(errS, want) {
			t.Errorf("refusal message must carry %q: %q", want, errS)
		}
	}
	post, perr := os.ReadFile(path)
	if had {
		if perr != nil || string(post) != string(pre) {
			t.Errorf("refusal did not restore the pre-write bytes:\npre %q\npost %q",
				pre, post)
		}
	} else if perr == nil {
		t.Errorf("a refused first waiver must leave no waivers.jsonl: %q", post)
	}
}

// TestR40cDoctorLossSentenceNamesTheRightDirection is the P3 pin: the human
// sentence must say the projection REMEMBERED the dropped rows and the log
// no longer holds them — the direction doctor.json spells with its
// dropped_from_projection key — and it must agree with the stores it is
// describing (the projection is the one holding MORE).
func TestR40cDoctorLossSentenceNamesTheRightDirection(t *testing.T) {
	root, cid := r39bCutFixture(t)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	// What the two stores hold BEFORE the repair.
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	logged := 0
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(ln) != "" {
			logged++
		}
	}
	st, err := c.State()
	if err != nil {
		t.Fatal(err)
	}
	mirrored := len(validation.ObjAt(st, "events").A)
	if mirrored <= logged {
		t.Fatalf("fixture is not the loss shape: projection %d, log %d",
			mirrored, logged)
	}

	code, out, errS := run(t, "--root", root, "doctor", cid, "--state-only")
	if code != 0 {
		t.Fatalf("doctor exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "3 event(s) the projection remembered are "+
		"GONE from the log") {
		t.Errorf("the loss must be named in the right direction "+
			"(projection remembered / log no longer holds): %q", out)
	}
	if strings.Contains(out, "the projection lost") {
		t.Errorf("INVERTED again — the projection did not lose the rows, "+
			"the log no longer holds them: %q", out)
	}
	if !strings.Contains(out, "the rebuild adopted the log's shorter "+
		"history") {
		t.Errorf("the sentence must say which history the rebuild adopted: %q",
			out)
	}
	if !strings.Contains(out, "(0 kept, 0 adopted from the log)") {
		t.Errorf("the parenthetical must carry the delta's own numbers: %q",
			out)
	}
	// doctor.json: the count the sentence renders IS dropped_from_projection,
	// and the ledger is untouched by the repair.
	jraw, err := os.ReadFile(filepath.Join(c.Dir, "doctor.json"))
	if err != nil {
		t.Fatal(err)
	}
	var journal []map[string]any
	if err := json.Unmarshal(jraw, &journal); err != nil {
		t.Fatalf("doctor.json: %v\n%s", err, jraw)
	}
	if len(journal) == 0 {
		t.Fatal("doctor.json holds no repair entry")
	}
	delta := journal[len(journal)-1]["delta"].(map[string]any)
	if got := delta["dropped_from_projection"].(float64); got != 3 {
		t.Errorf("doctor.json dropped_from_projection = %v, want 3", got)
	}
	for _, k := range []string{"kept", "added_from_log"} {
		if got := delta[k].(float64); got != 0 {
			t.Errorf("doctor.json %s = %v, want 0", k, got)
		}
	}
	after, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	afterCount := 0
	for _, ln := range strings.Split(string(after), "\n") {
		if strings.TrimSpace(ln) != "" {
			afterCount++
		}
	}
	if afterCount != logged {
		t.Errorf("doctor changed the ledger: %d -> %d event(s)",
			logged, afterCount)
	}
}

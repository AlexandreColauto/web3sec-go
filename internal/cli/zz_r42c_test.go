package cli

// zz_r42c_test.go — r42c P3 at the operator's surface.
//
// Repro (the finding's pinned shape): take a campaign, remove the trailing
// newline from events.jsonl — the "torn write" the write path's framing
// guard refuses with "the file does not end in a newline (torn write or
// external edit) ... restore the file from a snapshot or truncate" — and
// then ask the three health surfaces. Before the fix: verify printed
// {"ok": true, "problems": []} exit 0, doctor exited 0 with no warning, and
// audit said PASS, while EVERY mutating verb refused the campaign forever.
//
// These pins run the whole surface through the real CLI: verify must report
// the torn tail as a problem, doctor must disclose it in both views (without
// losing its rc-0 health contract), audit must not say PASS — and the
// mutating verb's refusal is asserted in the same test so the two sides can
// never drift apart again. Honest shapes stay green: a terminated ledger,
// and the documented cut-back recovery.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"websec/internal/state"
)

// zzR42cCLICampaign inits a campaign and gives it three ledger events.
func zzR42cCLICampaign(t *testing.T, root string) string {
	t.Helper()
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := c.Log("note.added", nil, nil); err != nil {
			t.Fatalf("log: %v", err)
		}
	}
	return cid
}

// zzR42cCLITear drops the ledger's trailing newline and returns the ledger
// path plus the number of bytes left unterminated.
func zzR42cCLITear(t *testing.T, root, cid string) (string, int) {
	t.Helper()
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(c.EventsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		t.Fatal("fixture is not a terminated ledger")
	}
	body := raw[:len(raw)-1]
	i := strings.LastIndex(string(body), "\n")
	if err := os.WriteFile(c.EventsPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return c.EventsPath, len(body) - i - 1
}

func zzR42cCLISub(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	v, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("json %s: want an object, got %#v", key, m[key])
	}
	return v
}

// TestR42cCLIHealthSurfacesAgreeWithTheWriter is the PIN: before/after over
// verify, doctor (human + --json, every mode) and audit.
func TestR42cCLIHealthSurfacesAgreeWithTheWriter(t *testing.T) {
	root := mkroot(t)
	cid := zzR42cCLICampaign(t, root)

	// Honest ledger: all three surfaces green, doctor silent.
	if code, out, errS := run(t, "--root", root, "verify", cid); code != 0 ||
		!strings.Contains(out, `"ok": true`) {
		t.Fatalf("verify on a terminated ledger: exit %d out=%q err=%q",
			code, out, errS)
	}
	code, out, errS := run(t, "--root", root, "doctor", cid)
	if code != 0 || strings.Contains(out, "WARNING") ||
		strings.Contains(out, "log_validation") || errS != "" {
		t.Fatalf("doctor on a terminated ledger: exit %d out=%q err=%q",
			code, out, errS)
	}
	if code, out, _ := run(t, "--root", root, "audit", cid); code != 0 ||
		!strings.Contains(out, "audit PASS") {
		t.Fatalf("audit on a terminated ledger: exit %d out=%q", code, out)
	}

	path, tailBytes := zzR42cCLITear(t, root, cid)

	// The write path's refusal — the fact the readers were blind to.
	if code, _, errS := run(t, "--root", root, "budget", cid,
		"--set", "3000"); code != 1 ||
		!strings.Contains(errS, "does not end in a newline") {
		t.Fatalf("the mutating verb must still refuse: exit %d err=%q",
			code, errS)
	}

	// verify: red, naming the file and the shape.
	code, out, errS = run(t, "--root", root, "verify", cid)
	if code != 1 {
		t.Fatalf("verify over a torn ledger must exit 1, got %d: %q %q",
			code, out, errS)
	}
	if !strings.Contains(out, `"ok": false`) ||
		!strings.Contains(out, "events.jsonl: the ledger does not end in a newline") {
		t.Fatalf("verify must report the torn tail: %q", out)
	}
	if !strings.Contains(out, `"chained": 3`) {
		t.Fatalf("the surviving prefix must still be reported: %q", out)
	}

	// doctor: still rc 0 (its health contract), never silent.
	code, out, errS = run(t, "--root", root, "doctor", cid)
	if code != 0 || errS != "" {
		t.Fatalf("doctor rc must stay 0 with a disclosure: exit %d err=%q",
			code, errS)
	}
	if !strings.Contains(out, "WARNING") ||
		!strings.Contains(out, "NOT certifiable") ||
		!strings.Contains(out, "does not end in a newline") ||
		!strings.Contains(out, "this bill is NOT clean") {
		t.Fatalf("doctor's human view must disclose the ledger: %q", out)
	}

	// doctor --json: machine-readable, with the path and the exact tail.
	code, out, _ = run(t, "--root", root, "doctor", cid, "--json")
	if code != 0 {
		t.Fatalf("doctor --json exit %d", code)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("doctor --json is not JSON: %v\n%s", err, out)
	}
	lv := zzR42cCLISub(t, doc, "log_validation")
	if ok, _ := lv["ok"].(bool); ok {
		t.Fatalf("log_validation.ok must be false: %s", out)
	}
	if got, _ := lv["path"].(string); got != path {
		t.Fatalf("log_validation.path = %q, want %q", got, path)
	}
	if term, _ := lv["tail_terminated"].(bool); term {
		t.Fatalf("log_validation.tail_terminated must be false: %s", out)
	}
	if n, _ := lv["tail_bytes"].(float64); int(n) != tailBytes {
		t.Fatalf("log_validation.tail_bytes = %v, want %d", lv["tail_bytes"],
			tailBytes)
	}
	if msg, _ := lv["error"].(string); !strings.Contains(msg,
		"does not end in a newline") {
		t.Fatalf("log_validation.error must name the shape: %q", msg)
	}

	// Every doctor mode discloses; the existing mode pins still hold
	// (--state-only shows no "snapshot", --snapshot-only no "state:").
	code, out, _ = run(t, "--root", root, "doctor", cid, "--state-only")
	if code != 0 || !strings.Contains(out, "WARNING") ||
		!strings.Contains(out, "state:") || strings.Contains(out, "snapshot") {
		t.Fatalf("doctor --state-only: exit %d out=%q", code, out)
	}
	code, out, _ = run(t, "--root", root, "doctor", cid, "--snapshot-only")
	if code != 0 || !strings.Contains(out, "WARNING") ||
		!strings.Contains(out, "snapshot") || strings.Contains(out, "state:") {
		t.Fatalf("doctor --snapshot-only: exit %d out=%q", code, out)
	}

	// audit: FAIL, and the human view attributes it to the event_log
	// section with the same sentence.
	code, out, _ = run(t, "--root", root, "audit", cid)
	if code != 1 || !strings.Contains(out, "audit FAIL") ||
		!strings.Contains(out, "event_log=1 problem(s)") ||
		!strings.Contains(out, "[event_log] events.jsonl: the ledger does "+
			"not end in a newline") {
		t.Fatalf("audit must not PASS over a torn ledger: exit %d out=%q",
			code, out)
	}
	code, out, _ = run(t, "--root", root, "audit", cid, "--json")
	if code != 1 {
		t.Fatalf("audit --json exit %d", code)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("audit --json is not JSON: %v\n%s", err, out)
	}
	if ok, _ := rep["ok"].(bool); ok {
		t.Fatalf("audit --json ok must be false: %s", out)
	}
	sec := zzR42cCLISub(t, zzR42cCLISub(t, rep, "sections"), "event_log")
	if ok, _ := sec["ok"].(bool); ok {
		t.Fatalf("event_log section must be false: %s", out)
	}
	if probs, _ := sec["problems"].([]any); len(probs) != 1 ||
		!strings.Contains(probs[0].(string), "does not end in a newline") {
		t.Fatalf("event_log problems = %#v", sec["problems"])
	}
}

// TestR42cCLRecoveryRestoresEverySurface: the documented cut-back (RUNBOOK
// step 3) returns all three surfaces to green, and the campaign is writable
// again.
func TestR42cCLRecoveryRestoresEverySurface(t *testing.T) {
	root := mkroot(t)
	cid := zzR42cCLICampaign(t, root)
	path, _ := zzR42cCLITear(t, root, cid)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	i := strings.LastIndex(string(raw), "\n")
	if i < 0 {
		t.Fatal("no newline to cut back to")
	}
	if err := os.WriteFile(path, raw[:i+1], 0o644); err != nil {
		t.Fatal(err)
	}
	// The cut drops the record whose newline was lost, so the projection is
	// one event ahead: RUNBOOK step 4's second branch. doctor rebuilds the
	// mirror from the ledger (the ledger is the record).
	if code, out, _ := run(t, "--root", root, "doctor", cid); code != 0 ||
		!strings.Contains(out, "rebuilt the events mirror") {
		t.Fatalf("doctor must re-derive the mirror: exit %d out=%q", code, out)
	}
	if code, out, errS := run(t, "--root", root, "verify", cid); code != 0 ||
		!strings.Contains(out, `"ok": true`) {
		t.Fatalf("verify after the documented recovery: exit %d out=%q err=%q",
			code, out, errS)
	}
	if code, out, _ := run(t, "--root", root, "audit", cid); code != 0 ||
		!strings.Contains(out, "audit PASS") {
		t.Fatalf("audit after the documented recovery: exit %d out=%q", code, out)
	}
	if code, _, errS := run(t, "--root", root, "budget", cid,
		"--set", "4000"); code != 0 {
		t.Fatalf("the campaign must be writable again: exit %d err=%q",
			code, errS)
	}
}

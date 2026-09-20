package planner

// r3_answered_test.go — R3-5 (Morph r3 defect 5, both halves).
// (i) A closure that links --finding never checked the finding describes
// THIS row: G-02's row closed with a causally wrong reason quoting the row's
// own identifiers. Now the deferred gate's row resolution WARNs (stderr
// notice, never a refusal — causal truth is not statically decidable).
// (ii) refutationBacked EXEC refs were bare existence checks doubling as
// resolveAnchor's escape hatch: ANY exec record could close a row whose
// anchor it never matched, unnamed. That half gets a real refusal.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func r3WriteFinding(t *testing.T, camp *state.Campaign, id, mechanism,
	description string) {
	t.Helper()
	if err := os.MkdirAll(camp.FindingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"finding_id":"` + id + `","title":"r3 fixture finding",` +
		`"status":"HYPOTHESIS","root_cause":{"class":"logic-error",` +
		`"mechanism":"` + mechanism + `","description":"` + description +
		`"}}`
	if err := os.WriteFile(filepath.Join(camp.FindingsDir, id+".json"),
		[]byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func r3WriteExec(t *testing.T, camp *state.Campaign, id, body string) {
	t.Helper()
	dir := filepath.Join(camp.ExecsDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "exec_record.json"),
		[]byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// (i) WARN: a linked finding whose mechanism shares no row symbol is
// announced on the notice channel; a matching or signal-less mechanism is
// silent; the closure lands either way (this half never refuses).
func TestLinkedFindingNamingNothingFromTheRowWarns(t *testing.T) {
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "r3-warn-link")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	reason5 := "commitBatch guards the entry path; read line by line"
	reason6 := "dropMessage is gated by the same modifier as its caller"
	reason7 := "getActiveStakers returns the canonical set; verified by reading"
	reason8 := "proveState checks the commitment before storage writes"
	off := "F-aaaaaaaaaaaa"
	r3WriteFinding(t, camp, off,
		"the Treasury multisig rotates keys quarterly", "unrelated mechanism")
	on := "F-bbbbbbbbbbbb"
	r3WriteFinding(t, camp, on,
		"dropMessage admits replays without a nonce bump", "matching mechanism")
	empty := "F-cccccccccccc"
	r3WriteFinding(t, camp, empty, "", "")

	notice := ""
	updated, err := MarkAnswered(camp, deepCopy(t, plan), "Q-005",
		"answered", AnsweredOpts{Reason: &reason5,
			Anchor: strPtr("consumer"), Finding: &off, SkipNotice: &notice})
	if err != nil {
		t.Fatalf("a mis-linked closure WARNS, it is not refused: %v", err)
	}
	if got := validation.ObjStr(probePriority(t, updated, "Q-005"),
		"status"); got != "answered" {
		t.Fatalf("status = %q, want the closure to have landed", got)
	}
	for _, want := range []string{"Q-005", "81dfad6492", off,
		"webv2 anchors", "commitBatch"} {
		if !strings.Contains(notice, want) {
			t.Errorf("notice missing %q: %q", want, notice)
		}
	}

	// A mechanism that names the row's own surface entry: silent.
	notice = ""
	if _, err := MarkAnswered(camp, deepCopy(t, plan), "Q-006", "answered",
		AnsweredOpts{Reason: &reason6, Anchor: strPtr("consumer"),
			Finding: &on, SkipNotice: &notice}); err != nil {
		t.Fatal(err)
	}
	if notice != "" {
		t.Fatalf("a row-symbol match must stay silent: %q", notice)
	}

	// An empty mechanism is no signal at all: silent (absence of prose
	// cannot share symbols, and inventing a warning there would spam
	// findings that carry no mechanism text).
	notice = ""
	if _, err := MarkAnswered(camp, deepCopy(t, plan), "Q-007", "answered",
		AnsweredOpts{Reason: &reason7, Anchor: strPtr("consumer"),
			Finding: &empty, SkipNotice: &notice}); err != nil {
		t.Fatal(err)
	}
	if notice != "" {
		t.Fatalf("an empty mechanism must stay silent: %q", notice)
	}

	// No --finding: nothing to cross-check.
	notice = ""
	if _, err := MarkAnswered(camp, deepCopy(t, plan), "Q-008", "answered",
		AnsweredOpts{Reason: &reason8, Anchor: strPtr("consumer"),
			SkipNotice: &notice}); err != nil {
		t.Fatal(err)
	}
	if notice != "" {
		t.Fatalf("no linked finding must stay silent: %q", notice)
	}
}

// (ii) REFUSE: an EXEC ref that escapes the anchor rule must be attributed —
// by --finding or by the exec record's own finding_id. INV refs and the
// matched-anchor path are unaffected.
func TestExecEscapeMustNameItsFinding(t *testing.T) {
	surface, index := maSurface(t)
	withProbes(t, probeEnv{surface: surface, index: index})
	camp := newCampaign(t, "r3-exec-escape")
	plan := deepCopy(t, maPlan(t, "plan_probe_rows.json"))
	reason := "the refuted path cannot be reached from the entry"
	ref := "EXEC-abcdef1234"
	r3WriteExec(t, camp, ref, `{"exec_id":"EXEC-abcdef1234"}`)

	// Anonymous exec, no --finding: the escape is refused, naming the cure.
	_, err := MarkAnswered(camp, deepCopy(t, plan), "Q-005", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"), Ref: &ref})
	if err == nil {
		t.Fatal("an unattributed EXEC escaping the anchor rule must be refused")
	}
	if !strings.Contains(err.Error(), "must name the finding it ran for "+
		"(--finding") {
		t.Fatalf("refusal missing the cure: %v", err)
	}
	if !strings.Contains(err.Error(), "must be the anchor it claims") {
		t.Fatalf("refusal lost the original anchor sentence: %v", err)
	}

	// --finding names it: the ref lands.
	fid := "F-0123456789ab"
	r3WriteFinding(t, camp, fid, "the row's commitBatch path never checks",
		"attributed refutation")
	updated, err := MarkAnswered(camp, deepCopy(t, plan), "Q-006",
		"answered", AnsweredOpts{Reason: &reason,
			Anchor: strPtr("consumer"), Ref: &ref, Finding: &fid})
	if err != nil {
		t.Fatalf("--finding attribution must let the ref through: %v", err)
	}
	if got := validation.ObjStr(probePriority(t, updated, "Q-006"),
		"closed_ref"); got != ref {
		t.Fatalf("closed_ref = %q, want %q", got, ref)
	}

	// The record names its own finding: trusted without the flag.
	named := "EXEC-1122334455"
	r3WriteExec(t, camp, named,
		`{"exec_id":"EXEC-1122334455","finding_id":"F-0123456789ab"}`)
	if _, err := MarkAnswered(camp, deepCopy(t, plan), "Q-007", "answered",
		AnsweredOpts{Reason: &reason, Anchor: strPtr("consumer"),
			Ref: &named}); err != nil {
		t.Fatalf("an exec record that names its finding must pass: %v", err)
	}
}

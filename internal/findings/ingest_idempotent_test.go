package findings

import (
	"regexp"
	"strings"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

// idemPayload is the ingest idempotency fixture: the semantic shape the door
// keys on (title + root_cause + affected), plus the rest of a real payload.
// Two calls with equal title/root_cause/affected are the SAME claim.
func idemPayload() validation.Value {
	return hypoPayload(kv("root_cause", validation.VObj(
		kv("class", validation.VStr("precision-rounding")),
		kv("description", validation.VStr(
			"share calculation rounds in the attacker's favor")),
		kv("mechanism", validation.VStr(
			"withdraw floors the share price after the transfer, leaving "+
				"a rounding remainder the caller keeps")),
	)))
}

// idemMutated is idemPayload under a DIFFERENT mechanism — a different claim
// that must never fold into the first finding.
func idemMutated() validation.Value {
	p := idemPayload()
	rc := validation.ObjAt(p, "root_cause")
	rc.O = validation.SetOrAppend(rc.O, "mechanism", validation.VStr(
		"deposit rounds the minted shares up, so the vault owes more than "+
			"it holds after every deposit"))
	p.O = validation.SetOrAppend(p.O, "root_cause", rc)
	return p
}

var contentShaRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// idemLiveFindings is LoadAllFindings with the count assertion the door
// tests all make.
func idemLiveFindings(t *testing.T, c *state.Campaign, want int) []validation.Value {
	t.Helper()
	live, err := LoadAllFindings(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != want {
		t.Fatalf("findings = %d, want %d", len(live), want)
	}
	return live
}

// assertIdempotentEvent pins the ledger record of an idempotent hit: the
// subject is the matched finding, and the data names both the finding that
// was NOT created and the digest that matched.
func assertIdempotentEvent(t *testing.T, c *state.Campaign, fid, sha string) {
	t.Helper()
	e := hasEvent(t, c, "finding.ingest_idempotent")
	if got := validation.ObjStr(e, "ref"); got != fid {
		t.Errorf("event subject = %q, want the matched finding %q", got, fid)
	}
	data := validation.ObjAt(e, "data")
	if got := validation.ObjStr(data, "matched_finding"); got != fid {
		t.Errorf("matched_finding = %q, want %q", got, fid)
	}
	if got := validation.ObjStr(data, "content_sha"); got != sha {
		t.Errorf("event content_sha = %q, want %q", got, sha)
	}
	// the finding_id the second call did NOT create is recorded, so the
	// operator can tell the ledger hit from a fresh mint.
	if got := validation.ObjStr(data, "finding_id"); got == "" || got == fid {
		t.Errorf("event finding_id = %q, want the un-minted id", got)
	}
}

// Re-ingesting the SAME payload is the same claim, not a new one: the first
// ingest creates the finding, the second returns it with the ledger saying so
// (morph §6.5: 258 duplicate ingests, one per re-submitted agent row).
func TestIngestIsContentIdempotent(t *testing.T) {
	c := ingestCamp(t)
	payload := idemPayload()
	f1, err := IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	sha := validation.ObjStr(validation.ObjAt(f1, "dedup"), "content_sha")
	if !contentShaRe.MatchString(sha) {
		t.Fatalf("content_sha = %q, want 16-hex", sha)
	}
	fid := validation.ObjStr(f1, "finding_id")
	f2, err := IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(f2, "finding_id"); got != fid {
		t.Fatalf("second ingest minted %s, want idempotent hit on %s", got, fid)
	}
	idemLiveFindings(t, c, 1)
	assertIdempotentEvent(t, c, fid, sha)
}

// A changed mechanism is a different claim: the digest covers root_cause, so
// the door must mint a second finding (the dedup sweep, not the door, owns
// near-duplicate judgment).
func TestIngestChangedMechanismIsANewClaim(t *testing.T) {
	c := ingestCamp(t)
	f1, err := IngestHypothesis(c, idemPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f1, "finding_id")
	f3, err := IngestHypothesis(c, idemMutated(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(f3, "finding_id") == fid {
		t.Fatal("a changed mechanism folded into the first finding")
	}
	idemLiveFindings(t, c, 2)
}

// A TERMINAL twin does not absorb the re-submission: a re-filed DISPROVED
// claim is an operator decision (the door answers with a fresh finding, the
// dedup sweep owns the duplicate question), not clutter the door folds.
func TestIngestTerminalTwinDoesNotAbsorb(t *testing.T) {
	c := ingestCamp(t)
	f1, err := IngestHypothesis(c, idemPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f1, "finding_id")
	if _, err := Transition(c, fid, "DISPROVED", "the path is guarded",
		"", "", false); err != nil {
		t.Fatal(err)
	}
	f2, err := IngestHypothesis(c, idemPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(f2, "finding_id") == fid {
		t.Fatal("a re-filed claim folded into a terminal twin")
	}
	if !strings.HasPrefix(validation.ObjStr(f2, "finding_id"), "F-") {
		t.Fatalf("finding_id = %q", validation.ObjStr(f2, "finding_id"))
	}
	idemLiveFindings(t, c, 2)
}

// --lint still answers "what WOULD a fresh ingest decide": it never takes the
// idempotent exit, so the returned finding is the one a real ingest would
// have minted (a NEW id), and nothing is written.
func TestLintSkipsTheIdempotentExit(t *testing.T) {
	c := ingestCamp(t)
	f1, err := IngestHypothesis(c, idemPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	lint, err := LintHypothesis(c, idemPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(lint, "finding_id") == validation.ObjStr(f1, "finding_id") {
		t.Fatal("--lint took the idempotent exit; it must model a fresh ingest")
	}
	if got := validation.ObjStr(validation.ObjAt(lint, "dedup"), "content_sha"); got == "" {
		t.Fatal("--lint finding carries no content_sha")
	}
	idemLiveFindings(t, c, 1) // lint writes nothing
}

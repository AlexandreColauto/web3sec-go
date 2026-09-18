package cli

// M4: `ingest --trajectory` accepts the A–H dispatch letters the runbook
// and prompt 39 teach (A=code … H=lifecycle), mapping them to the schema
// enum names. Full names pass through; chain|model have no letters; junk
// still fails at schema validation.

import (
	"testing"

	"websec/internal/validation"
)

func TestNormalizeTrajectoryLetters(t *testing.T) {
	cases := map[string]string{
		"A": "code", "a": "code",
		"B": "economic", "b": "economic",
		"C": "state-machine", "c": "state-machine",
		"D": "attacker", "d": "attacker",
		"E": "historical", "e": "historical",
		"F": "integration", "f": "integration",
		"G": "drift", "g": "drift",
		"H": "lifecycle", "h": "lifecycle",
		// full names and everything else pass through untouched
		"code": "code", "lifecycle": "lifecycle", "chain": "chain",
		"model": "model", "Z": "Z", "bogus": "bogus", "": "",
	}
	for in, want := range cases {
		if got := normalizeTrajectory(in); got != want {
			t.Errorf("normalizeTrajectory(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIngestTrajectoryLetterEndToEnd(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	payload := t14TestWrite(t, root, "payload.json", t14TestHypothesisJSON)
	code, _, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", payload, "--trajectory", "H")
	if code != 0 {
		t.Fatalf("ingest exit %d: %q", code, errS)
	}
	f := storedFinding(t, root, cid)
	if got := validation.PyRepr(validation.ObjAt(f, "trajectory")); got != "'lifecycle'" {
		t.Fatalf("stored trajectory = %s, want 'lifecycle'", got)
	}
}

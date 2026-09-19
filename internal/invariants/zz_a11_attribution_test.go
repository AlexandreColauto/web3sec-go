package invariants

// A11 (F14) attribution: the invariant.verified attestation event names the
// framework build that recorded it, beside the artifact reference, so a future
// review never grades an attestation against a different binary's semantics.
// Event data is free-form (the audit checks the hash chain, never data keys),
// so the key is additive and old events simply carry none.

import (
	"testing"

	"websec/internal/validation"
	"websec/internal/version"
)

func TestVerifyEventStampsFrameworkBuild(t *testing.T) {
	// The override stands in for a stamped release build (test binaries
	// never carry a VCS stamp).
	t.Setenv("WEBV2_BUILD", "attestbuild1")
	c := invCamp(t)
	if _, err := SeedFromModel(c, modelWithInvariants()); err != nil {
		t.Fatal(err)
	}
	artID := registeredArtifact(t, c, "a11-inv-check.md",
		"INV-2 checked against src/V.sol L40\n")
	if _, err := VerifyInvariantStatement(c, "INV-2", artID); err != nil {
		t.Fatal(err)
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, ev := range events {
		if validation.ObjStr(ev, "type") != "invariant.verified" ||
			validation.ObjStr(ev, "ref") != "INV-2" {
			continue
		}
		seen++
		data := validation.ObjAt(ev, "data")
		if got := validation.ObjStr(data, "framework_build"); got != version.Commit() {
			t.Fatalf("event framework_build = %q, want the running build %q",
				got, version.Commit())
		}
		if got := validation.ObjStr(data, "framework_build"); got == version.Unknown {
			t.Fatalf("framework_build = %q: the stamp must be the RUNNING "+
				"build, not the absence marker", got)
		}
		// The existing keys are untouched, and the new one is ADDITIVE: the
		// log canonicalizes every data object with sorted keys on disk, so
		// the exact key set is what this pins (and nothing else moved).
		if got := validation.ObjStr(data, "artifact"); got != artID {
			t.Fatalf("event artifact = %q, want %q", got, artID)
		}
		if got := validation.ObjStr(data, verificationMethodKey); got !=
			verificationMethodAttestation {
			t.Fatalf("event %s = %q", verificationMethodKey, got)
		}
		names := make([]string, 0, len(data.O))
		for _, kv := range data.O {
			names = append(names, kv.K)
		}
		want := []string{"artifact", "framework_build", verificationMethodKey}
		if len(names) != len(want) {
			t.Fatalf("event data keys = %v, want %v", names, want)
		}
		for i := range want {
			if names[i] != want[i] {
				t.Fatalf("event data keys = %v, want %v", names, want)
			}
		}
	}
	if seen != 1 {
		t.Fatalf("invariant.verified events for INV-2 = %d, want 1", seen)
	}
}

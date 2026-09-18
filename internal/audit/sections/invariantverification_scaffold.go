// Invariant verification — harness scaffold artifact bytes: derivation and refusal burns for missing/unbound scaffold evidence (split from invariantverification.go; pure structural move).

package sections

import (
	"fmt"
	"strings"

	"websec/internal/harness"
	"websec/internal/state"
	"websec/internal/validation"
)

// harnessScaffoldArtifactBytes reads the T17 scaffold artifact bytes the
// bind hashed and re-rendered: the latest harness_scaffold event for
// HARNESS-<INV>-<kind> names the registered artifact as its ref, and the
// bytes come back through the registry's OWN reader (state.ArtifactBytes,
// which refuses a path whose file no longer hashes to the pinned sha — the
// same r25 F2 discipline recheckRegistryEvidence applies to report bytes).
// why != "" means the bytes could not be obtained, and names what is
// missing (r28b F3 constraint 3: "cannot re-derive" is never a blessing).
func harnessScaffoldArtifactBytes(c *state.Campaign,
	events []validation.Value, iid string,
	kind harness.Kind) (raw []byte, why string) {
	want := "HARNESS-" + iid + "-" + string(kind)
	ref := ""
	for _, ev := range events {
		if validation.ObjStr(ev, "type") != "harness_scaffold" {
			continue
		}
		if validation.ObjStr(validation.ObjAt(ev, "data"), "artifact_id") != want {
			continue
		}
		ref = validation.ObjStr(ev, "ref")
	}
	if ref == "" {
		return nil, fmt.Sprintf("no harness_scaffold event names %s", want)
	}
	art, err := c.Artifact(ref)
	if err != nil {
		return nil, fmt.Sprintf("the scaffold artifact %s the bind "+
			"hashed is not registered any more", ref)
	}
	raw, err = c.ArtifactBytes(art)
	if err != nil {
		return nil, fmt.Sprintf("the scaffold artifact %s cannot be "+
			"re-read the way the row pins it: %v", ref, err)
	}
	return raw, ""
}

// harnessScaffoldBindBytes reads the scaffold bytes the way the BIND reads
// them (cli.harnessScaffoldBytes): the latest harness_scaffold event's ref,
// the registry row's own path, read whole and RAW — no sha re-check, because
// the bind makes none. It is the fallback the unbound arm of section 11 uses
// when the pinned reader (harnessScaffoldArtifactBytes) refused only because
// the FILE no longer hashes to the row's registered sha (r29b F3(c)).
// why != "" names what is missing and means the bind could not read the file
// either.
func harnessScaffoldBindBytes(c *state.Campaign,
	events []validation.Value, iid string,
	kind harness.Kind) (raw []byte, why string) {
	want := "HARNESS-" + iid + "-" + string(kind)
	ref := ""
	for _, ev := range events {
		if validation.ObjStr(ev, "type") != "harness_scaffold" {
			continue
		}
		if validation.ObjStr(validation.ObjAt(ev, "data"), "artifact_id") != want {
			continue
		}
		ref = validation.ObjStr(ev, "ref")
	}
	if ref == "" {
		return nil, fmt.Sprintf("no harness_scaffold event names %s", want)
	}
	art, err := c.Artifact(ref)
	if err != nil {
		return nil, fmt.Sprintf("the scaffold artifact %s the bind "+
			"hashed is not registered any more", ref)
	}
	raw, err = harness.ArtifactFileBytes(c.Root, validation.ObjStr(art, "path"))
	if err != nil {
		return nil, fmt.Sprintf("the scaffold artifact %s has no readable "+
			"file: %v", ref, err)
	}
	return raw, ""
}

// scaffoldUnavailableBurn is r28b F3 constraint 3 reasoned against the
// bind's own arms: a blessing's hash arm CANNOT be re-derived without the
// scaffold bytes it hashed (they are what the recorded sha256 is compared
// against, and what Validate re-renders), so a record that carries HARNESS
// FILE hash evidence burns as "not backed", naming the key it carries and
// what is missing.
//
// r29b F3(a)(b): the arm asks the REAL question through the bind's own
// predicate — harness.ScaffoldFileHashes, the scaffold-file keys (H.t.sol /
// F.t.sol / INV.mspec, r29b F5), not `len(hashes) > 0`. Every sandbox record
// carries the artifact_hashes stdout/stderr digests, so the old test was true
// for EVERY real record: pruning a normal campaign's scaffold row made this
// burn claim the record "carries recorded harness file hash(es) … bound to"
// bytes it never mentioned, sending the operator to repair the wrong thing.
// A record with no harness-file hash is the UNBOUND arm, and it is not this
// function's question at all — see scaffoldBytesForUnboundArm.
func scaffoldUnavailableBurn(iid, exec, why string,
	rec validation.Value) string {
	if why == "" {
		return ""
	}
	files := harness.ScaffoldFileHashes(rec)
	if len(files) == 0 {
		return ""
	}
	keys := make([]string, 0, len(files))
	for _, f := range files {
		keys = append(keys, validation.PyReprStr(f.Key))
	}
	return fmt.Sprintf("%s: exec %s records a harness-file hash (%s) whose "+
		"scaffold bytes cannot be re-derived (%s) — the bind's hash arm "+
		"compares that recorded sha against exactly those bytes and its "+
		"Validate re-render runs on them, so the rung is not backed", iid,
		exec, strings.Join(keys, ", "), why)
}

// scaffoldBytesForUnboundArm is the scaffold the UNBOUND arm judges
// (r29b F3(c)). When the pinned reader handed bytes back they are returned
// unchanged. Otherwise — and by the time this is reached
// scaffoldUnavailableBurn has already refused every record that carries a
// harness-file hash, so the bind's hash comparison here is vacuous by
// definition — the bind still Validates the scaffold FILE it read from disk
// against the CURRENT claim, and its only reader rule the pinned one lacks is
// the row's sha (which the bind never checks). So read the same file the same
// way and hand the audit the bytes the bind would have judged: a claim that
// drifted away from them is then refused here exactly as the bind refuses it.
//
// When even that read is unobtainable (no harness_scaffold event, no
// registry row, an unreadable file) the arm stays SILENT, deliberately:
// absence is inconclusive — never a blessing, and never a burn. There is no
// decision to reproduce in that world (a bind could not have produced this
// rung either), and burning would torch honest aged campaigns whose scaffold
// row was reconciled away. The hash-carrying shapes, where a recorded sha IS
// evidence this rail cannot compare, burn above.
func scaffoldBytesForUnboundArm(c *state.Campaign,
	events []validation.Value, iid string, kind harness.Kind, scaffold []byte,
	why string) []byte {
	if len(scaffold) != 0 || why == "" {
		return scaffold
	}
	if raw, bwhy := harnessScaffoldBindBytes(c, events, iid, kind); bwhy == "" {
		return raw
	}
	return nil
}

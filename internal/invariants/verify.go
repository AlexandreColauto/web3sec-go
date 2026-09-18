// Invariant verification statement — operator attestations and artifact-relevance matching (split from invariants.go; pure structural move).

package invariants

import (
	"fmt"
	"os"
	"regexp"

	"websec/internal/state"
	"websec/internal/validation"
)

// verificationMethodKey is the registry-entry / event-data key carrying the
// provenance of a verification-axis verdict. It is a LABEL an operator's own
// attestation carries — never an authorization decision, and never inferred
// from the stored status, the artifact token or the log's words.
const verificationMethodKey = "verification_method"

// The three labels VerificationMethod can return.
const (
	// verificationMethodAttestation is what this framework's own
	// invariant-verify records: the operator attested that a registered
	// artifact attributes the statement.
	verificationMethodAttestation = "operator-attestation"
	// verificationMethodLegacy is every historical entry: no provenance key
	// was ever recorded, and none is invented on read.
	verificationMethodLegacy = "legacy-unspecified"
	// verificationMethodUnrecognized is any other value or type — the entry
	// claims a method this build does not know.
	verificationMethodUnrecognized = "unrecognized"
)

// VerificationMethod reads the provenance label off a registry entry. It is a
// pure lookup: "operator-attestation" only for that exact stored string,
// "legacy-unspecified" when the key is absent, "unrecognized" for any other
// value or type. It never infers a method from status, verified_by, the
// artifact's bytes or the log — and it is NOT an authorization decision: the
// gates keep reading the verification axis exactly as before.
func VerificationMethod(entry validation.Value) string {
	v, ok := fieldAt(entry, verificationMethodKey)
	if !ok {
		return verificationMethodLegacy
	}
	if v.Kind == validation.Str && v.S == verificationMethodAttestation {
		return verificationMethodAttestation
	}
	return verificationMethodUnrecognized
}

// VerifyInvariantStatement is verify_invariant_statement: an OPERATOR
// ATTESTATION recorded on the verification axis, backed by a REGISTERED
// artifact. Only this API (and contradict) may move the axis — never seeding,
// never hand-editing.
//
// What it establishes: an operator asserted that a registered artifact
// attributes this statement, and that artifact's BYTES name what it verifies.
// What it does NOT establish: that the check is correct, that it passed, or
// that the statement holds. The relevance match below is a textual
// invariant/target reference — ATTRIBUTION ONLY. A regex match is not
// mechanical proof, and the stored status stays CHECKED_AGAINST_CODE for
// compatibility with the existing gates, not because the code was
// mechanically checked. The provenance is written explicitly as
// verification_method "operator-attestation" on the entry and on the
// invariant.verified event, beside the artifact reference.
//
// Nothing else is written: an existing verification.harness rung, bounded_k,
// proof sidecar or test outcome is left exactly as it was, and none is
// manufactured.
//
// Task 4 relevance law: the artifact's BYTES must name what it verifies — the
// invariant id (in the registry's spelling or NormalizeInvID's canonical one)
// or one of the entry's applies_to strings, matched on word boundaries,
// case-insensitively. The registry `note` is metadata, never evidence: if it
// counted, every `--exec` artifact would satisfy the gate by construction.
func VerifyInvariantStatement(c *state.Campaign, invariantID,
	artifactID string) (validation.Value, error) {
	a, err := c.Artifact(artifactID)
	if err != nil {
		return validation.VNull(), err
	}
	links, err := LoadLinks(c)
	if err != nil {
		return validation.VNull(), err
	}
	reg := regOf(links)
	if !validation.HasKey(reg, invariantID) {
		return validation.VNull(), unknownInvariant(invariantID)
	}
	entry := validation.ObjAt(reg, invariantID)
	if !artifactReferencesInvariant(c, a, invariantID, entry) {
		return validation.VNull(), irrelevantArtifact(artifactID, invariantID)
	}
	entry.O = validation.SetOrAppend(entry.O, "status",
		validation.VStr("CHECKED_AGAINST_CODE"))
	entry.O = validation.SetOrAppend(entry.O, "verified_by", validation.VStr(artifactID))
	entry.O = validation.SetOrAppend(entry.O, verificationMethodKey,
		validation.VStr(verificationMethodAttestation))
	entry.O = popKey(entry.O, "contradiction")
	entry.O = validation.SetOrAppend(entry.O, "modified_by", validation.VStr(state.NowIso()))
	entry.O = validation.SetOrAppend(entry.O, "updated_at", validation.VStr(state.NowIso()))
	reg.O = validation.SetOrAppend(reg.O, invariantID, entry)
	links = setObjKey(links, "invariants", reg)
	data := validation.VObj(
		pair("artifact", validation.VStr(artifactID)),
		pair(verificationMethodKey, validation.VStr(verificationMethodAttestation)),
	)
	// r40: the verification axis may only move with its event — a save
	// that lands CHECKED_AGAINST_CODE while invariant.verified is refused
	// asserts a verification nobody logged.
	if err := LinksThenLog(c, func() error {
		_, serr := SaveLinks(c, links)
		return serr
	}, func() error {
		_, lerr := c.Log("invariant.verified", &invariantID, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return entry, nil
}

// artifactReferencesInvariant is the relevance gate: the cited artifact's
// bytes name the invariant, or one of the entry's applies_to targets, on a
// word boundary and case-insensitively. This is ATTRIBUTION, not proof: it
// establishes that the artifact points at the invariant, never that the check
// is correct or that the statement holds. An artifact whose bytes cannot be
// read references nothing — the gate fails closed.
func artifactReferencesInvariant(c *state.Campaign, a validation.Value,
	invariantID string, entry validation.Value) bool {
	raw, err := os.ReadFile(c.ResolveArtifactPath(a))
	if err != nil {
		return false
	}
	text := string(raw)
	for _, tok := range referenceTokens(invariantID, entry) {
		// Word boundaries, not substring: an artifact citing INV-20 (or
		// recheckINV-2) must never satisfy INV-2.
		re, cerr := regexp.Compile(`(?i)\b` + regexp.QuoteMeta(tok) + `\b`)
		if cerr != nil {
			continue
		}
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

// referenceTokens is what an artifact may cite to back this invariant: the id
// in the registry's spelling and in NormalizeInvID's canonical spelling
// (INV-002 and INV-2 are one invariant), plus every applies_to target, each
// also in canonical spelling. Deduplicated; empty tokens dropped.
func referenceTokens(invariantID string, entry validation.Value) []string {
	cands := []string{invariantID}
	for _, t := range validation.ObjAt(entry, "applies_to").A {
		if t.Kind == validation.Str {
			cands = append(cands, t.S)
		}
	}
	seen := map[string]bool{}
	out := []string{}
	for _, cand := range cands {
		for _, tok := range []string{cand, NormalizeInvID(cand)} {
			if tok == "" || seen[tok] {
				continue
			}
			seen[tok] = true
			out = append(out, tok)
		}
	}
	return out
}

// irrelevantArtifact is the Task 4 refusal: the cited bytes name neither the
// invariant nor any of its applies_to targets.
func irrelevantArtifact(artifactID, invariantID string) error {
	return fmt.Errorf("artifact %s does not reference %s (nor its applies_to) "+
		"— cite a check that names what it verifies (invariant-verify with "+
		"--exec <id> re-registers stdout as the artifact)", artifactID,
		invariantID)
}

// ---- Task 1: exec relevance binding ---------------------------------------

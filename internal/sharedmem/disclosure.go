package sharedmem

// Task 9 / I6 (half B): the embargoed disclosure bundle.
//
// Safety property (the reason this is safe to ship):
//
//	The bundle's CONTENTS never enter shared memory. The campaign-local
//	artifact holds the prose; the publish RECORD carries only
//	disclosure_sha256 (hex) and disclosure_embargo_until. Shared memory is
//	a cross-campaign surface; free-text impact narratives do not belong on
//	it.
//
// Embargo is a POLICY FIELD, not enforcement: embargo_until is recorded
// verbatim (or null), and the framework does NOT refuse, delay, or suppress a
// publish while an embargo is open. An embargo is an agreement between the
// researcher and the program, and a tool that silently blocks publishing is a
// tool that silently loses the researcher's leverage. The one thing the
// framework does is make the state legible — the CLI line says "recorded, not
// enforced" — so nobody can mistake a recorded embargo for an enforced one.
//
// The rules are FAIL-CLOSED: a bundle that cites an unknown finding, an
// unconfirmed one, one outside the publish set, or the same finding twice is
// refused before anything is written to the shared store.

import (
	"fmt"
	"os"
	"path/filepath"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

const (
	// DisclosureArtifactName is the campaign-local artifact filename.
	DisclosureArtifactName = "disclosure-bundle.json"

	// DisclosureArtifactKind is the artifact-registry kind (and the reason
	// string is DisclosureArtifactReason, below).
	DisclosureArtifactKind = "disclosure"

	// DisclosureArtifactReason is the registry note the CLI passes.
	DisclosureArtifactReason = "operator-supplied disclosure bundle"

	// DisclosureSHA256Field / DisclosureEmbargoField are the two publish
	// record fields a bundle ADDS (present only when one was attached).
	DisclosureSHA256Field  = "disclosure_sha256"
	DisclosureEmbargoField = "disclosure_embargo_until"
)

// Disclosure is a loaded, validated operator bundle plus the derived fields
// the publish record and the CLI line need.
type Disclosure struct {
	// Path is the source file the operator named (informational).
	Path string
	// Doc is the schema-valid bundle document, in the operator's field order.
	Doc validation.Value
	// FindingIDs is finding_ids, in bundle order.
	FindingIDs []string
	// Summary and Impact are the bundle's prose (campaign-local only).
	Summary string
	Impact  string
	// EmbargoUntil is embargo_until verbatim, "" when the bundle says null.
	EmbargoUntil string
	// ArtifactPath and SHA256 are set by WriteDisclosureArtifact.
	ArtifactPath string
	SHA256       string
}

// LoadDisclosure reads path, schema-validates the bundle, and applies the
// fail-closed findings rules against campaign c. It writes nothing: the
// caller decides when the artifact lands (and a refused bundle never does).
func LoadDisclosure(c *state.Campaign, path string) (*Disclosure, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("disclosure: %w", err)
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		return nil, fmt.Errorf("disclosure: %s: %w", path, err)
	}
	if err := validation.Validate(doc, "disclosure", 1); err != nil {
		return nil, fmt.Errorf("disclosure: %s: %w", path, err)
	}
	ids := []string{}
	for _, v := range objAt(doc, "finding_ids").A {
		ids = append(ids, v.S)
	}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return nil, err
	}
	byID := map[string]validation.Value{}
	publishable := map[string]bool{}
	for _, f := range all {
		id := objStr(f, "finding_id")
		byID[id] = f
		// The publish pass publishes exactly these statuses; a disclosure may
		// not cite knowledge the publish cannot show.
		if inList(objStr(f, "status"), PublishableStatuses) {
			publishable[id] = true
		}
	}
	if err := disclosureRuleCheck(ids, byID, publishable); err != nil {
		return nil, err
	}
	d := &Disclosure{
		Path:       path,
		Doc:        doc,
		FindingIDs: ids,
		Summary:    objStr(doc, "summary"),
		Impact:     objStr(doc, "impact"),
	}
	if e := objAt(doc, "embargo_until"); e.Kind == validation.Str {
		d.EmbargoUntil = e.S
	}
	return d, nil
}

// disclosureRuleCheck is the fail-closed findings gate, in the plan's order:
// unknown id, unconfirmed status, outside the publish set, duplicate.
//
// "Confirmed" means CONFIRMED or CHAIN — the same PublishableStatuses the
// publish pass uses, so the two can never drift: a POSSIBLE or HYPOTHESIS
// finding gives "is not confirmed (status X)", and a terminal-but-not-
// confirmed status (DISPROVED, SUPERSEDED, ...) is refused the same way. The
// publish-set rule is checked separately against the set the pass actually
// considered, so a future narrowing of that set cannot silently widen what a
// bundle may cite.
func disclosureRuleCheck(ids []string,
	byID map[string]validation.Value, publishable map[string]bool) error {
	for _, id := range ids {
		f, ok := byID[id]
		if !ok {
			return fmt.Errorf("disclosure: unknown finding id %s", id)
		}
		status := objStr(f, "status")
		if !inList(status, PublishableStatuses) {
			return fmt.Errorf(
				"disclosure: finding %s is not confirmed (status %s)", id, status)
		}
		if !publishable[id] {
			return fmt.Errorf(
				"disclosure: finding %s is not part of this publish", id)
		}
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			return fmt.Errorf("disclosure: duplicate finding id %s", id)
		}
		seen[id] = true
	}
	return nil
}

// WriteDisclosureArtifact writes the (already validated) bundle to
// c.ArtifactsDir/disclosure-bundle.json, registers it on the campaign as a
// living artifact, and records the file's sha256 on d (plus its path).
//
// It is called BEFORE the publish, so a publish that then fails leaves the
// artifact on the campaign: campaign-local, harmless, and NOT in the shared
// store.
func WriteDisclosureArtifact(c *state.Campaign, d *Disclosure) error {
	out := filepath.Join(c.ArtifactsDir, DisclosureArtifactName)
	if err := validation.WriteJson(out, d.Doc, "disclosure"); err != nil {
		return err
	}
	if _, err := c.RegisterOrRefresh(DisclosureArtifactKind, out, "", nil,
		DisclosureArtifactReason); err != nil {
		return err
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		return err
	}
	d.ArtifactPath = out
	d.SHA256 = validation.Sha256Hex(raw)
	return nil
}

// disclosureEmbargoValue is the record encoding of the embargo date: the
// verbatim date string, or null when the bundle carries none (the key is
// required, the value may be null).
func disclosureEmbargoValue(date string) validation.Value {
	if date == "" {
		return validation.VNull()
	}
	return validation.VStr(date)
}

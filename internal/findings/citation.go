// citation.go: H5 — affected[].citations, the machine-checkable home for
// the citation hashes whose payloads stay stringly.
//
// A mitigation hit is stored TWICE by design:
//
//   - dedup_meta.mitigation_present — the stringly record every consumer
//     reads (byte-identical to its pre-H5 shape), and
//   - affected[<the cited site>].citations.mitigation_present — a digest of
//     that exact string.
//
// The digest makes the citation machine-checkable: a consumer holding the
// affected entry can re-hash the stringly record and see a rewrite. The
// citation is a MIRROR, never a replacement — it is written only when the
// stringly record is written and cleared when the record is cleared, so a
// stored finding can never carry a citation its record does not back.
//
// The component channel (citations.component) has the same contract but no
// producer yet: component citations still ride evidence description text
// (G9), and the schema field is the additive reservation for that writer.
package findings

import "websec/internal/validation"

const (
	// CitationsKey is the affected[].citations object (finding schema, H5).
	CitationsKey = "citations"
	// MitigationCitationKey is the mitigation channel inside it.
	MitigationCitationKey = "mitigation_present"
	// ComponentCitationKey is the component channel inside it.
	ComponentCitationKey = "component"
)

// CitationDigest is the affected[].citations value form: lowercase hex
// sha256 of the cited payload, truncated to the codebase's sha12 convention
// (the schema accepts 12..64 hex characters).
func CitationDigest(payload string) string {
	return validation.Sha256Hex([]byte(payload))[:12]
}

// StampMitigationCitation mirrors a mitigation_present record onto the
// affected entry that record cites, as
// affected[<i>].citations.mitigation_present. The cited entry is the first
// affected[].path equal to file — the scan's own anchor order, where
// affected[0] resolves first — and when no entry names the file the first
// entry carries the citation, exactly as the scan resolved it. It never
// invents an affected entry, never edits another key and leaves the
// stringly record untouched.
func StampMitigationCitation(f validation.Value, file, record string) validation.Value {
	aff, ok := affectedList(f)
	if !ok {
		return f
	}
	idx := 0
	for i, e := range aff.A {
		if e.Kind == validation.Obj && validation.ObjStr(e, "path") == file {
			idx = i
			break
		}
	}
	if aff.A[idx].Kind != validation.Obj {
		return f
	}
	entry := aff.A[idx]
	cits := validation.ObjAt(entry, CitationsKey)
	if cits.Kind != validation.Obj {
		cits = validation.VObj()
	}
	cits.O = validation.SetOrAppend(cits.O, MitigationCitationKey,
		validation.VStr(CitationDigest(record)))
	entry.O = validation.SetOrAppend(entry.O, CitationsKey, cits)
	next := make([]validation.Value, len(aff.A))
	copy(next, aff.A)
	next[idx] = entry
	aff.A = next
	f.O = validation.SetOrAppend(f.O, "affected", aff)
	return f
}

// ClearMitigationCitation drops the mitigation channel from every affected
// entry (and the citations object with it when nothing else is cited): the
// clean-scan half, so a stored finding can never cite a mitigation a later
// scan no longer finds. Other channels (a component citation) survive.
func ClearMitigationCitation(f validation.Value) validation.Value {
	aff, ok := affectedList(f)
	if !ok {
		return f
	}
	next := make([]validation.Value, len(aff.A))
	copy(next, aff.A)
	changed := false
	for i, e := range aff.A {
		if e.Kind != validation.Obj {
			continue
		}
		cits := validation.ObjAt(e, CitationsKey)
		if cits.Kind != validation.Obj {
			continue
		}
		kept := make([]validation.KV, 0, len(cits.O))
		for _, kv := range cits.O {
			if kv.K != MitigationCitationKey {
				kept = append(kept, kv)
			}
		}
		if len(kept) == len(cits.O) {
			continue
		}
		changed = true
		entry := e
		if len(kept) == 0 {
			o := make([]validation.KV, 0, len(entry.O))
			for _, kv := range entry.O {
				if kv.K != CitationsKey {
					o = append(o, kv)
				}
			}
			entry.O = o
		} else {
			cits.O = kept
			entry.O = validation.SetOrAppend(entry.O, CitationsKey, cits)
		}
		next[i] = entry
	}
	if !changed {
		return f
	}
	aff.A = next
	f.O = validation.SetOrAppend(f.O, "affected", aff)
	return f
}

// affectedList is the finding's affected array, ok=false when it is absent,
// empty or not an array (nothing to stamp onto — never invented).
func affectedList(f validation.Value) (validation.Value, bool) {
	aff := validation.ObjAt(f, "affected")
	if aff.Kind != validation.Arr || len(aff.A) == 0 {
		return aff, false
	}
	return aff, true
}

// Section 7: relations — every stored edge of the research memory graph
// must still be supported. Deterministic edges are re-derived against their
// anchor; human-gated edges must carry their actor and log event. An edge
// whose support disappeared is drift: the structure moved (or the edge was
// forged) and the graph no longer describes it.
//
// The re-derivation itself lives in internal/relations (the T28 port), so
// this section is a seam: RelationsAPI.VerifyRelations is the whole
// section, and the default is the exact dict Python returns when the
// campaign has no relations artifact at all
// (load_relations -> [] -> {"checked": 0, "problems": [], "ok": True}).
// Python does NOT wrap this section in try/except, so an error propagates
// out of audit_campaign; the Go section mirrors that.
package sections

import (
	"websec/internal/state"
	"websec/internal/validation"
)

// RelationsAPI is the relations.verify_relations seam. internal/relations
// implements it (relations.API); the default reproduces the empty-campaign
// answer byte-for-byte.
type RelationsAPI interface {
	VerifyRelations(c *state.Campaign) (validation.Value, error)
}

// noRelations is the absent-module default (no relations.json => no edges).
type noRelations struct{}

// VerifyRelations is verify_relations for a campaign with no stored edges.
func (noRelations) VerifyRelations(*state.Campaign) (validation.Value, error) {
	return relationsEmptySection(), nil
}

// relationsEmptySection is {"checked": 0, "problems": [], "ok": True} in
// Python's key order.
func relationsEmptySection() validation.Value {
	return validation.VObj(
		KV("checked", validation.VInt(0)),
		KV("problems", validation.VArr()),
		KV("ok", validation.VBool(true)),
	)
}

var relationsImpl RelationsAPI = noRelations{}

// SetRelations installs relations.verify_relations; nil restores the
// default (no relations artifact = Python's empty-campaign answer).
func SetRelations(r RelationsAPI) {
	if r == nil {
		r = noRelations{}
	}
	relationsImpl = r
}

// Relations is audit.py section 7: report["sections"]["relations"] =
// verify_relations(campaign).
func Relations(c *state.Campaign) (validation.Value, error) {
	return relationsImpl.VerifyRelations(c)
}

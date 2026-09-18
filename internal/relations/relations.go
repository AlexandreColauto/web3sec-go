// Package relations is a 1:1 port of webv2/relations.py: the typed finding
// relation graph. Every edge is log-anchored (relation.minted) and
// schema-validated; deterministic edges are re-derivable from an existing
// structure and re-checked by the audit; caused_by is human-gated;
// resembles is DERIVED and never stored.
package relations

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"websec/internal/state"
	"websec/internal/validation"
)

// NodeTypes is NODE_TYPES.
var NodeTypes = []string{"finding", "snapshot", "exec", "memory", "commit"}

// KindSpec is one RELATION_KINDS entry: src node type, dst node type,
// minting policy (deterministic / human-gated / derived).
type KindSpec struct {
	Kind   string
	Src    string
	Dst    string
	Policy string
}

// RelationKinds is RELATION_KINDS, in Python's dict order.
var RelationKinds = []KindSpec{
	{"chained_with", "finding", "finding", "deterministic"},
	{"validated_by", "finding", "exec", "deterministic"},
	{"observed_in", "finding", "snapshot", "deterministic"},
	{"disproved_by", "finding", "memory", "deterministic"},
	{"fixed_by", "finding", "commit", "deterministic"},
	{"reintroduced_by", "finding", "commit", "deterministic"},
	{"caused_by", "finding", "finding", "human-gated"},
	{"resembles", "finding", "finding", "derived"},
}

// evidenceLevels is _EVIDENCE_LEVELS.
var evidenceLevels = []string{"E4", "E5", "E6", "E7"}

func kindSpec(kind string) (KindSpec, bool) {
	for _, k := range RelationKinds {
		if k.Kind == kind {
			return k, true
		}
	}
	return KindSpec{}, false
}

// RelationsPath is _path: <campaign.dir>/relations.json.
func RelationsPath(c *state.Campaign) string {
	return filepath.Join(c.Dir, "relations.json")
}

// LoadRelations is load_relations: [] when the file is absent.
func LoadRelations(c *state.Campaign) ([]validation.Value, error) {
	p := RelationsPath(c)
	if _, err := os.Stat(p); err != nil {
		return nil, nil
	}
	v, err := validation.ReadJson(p)
	if err != nil {
		return nil, err
	}
	if v.Kind != validation.Arr {
		return nil, errors.New("relations.json must be a list of edges")
	}
	return v.A, nil
}

// SaveRelations is _save: validate every edge, then write the list.
func SaveRelations(c *state.Campaign, rels []validation.Value) error {
	for _, r := range rels {
		if err := validation.Validate(r, "relation", 1); err != nil {
			return err
		}
	}
	return validation.WriteJson(RelationsPath(c), validation.VArr(rels...), "")
}

// node is _node.
func node(type_, id string) validation.Value {
	return validation.VObj(kv("type", validation.VStr(type_)),
		kv("id", validation.VStr(id)))
}

// MintRelation is mint_relation: mint one edge, idempotent per
// (kind, src, dst).
func MintRelation(c *state.Campaign, kind string, src, dst validation.Value,
	support *validation.Value, actor, note *string) (validation.Value, error) {
	if _, ok := kindSpec(kind); !ok {
		return validation.VNull(), fmt.Errorf(
			"unknown relation kind %s; known: %s", pyReprStr(kind),
			pyReprSortedKinds())
	}
	rels, err := LoadRelations(c)
	if err != nil {
		return validation.VNull(), err
	}
	edge, created, err := mintInto(c, &rels, kind, src, dst, support, actor, note)
	if err != nil {
		return validation.VNull(), err
	}
	if created {
		if err := SaveRelations(c, rels); err != nil {
			return validation.VNull(), err
		}
	}
	return edge, nil
}

// mintInto is _mint_into: validation + dedupe + append (+ the log event).
func mintInto(c *state.Campaign, rels *[]validation.Value, kind string,
	src, dst validation.Value, support *validation.Value, actor,
	note *string) (validation.Value, bool, error) {
	spec, _ := kindSpec(kind)
	if spec.Policy == "derived" {
		return validation.VNull(), false, fmt.Errorf(
			"%s is a derived query — it is never stored (resemblance_report "+
				"recomputes it on demand)", pyReprStr(kind))
	}
	if validation.ObjStr(src, "type") != spec.Src || validation.ObjStr(dst, "type") != spec.Dst {
		return validation.VNull(), false, fmt.Errorf(
			"%s requires %s -> %s, got %s -> %s", kind, spec.Src, spec.Dst,
			validation.ObjStr(src, "type"), validation.ObjStr(dst, "type"))
	}
	if spec.Policy == "human-gated" {
		if actor == nil || *actor == "" {
			return validation.VNull(), false, fmt.Errorf(
				"%s is human-gated: a recorded actor is required", kind)
		}
	}
	if spec.Policy == "deterministic" && !supportTruthy(support) {
		return validation.VNull(), false, fmt.Errorf(
			"%s is deterministic: a non-empty support anchor is required", kind)
	}
	for _, r := range *rels {
		if validation.ObjStr(r, "kind") == kind &&
			validation.CanonCompact(validation.ObjAt(r, "src")) == validation.CanonCompact(src) &&
			validation.CanonCompact(validation.ObjAt(r, "dst")) == validation.CanonCompact(dst) {
			return r, false, nil // idempotent
		}
	}
	edge := validation.VObj(
		kv("relation_id", validation.VStr("REL-"+idTail(8))),
		kv("kind", validation.VStr(kind)),
		kv("src", src),
		kv("dst", dst),
		kv("support", supportOrNull(support)),
		kv("actor", strOrNull(actor)),
		kv("note", strOrNull(note)),
		kv("created_at", validation.VStr(state.NowIso())))
	if err := validation.Validate(edge, "relation", 1); err != nil {
		return validation.VNull(), false, err
	}
	*rels = append(*rels, edge)
	rid := validation.ObjStr(edge, "relation_id")
	data := validation.VObj(
		kv("kind", validation.VStr(kind)),
		kv("src", validation.VStr(validation.ObjStr(src, "id"))),
		kv("dst", validation.VStr(validation.ObjStr(dst, "id"))),
		kv("policy", validation.VStr(spec.Policy)))
	if _, err := c.Log("relation.minted", &rid, &data); err != nil {
		return validation.VNull(), false, err
	}
	return edge, true, nil
}

// API is the audit section seam (sections.RelationsAPI).
type API struct{}

// VerifyRelations is sections.RelationsAPI.
func (API) VerifyRelations(c *state.Campaign) (validation.Value, error) {
	return VerifyRelations(c)
}

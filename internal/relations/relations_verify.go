// relations_verify.go: verification — the audit re-runs the derivation
// for every stored edge, plus the grouped graph view.
package relations

import (
	"errors"
	"fmt"
	"slices"
	"websec/internal/findings"
	"websec/internal/learning"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- verification (the audit re-runs the derivation) ----------------------

// VerifyRelations is verify_relations: every stored edge must still be
// supported.
func VerifyRelations(c *state.Campaign) (validation.Value, error) {
	problems := []string{}
	rels, err := LoadRelations(c)
	if err != nil {
		return validation.VNull(), err
	}
	events, err := c.Events()
	if err != nil {
		return validation.VNull(), err
	}
	mintedRefs := map[string]struct{}{}
	for _, e := range events {
		if validation.ObjStr(e, "type") == "relation.minted" {
			mintedRefs[validation.ObjStr(e, "ref")] = struct{}{}
		}
	}
	for _, r := range rels {
		kind := validation.ObjStr(r, "kind")
		src, dst := validation.ObjAt(r, "src"), validation.ObjAt(r, "dst")
		support := validation.ObjAt(r, "support")
		if support.Kind != validation.Obj {
			support = validation.VObj()
		}
		rid := validation.ObjStr(r, "relation_id")
		if rid == "" {
			rid = "?"
		}
		spec, ok := kindSpec(kind)
		if !ok {
			continue
		}
		if spec.Policy == "derived" {
			problems = append(problems, fmt.Sprintf(
				"%s: %s is derived and must never be stored", rid, kind))
			continue
		}
		if spec.Policy == "human-gated" {
			if validation.ObjStr(r, "actor") == "" {
				problems = append(problems, fmt.Sprintf(
					"%s: %s lacks the recorded human actor", rid, kind))
			}
			if _, ok := mintedRefs[rid]; !ok {
				problems = append(problems, fmt.Sprintf(
					"%s: no relation.minted event for this edge", rid))
			}
			continue
		}
		if drift := reDerive(c, kind, src, dst, support); drift != nil {
			problems = append(problems, fmt.Sprintf("%s: %s edge drifted — %s",
				rid, kind, drift.Error()))
		}
	}
	return validation.VObj(
		kv("checked", validation.VInt(int64(len(rels)))),
		kv("problems", validation.StrArr(problems)),
		kv("ok", validation.VBool(len(problems) == 0))), nil
}

// reDerive is verify_relations' deterministic re-derivation; nil = still
// supported.
func reDerive(c *state.Campaign, kind string, src, dst,
	support validation.Value) error {
	switch kind {
	case "chained_with":
		chains, err := chainsOf(c)
		if err != nil {
			return err
		}
		for _, ch := range chains {
			if validation.ObjStr(ch, "chain_id") != validation.ObjStr(support, "chain_id") {
				continue
			}
			m := strList(validation.ObjAt(ch, "members"))
			si, di := indexOf(m, validation.ObjStr(src, "id")), indexOf(m, validation.ObjStr(dst, "id"))
			if si >= 0 && di >= 0 && si+1 == di {
				return nil
			}
			return errors.New("not consecutive members of the anchored chain")
		}
		return errors.New("")
	case "validated_by":
		f, err := findings.LoadFinding(c, validation.ObjStr(src, "id"))
		if err != nil {
			return err
		}
		var item validation.Value
		found := false
		for _, e := range validation.ObjAt(f, "evidence").A {
			if validation.ObjStr(e, "evidence_id") == validation.ObjStr(support, "evidence_id") {
				item, found = e, true
				break
			}
		}
		if !found || !slices.Contains(evidenceLevels, validation.ObjStr(item, "level")) ||
			validation.ObjStr(item, "artifact_id") != validation.ObjStr(dst, "id") {
			return errors.New("evidence no longer traces to this exec")
		}
		recs, err := sandbox.AllExecs(c)
		if err != nil {
			return err
		}
		ids := map[string]struct{}{}
		for _, rec := range recs {
			ids[validation.ObjStr(rec, "exec_id")] = struct{}{}
		}
		if _, ok := ids[validation.ObjStr(dst, "id")]; !ok {
			return errors.New("exec record missing")
		}
		return nil
	case "observed_in":
		f, err := findings.LoadFinding(c, validation.ObjStr(src, "id"))
		if err != nil {
			return err
		}
		if validation.ObjStr(validation.ObjAt(f, "snapshot_ids"), validation.ObjStr(support, "pin")) !=
			validation.ObjStr(dst, "id") {
			return errors.New("finding no longer pinned to this snapshot")
		}
		return nil
	case "disproved_by":
		mems, err := learning.AllMemory(c)
		if err != nil {
			return err
		}
		for _, mem := range mems {
			if validation.ObjStr(mem, "memory_id") != validation.ObjStr(support, "memory_id") {
				continue
			}
			if validation.ObjStr(mem, "status") != "DISPROVED" ||
				validation.ObjStr(mem, "finding_id") != validation.ObjStr(src, "id") {
				break
			}
			return nil
		}
		return errors.New("memory no longer disproves this finding")
	case "fixed_by", "reintroduced_by":
		s, err := matchingCommit(c, validation.ObjStr(src, "id"), validation.ObjStr(support, "commit"))
		if err != nil {
			return err
		}
		if s == nil {
			return errors.New("commit no longer matches the affected paths")
		}
		if validation.CanonCompact(validation.ObjAt(*s, "matched_files")) !=
			validation.CanonCompact(validation.ObjAt(support, "matched_files")) {
			return errors.New("matched files drifted")
		}
		if kind == "reintroduced_by" {
			e, err := matchingCommit(c, validation.ObjStr(src, "id"),
				validation.ObjStr(support, "after_commit"))
			if err != nil {
				return err
			}
			if e == nil || !(validation.ObjStr(*s, "date") > validation.ObjStr(*e, "date")) {
				return errors.New("date order no longer holds")
			}
		}
		return nil
	}
	return nil
}

// GraphView is graph_view: all stored edges, grouped by kind.
func GraphView(c *state.Campaign) (validation.Value, error) {
	rels, err := LoadRelations(c)
	if err != nil {
		return validation.VNull(), err
	}
	byKind := map[string][]validation.Value{}
	for _, r := range rels {
		k := validation.ObjStr(r, "kind")
		byKind[k] = append(byKind[k], r)
	}
	grouped := validation.VObj()
	policies := validation.VObj()
	for _, k := range RelationKinds {
		edges := byKind[k.Kind]
		if edges == nil {
			edges = []validation.Value{}
		}
		grouped.O = append(grouped.O, kv(k.Kind, validation.VArr(edges...)))
		policies.O = append(policies.O, kv(k.Kind, validation.VStr(k.Policy)))
	}
	return validation.VObj(
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("edge_count", validation.VInt(int64(len(rels)))),
		kv("by_kind", grouped),
		kv("policies", policies)), nil
}

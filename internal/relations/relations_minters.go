// relations_minters.go: the deterministic minters — one entry per
// deterministic RELATION_KINDS policy, plus mint_all_deterministic.
package relations

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"websec/internal/findings"
	"websec/internal/learning"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- deterministic minters -------------------------------------------------

// chainsOf is _chains: CHAIN-*.json sorted by path.
//
// r43a: an absent chains/ directory is an empty campaign; a chains/ directory
// that cannot be listed refuses rather than reporting zero chains — relation
// minting reads these docs to decide what exists.
func chainsOf(c *state.Campaign) ([]validation.Value, error) {
	paths, err := validation.ListPrefixedOptional(c.ChainsDir, "CHAIN-", ".json")
	if err != nil {
		return nil, fmt.Errorf("the chain store %s cannot be listed: %v",
			c.ChainsDir, err)
	}
	out := make([]validation.Value, 0, len(paths))
	for _, p := range paths {
		v, err := validation.ReadJson(p)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// appendEdge is _append_edge: mint_relation, or mintInto in batch mode.
func appendEdge(c *state.Campaign, rels *[]validation.Value, kind string,
	src, dst validation.Value, support validation.Value,
	note *string) (validation.Value, error) {
	if rels == nil {
		return MintRelation(c, kind, src, dst, &support, nil, note)
	}
	edge, _, err := mintInto(c, rels, kind, src, dst, &support, nil, note)
	return edge, err
}

// MintChainedWith is mint_chained_with: one edge per consecutive member
// pair of a materialized chain.
func MintChainedWith(c *state.Campaign, chainID string,
	rels *[]validation.Value) ([]validation.Value, error) {
	chains, err := chainsOf(c)
	if err != nil {
		return nil, err
	}
	var chain validation.Value
	found := false
	for _, ch := range chains {
		if validation.ObjStr(ch, "chain_id") == chainID {
			chain, found = ch, true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("no materialized chain %s", pyReprStr(chainID))
	}
	members := strList(validation.ObjAt(chain, "members"))
	out := []validation.Value{}
	for i := 0; i+1 < len(members); i++ {
		a, b := members[i], members[i+1]
		note := "consecutive members of " + chainID
		edge, err := appendEdge(c, rels, "chained_with",
			node("finding", a), node("finding", b),
			validation.VObj(kv("chain_id", validation.VStr(chainID))), &note)
		if err != nil {
			return nil, err
		}
		out = append(out, edge)
	}
	return out, nil
}

// MintValidatedBy is mint_validated_by: finding -> exec for every E4+
// evidence item whose artifact is an EXEC record.
func MintValidatedBy(c *state.Campaign, findingID string,
	rels *[]validation.Value, execIDs map[string]struct{}) ([]validation.Value, error) {
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return nil, err
	}
	if execIDs == nil {
		recs, err := sandbox.AllExecs(c)
		if err != nil {
			return nil, err
		}
		execIDs = map[string]struct{}{}
		for _, rec := range recs {
			execIDs[validation.ObjStr(rec, "exec_id")] = struct{}{}
		}
	}
	out := []validation.Value{}
	for _, item := range validation.ObjAt(f, "evidence").A {
		if !slices.Contains(evidenceLevels, validation.ObjStr(item, "level")) {
			continue
		}
		aid := validation.ObjStr(item, "artifact_id")
		if aid == "" {
			continue
		}
		if _, ok := execIDs[aid]; !ok {
			continue
		}
		note := validation.ObjStr(item, "level") + " " + pyStr(validation.ObjAt(item, "type")) + " evidence"
		edge, err := appendEdge(c, rels, "validated_by",
			node("finding", findingID), node("exec", aid),
			validation.VObj(kv("evidence_id",
				validation.VStr(validation.ObjStr(item, "evidence_id")))), &note)
		if err != nil {
			return nil, err
		}
		out = append(out, edge)
	}
	return out, nil
}

// MintObservedIn is mint_observed_in: finding -> snapshot for every pin the
// finding is recorded against.
func MintObservedIn(c *state.Campaign, findingID string,
	rels *[]validation.Value) ([]validation.Value, error) {
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return nil, err
	}
	out := []validation.Value{}
	for _, entry := range validation.ObjAt(f, "snapshot_ids").O {
		if entry.V.Kind != validation.Str || entry.V.S == "" {
			continue
		}
		edge, err := appendEdge(c, rels, "observed_in",
			node("finding", findingID), node("snapshot", entry.V.S),
			validation.VObj(kv("pin", validation.VStr(entry.K))), nil)
		if err != nil {
			return nil, err
		}
		out = append(out, edge)
	}
	return out, nil
}

// MintDisprovedBy is mint_disproved_by: finding -> memory for every
// DISPROVED memory row about it.
func MintDisprovedBy(c *state.Campaign, findingID string,
	rels *[]validation.Value, mems []validation.Value) ([]validation.Value, error) {
	if mems == nil {
		var err error
		mems, err = learning.AllMemory(c)
		if err != nil {
			return nil, err
		}
	}
	out := []validation.Value{}
	for _, mem := range mems {
		if validation.ObjStr(mem, "finding_id") != findingID ||
			validation.ObjStr(mem, "status") != "DISPROVED" {
			continue
		}
		note := head200(validation.ObjStr(mem, "evidence_summary"))
		if note == "" {
			note = head200(validation.ObjStr(mem, "pattern"))
		}
		var notePtr *string
		if note != "" {
			notePtr = &note
		}
		edge, err := appendEdge(c, rels, "disproved_by",
			node("finding", findingID), node("memory", validation.ObjStr(mem, "memory_id")),
			validation.VObj(
				kv("memory_id", validation.VStr(validation.ObjStr(mem, "memory_id"))),
				kv("status", validation.VStr("DISPROVED"))), notePtr)
		if err != nil {
			return nil, err
		}
		out = append(out, edge)
	}
	return out, nil
}

// historyCommits is _history_commits: the mined fix commits, or none.
func historyCommits(c *state.Campaign) ([]validation.Value, error) {
	p := filepath.Join(c.ArtifactsDir, "history_mining.json")
	if _, err := os.Stat(p); err != nil {
		return nil, nil
	}
	doc, err := validation.ReadJson(p)
	if err != nil {
		return nil, err
	}
	return validation.ObjAt(doc, "security_relevant_commits").A, nil
}

// affectedPaths is _affected_paths.
func affectedPaths(f validation.Value) map[string]struct{} {
	out := map[string]struct{}{}
	for _, a := range validation.ObjAt(f, "affected").A {
		if p := validation.ObjStr(a, "path"); p != "" {
			out[p] = struct{}{}
		}
	}
	return out
}

// matchingCommit is _matching_commit: the re-derivation core for
// fixed_by/reintroduced_by.
func matchingCommit(c *state.Campaign, findingID, commit string) (*validation.Value, error) {
	f, err := findings.LoadFinding(c, findingID)
	if err != nil {
		return nil, err
	}
	paths := affectedPaths(f)
	commits, err := historyCommits(c)
	if err != nil {
		return nil, err
	}
	for _, cm := range commits {
		if validation.ObjStr(cm, "commit") != commit {
			continue
		}
		matched := []string{}
		for _, fp := range strList(validation.ObjAt(cm, "files")) {
			if _, ok := paths[fp]; ok {
				matched = append(matched, fp)
			}
		}
		sort.Strings(matched)
		if len(matched) == 0 {
			return nil, nil
		}
		sup := validation.VObj(
			kv("commit", validation.VStr(commit)),
			kv("date", validation.ObjAt(cm, "date")),
			kv("subject", validation.ObjAt(cm, "subject")),
			kv("matched_files", validation.StrArr(matched)))
		return &sup, nil
	}
	return nil, nil
}

// MintFixedBy is mint_fixed_by.
func MintFixedBy(c *state.Campaign, findingID, commit string) (validation.Value, error) {
	s, err := matchingCommit(c, findingID, commit)
	if err != nil {
		return validation.VNull(), err
	}
	if s == nil {
		return validation.VNull(), fmt.Errorf(
			"commit %s does not touch a path affected by %s in the mined "+
				"history — fixed_by must be checkable", pyReprStr(commit), findingID)
	}
	return MintRelation(c, "fixed_by", node("finding", findingID),
		node("commit", commit), s, nil, nil)
}

// MintReintroducedBy is mint_reintroduced_by: a later mined commit
// re-touches the affected paths after a fix.
func MintReintroducedBy(c *state.Campaign, findingID, commit,
	afterCommit string) (validation.Value, error) {
	later, err := matchingCommit(c, findingID, commit)
	if err != nil {
		return validation.VNull(), err
	}
	earlier, err := matchingCommit(c, findingID, afterCommit)
	if err != nil {
		return validation.VNull(), err
	}
	if later == nil || earlier == nil {
		return validation.VNull(), fmt.Errorf(
			"both commits must touch paths affected by %s in the mined "+
				"history — reintroduced_by must be checkable", findingID)
	}
	laterDate := validation.ObjStr(*later, "date")
	earlierDate := validation.ObjStr(*earlier, "date")
	if !(laterDate > earlierDate) {
		return validation.VNull(), fmt.Errorf(
			"reintroduction commit %s (%s) is not dated after the fix commit "+
				"%s (%s)", commit, laterDate, afterCommit, earlierDate)
	}
	sup := validation.VObj()
	sup.O = append(sup.O, later.O...)
	sup.O = append(sup.O, kv("after_commit", validation.VStr(afterCommit)))
	return MintRelation(c, "reintroduced_by", node("finding", findingID),
		node("commit", commit), &sup, nil, nil)
}

// MintCausation is mint_causation: caused_by is a human attestation.
func MintCausation(c *state.Campaign, srcFinding, dstFinding, actor,
	note string) (validation.Value, error) {
	if _, err := findings.LoadFinding(c, srcFinding); err != nil {
		return validation.VNull(), err
	}
	if _, err := findings.LoadFinding(c, dstFinding); err != nil {
		return validation.VNull(), err
	}
	var notePtr *string
	if note != "" {
		notePtr = &note
	}
	return MintRelation(c, "caused_by", node("finding", srcFinding),
		node("finding", dstFinding),
		&validation.Value{Kind: validation.Obj, O: []validation.KV{
			kv("attested", validation.VBool(true))}}, &actor, notePtr)
}

// MintAllDeterministic is mint_all_deterministic: re-derive every
// deterministic edge from the current structures. Returns the number of NEW
// edges minted.
func MintAllDeterministic(c *state.Campaign) (int, error) {
	rels, err := LoadRelations(c)
	if err != nil {
		return 0, err
	}
	before := len(rels)
	recs, err := sandbox.AllExecs(c)
	if err != nil {
		return 0, err
	}
	execIDs := map[string]struct{}{}
	for _, rec := range recs {
		execIDs[validation.ObjStr(rec, "exec_id")] = struct{}{}
	}
	mems, err := learning.AllMemory(c)
	if err != nil {
		return 0, err
	}
	chains, err := chainsOf(c)
	if err != nil {
		return 0, err
	}
	for _, ch := range chains {
		if _, err := MintChainedWith(c, validation.ObjStr(ch, "chain_id"), &rels); err != nil {
			return 0, err
		}
	}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return 0, err
	}
	for _, f := range all {
		fid := validation.ObjStr(f, "finding_id")
		if _, err := MintValidatedBy(c, fid, &rels, execIDs); err != nil {
			return 0, err
		}
		if _, err := MintObservedIn(c, fid, &rels); err != nil {
			return 0, err
		}
		if _, err := MintDisprovedBy(c, fid, &rels, mems); err != nil {
			return 0, err
		}
	}
	if len(rels) != before {
		if err := SaveRelations(c, rels); err != nil {
			return 0, err
		}
	}
	return len(rels) - before, nil
}

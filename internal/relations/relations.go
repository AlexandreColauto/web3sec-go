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
	"sort"
	"strings"

	"websec/internal/capabilities"
	"websec/internal/chainengine"
	"websec/internal/findings"
	"websec/internal/immunize"
	"websec/internal/learning"
	"websec/internal/sandbox"
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
	if objStr(src, "type") != spec.Src || objStr(dst, "type") != spec.Dst {
		return validation.VNull(), false, fmt.Errorf(
			"%s requires %s -> %s, got %s -> %s", kind, spec.Src, spec.Dst,
			objStr(src, "type"), objStr(dst, "type"))
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
		if objStr(r, "kind") == kind &&
			validation.CanonCompact(objAt(r, "src")) == validation.CanonCompact(src) &&
			validation.CanonCompact(objAt(r, "dst")) == validation.CanonCompact(dst) {
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
	rid := objStr(edge, "relation_id")
	data := validation.VObj(
		kv("kind", validation.VStr(kind)),
		kv("src", validation.VStr(objStr(src, "id"))),
		kv("dst", validation.VStr(objStr(dst, "id"))),
		kv("policy", validation.VStr(spec.Policy)))
	if _, err := c.Log("relation.minted", &rid, &data); err != nil {
		return validation.VNull(), false, err
	}
	return edge, true, nil
}

// ---- deterministic minters -------------------------------------------------

// chainsOf is _chains: CHAIN-*.json sorted by path.
func chainsOf(c *state.Campaign) ([]validation.Value, error) {
	paths, err := filepath.Glob(filepath.Join(c.ChainsDir, "CHAIN-*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
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
		if objStr(ch, "chain_id") == chainID {
			chain, found = ch, true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("no materialized chain %s", pyReprStr(chainID))
	}
	members := strList(objAt(chain, "members"))
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
			execIDs[objStr(rec, "exec_id")] = struct{}{}
		}
	}
	out := []validation.Value{}
	for _, item := range objAt(f, "evidence").A {
		if !inList(objStr(item, "level"), evidenceLevels) {
			continue
		}
		aid := objStr(item, "artifact_id")
		if aid == "" {
			continue
		}
		if _, ok := execIDs[aid]; !ok {
			continue
		}
		note := objStr(item, "level") + " " + pyStr(objAt(item, "type")) + " evidence"
		edge, err := appendEdge(c, rels, "validated_by",
			node("finding", findingID), node("exec", aid),
			validation.VObj(kv("evidence_id",
				validation.VStr(objStr(item, "evidence_id")))), &note)
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
	for _, entry := range objAt(f, "snapshot_ids").O {
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
		if objStr(mem, "finding_id") != findingID ||
			objStr(mem, "status") != "DISPROVED" {
			continue
		}
		note := head200(objStr(mem, "evidence_summary"))
		if note == "" {
			note = head200(objStr(mem, "pattern"))
		}
		var notePtr *string
		if note != "" {
			notePtr = &note
		}
		edge, err := appendEdge(c, rels, "disproved_by",
			node("finding", findingID), node("memory", objStr(mem, "memory_id")),
			validation.VObj(
				kv("memory_id", validation.VStr(objStr(mem, "memory_id"))),
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
	return objAt(doc, "security_relevant_commits").A, nil
}

// affectedPaths is _affected_paths.
func affectedPaths(f validation.Value) map[string]struct{} {
	out := map[string]struct{}{}
	for _, a := range objAt(f, "affected").A {
		if p := objStr(a, "path"); p != "" {
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
		if objStr(cm, "commit") != commit {
			continue
		}
		matched := []string{}
		for _, fp := range strList(objAt(cm, "files")) {
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
			kv("date", objAt(cm, "date")),
			kv("subject", objAt(cm, "subject")),
			kv("matched_files", strArr(matched)))
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
	laterDate := objStr(*later, "date")
	earlierDate := objStr(*earlier, "date")
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
		execIDs[objStr(rec, "exec_id")] = struct{}{}
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
		if _, err := MintChainedWith(c, objStr(ch, "chain_id"), &rels); err != nil {
			return 0, err
		}
	}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return 0, err
	}
	for _, f := range all {
		fid := objStr(f, "finding_id")
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

// ---- the capability-coverage delta ----------------------------------------

// exploitPath is _exploit_path: the materialized chain the finding is a
// member of (if any), else the finding alone.
func exploitPath(c *state.Campaign, findingID string) ([]string, error) {
	chains, err := chainsOf(c)
	if err != nil {
		return nil, err
	}
	for _, ch := range chains {
		if inList(findingID, strList(objAt(ch, "members"))) {
			return strList(objAt(ch, "members")), nil
		}
	}
	return []string{findingID}, nil
}

// CapabilityCoverage is capability_coverage: set arithmetic over RECORDED
// capabilities — no code inference.
func CapabilityCoverage(c *state.Campaign, candidateID,
	primitiveID string) (validation.Value, error) {
	cand, err := findings.LoadFinding(c, candidateID)
	if err != nil {
		return validation.VNull(), err
	}
	prim, err := findings.LoadFinding(c, primitiveID)
	if err != nil {
		return validation.VNull(), err
	}
	pathP, err := exploitPath(c, primitiveID)
	if err != nil {
		return validation.VNull(), err
	}
	dependsRaw := map[string]struct{}{}
	for _, fid := range pathP {
		f, err := findings.LoadFinding(c, fid)
		if err != nil {
			return validation.VNull(), err
		}
		for _, lab := range capabilities.Required(f) {
			dependsRaw[lab] = struct{}{}
		}
	}
	pin := objStr(objAt(cand, "snapshot_ids"), "source")
	provides := map[string]struct{}{}
	codeSourced := map[string]struct{}{}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return validation.VNull(), err
	}
	for _, f := range all {
		if s := objStr(f, "status"); s == "DUPLICATE" || s == "OUT_OF_SCOPE" {
			continue
		}
		for _, lab := range capabilities.Granted(f) {
			codeSourced[lab] = struct{}{}
		}
		if objStr(objAt(f, "snapshot_ids"), "source") == pin {
			for _, lab := range capabilities.Granted(f) {
				provides[lab] = struct{}{}
			}
		}
	}
	depends := map[string]struct{}{}
	for lab := range dependsRaw {
		if _, ok := codeSourced[lab]; !ok {
			continue
		}
		if inList(lab, chainengine.AttackerBaseline) {
			continue
		}
		depends[lab] = struct{}{}
	}
	missing := []string{}
	for lab := range depends {
		if _, ok := provides[lab]; !ok {
			missing = append(missing, lab)
		}
	}
	sort.Strings(missing)
	satisfied := []string{}
	for lab := range depends {
		if _, ok := provides[lab]; ok {
			satisfied = append(satisfied, lab)
		}
	}
	sort.Strings(satisfied)
	candGranted := capabilities.Granted(cand)
	primGranted := capabilities.Granted(prim)
	overlap := []string{}
	for _, lab := range candGranted {
		if inList(lab, primGranted) {
			overlap = append(overlap, lab)
		}
	}
	sort.Strings(overlap)
	union := map[string]struct{}{}
	for _, lab := range candGranted {
		union[lab] = struct{}{}
	}
	for _, lab := range primGranted {
		union[lab] = struct{}{}
	}
	var sim validation.Value
	if len(union) > 0 {
		sim = validation.VFloat(validation.PyRound(
			float64(len(overlap))/float64(len(union)), 3))
	} else {
		sim = validation.VNull()
	}
	terminal := false
	for _, lab := range candGranted {
		if capabilities.IsTerminal(lab) {
			terminal = true
			break
		}
	}
	dependsSorted := sortedKeys(depends)
	bits := []string{}
	if len(missing) > 0 {
		bits = append(bits, fmt.Sprintf("the confirmed primitive's exploit "+
			"path required %s; the candidate context no longer provides %s — "+
			"the patch may have removed exactly those capabilities",
			pyReprList(dependsSorted), pyReprList(missing)))
	} else {
		bits = append(bits, "every capability the confirmed primitive "+
			"depended on is still provided by the candidate context")
	}
	if terminal && len(missing) > 0 {
		bits = append(bits, "the candidate still reaches an economic terminal "+
			"state — re-verify whether the missing capabilities are truly gone "+
			"or merely moved")
	}
	classMatch := objStr(objAt(cand, "root_cause"), "class") ==
		objStr(objAt(prim, "root_cause"), "class")
	return validation.VObj(
		kv("candidate_id", validation.VStr(candidateID)),
		kv("primitive_id", validation.VStr(primitiveID)),
		kv("class_match", validation.VBool(classMatch)),
		kv("granted_overlap", strArr(overlap)),
		kv("similarity", sim),
		kv("primitive_depended_on", strArr(dependsSorted)),
		kv("still_provided", strArr(satisfied)),
		kv("missing", strArr(missing)),
		kv("candidate_reaches_terminal", validation.VBool(terminal)),
		kv("advisory", validation.VStr(strings.Join(bits, " ")))), nil
}

// ResemblanceReport is resemblance_report: derived 'resembles' edges —
// computed, never stored.
func ResemblanceReport(c *state.Campaign,
	candidateID string) (validation.Value, error) {
	cand, err := findings.LoadFinding(c, candidateID)
	if err != nil {
		return validation.VNull(), err
	}
	out := []validation.Value{}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return validation.VNull(), err
	}
	for _, f := range all {
		fid := objStr(f, "finding_id")
		if fid == candidateID {
			continue
		}
		if s := objStr(f, "status"); s != "CONFIRMED" && s != "CHAIN" {
			continue
		}
		cov, err := CapabilityCoverage(c, candidateID, fid)
		if err != nil {
			return validation.VNull(), err
		}
		classMatch := objAt(cov, "class_match").B
		if !classMatch && len(objAt(cov, "granted_overlap").A) == 0 {
			continue
		}
		out = append(out, cov)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ci, cj := out[i], out[j]
		mi, mj := !objAt(ci, "class_match").B, !objAt(cj, "class_match").B
		if mi != mj {
			return !mi
		}
		si, sj := simOf(ci), simOf(cj)
		if si != sj {
			return si > sj
		}
		return len(objAt(ci, "missing").A) < len(objAt(cj, "missing").A)
	})
	return validation.VObj(
		kv("candidate_id", validation.VStr(candidateID)),
		kv("candidate_class", objAt(objAt(cand, "root_cause"), "class")),
		kv("candidate_required", strArr(capabilities.Required(cand))),
		kv("matches", validation.VArr(out...)),
		kv("note", validation.VStr("derived query — resemblance edges are "+
			"never stored; recomputed on demand so a heuristic can never "+
			"fossilize"))), nil
}

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
		if objStr(e, "type") == "relation.minted" {
			mintedRefs[objStr(e, "ref")] = struct{}{}
		}
	}
	for _, r := range rels {
		kind := objStr(r, "kind")
		src, dst := objAt(r, "src"), objAt(r, "dst")
		support := objAt(r, "support")
		if support.Kind != validation.Obj {
			support = validation.VObj()
		}
		rid := objStr(r, "relation_id")
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
			if objStr(r, "actor") == "" {
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
		kv("problems", strArr(problems)),
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
			if objStr(ch, "chain_id") != objStr(support, "chain_id") {
				continue
			}
			m := strList(objAt(ch, "members"))
			si, di := indexOf(m, objStr(src, "id")), indexOf(m, objStr(dst, "id"))
			if si >= 0 && di >= 0 && si+1 == di {
				return nil
			}
			return errors.New("not consecutive members of the anchored chain")
		}
		return errors.New("")
	case "validated_by":
		f, err := findings.LoadFinding(c, objStr(src, "id"))
		if err != nil {
			return err
		}
		var item validation.Value
		found := false
		for _, e := range objAt(f, "evidence").A {
			if objStr(e, "evidence_id") == objStr(support, "evidence_id") {
				item, found = e, true
				break
			}
		}
		if !found || !inList(objStr(item, "level"), evidenceLevels) ||
			objStr(item, "artifact_id") != objStr(dst, "id") {
			return errors.New("evidence no longer traces to this exec")
		}
		recs, err := sandbox.AllExecs(c)
		if err != nil {
			return err
		}
		ids := map[string]struct{}{}
		for _, rec := range recs {
			ids[objStr(rec, "exec_id")] = struct{}{}
		}
		if _, ok := ids[objStr(dst, "id")]; !ok {
			return errors.New("exec record missing")
		}
		return nil
	case "observed_in":
		f, err := findings.LoadFinding(c, objStr(src, "id"))
		if err != nil {
			return err
		}
		if objStr(objAt(f, "snapshot_ids"), objStr(support, "pin")) !=
			objStr(dst, "id") {
			return errors.New("finding no longer pinned to this snapshot")
		}
		return nil
	case "disproved_by":
		mems, err := learning.AllMemory(c)
		if err != nil {
			return err
		}
		for _, mem := range mems {
			if objStr(mem, "memory_id") != objStr(support, "memory_id") {
				continue
			}
			if objStr(mem, "status") != "DISPROVED" ||
				objStr(mem, "finding_id") != objStr(src, "id") {
				break
			}
			return nil
		}
		return errors.New("memory no longer disproves this finding")
	case "fixed_by", "reintroduced_by":
		s, err := matchingCommit(c, objStr(src, "id"), objStr(support, "commit"))
		if err != nil {
			return err
		}
		if s == nil {
			return errors.New("commit no longer matches the affected paths")
		}
		if validation.CanonCompact(objAt(*s, "matched_files")) !=
			validation.CanonCompact(objAt(support, "matched_files")) {
			return errors.New("matched files drifted")
		}
		if kind == "reintroduced_by" {
			e, err := matchingCommit(c, objStr(src, "id"),
				objStr(support, "after_commit"))
			if err != nil {
				return err
			}
			if e == nil || !(objStr(*s, "date") > objStr(*e, "date")) {
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
		k := objStr(r, "kind")
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

// ---- root-cause clustering (a DERIVED view, never stored) -----------------

var clusterStatuses = []string{"CONFIRMED", "CHAIN"}

// affectedSignature is _affected_signature.
func affectedSignature(f validation.Value) []string {
	parts := map[string]struct{}{}
	for _, a := range objAt(f, "affected").A {
		path := strings.TrimSpace(objStr(a, "path"))
		if path == "" {
			continue
		}
		fn := strings.TrimSpace(objStr(a, "function"))
		if fn != "" {
			parts[path+"::"+fn] = struct{}{}
		} else {
			parts[path] = struct{}{}
		}
	}
	return sortedKeys(parts)
}

// RootCauseClusters is root_cause_clusters.
func RootCauseClusters(c *state.Campaign) (validation.Value, error) {
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return validation.VNull(), err
	}
	byClass := map[string][]validation.Value{}
	for _, f := range all {
		if !inList(objStr(f, "status"), clusterStatuses) {
			continue
		}
		cls := strings.TrimSpace(objStr(objAt(f, "root_cause"), "class"))
		if cls == "" {
			continue
		}
		byClass[cls] = append(byClass[cls], f)
	}
	rels, err := LoadRelations(c)
	if err != nil {
		return validation.VNull(), err
	}
	classes := make([]string, 0, len(byClass))
	for cls := range byClass {
		classes = append(classes, cls)
	}
	sort.Strings(classes)
	clusters := []validation.Value{}
	for _, cls := range classes {
		members := byClass[cls]
		if len(members) < 2 {
			continue
		}
		sort.SliceStable(members, func(i, j int) bool {
			return objStr(members[i], "finding_id") < objStr(members[j], "finding_id")
		})
		memberIDs := map[string]struct{}{}
		for _, f := range members {
			memberIDs[objStr(f, "finding_id")] = struct{}{}
		}
		sigOrder := []string{}
		sub := map[string][]validation.Value{}
		for _, f := range members {
			key := strings.Join(affectedSignature(f), "\x00")
			if _, ok := sub[key]; !ok {
				sigOrder = append(sigOrder, key)
			}
			sub[key] = append(sub[key], f)
		}
		sort.SliceStable(sigOrder, func(i, j int) bool {
			si := strings.Split(sigOrder[i], "\x00")
			sj := strings.Split(sigOrder[j], "\x00")
			if len(si) != len(sj) {
				return len(si) < len(sj)
			}
			return strings.Join(si, "\x00") < strings.Join(sj, "\x00")
		})
		subclusters := []validation.Value{}
		for _, key := range sigOrder {
			fs := sub[key]
			sig := affectedSignature(fs[0])
			locations := sig
			if len(locations) == 0 {
				locations = []string{"(no affected location recorded)"}
			}
			ids := []string{}
			immunized := []string{}
			for _, f := range fs {
				fid := objStr(f, "finding_id")
				ids = append(ids, fid)
				if immunize.IsImmunized(f) {
					immunized = append(immunized, fid)
				}
			}
			sort.Strings(immunized)
			subclusters = append(subclusters, validation.VObj(
				kv("locations", strArr(locations)),
				kv("finding_ids", strArr(ids)),
				kv("immunized", strArr(immunized))))
		}
		rc := objAt(members[0], "root_cause")
		attested := []validation.Value{}
		for _, r := range rels {
			if objStr(r, "kind") != "caused_by" {
				continue
			}
			src, dst := objAt(r, "src"), objAt(r, "dst")
			_, sOK := memberIDs[objStr(src, "id")]
			_, dOK := memberIDs[objStr(dst, "id")]
			if sOK && dOK {
				attested = append(attested, validation.VObj(
					kv("src", validation.VStr(objStr(src, "id"))),
					kv("dst", validation.VStr(objStr(dst, "id"))),
					kv("actor", objAt(r, "actor"))))
			}
		}
		memberIDsList := []string{}
		for _, f := range members {
			memberIDsList = append(memberIDsList, objStr(f, "finding_id"))
		}
		clusters = append(clusters, validation.VObj(
			kv("class", validation.VStr(cls)),
			kv("description", validation.VStr(head300(objStr(rc, "description")))),
			kv("mechanism", objAt(rc, "mechanism")),
			kv("members", strArr(memberIDsList)),
			kv("subclusters", validation.VArr(subclusters...)),
			kv("attested_causation", validation.VArr(attested...))))
	}
	return validation.VObj(
		kv("clusters", validation.VArr(clusters...)),
		kv("note", validation.VStr("derived view — recomputed from finding "+
			"metadata on every call; only human-attested caused_by edges are "+
			"stored (the relations graph)"))), nil
}

// API is the audit section seam (sections.RelationsAPI).
type API struct{}

// VerifyRelations is sections.RelationsAPI.
func (API) VerifyRelations(c *state.Campaign) (validation.Value, error) {
	return VerifyRelations(c)
}

// ---- helpers --------------------------------------------------------------

func objAt(v validation.Value, key string) validation.Value {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

func objStr(v validation.Value, key string) string {
	f := objAt(v, key)
	if f.Kind == validation.Str {
		return f.S
	}
	return ""
}

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func strOrNull(s *string) validation.Value {
	if s == nil {
		return validation.VNull()
	}
	return validation.VStr(*s)
}

func supportOrNull(s *validation.Value) validation.Value {
	if s == nil || s.Kind != validation.Obj {
		return validation.VNull()
	}
	return *s
}

func supportTruthy(s *validation.Value) bool {
	return s != nil && s.Kind == validation.Obj && len(s.O) > 0
}

func strArr(items []string) validation.Value {
	out := make([]validation.Value, 0, len(items))
	for _, s := range items {
		out = append(out, validation.VStr(s))
	}
	return validation.VArr(out...)
}

func strList(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, e := range v.A {
		if e.Kind == validation.Str {
			out = append(out, e.S)
		}
	}
	return out
}

func inList(s string, list []string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func indexOf(list []string, s string) int {
	for i, item := range list {
		if item == s {
			return i
		}
	}
	return -1
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func simOf(v validation.Value) float64 {
	s := objAt(v, "similarity")
	if s.Kind == validation.Flt {
		return s.F
	}
	if s.Kind == validation.Int {
		return float64(s.I)
	}
	return 0
}

// head200 is (s or "")[:200] on code points.
func head200(s string) string { return headN(s, 200) }

// head300 is (s or "")[:300] on code points.
func head300(s string) string { return headN(s, 300) }

func headN(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}

// pyReprList is Python's list repr of strings: ['a', 'b'].
func pyReprList(items []string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, pyReprStr(it))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func pyReprStr(s string) string { return validation.PyReprStr(s) }

// pyStr is str(value): None renders as "None", strings as themselves.
func pyStr(v validation.Value) string {
	if v.Kind == validation.Null {
		return "None"
	}
	if v.Kind == validation.Str {
		return v.S
	}
	return validation.CanonCompact(v)
}

// pyReprSortedKinds is sorted(RELATION_KINDS) as a Python list repr.
func pyReprSortedKinds() string {
	names := make([]string, 0, len(RelationKinds))
	for _, k := range RelationKinds {
		names = append(names, k.Kind)
	}
	sort.Strings(names)
	return pyReprList(names)
}

// idTail is new_id('x', n).split('-')[1].
func idTail(n int) string {
	return strings.SplitN(state.NewID("x", n), "-", 2)[1]
}

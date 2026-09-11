// Package invariants ports webv2/invariants.py: the invariant registry, the
// audit's central object. Every hypothesis, PoC, fuzz property, symbolic
// query and detector hangs off an INV id; `test_status` is the test axis,
// `status` the orthogonal verification axis (only the framework's
// verify/contradict APIs may move it).
package invariants

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"websec/internal/state"
	"websec/internal/validation"
)

// Statuses is STATUSES: the test axis values, in Python tuple order.
var Statuses = []string{"untested", "violated", "held", "untestable"}

// VerificationStatuses is VERIFICATION_STATUSES: the verification axis.
var VerificationStatuses = []string{
	"UNVERIFIED", "CHECKED_AGAINST_CODE", "CONTRADICTED",
}

// curatedInvariantIDs is the playbooks.curated_invariant_ids seam: ids
// declared by any loadable playbook join the documented set (spec 3.2 §4.7).
// Default is the empty set — playbooks is not ported yet, so every id that
// is not in the target's own docs stays model-source.
var curatedInvariantIDs = func() map[string]struct{} {
	return map[string]struct{}{}
}

// SetCuratedInvariantIDs wires playbooks.curated_invariant_ids.
func SetCuratedInvariantIDs(f func() []string) {
	if f == nil {
		panic("invariants: nil curated id source")
	}
	curatedInvariantIDs = func() map[string]struct{} {
		out := map[string]struct{}{}
		for _, id := range f() {
			out[id] = struct{}{}
		}
		return out
	}
}

// ---- small Value helpers -------------------------------------------------

// pair is the keyed KV constructor for non-test code (test files define
// their own kv()).
func pair(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// objAt is dict.get(key) with a Null fallback.
func objAt(v validation.Value, key string) validation.Value {
	for _, e := range v.O {
		if e.K == key {
			return e.V
		}
	}
	return validation.VNull()
}

// fieldAt is (value, present) — the absent vs present-as-null distinction
// Python's .get(default) needs.
func fieldAt(v validation.Value, key string) (validation.Value, bool) {
	for _, e := range v.O {
		if e.K == key {
			return e.V, true
		}
	}
	return validation.VNull(), false
}

// objStr is objAt under Python str() ("" for a non-string).
func objStr(v validation.Value, key string) string {
	if x := objAt(v, key); x.Kind == validation.Str {
		return x.S
	}
	return ""
}

// hasKey is `key in dict`.
func hasKey(v validation.Value, key string) bool {
	for _, e := range v.O {
		if e.K == key {
			return true
		}
	}
	return false
}

// popKey is dict.pop(key, None).
func popKey(o []validation.KV, key string) []validation.KV {
	out := o[:0:0]
	for _, e := range o {
		if e.K != key {
			out = append(out, e)
		}
	}
	return out
}

// getOr is dict.get(key, default): present wins even when null.
func getOr(v validation.Value, key string, def validation.Value) validation.Value {
	if x, ok := fieldAt(v, key); ok {
		return x
	}
	return def
}

// pyStr is Python str() over a Value (f-string default formatting).
func pyStr(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return v.S
	case validation.Null:
		return "None"
	case validation.Bool:
		if v.B {
			return "True"
		}
		return "False"
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	}
	return validation.PyRepr(v)
}
func strPtr(s string) *string { return &s }

func inList(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func strArr(items []string) validation.Value {
	out := make([]validation.Value, len(items))
	for i, s := range items {
		out[i] = validation.VStr(s)
	}
	return validation.VArr(out...)
}

// ---- registry I/O --------------------------------------------------------

// linksPath is _links_path.
func linksPath(c *state.Campaign) string {
	return filepath.Join(c.ArtifactsDir, "invariant_links.json")
}

// emptyLinks is {"invariants": {}}.
func emptyLinks() validation.Value {
	return validation.VObj(pair("invariants", validation.VObj()))
}

// LoadLinks is load_links: the registry, migrating legacy entries on read.
func LoadLinks(c *state.Campaign) (validation.Value, error) {
	p := linksPath(c)
	if _, err := os.Stat(p); err != nil {
		return emptyLinks(), nil
	}
	links, err := validation.ReadJson(p)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := migrateLegacyEntries(c, &links); err != nil {
		return validation.VNull(), err
	}
	return links, nil
}

// SaveLinks is save_links: write the registry, return the path.
func SaveLinks(c *state.Campaign, links validation.Value) (string, error) {
	out := linksPath(c)
	if err := validation.WriteJson(out, links, ""); err != nil {
		return "", err
	}
	return out, nil
}

// migrateLegacyEntries is _migrate_legacy_entries: normalize pre-structured
// entries in place exactly once (test_status takes the old status value,
// status resets to UNVERIFIED, source derives from the live documented set),
// logging invariant.migrated per entry.
func migrateLegacyEntries(c *state.Campaign, links *validation.Value) (bool, error) {
	reg := objAt(*links, "invariants")
	if reg.Kind != validation.Obj {
		return false, nil
	}
	var legacy []int
	for i := range reg.O {
		if reg.O[i].V.Kind == validation.Obj && !hasKey(reg.O[i].V, "test_status") {
			legacy = append(legacy, i)
		}
	}
	if len(legacy) == 0 {
		return false, nil
	}
	doc, err := DocumentedInvariants(c, nil)
	if err != nil {
		return false, err
	}
	var migrated []validation.Value
	for _, i := range legacy {
		iid, e := reg.O[i].K, reg.O[i].V
		old, hasOld := fieldAt(e, "status")
		ts := validation.VStr("untested")
		if hasOld && old.Kind == validation.Str && inList(Statuses, old.S) {
			ts = validation.VStr(old.S)
		}
		e.O = validation.SetOrAppend(e.O, "test_status", ts)
		e.O = validation.SetOrAppend(e.O, "status", validation.VStr("UNVERIFIED"))
		if !hasKey(e, "source") {
			src, detail := deriveSource(iid, doc)
			e.O = validation.SetOrAppend(e.O, "source", validation.VStr(src))
			if detail != nil {
				e.O = validation.SetOrAppend(e.O, "source_detail", validation.VStr(*detail))
			}
		}
		e.O = validation.SetDefault(e.O, "findings", validation.VArr())
		e.O = validation.SetDefault(e.O, "tests", validation.VArr())
		e.O = validation.SetDefault(e.O, "detectors", validation.VArr())
		e.O = validation.SetOrAppend(e.O, "updated_at", validation.VStr(nowIso()))
		reg.O[i].V = e
		oldV := validation.VNull()
		if hasOld {
			oldV = old
		}
		migrated = append(migrated, validation.VObj(
			pair("id", validation.VStr(iid)),
			pair("old_status", oldV),
			pair("source", objAt(e, "source")),
		))
	}
	*links = setObjKey(*links, "invariants", reg)
	if _, err := SaveLinks(c, *links); err != nil {
		return false, err
	}
	for _, m := range migrated {
		ref := objStr(m, "id")
		data := validation.VObj(
			pair("old_status", objAt(m, "old_status")),
			pair("source", objAt(m, "source")),
		)
		if _, err := c.Log("invariant.migrated", &ref, &data); err != nil {
			return false, err
		}
	}
	return true, nil
}

// setObjKey is links["invariants"] = reg (position preserved when present).
func setObjKey(links validation.Value, key string, v validation.Value) validation.Value {
	links.O = validation.SetOrAppend(links.O, key, v)
	return links
}

// regOf is links.get("invariants", {}) under the port's fail-safe reading:
// a non-object value is treated as an empty registry.
func regOf(links validation.Value) validation.Value {
	reg := objAt(links, "invariants")
	if reg.Kind != validation.Obj {
		return validation.VObj()
	}
	return reg
}

// ---- source derivation ---------------------------------------------------

// deriveSource is _derive_source: (source, provenance) for an id.
func deriveSource(iid string, doc validation.Value) (string, *string) {
	n := NormalizeInvID(iid)
	if hasKey(doc, n) {
		return "documented", nil
	}
	if _, ok := curatedInvariantIDs()[n]; ok {
		return "documented", strPtr("playbook")
	}
	return "model", nil
}

// entrySource is _entry_source: the source keys for a fresh entry.
func entrySource(iid string, doc validation.Value) []validation.KV {
	src, detail := deriveSource(iid, doc)
	out := []validation.KV{pair("source", validation.VStr(src))}
	if detail != nil {
		out = append(out, pair("source_detail", validation.VStr(*detail)))
	}
	return out
}

// ---- seeding -------------------------------------------------------------

// SeedFromModel is seed_from_model: create registry entries for every
// invariant in the protocol model, refresh model→documented one way, and
// synthesize the liveness template when the model has state machines.
func SeedFromModel(c *state.Campaign, model validation.Value) (validation.Value, error) {
	links, err := LoadLinks(c)
	if err != nil {
		return validation.VNull(), err
	}
	reg := regOf(links)
	doc, err := DocumentedInvariants(c, nil)
	if err != nil {
		return validation.VNull(), err
	}
	invs := objAt(model, "invariants")
	for _, inv := range invs.A {
		iidV, ok := fieldAt(inv, "id")
		if !ok {
			return validation.VNull(), fmt.Errorf("'id'")
		}
		iid := pyStr(iidV)
		if !hasKey(reg, iid) {
			stmt, ok := fieldAt(inv, "statement")
			if !ok {
				return validation.VNull(), fmt.Errorf("'statement'")
			}
			reg.O = append(reg.O, pair(iid, freshEntry(inv, stmt, iid, doc)))
			continue
		}
		reg = refreshSource(reg, iid, doc)
	}
	if err := seedLiveness(c, model, &reg, doc); err != nil {
		return validation.VNull(), err
	}
	links = setObjKey(links, "invariants", reg)
	if _, err := SaveLinks(c, links); err != nil {
		return validation.VNull(), err
	}
	count := validation.VObj(pair("count", validation.VInt(int64(len(invs.A)))))
	if _, err := c.Log("invariants.seeded", nil, &count); err != nil {
		return validation.VNull(), err
	}
	return links, nil
}

// freshEntry is the seeding entry literal (exact Python key order).
func freshEntry(inv, stmt validation.Value, iid string, doc validation.Value) validation.Value {
	kvs := []validation.KV{
		pair("statement", stmt),
		pair("kind", getOr(inv, "kind", validation.VStr("security"))),
		pair("severity_if_broken",
			getOr(inv, "severity_if_broken", validation.VStr("high"))),
		pair("applies_to", getOr(inv, "applies_to", validation.VArr())),
		pair("test_status", validation.VStr("untested")),
		// the model's claimed status is DATA, never a verdict
		pair("status", validation.VStr("UNVERIFIED")),
		pair("model_belief", objAt(inv, "model_belief")),
		pair("depends_on", getOr(inv, "depends_on", validation.VArr())),
		pair("modified_by", objAt(inv, "modified_by")),
	}
	kvs = append(kvs, entrySource(iid, doc)...)
	kvs = append(kvs,
		pair("findings", validation.VArr()),
		pair("tests", validation.VArr()),
		pair("detectors", validation.VArr()),
		pair("updated_at", validation.VStr(nowIso())),
	)
	return validation.VObj(kvs...)
}

// refreshSource is the re-seed one-way flip model → documented.
func refreshSource(reg validation.Value, iid string, doc validation.Value) validation.Value {
	src, detail := deriveSource(iid, doc)
	e := objAt(reg, iid)
	if src != "documented" || objStr(e, "source") == "documented" {
		return reg
	}
	e.O = validation.SetOrAppend(e.O, "source", validation.VStr("documented"))
	if detail != nil {
		e.O = validation.SetOrAppend(e.O, "source_detail", validation.VStr(*detail))
	}
	e.O = validation.SetOrAppend(e.O, "modified_by",
		validation.VStr("source-refresh model->documented "+nowIso()))
	e.O = validation.SetOrAppend(e.O, "updated_at", validation.VStr(nowIso()))
	reg.O = validation.SetOrAppend(reg.O, iid, e)
	return reg
}

// seedLiveness is the liveness-template half of seed_from_model.
func seedLiveness(c *state.Campaign, model validation.Value, reg *validation.Value,
	doc validation.Value) error {
	kinds := map[string]struct{}{}
	for _, e := range reg.O {
		kinds[pyStr(objAt(e.V, "kind"))] = struct{}{}
	}
	var machines []string
	for _, sm := range objAt(model, "state_machines").A {
		if name, ok := fieldAt(sm, "name"); ok && validation.PyTruthy(name) {
			machines = append(machines, pyStr(name))
		}
	}
	if len(machines) == 0 {
		return nil
	}
	if _, ok := kinds["liveness"]; ok {
		return nil
	}
	nid := nextInvNum(*reg)
	stmt := "LIVENESS: every modeled state machine must be able to advance " +
		"to its terminal/finalized state; no reachable state may permanently " +
		"block finalize/withdraw/challenge/claim. Machines: " +
		strings.Join(machines, ", ")
	key := "INV-" + strconv.Itoa(nid)
	kvs := []validation.KV{
		pair("statement", validation.VStr(stmt)),
		pair("kind", validation.VStr("liveness")),
		pair("severity_if_broken", validation.VStr("critical")),
		pair("applies_to", strArr(machines)),
		pair("test_status", validation.VStr("untested")),
		pair("status", validation.VStr("UNVERIFIED")),
		pair("model_belief", validation.VNull()),
		pair("depends_on", validation.VArr()),
		pair("modified_by", validation.VNull()),
	}
	kvs = append(kvs, entrySource(key, doc)...)
	kvs = append(kvs,
		pair("findings", validation.VArr()),
		pair("tests", validation.VArr()),
		pair("detectors", validation.VArr()),
		pair("updated_at", validation.VStr(nowIso())),
		pair("synthesized", validation.VStr("liveness-template")),
	)
	reg.O = validation.SetOrAppend(reg.O, key, validation.VObj(kvs...))
	data := validation.VObj(
		pair("id", validation.VStr(key)),
		pair("machines", strArr(machines)),
	)
	if _, err := c.Log("invariants.liveness_template", nil, &data); err != nil {
		return err
	}
	return nil
}

// nextInvNum is max(int(k[4:]) for numeric INV-n keys) + 1 (1 when none).
func nextInvNum(reg validation.Value) int {
	best := 0
	for _, e := range reg.O {
		k := e.K
		if len(k) < 5 || !strings.HasPrefix(k, "INV-") {
			continue
		}
		if n, ok := pyIntText(k[4:]); ok && n > best {
			best = n
		}
	}
	return best + 1
}

// ---- linking -------------------------------------------------------------

// LinkFinding is link_finding: attach a finding to an invariant.
func LinkFinding(c *state.Campaign, invariantID, findingID string,
	violated bool) (validation.Value, error) {
	links, err := LoadLinks(c)
	if err != nil {
		return validation.VNull(), err
	}
	reg := regOf(links)
	if !hasKey(reg, invariantID) {
		return validation.VNull(), unknownInvariant(invariantID)
	}
	entry := objAt(reg, invariantID)
	findings := getOr(entry, "findings", validation.VArr())
	if !containsValue(findings, validation.VStr(findingID)) {
		findings.A = append(findings.A, validation.VStr(findingID))
	}
	entry.O = validation.SetOrAppend(entry.O, "findings", findings)
	if violated {
		entry.O = validation.SetOrAppend(entry.O, "test_status", validation.VStr("violated"))
		entry.O = validation.SetOrAppend(entry.O, "violated_by", validation.VStr(findingID))
	}
	entry.O = validation.SetOrAppend(entry.O, "updated_at", validation.VStr(nowIso()))
	reg.O = validation.SetOrAppend(reg.O, invariantID, entry)
	links = setObjKey(links, "invariants", reg)
	if _, err := SaveLinks(c, links); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		pair("finding", validation.VStr(findingID)),
		pair("violated", validation.VBool(violated)),
	)
	if _, err := c.Log("invariant.linked_finding", &invariantID, &data); err != nil {
		return validation.VNull(), err
	}
	return entry, nil
}

// LinkTest is link_test: register a test artifact against an invariant.
func LinkTest(c *state.Campaign, invariantID, artifactID string) (validation.Value, error) {
	if _, err := c.Artifact(artifactID); err != nil {
		return validation.VNull(), err
	}
	links, err := LoadLinks(c)
	if err != nil {
		return validation.VNull(), err
	}
	reg := regOf(links)
	if !hasKey(reg, invariantID) {
		return validation.VNull(), unknownInvariant(invariantID)
	}
	entry := objAt(reg, invariantID)
	tests := getOr(entry, "tests", validation.VArr())
	if !containsValue(tests, validation.VStr(artifactID)) {
		tests.A = append(tests.A, validation.VStr(artifactID))
	}
	entry.O = validation.SetOrAppend(entry.O, "tests", tests)
	ts := getOr(entry, "test_status", validation.VStr("untested"))
	if ts.Kind == validation.Str && (ts.S == "untested" || ts.S == "untestable") {
		entry.O = validation.SetOrAppend(entry.O, "test_status", validation.VStr("held"))
	}
	entry.O = validation.SetOrAppend(entry.O, "updated_at", validation.VStr(nowIso()))
	reg.O = validation.SetOrAppend(reg.O, invariantID, entry)
	links = setObjKey(links, "invariants", reg)
	if _, err := SaveLinks(c, links); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(pair("artifact", validation.VStr(artifactID)))
	if _, err := c.Log("invariant.linked_test", &invariantID, &data); err != nil {
		return validation.VNull(), err
	}
	return entry, nil
}

func containsValue(arr validation.Value, want validation.Value) bool {
	for _, e := range arr.A {
		if e.Kind == want.Kind && e.S == want.S && e.I == want.I && e.B == want.B {
			return true
		}
	}
	return false
}

func unknownInvariant(id string) error {
	return fmt.Errorf("unknown invariant %s", validation.PyReprStr(id))
}

// ---- coverage ------------------------------------------------------------

// Coverage is coverage: the registry's test-axis roll-up.
func Coverage(c *state.Campaign) (validation.Value, error) {
	links, err := LoadLinks(c)
	if err != nil {
		return validation.VNull(), err
	}
	reg := regOf(links)
	counts := make(map[string]int)
	var order []string
	for _, s := range Statuses {
		counts[s] = 0
		order = append(order, s)
	}
	for _, e := range reg.O {
		key := countKey(getOr(e.V, "test_status", validation.VStr("untested")))
		if _, seen := counts[key]; !seen {
			order = append(order, key)
		}
		counts[key]++
	}
	kvs := make([]validation.KV, len(order))
	for i, k := range order {
		kvs[i] = pair(k, validation.VInt(int64(counts[k])))
	}
	total := len(reg.O)
	tested := counts["held"] + counts["violated"]
	ratio := validation.VFloat(0)
	if total > 0 {
		ratio = validation.VFloat(validation.PythonRound(
			float64(tested)/float64(total), 3))
	}
	return validation.VObj(
		pair("total", validation.VInt(int64(total))),
		pair("statuses", validation.VObj(kvs...)),
		pair("test_coverage_ratio", ratio),
		pair("violated_invariants", strArr(sortedByStatus(reg, "violated"))),
		pair("uncovered", strArr(sortedByStatus(reg, "untested", "untestable"))),
	), nil
}

// countKey is the JSON object key Python's dict uses for a test_status
// value (json.dumps renders None as "null", bools lowercase, ints digits).
func countKey(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return v.S
	case validation.Null:
		return "null"
	case validation.Bool:
		if v.B {
			return "true"
		}
		return "false"
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	}
	return validation.PyRepr(v)
}

// sortedByStatus is the sorted registry keys whose test_status is one of
// want.
func sortedByStatus(reg validation.Value, want ...string) []string {
	var out []string
	for _, e := range reg.O {
		ts := getOr(e.V, "test_status", validation.VStr("untested"))
		if ts.Kind == validation.Str && inList(want, ts.S) {
			out = append(out, e.K)
		}
	}
	sort.Strings(out)
	return out
}

// UncoveredCritical is uncovered_critical: critical/high invariants with no
// test and no finding — the planner's next round draws from this.
func UncoveredCritical(c *state.Campaign, model validation.Value) ([]validation.Value, error) {
	links, err := LoadLinks(c)
	if err != nil {
		return nil, err
	}
	reg := regOf(links)
	norm := map[string]validation.Value{}
	for _, e := range reg.O {
		if e.V.Kind == validation.Obj {
			norm[NormalizeInvID(e.K)] = e.V
		}
	}
	out := []validation.Value{}
	for _, inv := range objAt(model, "invariants").A {
		idV, ok := fieldAt(inv, "id")
		if !ok {
			return nil, fmt.Errorf("'id'")
		}
		e, ok := norm[NormalizeInvID(pyStr(idV))]
		if !ok || len(e.O) == 0 {
			continue
		}
		ts := getOr(e, "test_status", validation.VStr("untested"))
		if ts.Kind != validation.Str || !inList([]string{"untested", "untestable"}, ts.S) {
			continue
		}
		sev := objAt(inv, "severity_if_broken")
		if sev.Kind != validation.Str || !inList([]string{"critical", "high"}, sev.S) {
			continue
		}
		out = append(out, validation.VObj(
			pair("invariant_id", idV),
			pair("statement", objAt(inv, "statement")),
			pair("applies_to", getOr(inv, "applies_to", validation.VArr())),
		))
	}
	return out, nil
}

// ---- verification axis ---------------------------------------------------

// VerifyInvariantStatement is verify_invariant_statement: CHECKED_AGAINST_CODE
// backed by a REGISTERED artifact. Only this API (and contradict) may move the
// verification axis — never seeding, never hand-editing.
func VerifyInvariantStatement(c *state.Campaign, invariantID,
	artifactID string) (validation.Value, error) {
	if _, err := c.Artifact(artifactID); err != nil {
		return validation.VNull(), err
	}
	links, err := LoadLinks(c)
	if err != nil {
		return validation.VNull(), err
	}
	reg := regOf(links)
	if !hasKey(reg, invariantID) {
		return validation.VNull(), unknownInvariant(invariantID)
	}
	entry := objAt(reg, invariantID)
	entry.O = validation.SetOrAppend(entry.O, "status",
		validation.VStr("CHECKED_AGAINST_CODE"))
	entry.O = validation.SetOrAppend(entry.O, "verified_by", validation.VStr(artifactID))
	entry.O = popKey(entry.O, "contradiction")
	entry.O = validation.SetOrAppend(entry.O, "modified_by", validation.VStr(nowIso()))
	entry.O = validation.SetOrAppend(entry.O, "updated_at", validation.VStr(nowIso()))
	reg.O = validation.SetOrAppend(reg.O, invariantID, entry)
	links = setObjKey(links, "invariants", reg)
	if _, err := SaveLinks(c, links); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(pair("artifact", validation.VStr(artifactID)))
	if _, err := c.Log("invariant.verified", &invariantID, &data); err != nil {
		return validation.VNull(), err
	}
	return entry, nil
}

// ContradictInvariantStatement is contradict_invariant_statement:
// CONTRADICTED with an evidence anchor (file#Lline or a registered artifact
// id). A finding that depends on a contradicted model invariant cannot
// advance.
func ContradictInvariantStatement(c *state.Campaign, invariantID,
	evidenceRef string) (validation.Value, error) {
	links, err := LoadLinks(c)
	if err != nil {
		return validation.VNull(), err
	}
	reg := regOf(links)
	if !hasKey(reg, invariantID) {
		return validation.VNull(), unknownInvariant(invariantID)
	}
	entry := objAt(reg, invariantID)
	entry.O = validation.SetOrAppend(entry.O, "status", validation.VStr("CONTRADICTED"))
	entry.O = validation.SetOrAppend(entry.O, "contradiction", validation.VStr(evidenceRef))
	entry.O = popKey(entry.O, "verified_by")
	entry.O = validation.SetOrAppend(entry.O, "modified_by", validation.VStr(nowIso()))
	entry.O = validation.SetOrAppend(entry.O, "updated_at", validation.VStr(nowIso()))
	reg.O = validation.SetOrAppend(reg.O, invariantID, entry)
	links = setObjKey(links, "invariants", reg)
	if _, err := SaveLinks(c, links); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(pair("evidence", validation.VStr(evidenceRef)))
	if _, err := c.Log("invariant.contradicted", &invariantID, &data); err != nil {
		return validation.VNull(), err
	}
	return entry, nil
}

// ---- ids -----------------------------------------------------------------

// NormalizeInvID is normalize_inv_id: “INV-001“ → “INV-1“. Non-matching
// ids pass through unchanged. CPython's “\d“ and “$“ semantics are kept:
// Unicode decimal digits count, and one trailing newline still matches.
func NormalizeInvID(iid string) string {
	if !strings.HasPrefix(iid, "INV-") {
		return iid
	}
	body := iid[4:]
	if strings.HasSuffix(body, "\n") {
		body = body[:len(body)-1]
	}
	digits, ok := ndDigits(body)
	if !ok {
		return iid
	}
	trimmed := strings.TrimLeft(digits, "0")
	if trimmed == "" {
		trimmed = "0"
	}
	return "INV-" + trimmed
}

// ndDigits maps a non-empty run of Unicode decimal digits to its ASCII
// decimal text (Python int() accepts any Nd digit).
func ndDigits(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	var b strings.Builder
	for _, r := range s {
		d, ok := ndDigit(r)
		if !ok {
			return "", false
		}
		b.WriteByte(byte('0' + d))
	}
	return b.String(), true
}

// ndDigit is the decimal value of an Nd rune. Every unicode.Nd range is a
// stride-1 run of ten digits (verified against CPython's unicodedata), so
// (r - Lo) % 10 is the digit.
func ndDigit(r rune) (int, bool) {
	if r >= '0' && r <= '9' {
		return int(r - '0'), true
	}
	if !unicode.IsDigit(r) {
		return 0, false
	}
	for _, x := range unicode.Nd.R16 {
		if r >= rune(x.Lo) && r <= rune(x.Hi) {
			return int(r-rune(x.Lo)) % 10, true
		}
	}
	for _, x := range unicode.Nd.R32 {
		if r >= rune(x.Lo) && r <= rune(x.Hi) {
			return int(r-rune(x.Lo)) % 10, true
		}
	}
	return 0, false
}

// pyIntText is int(text) for a run of Unicode decimal digits (Python's
// `k[4:].isdigit()` then `int(...)` in seed_from_model).
func pyIntText(text string) (int, bool) {
	digits, ok := ndDigits(text)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return 0, false
	}
	return n, true
}

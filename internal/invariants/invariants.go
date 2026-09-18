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
	"regexp"
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

// LinksThenLog is the r20 F3 / r40 unwind-on-refusal law for the
// INVARIANT_LINKS surface, and its ONE home (r42 P3-b): the registry is
// campaign STATE (artifacts/invariant_links.json) exactly like a finding file
// is, and several of its keys are STATUS FLIPS the gates read (test_status
// for coverage/uncovered-critical, status for the verification axis). A save
// that lands while its event is refused leaves a verified/contradicted/
// violated invariant the ledger never recorded — a half-landed rung invisible
// to audit, and the ledger asserting a verification nobody logged. Same
// discipline as findings.SaveThenLog (SaveThenLogMany's sibling, one fewer
// package import): snapshot the file pre-write, restore together on refusal,
// and hold the campaign process lock across the snapshot→save→log→restore
// window — the registry is a SHARED multi-key file; a whole-file restore over
// a sibling writer's concurrent change would revert its rung while its event
// stands — the same r21 F9 reason the CLI door needs.
//
// r42 P3-b: this door existed twice, byte-equivalent including the r21 F9 lock
// note, as invariants.linksThenLog and cli.linksThenLog. The project's law is
// one implementation of a law, so the cli copy is now a forwarding door
// (cli/cmd_verify_harness.go) that calls this one for the harness rungs and
// for cmd_verify_autoprove.go's rung.
func LinksThenLog(c *state.Campaign, save func() error, log func() error) error {
	path := linksPath(c)
	// r21 F9: the links file is a SHARED multi-key registry — a
	// whole-file restore over a sibling writer's concurrent change would
	// revert its rung while its event stands. Hold the campaign process
	// lock across the snapshot→save→log→restore window (the same lock
	// Log itself takes, re-entrant by depth).
	if err := c.LockProcess(); err != nil {
		return err
	}
	defer c.UnlockProcess()
	prevRaw, perr := os.ReadFile(path)
	had := perr == nil
	if perr != nil && !os.IsNotExist(perr) {
		return perr
	}
	if err := save(); err != nil {
		return err
	}
	if err := log(); err != nil {
		rerr := error(nil)
		if had {
			rerr = os.WriteFile(path, prevRaw, 0o644)
		} else {
			rerr = os.Remove(path)
		}
		if rerr != nil {
			return fmt.Errorf("%w (UNWIND ALSO FAILED: %v — the links "+
				"file holds a rung with no event; repair by hand)", err,
				rerr)
		}
		return err
	}
	return nil
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
	// r40: the migration is DESTRUCTIVE and one-shot (once an entry carries
	// test_status it never re-migrates), so a save whose event is refused
	// is a mutation the ledger never records and a retry can never re-log.
	if err := LinksThenLog(c, func() error {
		_, serr := SaveLinks(c, *links)
		return serr
	}, func() error {
		for _, m := range migrated {
			ref := objStr(m, "id")
			data := validation.VObj(
				pair("old_status", objAt(m, "old_status")),
				pair("source", objAt(m, "source")),
			)
			if _, lerr := c.Log("invariant.migrated", &ref, &data); lerr != nil {
				return lerr
			}
		}
		return nil
	}); err != nil {
		return false, err
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
	count := validation.VObj(pair("count", validation.VInt(int64(len(invs.A)))))
	// r40: fresh registry entries are campaign state the audit reads; a
	// seeded registry without its invariants.seeded event is a half-land.
	if err := LinksThenLog(c, func() error {
		_, serr := SaveLinks(c, links)
		return serr
	}, func() error {
		_, lerr := c.Log("invariants.seeded", nil, &count)
		return lerr
	}); err != nil {
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
	var machines []string
	for _, sm := range objAt(model, "state_machines").A {
		if name, ok := fieldAt(sm, "name"); ok && validation.PyTruthy(name) {
			machines = append(machines, pyStr(name))
		}
	}
	if len(machines) == 0 {
		return nil
	}
	// Stage 37 demands one liveness invariant PER state machine, so coverage
	// is counted per machine, never by the mere presence of a liveness kind.
	// (The old global "any liveness entry exists" check let two covered
	// machines hide a third uncovered one — the G-01 gap.)
	covered := map[string]struct{}{}
	for _, e := range reg.O {
		if pyStr(objAt(e.V, "kind")) != "liveness" {
			continue
		}
		for _, a := range objAt(e.V, "applies_to").A {
			covered[pyStr(a)] = struct{}{}
		}
	}
	var uncovered []string
	for _, m := range machines {
		if _, ok := covered[m]; !ok {
			uncovered = append(uncovered, m)
		}
	}
	if len(uncovered) == 0 {
		return nil
	}
	if len(uncovered) < len(machines) {
		// Partial coverage: refuse BEFORE any write (no registry mutation, no
		// template event), so the caller's unwind discipline is not needed
		// here — SeedFromModel never reaches SaveLinks on this path.
		return fmt.Errorf("protocol model: state machine(s) %s have no "+
			"liveness invariant (one per machine — stage 37)",
			strings.Join(uncovered, ", "))
	}
	// Zero coverage: the synthesis path below, unchanged.
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
	data := validation.VObj(
		pair("finding", validation.VStr(findingID)),
		pair("violated", validation.VBool(violated)),
	)
	// r40: test_status "violated" (and violated_by) is a gate-read flip —
	// coverage and uncovered_critical draw from it. Unwind on refusal.
	if err := LinksThenLog(c, func() error {
		_, serr := SaveLinks(c, links)
		return serr
	}, func() error {
		_, lerr := c.Log("invariant.linked_finding", &invariantID, &data)
		return lerr
	}); err != nil {
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
	data := validation.VObj(pair("artifact", validation.VStr(artifactID)))
	// r40: the test_status flip to "held" is a gate-read state change.
	if err := LinksThenLog(c, func() error {
		_, serr := SaveLinks(c, links)
		return serr
	}, func() error {
		_, lerr := c.Log("invariant.linked_test", &invariantID, &data)
		return lerr
	}); err != nil {
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
	if !hasKey(reg, invariantID) {
		return validation.VNull(), unknownInvariant(invariantID)
	}
	entry := objAt(reg, invariantID)
	if !artifactReferencesInvariant(c, a, invariantID, entry) {
		return validation.VNull(), irrelevantArtifact(artifactID, invariantID)
	}
	entry.O = validation.SetOrAppend(entry.O, "status",
		validation.VStr("CHECKED_AGAINST_CODE"))
	entry.O = validation.SetOrAppend(entry.O, "verified_by", validation.VStr(artifactID))
	entry.O = validation.SetOrAppend(entry.O, verificationMethodKey,
		validation.VStr(verificationMethodAttestation))
	entry.O = popKey(entry.O, "contradiction")
	entry.O = validation.SetOrAppend(entry.O, "modified_by", validation.VStr(nowIso()))
	entry.O = validation.SetOrAppend(entry.O, "updated_at", validation.VStr(nowIso()))
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
	for _, t := range objAt(entry, "applies_to").A {
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

// ExecTouchesInvariant is the exec-relevance gate: a cited exec only counts as
// a check of this invariant when the command it RAN targeted one of the
// entry's applies_to contracts. The captured output cannot decide this — a
// Foundry full-suite run names every contract in its log, so an exec can cite
// an invariant it never touched — hence the gate reads the recorded command
// line, never the log.
//
// An invariant bound to nothing cannot be exec-verified: empty applies_to is
// unbound, never a wildcard (the same law Task 4 pins for artifact
// references). The token set comes from applies_to ALONE — the invariant id is
// deliberately out of scope, because `--match-contract INV-3` names the
// bookkeeping id, not a contract.
//
// Reasons: "no-exec-record" (no such exec, or an exec store that cannot be
// read), "no-command-record" (the record carries no command line), and
// "no-target-match" (no applies_to token occurs at a left boundary).
func ExecTouchesInvariant(c *state.Campaign, invID, execID string) (bool, string) {
	execs, err := state.AllExecs(c)
	if err != nil {
		// A store that cannot be read names no exec: fail closed.
		return false, "no-exec-record"
	}
	var rec validation.Value
	found := false
	for _, e := range execs {
		if objStr(e, "exec_id") == execID {
			rec, found = e, true
			break
		}
	}
	if !found {
		return false, "no-exec-record"
	}
	command := stripShellQuotes(objStr(rec, "command"))
	if command == "" {
		return false, "no-command-record"
	}
	links, err := LoadLinks(c)
	if err != nil {
		// No readable registry, no applies_to targets: fail closed.
		return false, "no-target-match"
	}
	for _, tok := range appliesToTokens(objAt(regOf(links), invID)) {
		if tokenOccursLeftBound(command, tok) {
			return true, ""
		}
	}
	return false, "no-target-match"
}

// appliesToTokens is the exec-relevance token set: every applies_to string in
// its recorded spelling and in NormalizeInvID's canonical one, deduplicated,
// empties dropped. Unlike referenceTokens it excludes the invariant id — see
// ExecTouchesInvariant.
func appliesToTokens(entry validation.Value) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range objAt(entry, "applies_to").A {
		if t.Kind != validation.Str {
			continue
		}
		for _, tok := range []string{t.S, NormalizeInvID(t.S)} {
			if tok == "" || seen[tok] {
				continue
			}
			seen[tok] = true
			out = append(out, tok)
		}
	}
	return out
}

// tokenOccursLeftBound reports whether command contains token starting at a
// left boundary: the match begins the string, or the character before it is
// outside [0-9a-z_]. Matching is case-insensitive and there is deliberately NO
// trailing boundary.
//
// This intentionally differs from the Task 4 artifact matcher
// (artifactReferencesInvariant), which requires a full \b...\b word match.
// Foundry's --match-contract is a regex/prefix filter, so \bStaking\b would
// reject `--match-contract StakingTest` — exactly the targeted command this
// gate must accept — while the left boundary is what keeps `Unstaking` out.
// The Task 4 matcher stays byte-identical: its refusals are pinned.
func tokenOccursLeftBound(command, token string) bool {
	if token == "" {
		return false
	}
	cmd := strings.ToLower(command)
	tok := strings.ToLower(token)
	for from := 0; from < len(cmd); {
		i := strings.Index(cmd[from:], tok)
		if i < 0 {
			return false
		}
		at := from + i
		if at == 0 || !isLowerWordByte(cmd[at-1]) {
			return true
		}
		from = at + 1
	}
	return false
}

// isLowerWordByte is the left-boundary alphabet on the lowered command:
// [0-9a-z_] — the characters a contract name can be glued to.
func isLowerWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z')
}

// stripShellQuotes removes one layer of matching surrounding quotes from a
// recorded command line.
func stripShellQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
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
	data := validation.VObj(pair("evidence", validation.VStr(evidenceRef)))
	// r40: a CONTRADICTED entry without its event blocks dependent
	// findings on state the ledger never recorded. Unwind on refusal.
	if err := LinksThenLog(c, func() error {
		_, serr := SaveLinks(c, links)
		return serr
	}, func() error {
		_, lerr := c.Log("invariant.contradicted", &invariantID, &data)
		return lerr
	}); err != nil {
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

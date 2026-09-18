package structidx

import (
	"sort"
	"strings"
	"testing"

	"websec/internal/validation"
)

// enfFixture is testdata/structural_index.json: one entry point that reads a
// value it never writes (StateRoots.commitBatch), a helper it calls that reads
// the same value unguarded (StateRoots.getPrevStateHash), a second entry point
// that guards it (StateRoots.relayMessage), and a family of sibling gateway
// contracts sharing the tokenMapping variable.
func enfFixture(t *testing.T) validation.Value {
	t.Helper()
	return loadJSON(t, "testdata/structural_index.json")
}

func enfStat(t *testing.T, tbl validation.Value, key string) int64 {
	t.Helper()
	v := validation.ObjAt(validation.ObjAt(tbl, "stats"), key)
	if v.Kind != validation.Int {
		t.Fatalf("stats.%s: not an int (%v)", key, v)
	}
	return v.I
}

func enfSiteKeys(tbl validation.Value) []string {
	out := []string{}
	for _, s := range listOf(validation.ObjAt(tbl, "sites")) {
		out = append(out, validation.ObjStr(s, "function_id")+"|"+validation.ObjStr(s, "kind")+
			"|"+intText(intAt(s, "line"))+"|"+validation.ObjStr(s, "granularity"))
	}
	return out
}

func enfFunctions(tbl validation.Value) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range listOf(validation.ObjAt(tbl, "sites")) {
		id := validation.ObjStr(s, "function_id")
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func enfSignalKinds(tbl validation.Value) []string {
	out := []string{}
	for _, s := range listOf(validation.ObjAt(tbl, "signals")) {
		out = append(out, validation.ObjStr(s, "signal"))
	}
	return out
}

func enfSiteAt(t *testing.T, tbl validation.Value, function string, kind string) validation.Value {
	t.Helper()
	for _, s := range listOf(validation.ObjAt(tbl, "sites")) {
		if validation.ObjStr(s, "function_id") == function && validation.ObjStr(s, "kind") == kind {
			return s
		}
	}
	t.Fatalf("no %s site at %s in %s", kind, function, validation.CanonCompact(tbl))
	return validation.VNull()
}

const (
	enfCommitBatch = "folding/StateRoots.sol#StateRoots.commitBatch"
	enfPrevState   = "folding/StateRoots.sol#StateRoots.getPrevStateHash"
	enfRelay       = "folding/StateRoots.sol#StateRoots.relayMessage"
	enfGuardScale  = "folding/StateRoots.sol#StateRoots.guardScale"
)

// TestEnforcementTableNeverWrittenValue is the class the table exists for: a
// storage variable that consumers read and no function in the index ever
// writes. stateRoots is read once, under a class-4 equality guard.
func TestEnforcementTableNeverWrittenValue(t *testing.T) {
	tbl := EnforcementTable(enfFixture(t), "stateRoots")
	if got := validation.ObjStr(tbl, "match"); got != "storage" {
		t.Errorf("match = %q want storage", got)
	}
	want := []string{enfGuardScale + "|read|34|statement"}
	if got := enfSiteKeys(tbl); !equalStrings(got, want) {
		t.Errorf("sites = %v want %v", got, want)
	}
	if got := validation.ObjStr(tbl, "ordering"); got != "call-graph" {
		t.Errorf("ordering = %q want call-graph", got)
	}
	if got := validation.ObjStr(tbl, "note"); got != "" {
		t.Errorf("note = %q want empty", got)
	}
	for key, want := range map[string]int64{
		"sites": 1, "reachable_sites": 1, "writes": 0, "reads": 1,
		"unguarded_writes": 0, "unguarded_reads": 0,
		"stage_pairs": 0, "stage_gaps": 0, "stage_pairs_skipped": 0,
	} {
		if got := enfStat(t, tbl, key); got != want {
			t.Errorf("stats.%s = %d want %d", key, got, want)
		}
	}
	if got := enfSignalKinds(tbl); !equalStrings(got, []string{"no-writer"}) {
		t.Errorf("signals = %v want [no-writer]", got)
	}
	if got := intAt(enfSiteAt(t, tbl, enfGuardScale, "read"), "depth"); got != 0 {
		t.Errorf("guardScale depth = %d want 0 (it is an entry point)", got)
	}
}

// TestEnforcementTableStatementWriteBeatsStorageList pins the precedence rule
// and the index nuance that motivates it: commitBatch's writes_storage lists
// only storedHash, while its statement-level uses record the write of
// prevStateRoot at line 15. The table reports the statement-level truth and
// keeps the function-level lists as a fallback.
func TestEnforcementTableStatementWriteBeatsStorageList(t *testing.T) {
	tbl := EnforcementTable(enfFixture(t), "prevStateRoot")
	if got := validation.ObjStr(tbl, "match"); got != "storage" {
		t.Errorf("match = %q want storage", got)
	}
	want := []string{
		enfCommitBatch + "|read|14|statement",
		enfCommitBatch + "|read|15|statement",
		enfCommitBatch + "|write|15|statement",
		enfPrevState + "|read|21|statement",
	}
	if got := enfSiteKeys(tbl); !equalStrings(got, want) {
		t.Errorf("sites = %v want %v", got, want)
	}
	for key, want := range map[string]int64{
		"sites": 4, "reachable_sites": 4, "writes": 1, "reads": 3,
		"unguarded_writes": 0, "unguarded_reads": 1,
		"stage_pairs": 1, "stage_gaps": 0, "stage_pairs_skipped": 0,
	} {
		if got := enfStat(t, tbl, key); got != want {
			t.Errorf("stats.%s = %d want %d", key, got, want)
		}
	}
	// The single pair is commitBatch's write reaching getPrevStateHash's read,
	// and commitBatch's class-4 assertion about prevStateRoot covers it.
	pairs := listOf(validation.ObjAt(tbl, "stages"))
	if len(pairs) != 1 {
		t.Fatalf("stages = %d want 1", len(pairs))
	}
	if got := validation.ObjStr(validation.ObjAt(pairs[0], "read"), "function"); got != "getPrevStateHash" {
		t.Errorf("pair read = %q", got)
	}
	if b := validation.ObjAt(pairs[0], "write_guarded"); b.Kind != validation.Bool || !b.B {
		t.Errorf("commitBatch's write of prevStateRoot is guarded, so this is no gap")
	}
	if b := validation.ObjAt(pairs[0], "gap"); b.Kind != validation.Bool || b.B {
		t.Errorf("pair should not be a gap")
	}
	if got := enfSignalKinds(tbl); !equalStrings(got, []string{"unguarded-read"}) {
		t.Errorf("signals = %v want [unguarded-read]", got)
	}
}

// TestEnforcementTableGuardAttribution: a site's guards are its containing
// function's assertions, each marked with whether it is about the variable. A
// guard about something else does not cover it.
func TestEnforcementTableGuardAttribution(t *testing.T) {
	tbl := EnforcementTable(enfFixture(t), "prevStateRoot")

	guarded := enfSiteAt(t, tbl, enfCommitBatch, "read")
	if b := validation.ObjAt(guarded, "guarded"); b.Kind != validation.Bool || !b.B {
		t.Fatalf("commitBatch read site should be guarded: %s",
			validation.CanonCompact(guarded))
	}
	guards := listOf(validation.ObjAt(guarded, "guards"))
	if len(guards) != 1 {
		t.Fatalf("commitBatch guards = %d want 1", len(guards))
	}
	g := guards[0]
	if !boolAt(g, "about_variable") || intAt(g, "class") != 4 ||
		validation.ObjStr(g, "text") != "prevStateRoot[batchIndex] == stateRoot" {
		t.Errorf("guard = %s", validation.CanonCompact(g))
	}

	unguarded := enfSiteAt(t, tbl, enfPrevState, "read")
	if b := validation.ObjAt(unguarded, "guarded"); b.Kind != validation.Bool || b.B {
		t.Errorf("getPrevStateHash should have no guard about prevStateRoot")
	}
	if len(listOf(validation.ObjAt(unguarded, "guards"))) != 0 {
		t.Errorf("getPrevStateHash guards should be empty")
	}

	// relayMessage carries a storedHash guard; for prevStateRoot it is "not
	// about the variable" — and relayMessage has no prevStateRoot site, so the
	// table never shows it. Check the marking on the storedHash query below.
	sh := EnforcementTable(enfFixture(t), "storedHash")
	relay := enfSiteAt(t, sh, enfRelay, "read")
	if b := validation.ObjAt(relay, "guarded"); b.Kind != validation.Bool || !b.B {
		t.Errorf("relayMessage read of storedHash should be guarded")
	}
}

// TestEnforcementTableStagePairs: pairs are reported only between related
// sites (same contract, same inheritance family, or a call path); a pair is a
// GAP when its write side carries no assertion about the variable, and OPEN
// when the read side has none either.
func TestEnforcementTableStagePairs(t *testing.T) {
	idx := enfFixture(t)

	stored := EnforcementTable(idx, "storedHash")
	if got := enfSiteKeys(stored); !equalStrings(got, []string{
		enfCommitBatch + "|read|13|function",
		enfCommitBatch + "|write|16|statement",
		enfCommitBatch + "|write|17|statement",
		enfRelay + "|read|42|function",
	}) {
		t.Fatalf("storedHash sites = %v", got)
	}
	if got := enfStat(t, stored, "stage_pairs"); got != 2 {
		t.Errorf("storedHash stage_pairs = %d want 2", got)
	}
	// Both writes are unguarded w.r.t. storedHash (commitBatch's guards are
	// about prevStateRoot) and reach relayMessage's guarded comparison: gaps
	// whose read side IS guarded.
	if got := enfStat(t, stored, "stage_gaps"); got != 2 {
		t.Errorf("storedHash stage_gaps = %d want 2", got)
	}
	if got := enfStat(t, stored, "stage_open_gaps"); got != 0 {
		t.Errorf("storedHash stage_open_gaps = %d want 0", got)
	}
	stages := listOf(validation.ObjAt(stored, "stages"))
	if len(stages) != 2 {
		t.Fatalf("storedHash stages = %d want 2", len(stages))
	}
	if b := validation.ObjAt(stages[0], "read_guarded"); b.Kind != validation.Bool || !b.B {
		t.Errorf("relayMessage guards storedHash, so read_guarded should be true")
	}
	if b := validation.ObjAt(stages[0], "write_guarded"); b.Kind != validation.Bool || b.B {
		t.Errorf("commitBatch does not assert storedHash, so write_guarded is false")
	}
	stageSignals := 0
	for _, sig := range listOf(validation.ObjAt(stored, "signals")) {
		if validation.ObjStr(sig, "signal") == "unguarded-stage" {
			stageSignals++
		}
	}
	if stageSignals != 2 {
		t.Errorf("storedHash unguarded-stage signals = %d want 2", stageSignals)
	}

	// Sibling gateway contracts each declare their own tokenMapping: the
	// unrelated site pairs are skipped, so what is left is one gap per family
	// member's write -> its own checker, plus the one pair open on both ends
	// (BaseVault.updateTokenMapping -> onlyBase, which never checks it).
	tm := EnforcementTable(idx, "tokenMapping")
	if got := enfStat(t, tm, "stage_pairs"); got != 8 {
		t.Errorf("tokenMapping stage_pairs = %d want 8", got)
	}
	if got := enfStat(t, tm, "stage_gaps"); got != 8 {
		t.Errorf("tokenMapping stage_gaps = %d want 8", got)
	}
	if got := enfStat(t, tm, "stage_open_gaps"); got != 1 {
		t.Errorf("tokenMapping stage_open_gaps = %d want 1", got)
	}
	if got := enfStat(t, tm, "stage_pairs_skipped"); got == 0 {
		t.Errorf("tokenMapping should report the cross-contract pairs it skipped")
	}
	open := []validation.Value{}
	for _, p := range listOf(validation.ObjAt(tm, "stages")) {
		if b := validation.ObjAt(p, "read_guarded"); b.Kind == validation.Bool && !b.B {
			open = append(open, p)
		}
	}
	if len(open) != 1 {
		t.Fatalf("open pairs = %d want 1", len(open))
	}
	if got := validation.ObjStr(validation.ObjAt(open[0], "write"), "function"); got != "updateTokenMapping" {
		t.Errorf("open pair write = %q", got)
	}
	if got := validation.ObjStr(validation.ObjAt(open[0], "read"), "function"); got != "onlyBase" {
		t.Errorf("open pair read = %q", got)
	}
}

// TestEnforcementTableConceptName: a name the index does not know as a storage
// variable is tokenized the index's own way, so the concept form lands on
// exactly the same statement-level sites.
func TestEnforcementTableConceptName(t *testing.T) {
	idx := enfFixture(t)
	storage := EnforcementTable(idx, "prevStateRoot")
	concept := EnforcementTable(idx, "prev-state root")
	if got := validation.ObjStr(concept, "match"); got != "concept" {
		t.Errorf("match = %q want concept", got)
	}
	if got, want := enfSiteKeys(concept), enfSiteKeys(storage); !equalStrings(got, want) {
		t.Errorf("concept sites = %v want %v", got, want)
	}
	if got := validation.ObjStr(concept, "concept_key"); got != "prev:state:root" {
		t.Errorf("concept_key = %q want prev:state:root", got)
	}
	// The maximal key is what keeps a partial overlap out: guardScale's
	// stateRoots expression shares the "root" token but not the whole key.
	for _, s := range listOf(validation.ObjAt(concept, "sites")) {
		if got := validation.ObjStr(s, "function_id"); got == enfGuardScale {
			t.Errorf("guardScale must not match the prevStateRoot concept key")
		}
	}
}

// TestEnforcementTableScope: opts.Contract restricts the table to one
// contract, which is what makes a shared variable name usable.
func TestEnforcementTableScope(t *testing.T) {
	idx := enfFixture(t)
	all := EnforcementTable(idx, "tokenMapping")
	contracts := map[string]bool{}
	for _, s := range listOf(validation.ObjAt(all, "sites")) {
		contracts[validation.ObjStr(s, "contract")] = true
	}
	if len(contracts) < 2 {
		t.Fatalf("fixture should have tokenMapping in several contracts: %v", contracts)
	}
	scoped := EnforcementTableOpts(idx, "tokenMapping",
		EnforcementOpts{Contract: "L1ERC20Gateway"})
	if len(contracts) == 1 {
		t.Fatal("scope test needs more than one contract")
	}
	if got := enfStat(t, scoped, "sites"); got != 3 {
		t.Errorf("scoped sites = %d want 3", got)
	}
	for _, s := range listOf(validation.ObjAt(scoped, "sites")) {
		if got := validation.ObjStr(s, "contract"); got != "L1ERC20Gateway" {
			t.Errorf("scoped site contract = %q", got)
		}
	}
	if got := validation.ObjStr(scoped, "note"); got == "" {
		t.Errorf("a scoped table should say so in note")
	}
	if got := validation.ObjStr(all, "note"); strings.HasPrefix(got, "filtered to contract") {
		t.Errorf("unscoped note = %q should not mention a filter", got)
	}
	empty := EnforcementTableOpts(idx, "tokenMapping",
		EnforcementOpts{Contract: "NoSuchContract"})
	if got := enfStat(t, empty, "sites"); got != 0 {
		t.Errorf("empty scope sites = %d want 0", got)
	}
}

func TestEnforcementTableUnknownName(t *testing.T) {
	tbl := EnforcementTable(enfFixture(t), "noSuchValue")
	if got := validation.ObjStr(tbl, "match"); got != "none" {
		t.Errorf("match = %q want none", got)
	}
	if got := enfStat(t, tbl, "sites"); got != 0 {
		t.Errorf("sites = %d want 0", got)
	}
	if got := len(listOf(validation.ObjAt(tbl, "signals"))); got != 0 {
		t.Errorf("signals = %d want 0", got)
	}
	if got := len(listOf(validation.ObjAt(tbl, "stages"))); got != 0 {
		t.Errorf("stages = %d want 0", got)
	}
	if got := strList(validation.ObjAt(tbl, "concept_keys")); len(got) == 0 {
		t.Errorf("concept_keys should record what was tried")
	}
	if got := validation.ObjStr(tbl, "ordering"); got != "declaration" {
		t.Errorf("ordering = %q want declaration", got)
	}
}

// TestEnforcementTableDeterminism: the same index always yields the same
// rows in the same order.
func TestEnforcementTableDeterminism(t *testing.T) {
	idx := enfFixture(t)
	a := EnforcementTable(idx, "tokenMapping")
	b := EnforcementTable(idx, "tokenMapping")
	if validation.CanonCompact(a) != validation.CanonCompact(b) {
		t.Fatalf("table is not deterministic")
	}
}

// TestEnforcementOrderingPartial covers the two non-call-graph orderings on a
// synthetic index: no entry point at all (declaration order), and an entry
// point that cannot reach every site (partial, unreachable sites last).
func TestEnforcementOrderingPartial(t *testing.T) {
	fn := func(id string, entry bool, reads, writes []string) validation.Value {
		return validation.VObj(
			validation.KV{K: "id", V: validation.VStr(id)},
			validation.KV{K: "kind", V: validation.VStr("function")},
			validation.KV{K: "name", V: validation.VStr(id[strings.Index(id, ".")+1:])},
			validation.KV{K: "line", V: validation.VInt(1)},
			validation.KV{K: "is_entry_point", V: validation.VBool(entry)},
			validation.KV{K: "reads_storage", V: validation.StrArr(reads)},
			validation.KV{K: "writes_storage", V: validation.StrArr(writes)},
		)
	}
	orphan := "a.sol#A.readTheValue"
	idx := validation.VObj(
		validation.KV{K: "nodes", V: validation.VArr(
			fn(orphan, false, []string{"v"}, nil))},
		validation.KV{K: "edges", V: validation.VArr()},
	)
	tbl := EnforcementTable(idx, "v")
	if got := validation.ObjStr(tbl, "ordering"); got != "declaration" {
		t.Errorf("ordering = %q want declaration", got)
	}
	if got := validation.ObjStr(tbl, "note"); got == "" {
		t.Errorf("declaration ordering should carry a note")
	}
	entry := "a.sol#A.entryPoint"
	idx = validation.VObj(
		validation.KV{K: "nodes", V: validation.VArr(
			fn(entry, true, []string{"v"}, nil),
			fn(orphan, false, []string{"v"}, nil))},
		validation.KV{K: "edges", V: validation.VArr()},
	)
	tbl = EnforcementTable(idx, "v")
	if got := validation.ObjStr(tbl, "ordering"); got != "partial" {
		t.Errorf("ordering = %q want partial", got)
	}
	if got := enfSiteKeys(tbl); !equalStrings(got, []string{
		entry + "|read|1|function", orphan + "|read|1|function"}) {
		t.Errorf("partial order = %v (unreachable last)", got)
	}
	if got := validation.ObjStr(tbl, "note"); got == "" {
		t.Errorf("partial ordering should carry a note")
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

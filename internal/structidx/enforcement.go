// enforcement.go — IMPROVEMENTS C1: the enforcement-timing table.
//
// The assertion-strength probe finds single (assertion, consumer) pairs. The
// question that actually matters is the whole stage table for one storage
// variable: where is it written, where is it read, which of those sites is
// guarded and by what, and at which stage is the invariant enforced? The
// structural index already records everything needed (per-function
// reads_storage/writes_storage, statement-level `uses` with their concept
// keys, per-function `guards` with their class, and the `calls` edges), but
// nothing assembled it — so an operator had to infer the table by hand.
//
// EnforcementTable is that assembly, and it is deterministic: the same index
// always yields the same rows in the same order. It is the backbone for the
// G-01-class question ("prevStateRoot is read in commitBatch, read again in a
// later stage, and NOTHING in the index ever writes or checks it") which the
// model previously had to stumble onto.
//
// Matching is by the index's own concept key. `name` is a storage variable
// name when the index knows it as a state variable or as a
// reads_storage/writes_storage entry; every site is then matched through the
// maximal concept key of that name (splitIdent + synonym fold, joined by ":",
// i.e. `storedHash` -> "stored:root"). A name the index does not know is
// matched the same way, so `prev-state root` finds exactly the sites of
// `prevStateRoot`. There is no separate concept->variable map to consult:
// concept keys ARE the tokenized form of the expressions the parser saw. The
// maximal key (rather than "any shared token") is what keeps `storedHash`
// from matching every `...root...` expression: a partial token overlap is a
// different variable.
package structidx

import (
	"fmt"
	"os"

	"websec/internal/state"
	"websec/internal/validation"
)

// unReachable is the depth rank of a site no entry point can reach: it sorts
// after every reachable site.
const unReachable = 1 << 30

// LoadIndex reads the stored structural index as-is (no freshness check, no
// source tree needed): the read-only queries answer from what is on disk.
func LoadIndex(c *state.Campaign) (validation.Value, error) {
	p := IndexPath(c)
	if _, err := os.Stat(p); err != nil {
		return validation.VNull(), fmt.Errorf(
			"no structural index for %s; run `webv2 index --src SRC %s` first",
			c.CampaignID, c.CampaignID)
	}
	return validation.ReadJson(p)
}

// enfGuard is one assertion attached to a site's containing function.
type enfGuard struct {
	line  int64
	class int64
	text  string
	about bool // the assertion's concept keys contain the queried maximal key
}

// enfSite is one write or read site of the queried variable.
type enfSite struct {
	contract string
	function string
	id       string
	kind     string // "write" | "read"
	line     int64
	gran     string // "statement" (a use was found) | "function"
	guards   []enfGuard
	guarded  bool
	entry    bool
	depth    int
	hasDepth bool
}

// EnforcementOpts scopes the table. An empty Contract is the honest default:
// every site in the index, which is what you want when a variable name is
// unique but noise when eight gateway contracts share it.
type EnforcementOpts struct {
	Contract string
}

// EnforcementTable is enforcement_table(index, name): every write and read
// site of `name`, ordered by call-graph depth from an entry point, each with
// the assertions its containing function carries, plus the (write, read) stage
// pairs between related sites, each marked with which side carries an
// assertion about the name.
func EnforcementTable(index validation.Value, name string) validation.Value {
	return EnforcementTableOpts(index, name, EnforcementOpts{})
}

// EnforcementTableOpts is EnforcementTable scoped to one contract.
func EnforcementTableOpts(index validation.Value, name string,
	opts EnforcementOpts) validation.Value {
	keys := ConceptKeys(name)
	key := conceptKeyOf(name)
	storageMatch := indexHasStorageName(index, name)
	depths := enforcementDepths(index)
	sites := enforcementSites(index, name, key, storageMatch, depths)
	if opts.Contract != "" {
		kept := make([]enfSite, 0, len(sites))
		for _, s := range sites {
			if s.contract == opts.Contract {
				kept = append(kept, s)
			}
		}
		sites = kept
	}

	match := "none"
	switch {
	case storageMatch:
		match = "storage"
	case len(sites) > 0:
		match = "concept"
	}
	sortEnfSites(sites)

	stages, skippedPairs := enforcementStages(index, sites)
	signals := enforcementSignals(name, sites, stages)

	reachable := 0
	writes, reads, unguardedWrites, unguardedReads, gaps := 0, 0, 0, 0, 0
	for _, s := range sites {
		if s.hasDepth {
			reachable++
		}
		switch s.kind {
		case "write":
			writes++
			if !s.guarded {
				unguardedWrites++
			}
		case "read":
			reads++
			if !s.guarded {
				unguardedReads++
			}
		}
	}
	stageRows := []validation.Value{}
	openGaps := 0
	for _, p := range stages {
		if p.gap() {
			gaps++
		}
		if p.open() {
			openGaps++
		}
		w, r := sites[p.write], sites[p.read]
		stageRows = append(stageRows, validation.VObj(
			validation.KV{K: "write", V: enfSiteRef(w)},
			validation.KV{K: "read", V: enfSiteRef(r)},
			validation.KV{K: "write_guarded", V: validation.VBool(p.writeGuarded)},
			validation.KV{K: "read_guarded", V: validation.VBool(p.readGuarded)},
			validation.KV{K: "gap", V: validation.VBool(p.gap())}))
	}

	kvs := []validation.KV{
		{K: "name", V: validation.VStr(name)},
		{K: "match", V: validation.VStr(match)},
		{K: "concept_key", V: validation.VStr(key)},
		{K: "concept_keys", V: validation.StrArr(keys)},
	}
	if opts.Contract != "" {
		kvs = append(kvs, validation.KV{K: "contract", V: validation.VStr(opts.Contract)})
	}
	ordering, note := enforcementOrdering(index, sites)
	if opts.Contract != "" {
		scope := "filtered to contract " + opts.Contract
		if note == "" {
			note = scope
		} else {
			note = scope + "; " + note
		}
	}
	kvs = append(kvs, validation.KV{K: "ordering", V: validation.VStr(ordering)})
	if note != "" {
		kvs = append(kvs, validation.KV{K: "note", V: validation.VStr(note)})
	}
	kvs = append(kvs,
		validation.KV{K: "sites", V: validation.VArr(enfSiteValues(sites)...)},
		validation.KV{K: "stages", V: validation.VArr(stageRows...)},
		validation.KV{K: "signals", V: validation.VArr(signals...)},
		validation.KV{K: "stats", V: validation.VObj(
			validation.KV{K: "sites", V: validation.VInt(int64(len(sites)))},
			validation.KV{K: "reachable_sites", V: validation.VInt(int64(reachable))},
			validation.KV{K: "writes", V: validation.VInt(int64(writes))},
			validation.KV{K: "reads", V: validation.VInt(int64(reads))},
			validation.KV{K: "unguarded_writes", V: validation.VInt(int64(unguardedWrites))},
			validation.KV{K: "unguarded_reads", V: validation.VInt(int64(unguardedReads))},
			validation.KV{K: "stage_pairs", V: validation.VInt(int64(len(stages)))},
			validation.KV{K: "stage_gaps", V: validation.VInt(int64(gaps))},
			validation.KV{K: "stage_open_gaps", V: validation.VInt(int64(openGaps))},
			validation.KV{K: "stage_pairs_skipped", V: validation.VInt(int64(skippedPairs))},
		)})
	return validation.VObj(kvs...)
}

// enfPair is one (write site, read site) stage pair, as indices into sites.
// Each side records whether its function carries an assertion about the
// variable. A pair is a GAP when the write side is unguarded — the value was
// committed without anything asserting about it — and it is OPEN on both ends
// when the read side is unguarded too. A guarded write reaching an unguarded
// read is neither: the write was checked, the consumer simply trusts it.
type enfPair struct {
	write, read               int
	writeGuarded, readGuarded bool
}

// gap is an unguarded write side; open is neither side guarded.
func (p enfPair) gap() bool  { return !p.writeGuarded }
func (p enfPair) open() bool { return !p.writeGuarded && !p.readGuarded }

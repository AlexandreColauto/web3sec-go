package probes

// absence.go — IMPROVEMENTS C3: never-asserted-consumption rows, NOT SHIPPED.
//
// The reference assertion-strength probe asks "validated here (class 4),
// consumed there (class <= 1)?" It is silent when NOTHING asserts the
// concept at any class: the skip in assertionConsumers drops the key before
// a row or even a rejected-site blind entry is recorded. That silence looks
// like the G-01 class — prevStateRoot consumed at commit with no check at
// any stage — so this file is the backstop for it.
//
// It sits behind ProbeOpts.AbsenceRows, and ProdProbeOpts does NOT set it.
// The measurements that retired it, taken on the Morph tree the campaign
// actually ran against (500 files, 8082 index entries, 14404 probe sites):
//
//	ungated rule      -> 421 enforcement-timing rows; the ones reaching the
//	                     emitted quota are constructors, pure address/hash
//	                     computations (computeL2TokenAddress), test
//	                     scaffolding (L2ERC1155GatewayTest._deployERC1155)
//	                     and msg:sender — all tier 0 with assertion_gap 4,
//	                     i.e. ranked ABOVE the rows carrying real defects.
//	hand-off gate     -> 276 rows, and the 7 that survive the quota are the
//	                     same families of noise.
//	the row that paid -> `Rollup.commitBatch#204 ... asserter=finalizeBatch`
//	                     (the G-01 shape) is emitted by the REFERENCE probe
//	                     once the custody enum defect is fixed and the
//	                     surface can be built at all.
//
// So the enrichment bought noise, not coverage; the axis is better served
// by the reference rows plus the L-03 routing the brief already prints. The
// code stays here, tested, behind the flag for a future iteration that
// finds an obligation shape with a real differential.
//
// The gate it ended up with — kept, because it is the honest statement of
// "this is a lifecycle hand-off, not merely an unguarded setter" — is: the
// concept is WRITTEN to storage somewhere in the closure, a function
// DECLARED BELOW the writing stage READS it (source order is the cheap proxy
// for lifecycle order), the consuming function is not `constructor`, and
// nothing in the closure asserts it at any class. It is the precise
// complement of the reference skip set: disjoint from joined rows (which
// need a class-4 asserter) and from rejected-site blind entries (which need
// a found assertion), so enabling it can only add obligations, never move
// or rename existing ones.
//
// The zero ProbeOpts value stays byte-identical to the reference surface,
// which the parity goldens pin. Rows ride the existing assertion-strength
// axis, probe id, anchors and schema (asserter "" / 0 lines and classes are
// schema-legal); attachAbsence rewrites their `why`, since the reference
// template assumes an asserter.

import (
	"sort"
	"strings"

	"websec/internal/structidx"
	"websec/internal/validation"
)

// absenceRawRows scans one (index, model) for never-asserted consumption
// across a LIFECYCLE HAND-OFF: one stage writes a concept to storage that a
// LATER stage (a function further down the same closure) reads, and no
// assertion on it exists anywhere in the closure. Returns the raw rows plus
// the absence set: contract\x00function\x00concept for every emitted key,
// valued with the downstream reader. The set survives the sibling collapse
// (which merges same-site concepts and re-keys row ids), so attachAbsence can
// still name the absence-originated concepts of a merged row.
//
// The hand-off shape is the whole gate, and it is what keeps the rule from
// firing on every unguarded setter. Two measurements from the Morph tree
// (the campaign the rule was written for) set it: the ungated form emitted
// 421 enforcement-timing rows — constructors, `_updateRewardIndex`, pure
// address/hash computations, parameter-only concepts like `accrued:div` —
// and drowned the one row that mattered. Requiring (a) the concept to be
// WRITTEN somewhere in the closure (persisted, not a parameter), (b) a
// function BELOW the writing stage to READ it (source order is the cheap
// proxy for lifecycle order: the stage that acts on a value is declared
// after the one producing it), and (c) the writing stage not to be
// `constructor` (no stage runs before one) leaves the actual hand-offs.
func absenceRawRows(index, model validation.Value) ([]validation.Value, map[string]string, error) {
	if err := structidx.RequireParseVersion(index, "structural index"); err != nil {
		return nil, nil, err
	}
	fns := functionNodes(index)
	raw := []validation.Value{}
	absent := map[string]string{}
	for _, cnode := range contractNodes(index) {
		cname := vStr(cnode, "name")
		entries := vObjList(cnode, "contract_closure")
		strongest := strongestAssertions(entries)
		readBy, written := conceptFlow(entries)
		for _, e := range entries {
			node, ok := fns[nodeID(e)]
			if !ok || !vBool(node, "is_entry_point") {
				continue
			}
			fn := vStr(e, "name")
			if fn == "constructor" {
				continue
			}
			if !anyWriteUse(usesOf(e)) {
				continue
			}
			mods := nodeModifiers(node)
			for _, key := range sortedUsesConcepts(usesOf(e)) {
				if !strings.Contains(key, ":") {
					continue
				}
				if st, found := strongest[key]; found && st.class >= 1 {
					continue
				}
				if !written[key] {
					continue
				}
				reader, found := laterReader(readBy[key], fn, vInt(e, "line"))
				if !found {
					continue
				}
				absent[cname+"\x00"+fn+"\x00"+key] =
					reader.name + "#" + itoa(reader.line)
				raw = append(raw, rawRow(cname, fn,
					vInt(e, "line"), key, TierOfGate(mods, model),
					GateLabel(mods, model), 4, fn,
					kv("asserter", validation.VStr("")),
					kv("asserter_line", validation.VInt(0)),
					kv("own_class", validation.VInt(0)),
					kv("assert_class", validation.VInt(0))))
			}
		}
	}
	return raw, absent, nil
}

// flowSite is one function that touches a concept, for the hand-off gate.
type flowSite struct {
	name string
	line int
}

// conceptFlow is the closure's data flow per concept key: the functions that
// READ it (each named once, in closure order) and whether anything WRITES it
// to storage. `param` uses are deliberately neither: a parameter is not
// persisted state, so a concept that only ever arrives as an argument cannot
// be a stage hand-off.
func conceptFlow(entries []validation.Value) (map[string][]flowSite, map[string]bool) {
	readBy := map[string][]flowSite{}
	written := map[string]bool{}
	for _, e := range entries {
		name, line := vStr(e, "name"), vInt(e, "line")
		seen := map[string]bool{}
		for _, u := range usesOf(e) {
			kind := vStr(u, "kind")
			if kind != "read" && kind != "write" {
				continue
			}
			for _, key := range vStrList(u, "concept_keys") {
				if kind == "write" {
					written[key] = true
					continue
				}
				if seen[key] {
					continue
				}
				seen[key] = true
				readBy[key] = append(readBy[key], flowSite{name, line})
			}
		}
	}
	return readBy, written
}

// laterReader is the earliest reader declared BELOW the writing stage — the
// later stage that acts on the value. Readers above it are the stages that
// produced the value (or its inputs); reading them back is not a hand-off.
func laterReader(sites []flowSite, writer string, writerLine int) (flowSite, bool) {
	best, found := flowSite{}, false
	for _, s := range sites {
		if s.name == writer || s.line <= writerLine {
			continue
		}
		if !found || s.line < best.line ||
			(s.line == best.line && s.name < best.name) {
			best, found = s, true
		}
	}
	return best, found
}

// attachAbsence rewrites the `why` of finalized rows carrying
// absence-originated concepts. A row no asserter joined gets the full
// absence question; a merged row (same-site concepts folded into a joined
// row) keeps the joined question and gains the absence clause, so the
// never-checked concept cannot hide behind an asserter that never
// asserted it. B4 already forces dispositions to name row concepts; the
// clause tells the operator which ones need independent justification.
func attachAbsence(rows []validation.Value, absent map[string]string) []validation.Value {
	for i := range rows {
		hits := absenceHits(rows[i], absent)
		if len(hits) == 0 {
			continue
		}
		if vStr(rows[i], "asserter") == "" {
			vSet(&rows[i], "why", validation.VStr(absenceQuestion(
				vStr(rows[i], "contract"), vStr(rows[i], "consumer"),
				vInt(rows[i], "consumer_line"), hits)))
			continue
		}
		vSet(&rows[i], "why", validation.VStr(
			vStr(rows[i], "why")+" Also never asserted anywhere: "+
				absenceList(hits)+" — nothing in "+
				vStr(rows[i], "contract")+" checks them at any class."))
	}
	return rows
}

// absenceHit is one absence-originated concept of a row plus the downstream
// stage that already reads it.
type absenceHit struct {
	key    string
	reader string
}

// absenceHits is the row's concepts the absence scan originated: the rep
// site plus every sibling site (a fold merges groups across contracts,
// and each member contract has its own closure).
func absenceHits(row validation.Value, absent map[string]string) []absenceHit {
	contract := vStr(row, "contract")
	function := vStr(row, "consumer")
	hits := []absenceHit{}
	seen := map[string]struct{}{}
	sites := []string{contract}
	for _, s := range vObjList(row, "siblings") {
		sites = append(sites, vStr(s, "contract"))
	}
	for _, key := range vStrList(row, "concept_keys") {
		for _, c := range sites {
			reader, ok := absent[c+"\x00"+function+"\x00"+key]
			if !ok {
				continue
			}
			if _, dup := seen[key]; !dup {
				seen[key] = struct{}{}
				hits = append(hits, absenceHit{key: key, reader: reader})
			}
			break
		}
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].key < hits[j].key })
	return hits
}

// absenceKeys is the concept list, bare.
func absenceKeys(hits []absenceHit) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.key)
	}
	return out
}

// absenceList is the concept list with each key's downstream reader named —
// the row that says WHY the missing check is a timing question (something
// already acts on the value) rather than a stylistic gap.
func absenceList(hits []absenceHit) string {
	parts := make([]string, 0, len(hits))
	for _, h := range hits {
		if h.reader == "" {
			parts = append(parts, h.key)
			continue
		}
		parts = append(parts, h.key+" (read by "+h.reader+")")
	}
	return strings.Join(parts, ", ")
}

// absenceQuestion is the why of one absence row.
func absenceQuestion(contract, consumer string, line int, hits []absenceHit) string {
	keys := strings.Join(absenceKeys(hits), ", ")
	return sprintf("%s#%d consumes %s while writing state, and nothing "+
		"in %s asserts %s at any class; the value is already trusted "+
		"downstream (%s) — which stage should check it, and what "+
		"finalizes before it does?",
		consumer, line, keys, contract, keys, absenceList(hits))
}

// nearKeyCap bounds the near-key blind entries published per (contract,
// key): OBS-1 showed one joined key fanning out into near-dup near values
// that attest the tokenizer, not the code.
const nearKeyCap = 5

// collapseNearKeys dedupes near-key blind entries whose near values carry
// the same token set (`batch:header:parent` vs `header:parent:batch`) and
// caps each (contract, key) group. Other blind kinds pass through
// untouched and relative order is preserved. A blank attestation cites the
// blind KEY, never the near value, and first occurrences are kept — so a
// stored attestation still resolves after the collapse.
func collapseNearKeys(blind []validation.Value) []validation.Value {
	seen := map[string]struct{}{}
	counts := map[string]int{}
	out := make([]validation.Value, 0, len(blind))
	for _, b := range blind {
		if vStr(b, "kind") != "near-key" {
			out = append(out, b)
			continue
		}
		group := vStr(b, "contract") + "\x00" + vStr(b, "key")
		sig := group + "\x00" + nearSig(blindNear(b))
		if _, dup := seen[sig]; dup {
			continue
		}
		if counts[group] >= nearKeyCap {
			continue
		}
		seen[sig] = struct{}{}
		counts[group]++
		out = append(out, b)
	}
	return out
}

// nearSig is the order-insensitive signature of a near key: its sorted
// token set. Keys that differ only by token order or repetition collapse.
func nearSig(near string) string {
	toks := strings.Split(near, ":")
	sort.Strings(toks)
	return strings.Join(toks, ":")
}

// memory.go: visible_memory_rows / _canonical_row_hash / compute_row_digest /
// record_memory_check / memory_check_fails (webv2.findings).
//
// The graph-memory check replaces the dead corpus-check: a finding reaches
// CONFIRMED only with a recorded consultation whose stamp (row_digest over
// the referenced rows) still verifies against the live store. Unknown ids
// cannot be recorded; a store that changes after recording makes the check
// stale, and the gate says so instead of passing on faith.
package findings

import (
	"fmt"
	"sort"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// ---- store seams (learning / shared_memory own the real loaders). The
// ---- defaults see an empty store, which makes every check fail closed.

// sharedMemoryRowsFunc is shared_memory.load_shared_memory(root): the merged
// approved rows across every tier, each wrapped as {..., "row": row}.
var sharedMemoryRowsFunc = func(root string) ([]validation.Value, error) {
	return nil, nil
}

// SetSharedMemoryRows wires shared_memory.load_shared_memory.
func SetSharedMemoryRows(f func(string) ([]validation.Value, error)) {
	if f == nil {
		panic("findings: nil shared-memory loader")
	}
	sharedMemoryRowsFunc = f
}

// learningAllMemoryFunc is learning.all_memory(campaign): within-campaign
// learning memory rows.
var learningAllMemoryFunc = func(*state.Campaign) ([]validation.Value, error) {
	return nil, nil
}

// SetLearningAllMemory wires learning.all_memory.
func SetLearningAllMemory(f func(*state.Campaign) ([]validation.Value, error)) {
	if f == nil {
		panic("findings: nil learning-memory loader")
	}
	learningAllMemoryFunc = f
}

// VisibleMemoryRows is visible_memory_rows: memory_id -> row over everything
// this campaign may consult — the shared store (both tiers; its publish
// discipline already restricts to approved rows) plus within-campaign
// learning memory.
func VisibleMemoryRows(campaign *state.Campaign) (map[string]validation.Value, error) {
	out := map[string]validation.Value{}
	// campaign.root (a path), NOT the Campaign object: passing the object
	// resolves the root tier to <campaign.dir>/shared-memory, where
	// publish_campaign never writes — root-tier rows would be invisible and
	// every recorded check referencing one would verify stale forever.
	shared, err := sharedMemoryRowsFunc(campaign.Root)
	if err != nil {
		return nil, err
	}
	for _, w := range shared {
		row := w
		if w.Kind == validation.Obj {
			if inner, ok := fieldAt(w, "row"); ok {
				row = inner
			}
		}
		if id := objStr(row, "memory_id"); id != "" {
			out[id] = row
		}
	}
	learned, err := learningAllMemoryFunc(campaign)
	if err != nil {
		return nil, err
	}
	for _, row := range learned {
		if id := objStr(row, "memory_id"); id != "" {
			if _, exists := out[id]; !exists {
				out[id] = row
			}
		}
	}
	return out, nil
}

// canonicalRowHash is _canonical_row_hash:
// sha256(json.dumps(row, sort_keys=True, ensure_ascii=True)).
func canonicalRowHash(row validation.Value) string {
	return validation.Sha256Hex([]byte(validation.CanonSpaced(row)))
}

// ComputeRowDigest is compute_row_digest: sha256 of the sorted JSON pair list
// [(memory_id, canonical-row-hash), ...]. Deterministic; an empty list gives
// the digest of [].
func ComputeRowDigest(memoryIDs []string,
	rowsByID map[string]validation.Value) string {
	type pair struct{ mid, hash string }
	pairs := make([]pair, 0, len(memoryIDs))
	for _, mid := range memoryIDs {
		if row, ok := rowsByID[mid]; ok {
			pairs = append(pairs, pair{mid, canonicalRowHash(row)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].mid != pairs[j].mid {
			return pairs[i].mid < pairs[j].mid
		}
		return pairs[i].hash < pairs[j].hash
	})
	items := make([]validation.Value, len(pairs))
	for i, p := range pairs {
		items[i] = validation.VArr(validation.VStr(p.mid),
			validation.VStr(p.hash))
	}
	return validation.Sha256Hex([]byte(validation.CanonSpaced(
		validation.VArr(items...))))
}

// memoryCheckKey is Python's (frozenset(memory_ids), mode) dedupe key.
func memoryCheckKey(ids []string, mode validation.Value) string {
	uniq := make([]string, 0, len(ids))
	seen := map[string]struct{}{}
	for _, id := range ids {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			uniq = append(uniq, id)
		}
	}
	sort.Strings(uniq)
	return strings.Join(uniq, "\x00") + "\x01" + validation.PyRepr(mode)
}

// RecordMemoryCheck is record_memory_check: record graph-memory consultations
// for a finding (the CONFIRMED gate's required evidence, replacing the dead
// corpus-check).
//
// Each check: {"memory_ids": [str], "mode": "negative"|"comparative",
// "note"?: str}. Every memory_id must exist in VisibleMemoryRows — ids that
// were never in the store cannot be recorded. The stamp (row_digest) is
// computed from the live store at record time; the gate re-verifies it, so a
// check survives only while the referenced rows are unchanged. Appends;
// dedupes on (frozenset(memory_ids), mode); never rewrites prior entries.
//
// Each NEW entry also carries the relevance verdict (B3/D2): the cited rows
// that share a structural tag with the finding, and the bases that fired.
// Zero overlap stamps recalled_irrelevant and logs one corpus.gap — the act
// still satisfies the gate; the signal is honest. A bug_class that is
// non-discriminative on its own (see CoarseClassRule) does not count by
// itself: it is recorded as relevance.discounted and a second basis is
// required. The gap event says which of those happened (reason_code +
// reason, see IrrelevantReason) — sharing only the catch-all label is NOT
// the corpus being silent on the lineage. Entries recorded before B3 are
// left exactly as they are.
//
// r42 P3-a: the signal is derived from the RECORD, never from the batch of
// checks this call happened to add. Every recorded entry that still owes a
// corpus.gap — the verdict travels with the entry (relevance +
// recalled_irrelevant), so "owes one" is recomputable from the file — is
// re-derived on every call and emitted unless the LEDGER already holds that
// event; see emitOwedCorpusGaps. A refused gap append is therefore
// retryable: the next call re-derives it instead of reporting the
// truth-shaped `finding.memory_checked {"added": 0}` no-op while the
// relevance signal stays unrecorded.
func RecordMemoryCheck(campaign *state.Campaign, findingID string,
	checks []validation.Value) (validation.Value, error) {
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	prov := objAt(finding, "provenance")
	if prov.Kind != validation.Obj {
		prov = validation.VObj()
	}
	existing := objAt(prov, "memory_checks")
	if existing.Kind != validation.Arr {
		existing = validation.VArr()
	}
	seen := map[string]struct{}{}
	for _, r := range existing.A {
		if r.Kind != validation.Obj {
			continue
		}
		seen[memoryCheckKey(valueStrings(objAt(r, "memory_ids")),
			objAt(r, "mode"))] = struct{}{}
	}
	rowsByID, err := VisibleMemoryRows(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	added, irrelevant := 0, 0
	for _, c := range checks {
		key, entry, owesGap, err := memoryCheckEntry(c, rowsByID, finding)
		if err != nil {
			return validation.VNull(), err
		}
		if _, dup := seen[key]; dup {
			continue
		}
		existing.A = append(existing.A, entry)
		seen[key] = struct{}{}
		added++
		if owesGap {
			irrelevant++
		}
	}
	prov.O = validation.SetOrAppend(prov.O, "memory_checks", existing)
	finding.O = validation.SetOrAppend(finding.O, "provenance", prov)
	// The signal is logged only once the entry that carries it is persisted:
	// a gap event for a check that never landed would be a lie of its own.
	data := validation.VObj(
		validation.KV{K: "added", V: validation.VInt(int64(added))},
		validation.KV{K: "irrelevant", V: validation.VInt(int64(irrelevant))},
		validation.KV{K: "modes", V: strArr(checkModes(checks))},
	)
	// r41 P1: the persisted entry IS the gate's evidence — MemoryCheckFails
	// (below) reads provenance.memory_checks off the FILE, not the ledger —
	// so a refused append used to leave the finder "certified" by an act the
	// ledger never recorded: `recall` printed the projection refusal and
	// exited 1 while the CONFIRMED gate clause flipped to ✓ memory-check
	// with 0 finding.memory_checked events behind it, and the retry then
	// logged {"added": 0} forever. SaveThenLog is the package's unwind door
	// (r17/r18/r40b siblings: ingest.go, mitigscan.go, ackscan.go,
	// transitions.go) and it fits THIS write even though the write EDITS an
	// existing finding rather than minting one: prevBytes snapshots the
	// file's pre-save bytes before SaveFinding, so a refusal restores them
	// exactly (or removes the file, had it never existed).
	if err := SaveThenLog(campaign, &finding, func() error {
		_, lerr := campaign.Log("finding.memory_checked", &findingID, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	// The gap events trail the authoritative file+event pair on purpose: the
	// pair cannot be un-appended once logged, and a check that DID land may
	// still owe its corpus.gap signal. A refusal there is reported, but the
	// recorded check is already honest — the ledger holds its event.
	//
	// r42 P3-a: the owed set is recomputed from the RECORDED entries (which
	// now include the ones added above), not from this call's batch, so a
	// signal a previous, refused append never landed is emitted by the
	// retry. emitOwedCorpusGaps reads the ledger for what already landed.
	if err := emitOwedCorpusGaps(campaign, findingID, finding, existing); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// emitOwedCorpusGaps logs the corpus.gap signal for every RECORDED check
// entry that still owes one and whose event the ledger does not already
// hold. It is the one place the signal is emitted, and it derives both the
// owed set and the payload from the recorded state.
//
// r42 P3-a: the payloads used to be built only for the checks that were NEW
// in the call, and the recorded entry carried no way back to them — once the
// entry was written, a refused corpus.gap append could never be recomputed.
// Every retry then saw a duplicate check, emitted nothing and reported
// `finding.memory_checked {"added": 0}` forever while the relevance signal
// stayed unrecorded: the retry lied by omission, and absence of the signal
// was read as "nothing to say". Re-deriving it from the entry (which carries
// the verdict: relevance + recalled_irrelevant) plus the ledger (which
// carries what landed) makes the signal land-or-be-retryable: the absence
// that re-arms the retry is the EVENT's, read off the log itself, and a log
// that cannot be read refuses instead of guessing that the signal landed.
//
// Refusals are reported, never swallowed, and one refused append does not
// strand the others: every owed signal is attempted and the first refusal is
// returned. Nothing is unwound — the entry and its finding.memory_checked
// anchor have landed, and the next call re-derives whatever is still missing.
func emitOwedCorpusGaps(c *state.Campaign, findingID string,
	finding, recorded validation.Value) error {
	var owed []validation.Value
	for _, e := range recorded.A {
		if corpusGapOwed(e) {
			owed = append(owed, e)
		}
	}
	if len(owed) == 0 {
		return nil
	}
	logged, err := loggedCorpusGaps(c, findingID)
	if err != nil {
		return err
	}
	var firstErr error
	for _, e := range owed {
		if _, ok := logged[corpusGapKey(findingID, e)]; ok {
			continue
		}
		gap := corpusGapPayload(finding, e)
		if _, lerr := c.Log("corpus.gap", &findingID, &gap); lerr != nil {
			if firstErr == nil {
				firstErr = lerr
			}
		}
	}
	return firstErr
}

// corpusGapOwed reports whether one RECORDED check entry still owes its
// corpus.gap signal. memoryCheckEntry stamps recalled_irrelevant exactly
// when the entry's own relevance verdict found no overlapping row, and the
// verdict subtree travels with the entry — so the question is answered from
// the file alone, with no second computation of the overlap. Entries
// recorded before B3 carry no relevance subtree and never owed a signal:
// they are deliberately NOT re-armed (their history stays as it is).
func corpusGapOwed(entry validation.Value) bool {
	if entry.Kind != validation.Obj {
		return false
	}
	if v := objAt(entry, "recalled_irrelevant"); v.Kind != validation.Bool || !v.B {
		return false
	}
	rel := objAt(entry, "relevance")
	if rel.Kind != validation.Obj {
		return false
	}
	overlapping := objAt(rel, "overlapping")
	return overlapping.Kind == validation.Arr && len(overlapping.A) == 0
}

// corpusGapKey identifies one corpus.gap signal — owed or landed — by the
// finding, the check's mode and its cited id set, the same triple
// memoryCheckKey dedupes on, in a canonical encoding (no separator can be
// forged inside an id).
func corpusGapKey(findingID string, entry validation.Value) string {
	return findingID + "\x01" + validation.PyRepr(objAt(entry, "mode")) +
		"\x01" + validation.CanonCompact(strArr(
		valueStrings(objAt(entry, "memory_ids"))))
}

// corpusGapPayload builds one corpus.gap event payload from a RECORDED check
// entry: the ONE implementation of the signal's shape, used both when the
// entry lands and when a later call re-emits it. The reason comes from the
// entry's own relevance verdict — never from a fresh look at the live store,
// where the cited rows may have moved since: the event states the verdict the
// record holds. lineage names the finding's tags as they stand when the
// signal is finally emitted.
func corpusGapPayload(finding, entry validation.Value) validation.Value {
	ids := valueStrings(objAt(entry, "memory_ids"))
	reasonCode, reason := IrrelevantReason(objAt(entry, "relevance"), ids)
	return validation.VObj(
		validation.KV{K: "finding", V: validation.VStr(objStr(finding,
			"finding_id"))},
		validation.KV{K: "memory_ids", V: strArr(ids)},
		validation.KV{K: "mode", V: objAt(entry, "mode")},
		validation.KV{K: "lineage", V: strArr(LineageTags(finding))},
		validation.KV{K: "reason_code", V: validation.VStr(reasonCode)},
		validation.KV{K: "reason", V: validation.VStr(reason)},
	)
}

// loggedCorpusGaps is the set of corpus.gap signals the ledger already holds
// for one finding, keyed like corpusGapKey. The log is the complete record
// of what landed (the state mirror keeps only a tail), so an entry whose
// event is present is not re-emitted — no duplicate signal — while one whose
// event is absent still is. A ledger that cannot be read returns the error:
// the caller refuses rather than assuming a signal landed.
func loggedCorpusGaps(c *state.Campaign, findingID string) (map[string]struct{},
	error) {
	events, err := c.Events()
	if err != nil {
		return nil, err
	}
	out := map[string]struct{}{}
	for _, ev := range events {
		if objStr(ev, "type") != "corpus.gap" {
			continue
		}
		data := objAt(ev, "data")
		// Either spelling of the finding identifies the event: the write
		// path sets both, and matching both directions can only avoid a
		// duplicate signal, never manufacture one.
		if objStr(ev, "ref") != findingID &&
			objStr(data, "finding") != findingID {
			continue
		}
		out[corpusGapKey(findingID, data)] = struct{}{}
	}
	return out, nil
}

// memoryCheckEntry validates one check against the visible store and builds
// its dedup key + stamped entry (Python's in-loop body), reporting whether
// the entry owes the corpus.gap signal. The payload itself is not built here:
// corpusGapPayload derives it from the entry, so a check that lands now and a
// check whose signal is re-emitted later produce the same bytes through ONE
// implementation.
func memoryCheckEntry(c validation.Value,
	rowsByID map[string]validation.Value, finding validation.Value) (
	string, validation.Value, bool, error) {
	ids := valueStrings(objAt(c, "memory_ids"))
	mode := objAt(c, "mode")
	if mode.Kind != validation.Str ||
		(mode.S != "negative" && mode.S != "comparative") {
		return "", validation.VNull(), false, fmtUnknownMode(mode)
	}
	var unknown []string
	for _, mid := range ids {
		if _, ok := rowsByID[mid]; !ok {
			unknown = append(unknown, mid)
		}
	}
	if len(unknown) > 0 {
		return "", validation.VNull(), false,
			fmtUnknownMemoryIDs(unknown)
	}
	sortedIDs := sortedStrings(ids)
	entry := validation.VObj(
		validation.KV{K: "memory_ids", V: strArr(sortedIDs)},
		validation.KV{K: "mode", V: mode},
		validation.KV{K: "consulted_at", V: validation.VStr(nowIso())},
		validation.KV{K: "row_digest",
			V: validation.VStr(ComputeRowDigest(ids, rowsByID))},
	)
	relevance := MemoryCheckRelevance(finding, ids, rowsByID)
	entry.O = append(entry.O, validation.KV{K: "relevance", V: relevance})
	if overlapping := objAt(relevance, "overlapping"); len(overlapping.A) == 0 {
		entry.O = append(entry.O,
			validation.KV{K: "recalled_irrelevant", V: validation.VBool(true)})
	}
	if note := objAt(c, "note"); validation.PyTruthy(note) {
		entry.O = append(entry.O, validation.KV{K: "note", V: note})
	}
	return memoryCheckKey(ids, mode), entry, corpusGapOwed(entry), nil
}

// joinComma is ", ".join(items).
func joinComma(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

func fmtUnknownMode(mode validation.Value) error {
	return fmt.Errorf("memory check mode must be negative|comparative, got %s",
		validation.PyRepr(mode))
}

func fmtUnknownMemoryIDs(unknown []string) error {
	return fmt.Errorf("unknown memory id(s) %s — not in the visible store",
		listRepr(unknown))
}

// checkModes is sorted({c.get("mode") or "-" for c in checks}).
func checkModes(checks []validation.Value) []string {
	seen := map[string]struct{}{}
	for _, c := range checks {
		m := objAt(c, "mode")
		if m.Kind == validation.Str && m.S != "" {
			seen[m.S] = struct{}{}
			continue
		}
		seen["-"] = struct{}{}
	}
	return sortedSetKeys(seen)
}

func sortedStrings(items []string) []string {
	out := append([]string(nil), items...)
	sort.Strings(out)
	return out
}

// MemoryCheckFails is memory_check_fails: the gate's memory-check portion.
// Returns nil when a recorded check verifies, else the failure message.
// Verification: mode valid; every referenced id still in the visible store;
// recomputed digest matches the stamp. A hand-written legacy corpus-reference
// list in provenance is NOT a memory check.
func MemoryCheckFails(campaign *state.Campaign,
	findingID string) (*string, error) {
	finding, err := LoadFinding(campaign, findingID)
	if err != nil {
		return nil, err
	}
	checks := objAt(asDict(objAt(finding, "provenance")), "memory_checks")
	if checks.Kind != validation.Arr {
		checks = validation.VArr()
	}
	rowsByID, err := VisibleMemoryRows(campaign)
	if err != nil {
		return nil, err
	}
	for _, c := range checks.A {
		if c.Kind != validation.Obj {
			continue
		}
		mode := objAt(c, "mode")
		if mode.Kind != validation.Str ||
			(mode.S != "negative" && mode.S != "comparative") {
			continue
		}
		ids := valueStrings(objAt(c, "memory_ids"))
		stale := false
		for _, mid := range ids {
			if _, ok := rowsByID[mid]; !ok {
				stale = true // stale: referenced row gone
				break
			}
		}
		if stale {
			continue
		}
		if ComputeRowDigest(ids, rowsByID) != objStr(c, "row_digest") {
			continue // stale: row content changed since recording
		}
		return nil, nil
	}
	msg := "no verified graph-memory recall recorded — none recorded, or " +
		"every recorded check is stale (a referenced row changed or left " +
		"the store) — run `webv2 recall " + campaign.CampaignID + " --finding " +
		findingID + "`"
	return &msg, nil
}

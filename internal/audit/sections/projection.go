// Section 5: projection consistency — the state file is a working
// projection of the log. An entry the projection holds that the log never
// recorded is a hand-edit of the state file; the reverse (log events with
// no state entry) is what legacy campaigns look like, so it is not
// flagged. Most checks run only when the log records at least one event
// of that kind — the SNAPSHOT-ROW direction does not (r10): gating it on
// the ledger's pinned-event count let an event erased from BOTH ledger
// copies blind the check over a lying state row. Messages are for-
// message with audit.py section 5; the un-gating is a documented
// divergence, and r11 made a plain re-pin the sanctioned heal.
package sections

import (
	"fmt"
	"path/filepath"
	"sort"

	"websec/internal/state"
	"websec/internal/validation"

	"strings"
	"websec/internal/costs"
)

// Projection is audit.py section 5. checked is hardcoded to 4.
func Projection(c *state.Campaign) (validation.Value, error) {
	events, err := c.Events()
	if err != nil {
		return validation.Value{}, err
	}
	st, err := c.State()
	if err != nil {
		return validation.Value{}, err
	}
	var proj []validation.Value

	// artifact_refs: refs of artifact.registered events.
	artifactRefs := refsOf(events, "artifact.registered")
	if len(artifactRefs) > 0 {
		for _, a := range objAt(st, "artifacts").A {
			if _, ok := artifactRefs[objStr(a, "artifact_id")]; !ok {
				proj = append(proj, validation.VStr(
					fmt.Sprintf("state lists artifact %s with no artifact.registered event",
						objStr(a, "artifact_id"))))
			}
		}
	}

	// snapshot_refs: refs of snapshot.pinned events. r10: the state-row
	// direction is UNCONDITIONAL — gating it on "the log has pinned
	// events" let an attacker (or the r9 bug's twin: strip the event from
	// BOTH ledger copies while the state row survives) blind the very
	// check that polices it: zero pinned events then skipped the whole
	// loop, and the lying projection audited green. A campaign state that
	// lists a snapshot the ledger never recorded is a hand-edit regardless
	// of how many other pinned events exist. The ledger->state direction
	// stays lenient (legacy), and the message is the twin's.
	snapshotRefs := refsOf(events, "snapshot.pinned")
	for _, s := range objAt(st, "snapshots").A {
		if _, ok := snapshotRefs[objStr(s, "snapshot_id")]; !ok {
			proj = append(proj, validation.VStr(
				fmt.Sprintf("state lists snapshot %s with no snapshot.pinned event",
					objStr(s, "snapshot_id"))))
		}
	}

	// ingested: refs of finding.ingested; chain_super: data.super_finding
	// of chain.materialized.
	ingested := refsOf(events, "finding.ingested")
	chainSuper := superOf(events)
	if len(ingested) > 0 || len(chainSuper) > 0 {
		// r43a: a finding store that cannot be listed refuses; the old
		// silent-empty read made this direction vacuous exactly when the
		// store was unreadable.
		findingPaths, ferr := findingFiles(c)
		if ferr != nil {
			return validation.Value{}, ferr
		}
		for _, p := range findingPaths {
			fid := filepath.Base(p)
			fid = fid[:len(fid)-len(".json")]
			_, inIngested := ingested[fid]
			_, inSuper := chainSuper[fid]
			if !inIngested && !inSuper {
				proj = append(proj, validation.VStr(
					fmt.Sprintf("finding %s exists on disk but the log records neither finding.ingested nor chain.materialized for it",
						fid)))
			}
		}
	}

	// refresh_refs: refs of artifact.refreshed. r37a: the check is
	// ORDER-AWARE. Before, any refreshed ref with no state row was a
	// problem — but a SANCTIONED artifact-prune retires the row while the
	// log keeps its trail (artifact.registered, any artifact.refreshed,
	// then artifact.pruned), so the honest sequence register -> refresh ->
	// prune audited RED with a false accusation: the row is absent
	// BECAUSE the log's own pruned event retired it. The matrix, each row
	// decided explicitly:
	//
	//   refreshed-then-pruned (state row absent, last refresh BEFORE the
	//   prune): history — the prune is exactly why the row is gone. PASS.
	//
	//   pruned-then-re-registered-under-a-new-id: registration mints a
	//   fresh uuid (state.id.go newId), so the new id has its own
	//   registered event and its own row; the old id's prune stays
	//   history and its row-1 verdict is unchanged. PASS (both ids).
	//
	//   pruned-then-refreshed (a refresh event for the id AFTER its
	//   prune, no re-registration under the SAME id): impossible through
	//   the verbs — prune removes the row, refresh requires it, and a
	//   re-register would carry a different id — so any refresh seq
	//   after the first prune seq means the log (or the state) was
	//   hand-altered. REFUSE LOUDLY, with its own message, never the
	//   generic one and never a silent skip.
	//
	//   a prune for an id that was never registered: still a problem —
	//   prune retires a registered row, so an unregistered prune is a
	//   forged trail (new check below).
	//
	//   a state row that survives its own prune: still a problem — prune
	//   removes the row and nothing sanctioned puts it back (a heal
	//   re-registers under a NEW id), so a surviving row is a hand-edit
	//   of campaign_state (new check below).
	//
	// The whole block stays presence-gated (a campaign with neither
	// refreshed nor pruned events stays byte-identical to the ported
	// output), and the generic message is kept byte-identical for the
	// case that genuinely is one (refresh with no prune and no row).
	refreshRefs := refsOf(events, "artifact.refreshed")
	prunedRefs := refsOf(events, "artifact.pruned")
	if len(refreshRefs) > 0 || len(prunedRefs) > 0 {
		artIDs := map[string]struct{}{}
		for _, a := range objAt(st, "artifacts").A {
			artID := objStr(a, "artifact_id")
			if artID != "" {
				artIDs[artID] = struct{}{}
			}
		}
		_, refreshLast := refSeqBounds(events, "artifact.refreshed")
		pruneFirst, _ := refSeqBounds(events, "artifact.pruned")
		for _, r := range sortedKeys(refreshRefs) {
			if _, ok := artIDs[r]; ok {
				continue
			}
			if pseq, pruned := pruneFirst[r]; pruned {
				// A later refresh than the earliest prune cannot be
				// explained by the verbs: refuse loudly (matrix row 3).
				if lseq, seen := refreshLast[r]; seen && lseq > pseq {
					proj = append(proj, validation.VStr(
						fmt.Sprintf("log records artifact.refreshed for %s after its artifact.pruned event — a pruned row cannot refresh and a re-register mints a new id, so the log or the state has been hand-altered",
							validation.PyReprStr(r))))
				}
				// Otherwise: refreshed-then-pruned — the prune is the
				// log's own account of why the row is absent. History,
				// not a problem (matrix row 1).
				continue
			}
			proj = append(proj, validation.VStr(
				fmt.Sprintf("log records artifact.refreshed for %s but the state has no such artifact",
					validation.PyReprStr(r))))
		}
		// Matrix row 4: a prune for an id the ledger never registered.
		// artifactRefs is the artifact.registered ref set computed above;
		// every pruned row was once a registered row, so the registered
		// event must be on the log.
		for _, r := range sortedKeys(prunedRefs) {
			if _, ok := artifactRefs[r]; !ok {
				proj = append(proj, validation.VStr(
					fmt.Sprintf("log records artifact.pruned for %s but no artifact.registered event for it — a prune retires a registered row, so this trail is forged",
						validation.PyReprStr(r))))
			}
		}
		// Matrix row 5: a state row that survived its own prune. The
		// sanctioned heal re-registers under a NEW id, so no id in the
		// state may also carry an artifact.pruned event.
		for _, a := range objAt(st, "artifacts").A {
			id := objStr(a, "artifact_id")
			if _, ok := pruneFirst[id]; ok {
				proj = append(proj, validation.VStr(
					fmt.Sprintf("state lists artifact %s but the log records artifact.pruned for it — a retired row reappeared in the state; the sanctioned heal is artifact-register, which mints a new id",
						validation.PyReprStr(id))))
			}
		}
	}

	// r14: costs.jsonl is a file projection like waivers — the ledger
	// says what was spent (cost.recorded carries kind/amount/actor) and
	// budget reads ONLY the file, so a deleted file made spend silently
	// $0.00 while the chain still testified, and a hand-written ghost
	// row inflated it; both directions audit green. Folded here (same
	// home r12 gave waivers) — presence-gated so campaigns without
	// costs are byte-identical to the ported output.
	{
		// r15: one law, one implementation — the SAME cross-check the
		// budget enforcement refuses on (costs.CostMirrorProblems).
		// Presence-gated by the helper itself, so costless campaigns
		// stay byte-identical to the ported output.
		for _, msg := range costs.CostMirrorProblems(c) {
			proj = append(proj, validation.VStr(msg))
		}
		// r16: chains/ was the last projection with NO direction either
		// way — MaterializeChain logs chain.materialized(_unproven) and
		// writes chains/CHAIN-*.json; deleting or forging a doc moved
		// nothing. Events->docs catches vanished chains; docs->events
		// catches hand-planted chains claiming a materialization that
		// never ran (both presence-gated by the file/dir being empty).
		chainEvents := map[string]string{}
		for _, e := range events {
			if typ := objStr(e, "type"); typ == "chain.materialized" ||
				typ == "chain.materialized_unproven" {
				chainEvents[objStr(e, "ref")] = typ
			}
		}
		docNames := map[string]bool{}
		// r43a: "no chain documents" is the premise that makes both
		// directions below vacuous (no doc -> nothing hand-planted; and with
		// no docs, every materialized event reads as "is gone"). An
		// unreadable chains/ directory must therefore refuse, not read as
		// empty.
		chainPaths, cerr := validation.ListPrefixedOptional(c.ChainsDir,
			"CHAIN-", ".json")
		if cerr != nil {
			return validation.Value{}, fmt.Errorf(
				"the chain store %s cannot be listed: %v", c.ChainsDir, cerr)
		}
		for _, path := range chainPaths {
			base := filepath.Base(path)
			docNames[strings.TrimSuffix(base, ".json")] = true
		}
		for id := range chainEvents {
			if !docNames[id] {
				proj = append(proj, validation.VStr(fmt.Sprintf(
					"the ledger materialized chain %s but chains/%s.json "+
						"is gone — a chain the campaign still proposes "+
						"(terminals, super-findings) with no document",
					id, id)))
			}
		}
		for name := range docNames {
			if _, ok := chainEvents[name]; !ok {
				proj = append(proj, validation.VStr(fmt.Sprintf(
					"chains/%s.json exists with no chain.materialized "+
						"event — hand-planted chains bypass the floor and "+
						"provenance laws; chains are owed through "+
						"`webv2 chains --materialize`", name)))
			}
		}
	}
	return validation.VObj(
		KV("checked", validation.VInt(4)),
		KV("problems", validation.VArr(proj...)),
		KV("ok", validation.VBool(len(proj) == 0)),
	), nil
}

// refsOf is {e.get("ref") for e in events if e["type"] == typ}: the set of
// string refs (None refs are dropped; a None-only set is truthy-but-empty,
// matching Python where {None} is a non-empty set of one None — but since
// "r not in art_ids" is the only consumer and None never matches a string
// id, dropping None is behaviorally identical for the realistic cases).
func refsOf(events []validation.Value, typ string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, e := range events {
		if objStr(e, "type") != typ {
			continue
		}
		r := objAt(e, "ref")
		if r.Kind == validation.Str && r.S != "" {
			out[r.S] = struct{}{}
		}
	}
	return out
}

// superOf is {(e.get("data") or {}).get("super_finding") for e in events
// if e["type"] == "chain.materialized"}: the set of non-empty string
// super_finding ids.
func superOf(events []validation.Value) map[string]struct{} {
	out := map[string]struct{}{}
	for _, e := range events {
		if objStr(e, "type") != "chain.materialized" {
			continue
		}
		data := objAt(e, "data")
		sf := objStr(data, "super_finding")
		if sf != "" {
			out[sf] = struct{}{}
		}
	}
	return out
}

// refSeqBounds scans the events of one type and returns, per non-empty
// string ref, the seq of the FIRST and LAST event carrying it. Events
// without a usable seq (non-int) or ref are skipped; the log guarantees
// one int seq per line (state.eventlog writes kv("seq", ...)), so in
// practice every event contributes. r37a: order-aware projection needs
// the sequence numbers, not just the ref set.
func refSeqBounds(events []validation.Value, typ string) (first, last map[string]int64) {
	first = map[string]int64{}
	last = map[string]int64{}
	for _, e := range events {
		if objStr(e, "type") != typ {
			continue
		}
		r := objAt(e, "ref")
		if r.Kind != validation.Str || r.S == "" {
			continue
		}
		seq := objAt(e, "seq")
		if seq.Kind != validation.Int {
			continue
		}
		if _, ok := first[r.S]; !ok {
			first[r.S] = seq.I
		}
		last[r.S] = seq.I
	}
	return first, last
}

// sortedKeys returns the sorted string keys of a set (Python sorted(ref)).
func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	// Python sorts the raw values; we sort string form (see note: mixed
	// None/str would crash Python, so strings-only it is).
	sort.Strings(out)
	return out
}

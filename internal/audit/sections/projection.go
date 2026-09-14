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

	"os"
	"strings"
	"websec/internal/state"
	"websec/internal/validation"
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
		for _, p := range findingFiles(c) {
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

	// refresh_refs: refs of artifact.refreshed.
	refreshRefs := refsOf(events, "artifact.refreshed")
	if len(refreshRefs) > 0 {
		artIDs := map[string]struct{}{}
		for _, a := range objAt(st, "artifacts").A {
			artID := objStr(a, "artifact_id")
			if artID != "" {
				artIDs[artID] = struct{}{}
			}
		}
		for _, r := range sortedKeys(refreshRefs) {
			if _, ok := artIDs[r]; !ok {
				proj = append(proj, validation.VStr(
					fmt.Sprintf("log records artifact.refreshed for %s but the state has no such artifact",
						validation.PyReprStr(r))))
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
		// UNCONDITIONAL like r10 taught: ghost rows with no events at
		// all are the loudest case, not the gate's excuse.
		costEvents := eventsOfType(events, "cost.recorded")
		rows, rerr := readCostRowsR14(c)
		if rerr != nil {
			proj = append(proj, validation.VStr(
				fmt.Sprintf("costs.jsonl: unreadable (%v) — recorded "+
					"spend cannot be trusted", rerr)))
		} else if len(rows) > 0 || len(costEvents) > 0 {
			have := map[string]bool{}
			for _, r := range rows {
				have[objStr(r, "cost_id")] = true
			}
			for _, e := range costEvents {
				if !have[objStr(e, "ref")] {
					proj = append(proj, validation.VStr(fmt.Sprintf(
						"the ledger records cost %s ($%s %s) but "+
							"costs.jsonl has no row for it — spend went "+
							"missing from the projection budget reads",
						objStr(e, "ref"),
						pyStrValue(objAt(objAt(e, "data"), "amount_usd")),
						objStr(objAt(e, "data"), "kind"))))
				}
			}
			seen := refsOf(events, "cost.recorded")
			for _, r := range rows {
				if _, ok := seen[objStr(r, "cost_id")]; !ok {
					proj = append(proj, validation.VStr(fmt.Sprintf(
						"costs.jsonl row %s was never recorded in the "+
							"ledger — ghost spend inflates the budget "+
							"silently; costs are owed through `webv2 "+
							"cost`, not by editing the file",
						objStr(r, "cost_id"))))
				}
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

// eventsOfType is refsOf's sibling: the full events of one type, log order.
func eventsOfType(events []validation.Value, typ string) []validation.Value {
	var out []validation.Value
	for _, e := range events {
		if objStr(e, "type") == typ {
			out = append(out, e)
		}
	}
	return out
}

// readCostRowsR14 loads costs.jsonl rows (bare-JSON twin format, one per
// line); a missing file is zero rows, not an error.
func readCostRowsR14(c *state.Campaign) ([]validation.Value, error) {
	raw, err := os.ReadFile(filepath.Join(c.Dir, "costs.jsonl"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []validation.Value
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		v, perr := validation.ParseOrdered([]byte(ln))
		if perr != nil {
			return nil, perr
		}
		out = append(out, v)
	}
	return out, nil
}

package learning

import (
	"fmt"
	"path/filepath"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// Reading and promoting memory rows: listing, the pending filter, the
// promotion command and the stale-bug-class drift check. Split from
// learning.go (same package).

// PromotionCommands is promotion_commands: the approved write path for a
// human-approved candidate. The command is not executed here: promotion
// crosses the campaign boundary, which is an operator/harness act.
func PromotionCommands(c *state.Campaign, memoryID, actor string) ([]validation.Value, error) {
	if actor == "" {
		actor = "<human>"
	}
	mem, err := validation.ReadJson(filepath.Join(c.MemoryDir, memoryID+".json"))
	if err != nil {
		return nil, err
	}
	status := validation.ObjStr(mem, "promotion_status")
	if status != "human-approved" {
		return nil, fmt.Errorf("%s is %s; human approval required before any "+
			"promotion", memoryID, pyReprStr(status))
	}
	return []validation.Value{validation.VObj(
		kv("substrate", validation.VStr("shared-memory-store")),
		kv("command", validation.VStr("webv2 publish "+c.CampaignID+
			" --actor "+actor)),
		kv("note", validation.VStr("promotes every approved memory row + "+
			"confirmed-finding signatures to the shared store (idempotent)")))}, nil
}

// PendingMemory is pending_memory: rows whose promotion_status is 'pending'.
func PendingMemory(c *state.Campaign) ([]validation.Value, error) {
	rows, err := AllMemory(c)
	if err != nil {
		return nil, err
	}
	out := []validation.Value{}
	for _, m := range rows {
		if validation.ObjStr(m, "promotion_status") == "pending" {
			out = append(out, m)
		}
	}
	return out, nil
}

// AllMemory is all_memory: every MEM-*.json row, filename-sorted.
//
// r43a: an absent memory/ directory is an empty campaign; a memory/ directory
// that cannot be listed refuses, naming the path — a reader with no evidence
// about the store must not answer "no memory rows".
func AllMemory(c *state.Campaign) ([]validation.Value, error) {
	paths, err := validation.ListPrefixedOptional(c.MemoryDir, "MEM-", ".json")
	if err != nil {
		return nil, fmt.Errorf("the memory store %s cannot be listed: %v",
			c.MemoryDir, err)
	}
	out := make([]validation.Value, 0, len(paths))
	for _, p := range paths {
		row, err := validation.ReadJson(p)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, nil
}

// StaleBugClass reports whether an approved row's bug_class no longer
// matches its source finding's root class (an amend --class after queueing
// moves the finding out from under the row). Returns the pair and true
// when the drift exists; absent finding id, missing row, or matching
// class all report false (r7: the promotion should not silently carry a
// stale taxonomy label — the CLI warns; the human decides).
func StaleBugClass(c *state.Campaign, mem validation.Value) (
	rowClass, findingClass string, stale bool) {
	fid := validation.ObjStr(mem, "finding_id")
	rowClass = validation.ObjStr(mem, "bug_class")
	if fid == "" || rowClass == "" {
		return "", "", false
	}
	// r8: follow supersession before judging. The superseded row keeps a
	// FROZEN class (supersede never rewrites root_cause); the live
	// successor carries the taxonomy the finding actually has now. The
	// chain is read from the event ledger — the append-only truth — not
	// from dedup_meta, and a visited set keeps a hand-forged cycle from
	// looping the check.
	seen := map[string]bool{fid: true}
	cur := fid
	for {
		f, err := findings.LoadFinding(c, cur)
		if err != nil {
			if cur == fid {
				return "", "", false // the row's own finding is gone
			}
			// r9: a chain that goes unread must not FAIL OPEN into
			// silence — the successor exists (the ledger says so) but its
			// row cannot be loaded. Report the drift as unknown-but-broken
			// and let the operator see it (stale carries the broken
			// marker).
			return rowClass, "(successor " + cur + " unreadable)", true
		}
		findingClass = rootClass(f)
		next := supersededBy(c, cur)
		if next == "" || seen[next] {
			break
		}
		seen[next] = true
		cur = next
	}
	if findingClass == "" {
		return rowClass, "", false
	}
	if findingClass == "" || findingClass == rowClass {
		return rowClass, findingClass, false
	}
	return rowClass, findingClass, true
}

// rootClass is root_cause.class of a finding row.
func rootClass(f validation.Value) string {
	rc := validation.ObjAt(f, "root_cause")
	if rc.Kind != validation.Obj {
		return ""
	}
	for _, kv := range rc.O {
		if kv.K == "class" && kv.V.Kind == validation.Str {
			return kv.V.S
		}
	}
	return ""
}

// supersededBy returns the LATEST successor recorded for fid via
// finding.superseded events (the ledger keeps the full chain history);
// "" when none.
func supersededBy(c *state.Campaign, fid string) string {
	events, err := c.Events()
	if err != nil {
		return ""
	}
	next := ""
	for _, ev := range events {
		if validation.ObjStr(ev, "type") != "finding.superseded" {
			continue
		}
		d := validation.ObjAt(ev, "data")
		if validation.ObjStr(d, "old") == fid {
			next = validation.ObjStr(d, "new")
		}
	}
	return next
}

package learning

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"websec/internal/state"
	"websec/internal/validation"
)

// Sanctioned field-stripping from campaign-local memory rows
// (strip_campaign_memory_field). Split from learning.go (same package).

// StripCampaignMemoryField is strip_campaign_memory_field: sanctioned,
// actor-attributed removal of a retired field from campaign-local memory
// rows (<root>/campaigns/*/memory/*.json). Returns {"campaigns":
// [{"campaign_id", "rows_stripped"}], "total_stripped": int}.
func StripCampaignMemoryField(root, field, actor, reason string) (validation.Value, error) {
	campaignsDir := filepath.Join(root, "campaigns")
	entries, err := os.ReadDir(campaignsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return validation.VObj(
				kv("campaigns", validation.VArr()),
				kv("total_stripped", validation.VInt(0))), nil
		}
		return validation.VNull(), err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	out := []validation.Value{}
	total := 0
	for _, name := range names {
		stripped, err := stripCampaignOne(root, name, field, actor, reason)
		if err != nil {
			return validation.VNull(), err
		}
		if stripped == nil {
			continue
		}
		out = append(out, validation.VObj(
			kv("campaign_id", validation.VStr(name)),
			kv("rows_stripped", validation.VInt(int64(len(stripped))))))
		total += len(stripped)
	}
	return validation.VObj(
		kv("campaigns", validation.VArr(out...)),
		kv("total_stripped", validation.VInt(int64(total)))), nil
}

// stripCampaignOne strips `field` from one campaign's local memory rows and
// writes the rows back under the campaign's write-then-log discipline. It
// returns the stripped paths, or nil when the campaign has nothing to strip
// (no campaign or memory directory, or no row carrying the field).
func stripCampaignOne(root, name, field, actor, reason string) ([]string, error) {
	cdir := filepath.Join(root, "campaigns", name)
	if fi, err := os.Stat(cdir); err != nil || !fi.IsDir() {
		return nil, nil
	}
	memdir := filepath.Join(cdir, "memory")
	rows, targets, err := stripCampaignTargets(memdir, field)
	if err != nil || targets == nil {
		return nil, err
	}
	c, err := state.Open(root, name)
	if err != nil {
		return nil, err
	}
	data := validation.VObj(
		kv("actor", validation.VStr(actor)),
		kv("field", validation.VStr(field)),
		kv("reason", validation.VStr(reason)),
		kv("rows_stripped", validation.VInt(int64(len(targets)))))
	ref := name
	// The rows are written BEFORE the event: the event claims the strip
	// happened, so it may only be logged once it did. (Logging first left
	// a hash-chained record of work that a failed write never performed.)
	// r40: and the whole strip now unwinds together when the event is
	// refused — the removal is destructive and sanctioned ONLY by its
	// event, so rows stripped with no event are exactly the hand-edit
	// shape this verb exists to avoid.
	if err := writeThenLog(c, targets, func() error {
		for _, p := range targets {
			row := rows[p]
			row.O = removeKey(row.O, field)
			if err := validation.WriteJson(p, row, ""); err != nil {
				return err
			}
		}
		return nil
	}, func() error {
		_, lerr := c.Log("memory.field-stripped", &ref, &data)
		return lerr
	}); err != nil {
		return nil, err
	}
	return targets, nil
}

// stripCampaignTargets reads one campaign's memory rows and returns the
// parsed rows plus the paths of every row carrying the field; nil targets
// when the memory directory is absent or no row carries the field.
func stripCampaignTargets(memdir, field string) (map[string]validation.Value, []string, error) {
	memfi, serr := os.Stat(memdir)
	if serr != nil {
		if os.IsNotExist(serr) {
			return nil, nil, nil // no memory/ directory: nothing to strip
		}
		// r43a: a memory/ directory that cannot be examined is not an
		// empty one; skipping it would under-report the strip.
		return nil, nil, fmt.Errorf(
			"the memory directory %s cannot be examined: %v", memdir, serr)
	}
	if !memfi.IsDir() {
		return nil, nil, nil
	}
	paths, err := validation.ListPrefixedOptional(memdir, "", ".json")
	if err != nil {
		return nil, nil, fmt.Errorf(
			"the memory store %s cannot be listed: %v", memdir, err)
	}
	sort.Strings(paths)
	rows := make(map[string]validation.Value, len(paths))
	targets := []string{}
	for _, p := range paths {
		row, err := validation.ReadJson(p)
		if err != nil {
			return nil, nil, err
		}
		rows[p] = row
		if _, ok := fieldAt(row, field); ok {
			targets = append(targets, p)
		}
	}
	if len(targets) == 0 {
		return nil, nil, nil
	}
	return rows, targets, nil
}

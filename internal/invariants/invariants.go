// Package invariants ports webv2/invariants.py: the invariant registry, the
// audit's central object. Every hypothesis, PoC, fuzz property, symbolic
// query and detector hangs off an INV id; `test_status` is the test axis,
// `status` the orthogonal verification axis (only the framework's
// verify/contradict APIs may move it).
package invariants

import (
	"fmt"
	"os"
	"slices"

	"path/filepath"
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

// hasKey is `key in dict`.

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
func strPtr(s string) *string { return &s }

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
	reg := validation.ObjAt(*links, "invariants")
	if reg.Kind != validation.Obj {
		return false, nil
	}
	var legacy []int
	for i := range reg.O {
		if reg.O[i].V.Kind == validation.Obj && !validation.HasKey(reg.O[i].V, "test_status") {
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
		if hasOld && old.Kind == validation.Str && slices.Contains(Statuses, old.S) {
			ts = validation.VStr(old.S)
		}
		e.O = validation.SetOrAppend(e.O, "test_status", ts)
		e.O = validation.SetOrAppend(e.O, "status", validation.VStr("UNVERIFIED"))
		if !validation.HasKey(e, "source") {
			src, detail := deriveSource(iid, doc)
			e.O = validation.SetOrAppend(e.O, "source", validation.VStr(src))
			if detail != nil {
				e.O = validation.SetOrAppend(e.O, "source_detail", validation.VStr(*detail))
			}
		}
		e.O = validation.SetDefault(e.O, "findings", validation.VArr())
		e.O = validation.SetDefault(e.O, "tests", validation.VArr())
		e.O = validation.SetDefault(e.O, "detectors", validation.VArr())
		e.O = validation.SetOrAppend(e.O, "updated_at", validation.VStr(state.NowIso()))
		reg.O[i].V = e
		oldV := validation.VNull()
		if hasOld {
			oldV = old
		}
		migrated = append(migrated, validation.VObj(
			pair("id", validation.VStr(iid)),
			pair("old_status", oldV),
			pair("source", validation.ObjAt(e, "source")),
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
			ref := validation.ObjStr(m, "id")
			data := validation.VObj(
				pair("old_status", validation.ObjAt(m, "old_status")),
				pair("source", validation.ObjAt(m, "source")),
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
	reg := validation.ObjAt(links, "invariants")
	if reg.Kind != validation.Obj {
		return validation.VObj()
	}
	return reg
}

// ---- source derivation ---------------------------------------------------

// deriveSource is _derive_source: (source, provenance) for an id.
func deriveSource(iid string, doc validation.Value) (string, *string) {
	n := NormalizeInvID(iid)
	if validation.HasKey(doc, n) {
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

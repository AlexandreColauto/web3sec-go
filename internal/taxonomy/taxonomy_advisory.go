package taxonomy

// Class-report and ingest-advisory concerns: the taxonomy verdict for one
// class and the one-line ingest advisory split by WHY a class is strict.
// Split from taxonomy.go (same package).
import (
	"fmt"
	"sort"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ClassReport is class_report: the taxonomy verdict for one class — known?,
// its floor, and (when unknown) the closest canonical names, if any are
// plausibly the same bug under a different label. Rendered as an ordered
// object (class, known, floor, suggestions) exactly like the Python dict.
func ClassReport(bugClass *string) validation.Value {
	if bugClass == nil || *bugClass == "" {
		return validation.VObj(
			kv("class", validation.VNull()),
			kv("known", validation.VBool(false)),
			kv("floor", validation.VStr(DefaultFloor(nil))),
			kv("suggestions", validation.VArr()),
		)
	}
	_, known := knownRaw()[*bugClass]
	suggestions := validation.VArr()
	if !known {
		suggestions = validation.StrArr(closeMatches(*bugClass, validation.SortedKeys(knownRaw()), 3, 0.6))
	}
	return validation.VObj(
		kv("class", validation.VStr(*bugClass)),
		kv("known", validation.VBool(known)),
		kv("floor", validation.VStr(DefaultFloor(bugClass))),
		kv("suggestions", suggestions),
	)
}

// ClassAdvisory is class_advisory: the one-line advisory for ingest
// output/logs, or "" when there is nothing to say (the class is a known,
// unambiguous one — Python returns None). A nil bugClass is Python's None and
// renders as such in the message text.
//
// Wave N, T6: a KNOWN class is no longer silent when its CONFIRMED floor is
// STRICTER than the loosest known-class floor. The G-02 failure was exactly
// that silence — an ingest-time taxonomy choice (bridge-message, E6) pinned a
// floor the finding's evidence could never reach, and nothing said so. The
// warning names the class floor, the loosest known-class floor, the number of
// known classes pinned above it and two examples of that stricter pool,
// sorted deterministically by (floor, name); the floor table read here is the
// same one findings.RequiredLevelFor consults (DefaultFloor). A class AT the
// loosest floor still returns "" (nothing to say), and unknown classes keep
// the legacy message byte-for-byte.
//
// I-6 split the known-class half by WHY the class is strict. A class with a
// floor-table entry says "class X pins a CONFIRMED floor of E6" because the
// table really pins it, and the re-file advice is honest: the author chose a
// class whose table entry is expensive. A class WITHOUT an entry (donation,
// centralization-risk, precision-rounding, unchecked-external-call today)
// pins nothing — it inherits the CONFIRMED status default — so it says that
// instead, and gets NO re-file advice: there is no cheaper table class to
// file this class's content under, and the class choice is the author's.
//
// This is the findings.SetClassAdvisory seam target: it must keep the
// func(bugClass *string, campaign *state.Campaign) string signature (critic
// I-2: a campaign makes the warning floor-AWARE via the same lookup the
// gate reads; nil campaign = the built-in table).
func ClassAdvisory(bugClass *string, campaign *state.Campaign) string {
	if bugClass != nil {
		if canon := CanonicalClass(*bugClass); canon != *bugClass {
			return fmt.Sprintf("class %s is a synonym of canonical %s — use %s "+
				"(it decides the CONFIRMED floor AND whether the finding can "+
				"anchor a gold case).",
				validation.PyReprStr(*bugClass), validation.PyReprStr(canon), canon)
		}
	}
	rep := ClassReport(bugClass)
	if validation.ObjAt(rep, "known").B {
		return classFloorWarning(*bugClass, campaign)
	}
	msg := fmt.Sprintf("unknown class %s; known classes: %s; "+
		"no floor-table entry -> CONFIRMED defaults to %s "+
		"(the most conservative floor).",
		pyReprPtr(bugClass), strings.Join(validation.SortedKeys(knownRaw()), ", "),
		validation.ObjStr(rep, "floor"))
	if sugg := validation.ObjAt(rep, "suggestions"); len(sugg.A) > 0 {
		names := make([]string, 0, len(sugg.A))
		for _, s := range sugg.A {
			names = append(names, s.S)
		}
		msg += " Closest canonical classes: " + strings.Join(names, ", ") +
			" — if this is the same bug under a new label, use the " +
			"canonical name (it changes the CONFIRMED gate)."
	}
	return msg
}

// classFloorWarning is class_advisory's known-class half (wave N, T6): the
// warning that this class's CONFIRMED floor is stricter than the loosest floor
// any known class pins, or "" when the class is already at that loosest floor.
// I-6 splits it by whether the floor table actually carries the class — see
// ClassAdvisory's comment.
//
// The count and the examples of the with-entry warning describe the SAME set —
// the known classes pinned strictly above the loosest floor — so the examples'
// (floor, name) ordering is load-bearing: the set spans floors (E5 and E6,
// today), and a different order would make the advisory unstable across runs.
// The class itself is never offered as its own example.
func classFloorWarning(bugClass string, campaign *state.Campaign) string {
	loosest := loosestKnownFloorCampaign(campaign)
	floor := effectiveFloorCampaign(campaign, bugClass)
	if floorRank(floor) <= floorRank(loosest) {
		return ""
	}
	// Attribution honesty (critic r2): when a CAMPAIGN floor policy raised
	// this class above the table value, saying "the class pins" is a lie of
	// omission — name the override and its own undo hatch instead of the
	// re-file advice (which the override made moot anyway).
	table := DefaultFloor(&bugClass)
	if campaign != nil && floorRank(floor) > floorRank(table) {
		if _, ok := findings.CLASS_CONFIRM_FLOOR[bugClass]; !ok {
			table = findings.STATUS_FLOOR["CONFIRMED"]
		}
		return fmt.Sprintf("class %s carries a CONFIRMED floor of %s in THIS "+
			"campaign — its built-in floor is %s; a recorded floor policy "+
			"raised it. If the policy is not what you want: `webv2 floors "+
			"<campaign> unset %s`.", validation.PyReprStr(bugClass), floor,
			table, bugClass)
	}
	if _, ok := findings.CLASS_CONFIRM_FLOOR[bugClass]; !ok {
		return noFloorEntryWarning(bugClass, floor)
	}
	type row struct{ name, floor string }
	stricter := make([]row, 0, len(knownRaw()))
	for cls := range knownRaw() {
		f := DefaultFloor(&cls)
		if floorRank(f) > floorRank(loosest) {
			stricter = append(stricter, row{cls, f})
		}
	}
	sort.Slice(stricter, func(i, j int) bool {
		if a, b := floorRank(stricter[i].floor), floorRank(stricter[j].floor); a != b {
			return a < b
		}
		return stricter[i].name < stricter[j].name
	})
	examples := make([]string, 0, 2)
	for _, r := range stricter {
		if r.name == bugClass {
			continue
		}
		examples = append(examples, r.name+" ("+r.floor+")")
		if len(examples) == 2 {
			break
		}
	}
	msg := fmt.Sprintf("class %s pins a CONFIRMED floor of %s, stricter than "+
		"the loosest known-class floor %s — %d of the %d known classes pin a "+
		"stricter floor", validation.PyReprStr(bugClass), floor, loosest, len(stricter),
		len(knownRaw()))
	if len(examples) > 0 {
		msg += " (e.g. " + strings.Join(examples, ", ") + ")"
	}
	return msg + ". If the reachable evidence is local, re-file by true root " +
		"cause with `webv2 amend <campaign> <finding> --class <cls>` — the " +
		"floor recomputes on the next gate read."
}

// noFloorEntryWarning is class_advisory's wording for a KNOWN class the floor
// table does not carry (I-6): the class is in the taxonomy (the compat
// vocabulary), but findings.CLASS_CONFIRM_FLOOR has no entry for it, so its
// CONFIRMED floor is the STATUS_FLOOR default and NOTHING about the class pins
// it. Claiming "class 'donation' PINS a CONFIRMED floor of E5" was false, and
// the re-file advice was worse than false: "re-file by true root cause" tells
// the author to switch classes, but every cheaper floor belongs to a DIFFERENT
// class's content — there is no cheaper table class to file THIS bug under, so
// the choice is the author's and no command is suggested.
//
// The pool named here is the mirror image of the with-entry warning's: the
// known classes whose floor is LOOSER (strictly lower rank) than the inherited
// default, counted and exemplified in the same deterministic (floor, name)
// order. floor is the inherited default the caller already computed.
func noFloorEntryWarning(bugClass, floor string) string {
	type row struct{ name, floor string }
	looser := make([]row, 0, len(knownRaw()))
	for cls := range knownRaw() {
		f := DefaultFloor(&cls)
		if floorRank(f) < floorRank(floor) {
			looser = append(looser, row{cls, f})
		}
	}
	sort.Slice(looser, func(i, j int) bool {
		if a, b := floorRank(looser[i].floor), floorRank(looser[j].floor); a != b {
			return a < b
		}
		return looser[i].name < looser[j].name
	})
	examples := make([]string, 0, 2)
	for _, r := range looser {
		if r.name == bugClass {
			continue // defensive: an entry-less class is never in this pool
		}
		examples = append(examples, r.name+" ("+r.floor+")")
		if len(examples) == 2 {
			break
		}
	}
	msg := fmt.Sprintf("class %s has no floor-table entry — it inherits the "+
		"CONFIRMED default %s; %d known classes pin looser floors",
		validation.PyReprStr(bugClass), floor, len(looser))
	if len(examples) > 0 {
		msg += " (e.g. " + strings.Join(examples, ", ") + ")"
	}
	return msg + ". The class choice is the author's — no cheaper table class " +
		"exists for this class's content."
}

// loosestKnownFloor is the cheapest CONFIRMED floor any known class pins: the
// bar to compare a chosen class against. Unknown classes do not participate —
// they have no floor-table entry, and the ingest line already reports their
// conservative default.
func loosestKnownFloor() string {
	loosest := DefaultFloor(nil)
	rank := floorRank(loosest)
	for cls := range knownRaw() {
		f := DefaultFloor(&cls)
		if r := floorRank(f); r >= 0 && r < rank {
			loosest, rank = f, r
		}
	}
	return loosest
}

// effectiveFloorCampaign is the campaign-aware floor (nil campaign = the
// built-in table): findings.RequiredLevelForCampaign — the same call the
// acceptance line and the gate run, so an instance floor override can never
// leave the advisory recommending a re-file the override made pointless.
func effectiveFloorCampaign(campaign *state.Campaign, bugClass string) string {
	if campaign == nil {
		return DefaultFloor(&bugClass)
	}
	return findings.RequiredLevelForCampaign(campaign, "CONFIRMED", bugClass)
}

// loosestKnownFloorCampaign is loosestKnownFloor over the campaign's
// effective floors.
func loosestKnownFloorCampaign(campaign *state.Campaign) string {
	if campaign == nil {
		return loosestKnownFloor()
	}
	best := ""
	for cls := range knownRaw() {
		f := findings.RequiredLevelForCampaign(campaign, "CONFIRMED", cls)
		if best == "" || floorRank(f) < floorRank(best) {
			best = f
		}
	}
	if best == "" {
		return loosestKnownFloor()
	}
	return best
}

// floorRank is a floor's ladder position (E0=0 .. E7=7), or -1 for a name the
// ladder does not carry. DefaultFloor never produces the latter; the sentinel
// keeps an unknown floor from ordering as the loosest one.
func floorRank(floor string) int {
	i, err := findings.LevelIndex(floor)
	if err != nil {
		return -1
	}
	return i
}

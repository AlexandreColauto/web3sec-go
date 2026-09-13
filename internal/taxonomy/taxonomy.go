// Package taxonomy ports webv2.taxonomy: the bug-class taxonomy — the
// canonical class list the framework actually tracks.
//
// Before this module, the taxonomy was invisible outside the source: a model
// that invented a class on the spot (e.g. share-price-accounting) got no
// signal that share-price-inflation already existed with a different gate,
// and unknown classes silently defaulted to the most conservative floor (E5).
//
// Now ingest consults this module and the operator gets a one-line advisory:
//
//   - known class -> its default floor, so the gate consequence is visible;
//   - unknown class -> "unknown class; known: ...; floor: E5 (default)" plus
//     the closest canonical names, when they are close enough to matter.
//
// The taxonomy is the union of every place the framework keys behavior to a
// class: the CONFIRMED floor table (findings.CLASS_CONFIRM_FLOOR), the dedup
// economic compatibility groups and the asset-class hints. The dataset-
// ingestion sprint adds the LABEL-ALIAS MAP LAYER on top: public datasets
// label the same bug with different vocabularies ("Access Control", "price
// manipulation", ...), and the map layer turns a raw dataset label into a
// canonical class — or, deliberately, into the literal "unmapped". Honesty
// over coverage: anything not obviously mappable stays "unmapped" instead of
// being guessed into a wrong floor table.
package taxonomy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"

	"gopkg.in/yaml.v3"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// UNMAPPED is UNMAPPED: the explicit not-a-canonical-class verdict. Eval
// records may carry it (gold.bug_class) but it never keys a floor or a
// playbook.
const UNMAPPED = "unmapped"

// CommonMapName is COMMON_MAP_NAME: the shared map file, one per repo.
const CommonMapName = "taxonomy_map.yaml"

// datasetMapGlob is _DATASET_MAP_GLOB.
const datasetMapGlob = "taxonomy_*.yaml"

var (
	// RepoRoot is REPO_ROOT: the tree the config dir hangs off. Python
	// derives it from __file__ (the repo root above src/webv2); a Go binary
	// has no source-relative root, so it defaults to the working directory
	// and is settable (SetConfigDir) by the CLI/embedding host.
	RepoRoot = "."

	// ConfigDir is CONFIG_DIR: REPO_ROOT/config. Tests and embedders point it
	// at their own tree (the Python tests monkeypatch it the same way).
	ConfigDir = "config"
)

// SetConfigDir points the map loader at root's config directory (the twin of
// a test setting taxonomy.CONFIG_DIR). An empty root restores ".".
func SetConfigDir(root string) {
	if root == "" {
		root = "."
	}
	RepoRoot = root
	ConfigDir = filepath.Join(root, "config")
}

// compatClassesFunc is _compat_classes: the union of dedup's
// _ECONOMIC_COMPAT_GROUPS and _ASSET_CLASS_HINTS. dedup is not ported yet, so
// the default carries those two tables verbatim; when internal/dedup lands it
// calls SetCompatClasses(dedup.CompatClasses) and becomes the single source
// of truth again.
var compatClassesFunc = defaultCompatClasses

// SetCompatClasses installs the dedup compat-class source; nil restores the
// built-in default. The known-class cache is invalidated either way.
func SetCompatClasses(f func() []string) {
	knownMu.Lock()
	defer knownMu.Unlock()
	if f == nil {
		compatClassesFunc = defaultCompatClasses
	} else {
		compatClassesFunc = f
	}
	knownCache = nil
}

// defaultCompatClasses is _compat_classes() evaluated against the dedup
// tables as of the port (webv2/dedup.py): the union of the five economic
// compatibility groups and the five asset-class hint sets.
func defaultCompatClasses() []string {
	return []string{
		"oracle-manipulation", "flash-loan", "frontend-injection",
		"infra-boundary", "economic-invariant",
		"share-price-inflation", "precision-rounding", "token-integration",
		"logic-error", "access-control", "authorization", "upgrade-initializer",
		"centralization-risk", "signature-replay", "reentrancy",
		"unchecked-external-call", "dos-griefing", "bridge-message",
		"cross-chain-replay", "liquidation-logic", "donation",
	}
}

var (
	knownMu    sync.Mutex
	knownCache map[string]struct{}
)

// KnownClasses is known_classes: every class the framework tracks — the
// CONFIRMED floor table plus the dedup compatibility vocabulary. The
// returned set is a copy; mutating it never affects the taxonomy.
func KnownClasses() map[string]struct{} {
	return copySet(knownRaw())
}

// CanonicalClasses is CANONICAL_CLASSES: the canonical classes as one
// importable set. Derived from KnownClasses() — the single source of truth —
// never re-declared by hand.
func CanonicalClasses() map[string]struct{} {
	return copySet(knownRaw())
}

// knownRaw is the cached set behind KnownClasses/CanonicalClasses.
func knownRaw() map[string]struct{} {
	knownMu.Lock()
	if knownCache != nil {
		c := knownCache
		knownMu.Unlock()
		return c
	}
	f := compatClassesFunc
	knownMu.Unlock()
	built := make(map[string]struct{},
		len(findings.CLASS_CONFIRM_FLOOR)+len(f()))
	for k := range findings.CLASS_CONFIRM_FLOOR {
		built[k] = struct{}{}
	}
	for _, c := range f() {
		built[c] = struct{}{}
	}
	knownMu.Lock()
	if knownCache == nil {
		knownCache = built
	}
	c := knownCache
	knownMu.Unlock()
	return c
}

// DefaultFloor is default_floor: the built-in CONFIRMED floor for a class,
// or the conservative STATUS_FLOOR default when the class has no entry.
func DefaultFloor(bugClass *string) string {
	if bugClass != nil {
		if f, ok := findings.CLASS_CONFIRM_FLOOR[*bugClass]; ok {
			return f
		}
	}
	return findings.STATUS_FLOOR["CONFIRMED"]
}

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
		suggestions = strArr(closeMatches(*bugClass, sortedKeys(knownRaw()), 3, 0.6))
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
	rep := ClassReport(bugClass)
	if objAt(rep, "known").B {
		return classFloorWarning(*bugClass, campaign)
	}
	msg := fmt.Sprintf("unknown class %s; known classes: %s; "+
		"no floor-table entry -> CONFIRMED defaults to %s "+
		"(the most conservative floor).",
		pyReprPtr(bugClass), strings.Join(sortedKeys(knownRaw()), ", "),
		objStr(rep, "floor"))
	if sugg := objAt(rep, "suggestions"); len(sugg.A) > 0 {
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

// init wires the findings advisory seam. findings cannot import taxonomy
// (taxonomy imports findings), so the twin of Python's module-level
// `from .taxonomy import class_advisory` happens here.
func init() {
	findings.SetClassAdvisory(ClassAdvisory)
}

// ---- label-alias map layer ----------------------------------------------
//
// Map files are repo-level config, YAML, in the shape:
//
//	default: unmapped
//	aliases:
//	  <raw-source-label-lowercased>: <canonical-class | unmapped>
//
// One COMMON file plus one file per dataset. A missing per-dataset file is a
// normal miss, not an error; a PRESENT-but-bad file is a deployment error and
// fails loud, the same posture as playbooks.

// mapAlias is one aliases entry, in file order.
type mapAlias struct{ key, target string }

// mapData is the parsed shape of one map file: its default and its ordered
// aliases.
type mapData struct {
	def     string
	aliases []mapAlias
}

// MissingMapError is the twin of the FileNotFoundError validate_map_file
// raises for an absent file. errors.Is(err, fs.ErrNotExist) reports true.
type MissingMapError struct{ Path string }

func (e *MissingMapError) Error() string { return "taxonomy map missing: " + e.Path }

// Is makes errors.Is(err, fs.ErrNotExist) true, like Python's
// FileNotFoundError.
func (e *MissingMapError) Is(target error) bool { return target == fs.ErrNotExist }

// normLabel is _norm_label: case/whitespace/punctuation-insensitive
// normalization so 'Access Control', 'access-control' and 'ACCESS  control'
// are one lookup key.
func normLabel(label string) string {
	return pyStrip(normSpaceRe.ReplaceAllString(strings.ToLower(label), " "))
}

// normSpaceRe is Python's re.sub(r"[^a-z0-9]+", " ", ...): every run of
// characters outside the ASCII alphanumeric set collapses to one space.
var normSpaceRe = regexp.MustCompile(`[^a-z0-9]+`)

// checkMapValue is _check_map_value: every alias value (and the default) must
// be a canonical class or "unmapped".
func checkMapValue(path, where, value string) error {
	if value == UNMAPPED {
		return nil
	}
	if _, ok := knownRaw()[value]; ok {
		return nil
	}
	return fmt.Errorf("taxonomy map %s: %s -> %s is neither a canonical "+
		"class nor %s (%d canonical classes: %s)", path, where,
		validation.PyReprStr(value), validation.PyReprStr(UNMAPPED),
		len(knownRaw()), strings.Join(sortedKeys(knownRaw()), ", "))
}

// readMapFile is _read_map_file: parse + value-check one map file. A missing
// file is nil (a normal miss); a present-but-invalid file is an error (fail
// loud, like a broken playbook).
func readMapFile(path string) (*mapData, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("taxonomy map %s is not valid YAML: %s", path, err)
	}
	root := &doc
	if len(doc.Content) > 0 {
		root = doc.Content[0]
	}
	if isNullNode(root) {
		return &mapData{def: UNMAPPED}, nil
	}
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("taxonomy map %s must be a YAML mapping", path)
	}
	out, err := parseMapMapping(path, root)
	if err != nil {
		return nil, err
	}
	if err := checkMapValue(path, "default", out.def); err != nil {
		return nil, err
	}
	for _, a := range out.aliases {
		where := fmt.Sprintf("aliases[%s]", validation.PyReprStr(a.key))
		if err := checkMapValue(path, where, a.target); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// parseMapMapping reads the default/aliases fields of a map mapping node and
// applies Python's type checks (both must be str, aliases a str -> str map).
func parseMapMapping(path string, root *yaml.Node) (*mapData, error) {
	typeErr := fmt.Errorf("taxonomy map %s: expected 'default' (str) and "+
		"'aliases' (mapping of str -> str)", path)
	out := &mapData{def: UNMAPPED}
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, val := root.Content[i], root.Content[i+1]
		if key.Kind != yaml.ScalarNode {
			continue
		}
		switch key.Value {
		case "default":
			s, ok := strScalar(val)
			if !ok {
				return nil, typeErr
			}
			out.def = s
		case "aliases":
			if isFalsyNode(val) {
				continue
			}
			if val.Kind != yaml.MappingNode {
				return nil, typeErr
			}
			for j := 0; j+1 < len(val.Content); j += 2 {
				k, ok1 := strScalar(val.Content[j])
				v, ok2 := strScalar(val.Content[j+1])
				if !ok1 || !ok2 {
					return nil, typeErr
				}
				out.aliases = putAlias(out.aliases, k, v)
			}
		}
	}
	return out, nil
}

// putAlias is dict assignment: an existing raw key keeps its position and
// takes the new value, a new key appends.
func putAlias(aliases []mapAlias, key, target string) []mapAlias {
	for i := range aliases {
		if aliases[i].key == key {
			aliases[i].target = target
			return aliases
		}
	}
	return append(aliases, mapAlias{key: key, target: target})
}

// LoadMaps is load_maps: merge the common map with the per-dataset map files
// into one lookup — an ordered object {"default": str, "aliases": {label:
// target}}. Dataset-specific aliases WIN over common ones. A nil datasets
// slice is Python's None (load every per-dataset file present, sorted by name
// for determinism); an empty non-nil slice loads only the common map. A
// missing file is a normal miss, never an error.
func LoadMaps(datasets []string) (validation.Value, error) {
	common, err := readMapFile(filepath.Join(ConfigDir, CommonMapName))
	if err != nil {
		return validation.VNull(), err
	}
	var merged *mapData
	if common != nil {
		merged = common
	}
	var names []string
	if datasets == nil {
		matches, err := filepath.Glob(filepath.Join(ConfigDir, datasetMapGlob))
		if err != nil {
			return validation.VNull(), err
		}
		for _, m := range matches {
			base := filepath.Base(m)
			if base == CommonMapName {
				continue
			}
			stem := strings.TrimSuffix(base, filepath.Ext(base))
			names = append(names, strings.TrimPrefix(stem, "taxonomy_"))
		}
		sort.Strings(names)
	} else {
		names = append(names, datasets...)
	}
	for _, name := range names {
		data, err := readMapFile(filepath.Join(ConfigDir, "taxonomy_"+name+".yaml"))
		if err != nil {
			return validation.VNull(), err
		}
		if data == nil {
			continue
		}
		if merged == nil {
			// Python would raise KeyError('aliases') here (a dataset map
			// with no common map to merge into); the twin starts an empty
			// projection instead of crashing.
			merged = &mapData{def: UNMAPPED}
		}
		for _, a := range data.aliases {
			merged.aliases = putAlias(merged.aliases, a.key, a.target)
		}
		merged.def = data.def
	}
	if merged == nil {
		return validation.VObj(), nil
	}
	return mapValue(merged), nil
}

// mapValue renders a parsed map as the ordered object load_maps returns:
// {"default": str, "aliases": {label: target}} in file order.
func mapValue(m *mapData) validation.Value {
	pairs := make([]validation.KV, 0, len(m.aliases))
	for _, a := range m.aliases {
		pairs = append(pairs, kv(a.key, validation.VStr(a.target)))
	}
	return validation.VObj(
		kv("default", validation.VStr(m.def)),
		kv("aliases", validation.VObj(pairs...)),
	)
}

// NormalizeClass is normalize_class: map a raw dataset label to
// (canonical | "unmapped", mapped).
//
// Lookup is case/whitespace/punctuation-insensitive. An alias explicitly
// mapped to "unmapped" is a RECORDED DECISION (that dataset label is
// deliberately not one of ours), not a miss — but it is still not a canonical
// class, so mapped is false. A label that names a canonical class outright
// maps to itself even when no alias mentions it. Anything else falls back to
// the maps' default ("unmapped") with mapped=false — honesty over coverage.
//
// A nil label is Python's None; nil maps loads the configured map files.
func NormalizeClass(label *string, maps *validation.Value) (string, bool, error) {
	var m validation.Value
	if maps == nil {
		loaded, err := LoadMaps(nil)
		if err != nil {
			return "", false, err
		}
		m = loaded
	} else {
		m = *maps
	}
	def := objStr(m, "default")
	if def == "" {
		def = UNMAPPED
	}
	if label == nil || pyStrip(*label) == "" {
		return def, false, nil
	}
	norm := normLabel(*label)
	for _, a := range objAt(m, "aliases").O {
		if normLabel(a.K) == norm {
			return a.V.S, a.V.S != UNMAPPED, nil
		}
	}
	for _, cls := range sortedKeys(knownRaw()) {
		if normLabel(cls) == norm {
			return cls, true, nil
		}
	}
	return def, false, nil
}

// ValidateMapFile is validate_map_file: alias values (and default) must each
// be a canonical class or "unmapped". A bad map is a deployment error — fail
// loud, never silently degrade the adapters' class labels. A missing file
// yields *MissingMapError: you asked about a specific file, and LoadMaps
// treats absence as a miss.
func ValidateMapFile(path string) error {
	p := filepath.Clean(path)
	if _, err := os.Stat(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &MissingMapError{Path: p}
		}
		return err
	}
	_, err := readMapFile(p)
	return err
}

// ---- difflib (SequenceMatcher / get_close_matches) ----------------------
//
// class_report's suggestions come from difflib.get_close_matches, so the
// suggestion list is part of the byte-exact contract. This is a faithful port
// of CPython 3.14's difflib for the no-junk case get_close_matches uses
// (SequenceMatcher() with isjunk=None, autojunk=True).

// seqRatio is SequenceMatcher(None, a, b).ratio(): 2*M/T over the rune
// positions the longest-matching-block recursion covers.
func seqRatio(a, b string) float64 {
	ra, rb := []rune(a), []rune(b)
	return calcRatio(matchedRunes(ra, rb), len(ra)+len(rb))
}

// quickRatio is quick_ratio: the multiset-intersection upper bound.
func quickRatio(a, b string) float64 {
	ra, rb := []rune(a), []rune(b)
	full := make(map[rune]int, len(rb))
	for _, r := range rb {
		full[r]++
	}
	avail := make(map[rune]int, len(ra))
	matches := 0
	for _, r := range ra {
		numb, ok := avail[r]
		if !ok {
			numb = full[r]
		}
		avail[r] = numb - 1
		if numb > 0 {
			matches++
		}
	}
	return calcRatio(matches, len(ra)+len(rb))
}

// realQuickRatio is real_quick_ratio: can't have more matches than the
// shorter sequence has elements.
func realQuickRatio(a, b string) float64 {
	la, lb := len([]rune(a)), len([]rune(b))
	return calcRatio(min(la, lb), la+lb)
}

// calcRatio is difflib._calculate_ratio.
func calcRatio(matches, length int) float64 {
	if length > 0 {
		return 2.0 * float64(matches) / float64(length)
	}
	return 1.0
}

// matchedRunes is get_matching_blocks' total match size: the recursive
// longest-match partition, which is all ratio() sums.
func matchedRunes(a, b []rune) int {
	b2j := buildB2J(b)
	total := 0
	queue := [][4]int{{0, len(a), 0, len(b)}}
	for len(queue) > 0 {
		q := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		i, j, k := findLongestMatch(a, b, b2j, q[0], q[1], q[2], q[3])
		if k == 0 {
			continue
		}
		total += k
		if q[0] < i && q[2] < j {
			queue = append(queue, [4]int{q[0], i, q[2], j})
		}
		if i+k < q[1] && j+k < q[3] {
			queue = append(queue, [4]int{i + k, q[1], j + k, q[3]})
		}
	}
	return total
}

// buildB2J is SequenceMatcher's b2j index with autojunk: elements that appear
// more than n//100+1 times in a sequence of 200+ runes are "popular" and drop
// out of the index.
func buildB2J(b []rune) map[rune][]int {
	idx := make(map[rune][]int)
	for i, r := range b {
		idx[r] = append(idx[r], i)
	}
	if len(b) < 200 {
		return idx
	}
	ntest := len(b)/100 + 1
	for r, positions := range idx {
		if len(positions) > ntest {
			delete(idx, r)
		}
	}
	return idx
}

// findLongestMatch is SequenceMatcher.find_longest_match for the no-junk
// case: of all maximal matching blocks, the one that starts earliest in a,
// and of those the one that starts earliest in b.
func findLongestMatch(a, b []rune, b2j map[rune][]int,
	alo, ahi, blo, bhi int) (int, int, int) {
	besti, bestj, bestsize := alo, blo, 0
	j2len := map[int]int{}
	for i := alo; i < ahi; i++ {
		newj2len := make(map[int]int, len(j2len)+1)
		for _, j := range b2j[a[i]] {
			if j < blo {
				continue
			}
			if j >= bhi {
				break
			}
			k := j2len[j-1] + 1
			newj2len[j] = k
			if k > bestsize {
				besti, bestj, bestsize = i-k+1, j-k+1, k
			}
		}
		j2len = newj2len
	}
	for besti > alo && bestj > blo && a[besti-1] == b[bestj-1] {
		besti, bestj, bestsize = besti-1, bestj-1, bestsize+1
	}
	for besti+bestsize < ahi && bestj+bestsize < bhi &&
		a[besti+bestsize] == b[bestj+bestsize] {
		bestsize++
	}
	return besti, bestj, bestsize
}

// closeMatches is difflib.get_close_matches(word, possibilities, n, cutoff):
// the best (no more than n) matches at or above cutoff, most similar first,
// ties broken by possibilities order (heapq.nlargest is a stable sort).
func closeMatches(word string, possibilities []string, n int, cutoff float64) []string {
	type cand struct {
		score float64
		index int
	}
	var cands []cand
	for i, x := range possibilities {
		if realQuickRatio(x, word) < cutoff {
			continue
		}
		if quickRatio(x, word) < cutoff {
			continue
		}
		if r := seqRatio(x, word); r >= cutoff {
			cands = append(cands, cand{score: r, index: i})
		}
	}
	sort.SliceStable(cands, func(i, j int) bool {
		return cands[i].score > cands[j].score
	})
	if len(cands) > n {
		cands = cands[:n]
	}
	out := make([]string, len(cands))
	for i, c := range cands {
		out[i] = possibilities[c.index]
	}
	return out
}

// ---- local helpers -------------------------------------------------------

// isNullNode reports whether a YAML node is the null document/valued node.
func isNullNode(n *yaml.Node) bool {
	if n == nil || n.Kind == 0 {
		return true
	}
	return n.Kind == yaml.ScalarNode && (n.Tag == "!!null" || n.Tag == "")
}

// strScalar is Python's isinstance(value, str) on a YAML node.
func strScalar(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return "", false
	}
	return n.Value, true
}

// isFalsyNode is Python truthiness on a YAML node, for `data.get("aliases")
// or {}`: null, false, zero, the empty string and empty collections all fall
// back to an empty mapping.
func isFalsyNode(n *yaml.Node) bool {
	if isNullNode(n) {
		return true
	}
	switch n.Kind {
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!bool":
			return n.Value == "false"
		case "!!int":
			return n.Value == "0" || n.Value == "0x0" || n.Value == "0o0"
		case "!!float":
			return n.Value == "0" || n.Value == "0.0"
		case "!!str":
			return n.Value == ""
		}
		return false
	case yaml.SequenceNode, yaml.MappingNode:
		return len(n.Content) == 0
	}
	return false
}

// objAt is the dict lookup: the value for key, or Null when absent.
func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

// objStr is the string flavor of objAt ("" when absent or not a string).
func objStr(v validation.Value, key string) string {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V.S
		}
	}
	return ""
}

// kv is the keyed KV constructor (non-test code cannot use a test helper).
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// strArr renders a []string as a JSON array Value.
func strArr(items []string) validation.Value {
	out := make([]validation.Value, len(items))
	for i, s := range items {
		out[i] = validation.VStr(s)
	}
	return validation.VArr(out...)
}

// sortedKeys returns a set's keys in Python's sorted() order.
func sortedKeys(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// copySet is a fresh copy, so a caller can never mutate the taxonomy.
func copySet(s map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(s))
	for k := range s {
		out[k] = struct{}{}
	}
	return out
}

// pyReprPtr is Python's repr() of a str | None.
func pyReprPtr(s *string) string {
	if s == nil {
		return "None"
	}
	return validation.PyReprStr(*s)
}

// pyStrip is Python's str.strip() (Go's unicode.IsSpace misses U+001C-U+001F).
func pyStrip(s string) string {
	return strings.TrimFunc(s, pyIsSpace)
}

func pyIsSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

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
	"path/filepath"
	"strings"
	"sync"

	"websec/internal/findings"
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

// classSynonyms maps labels auditors file in practice (the standards
// vocabulary and informal kebab-case) to the canonical class. Applied by
// CanonicalClass on BOTH sides of the eval join and by the ingest advisory.
// Identity for any label not listed — an unlisted label keeps anchoring
// nothing. ponytail: three entries where the campaign measured misses; add
// entries as measured misses arrive, not speculatively.
var classSynonyms = map[string]string{
	"denial-of-service": "dos-griefing",
}

// CanonicalClass is the synonym layer over the taxonomy: a listed label
// becomes its canonical class (keyed case-insensitively, the canonical form
// is returned lowercase); everything else is returned unchanged and stays
// non-canonical. It never returns "unmapped" — only explicit entries move a
// label, so the eval join's fail-closed behavior is untouched.
func CanonicalClass(class string) string {
	if c, ok := classSynonyms[strings.ToLower(strings.TrimSpace(class))]; ok {
		return c
	}
	return class
}

// init wires the findings advisory seam. findings cannot import taxonomy
// (taxonomy imports findings), so the twin of Python's module-level
// `from .taxonomy import class_advisory` happens here.
func init() {
	findings.SetClassAdvisory(ClassAdvisory)
}

// kv is the keyed KV constructor (non-test code cannot use a test helper).
func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// sortedKeys returns a set's keys in Python's sorted() order.

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

// Package defihacklabs ports webv2.datasets.defihacklabs: the DeFiHackLabs +
// Incident Explorer adapter, incidents into the common ingest shape.
//
// WHY (verbatim intent): the ground-truth unit here is a real, executed
// on-chain exploit, not an audit opinion — so every record is
// confirmed-exploitable AND a capability prior (prior=True with the RCA atomic
// labels as pattern). The source dialect is messy three ways: (1) metadata
// lives in the explorer clone (incidents.json: 930 uniform rows;
// rootcause_data.json: 767 prose RCA records keyed by protocol name, joined by
// normalized name with first-in-file-order wins on the 29 collision groups);
// (2) PoCs are flat Foundry files (src/test/<YYYY-MM>/<Name>_exp.sol)
// cross-referenced by the Contract field, a commit-pinned pocLink, or a
// normalized-stem fallback — 794/930 resolve, 136 have prose but no PoC;
// (3) dates decide the leakage partition (ascending sort, most recent
// ceil(30%) held-out) and Lost is a loss magnitude, never a severity (so
// severity is None). This module owns all of that dialect so webv2.ingest only
// sees clean common-shape records; campaign seeds (records with a resolvable
// PoC) are the Phase A launch list.
package defihacklabs

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"websec/internal/ingest"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

const (
	// Dataset is DATASET.
	Dataset = "defihacklabs"
	// ProgramKey is the campaign-known program key for the published
	// prior-knowledge rows.
	ProgramKey = "defihacklabs-prior-knowledge|other|-"
	// RepoURL is REPO_URL.
	RepoURL = "https://github.com/SunWeb3Sec/DeFiHackLabs"
	// CloneHead / ExplorerHead are the shallow-clone HEADs at recon time: the
	// only commit the on-disk PoC files are known to correspond to.
	CloneHead    = "6b882d98fca8cffee723a817796b5e57d2df2d18"
	ExplorerHead = "e46aa8fa326a6e1e0116ad4367ece2b4ccae2281"
	// HeldOutRatio is the leakage partition ratio: date-ascending sort, most
	// recent ceil(30%) held-out.
	HeldOutRatio   = 0.3
	DescriptionMax = 10000
	RootCauseMin   = 10
	RootCauseMax   = 2000
)

// RepoRoot is taxonomy.REPO_ROOT (the tree above src/webv2). A Go binary has
// no source-relative root, so the dataset paths are cwd-relative exactly like
// corpus.PocRoot; WEBV2_POC_ROOT (SetRoots) repoints them for the harness.
var RepoRoot = ""

func rootPath(parts ...string) string {
	return filepath.Join(append([]string{RepoRoot}, parts...)...)
}

// The three dataset roots, Python's EXPLORER_DIR / INCIDENTS_FILE /
// ROOTCAUSE_FILE / POC_ROOT.
var (
	ExplorerDir   = rootPath("data", "datasets", "DeFiHackLabs-Incident-Explorer")
	IncidentsFile = filepath.Join(ExplorerDir, "incidents.json")
	RootCauseFile = filepath.Join(ExplorerDir, "rootcause_data.json")
	PocRoot       = rootPath("data", "datasets", "DeFiHackLabs")
)

// SetRoots is the golden harness's WEBV2_POC_ROOT patch: the reference
// sitecustomize repoints EXPLORER_DIR/INCIDENTS_FILE/ROOTCAUSE_FILE at
// <base>/explorer and POC_ROOT at <base>/DeFiHackLabs, so the Go twin must
// resolve the same three roots from the same one variable.
func SetRoots(base string) {
	ExplorerDir = filepath.Join(base, "explorer")
	IncidentsFile = filepath.Join(ExplorerDir, "incidents.json")
	RootCauseFile = filepath.Join(ExplorerDir, "rootcause_data.json")
	PocRoot = filepath.Join(base, "DeFiHackLabs")
}

// CloneAbsentError is Python's FileNotFoundError from load_records: the
// explorer clone (or one of its two files) is absent. The corpus seam treats
// it as the documented absent-data signal.
type CloneAbsentError struct{ Path string }

func (e *CloneAbsentError) Error() string {
	return "defihacklabs explorer clone absent: " + e.Path
}

// ErrCloneAbsent matches every CloneAbsentError (errors.Is).
var ErrCloneAbsent = errors.New("defihacklabs explorer clone absent")

// Is reports the sentinel so errors.Is(err, ErrCloneAbsent) holds.
func (e *CloneAbsentError) Is(target error) bool { return target == ErrCloneAbsent }

var (
	// _FULL_SHA.
	fullSHARe = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// _POCLINK_REF (Python \Z -> Go \z, strict end of text).
	pocLinkRefRe = regexp.MustCompile(`/(?:blob|tree)/([^/]+)/(.+?)(?:#.*)?\z`)
	// normalize_name's strip class.
	nonAlnumRe = regexp.MustCompile(`[^a-z0-9]+`)
	// normalize_chain's raw-id test.
	allDigitsRe = regexp.MustCompile(`^[0-9]+$`)
)

// chainAliases is _CHAIN_ALIASES.
var chainAliases = map[string]string{
	"ethereum":            "Ethereum",
	"mainnet":             "Ethereum",
	"eth":                 "Ethereum",
	"bsc":                 "BNB Chain",
	"bnb chain":           "BNB Chain",
	"binance smart chain": "BNB Chain",
	"arbitrum":            "Arbitrum",
	"base":                "Base",
	"polygon":             "Polygon",
	"avalanche":           "Avalanche",
	"optimism":            "Optimism",
	"solana":              "Solana",
	"fantom":              "Fantom",
	"linea":               "Linea",
	"blast":               "Blast",
	"gnosis":              "Gnosis",
	"cronos":              "Cronos",
	"mantle":              "Mantle",
	"moonriver":           "Moonriver",
	"maya":                "Maya",
	"mayachain":           "Maya",
	"sei":                 "Sei",
	"taiko":               "Taiko",
	"hedera":              "Hedera",
	"aztec":               "Aztec",
}

// noChain is _NO_CHAIN: the non-chain markers carrying no chain signal.
var noChain = map[string]bool{
	"": true, "unknown": true, "none": true,
	"multi-chain": true, "multichain": true,
}

// pyStr is Python's str(v): raw text for strings, repr otherwise.

// pyStrOrEmpty is Python's str(v or "") for the JSON value types.
func pyStrOrEmpty(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return ""
	case validation.Bool:
		if !v.B {
			return ""
		}
		return "True"
	case validation.Int:
		if v.I == 0 && v.Big == "" {
			return ""
		}
		return validation.IntText(v)
	case validation.Flt:
		if v.F == 0 {
			return ""
		}
		return validation.PythonFloat(v.F)
	case validation.Str:
		return v.S
	case validation.Arr:
		if len(v.A) == 0 {
			return ""
		}
		return validation.PyRepr(v)
	case validation.Obj:
		if len(v.O) == 0 {
			return ""
		}
		return validation.PyRepr(v)
	}
	return ""
}

// at is v.get(key) for an object (None otherwise).
func at(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, p := range v.O {
		if p.K == key {
			return p.V
		}
	}
	return validation.VNull()
}

// setKey replaces (or appends) key in an object, returning the new value.
func setKey(v validation.Value, key string, val validation.Value) validation.Value {
	out := make([]validation.KV, 0, len(v.O)+1)
	replaced := false
	for _, p := range v.O {
		if p.K == key {
			out = append(out, validation.KV{K: key, V: val})
			replaced = true
			continue
		}
		out = append(out, p)
	}
	if !replaced {
		out = append(out, validation.KV{K: key, V: val})
	}
	v.O = out
	return v
}

// runeLen is Python's len(str).
func runeLen(s string) int { return utf8.RuneCountInString(s) }

// runeSlice is Python's s[i:j] on a str.
func runeSlice(s string, from, to int) string {
	r := []rune(s)
	if from < 0 {
		from = 0
	}
	if to > len(r) {
		to = len(r)
	}
	if from > to {
		return ""
	}
	return string(r[from:to])
}

// lastIndexRunes is str.rfind(sep) in CHARACTER index space (-1 when absent).
func lastIndexRunes(s, sep string) int {
	rs, rsep := []rune(s), []rune(sep)
	if len(rsep) == 0 {
		return len(rs)
	}
	for i := len(rs) - len(rsep); i >= 0; i-- {
		match := true
		for j := range rsep {
			if rs[i+j] != rsep[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// pyStrip is Python's str.strip().
func pyStrip(s string) string { return strings.TrimSpace(s) }

// isFile is Path.is_file().
func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// isDir is Path.is_dir().
func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// NormalizeName is normalize_name: lowercase + strip non-alphanumerics (recon
// §10.4 name chaos). "Hundred Finance" and "HundredFinance" (and "Paribus" /
// "Paribus_") are one key — which is exactly why RCA collision groups exist
// and why incident id slugs need the chain/type fallback.
func NormalizeName(name validation.Value) string {
	return nonAlnumRe.ReplaceAllString(strings.ToLower(pyStrOrEmpty(name)), "")
}

// NormalizeChain is normalize_chain: the noisy single-chain string to a
// display name. nil for raw chain ids, nulls, and the non-chain markers —
// the caller then emits platform=None + chains=[] (brief pin). Unknown-but-
// plausible names pass through stripped (never invent a mapping for a chain we
// have not seen).
func NormalizeChain(chain validation.Value) *string {
	if chain.Kind != validation.Str {
		return nil
	}
	text := pyStrip(chain.S)
	key := strings.ToLower(text)
	if noChain[key] || allDigitsRe.MatchString(key) {
		return nil
	}
	if v, ok := chainAliases[key]; ok {
		return &v
	}
	return &text
}

// ExtractPocLink is extract_poclink: split an RCA pocLink blob URL into
// (url, path, commit). The #L… line fragment is stripped (3 records carry
// one); commit is set only for a 40-hex pinned ref (24 records) — blob/main
// links carry no commit. Returns (nil, nil, nil) for empty input.
func ExtractPocLink(url validation.Value) (u, path, commit *string) {
	raw := pyStrip(pyStrOrEmpty(url))
	if raw == "" {
		return nil, nil, nil
	}
	urlClean := raw
	if i := strings.Index(urlClean, "#"); i >= 0 {
		urlClean = urlClean[:i]
	}
	m := pocLinkRefRe.FindStringSubmatch(urlClean)
	if m == nil {
		return &urlClean, nil, nil
	}
	ref, p := m[1], m[2]
	if fullSHARe.MatchString(ref) {
		return &urlClean, &p, &ref
	}
	return &urlClean, &p, nil
}

// ClipText is clip_text: truncate to limit chars at a paragraph/sentence
// boundary. Deterministic rule: hard-cut at limit, then back off to the last
// blank line, newline, sentence end, clause break, or word break — whichever
// is latest but keeps at least 10 chars (so the root-cause minimum survives
// clipping). A single over-long token with no break is hard-cut.
func ClipText(text string, limit int) string {
	text = pyStrip(text)
	if runeLen(text) <= limit {
		return text
	}
	cut := runeSlice(text, 0, limit)
	for _, sep := range []string{"\n\n", "\n", ". ", "; ", " "} {
		idx := lastIndexRunes(cut, sep)
		if idx < 10 {
			continue
		}
		end := idx
		if sep == ". " {
			end = idx + 1
		}
		clipped := pyStrip(runeSlice(cut, 0, end))
		if runeLen(clipped) >= 10 {
			return clipped
		}
	}
	return pyStrip(cut)
}

// PocIndex is build_poc_index's return: the exact repo-relative posix paths,
// a lowercased-path lookup (the clone lives on a case-sensitive filesystem but
// the explorer metadata has case drift, recon §10.3), and a normalized-stem
// index over *_exp.sol files only (helper files like interface.sol must never
// match an incident name).
type PocIndex struct {
	Files map[string]bool
	Lower map[string]string
	Stems map[string][]string
}

// BuildPocIndex is build_poc_index.
func BuildPocIndex(pocRoot string) PocIndex {
	root := pocRoot
	testDir := filepath.Join(root, "src", "test")
	idx := PocIndex{Files: map[string]bool{}, Lower: map[string]string{},
		Stems: map[string][]string{}}
	var rels []string
	if isDir(testDir) {
		_ = filepath.WalkDir(testDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".sol") {
				return nil
			}
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				return nil
			}
			rels = append(rels, filepath.ToSlash(rel))
			return nil
		})
	}
	sort.Slice(rels, func(i, j int) bool { return lessPathParts(rels[i], rels[j]) })
	for _, p := range rels {
		idx.Files[p] = true
	}
	for _, p := range rels {
		idx.Lower[strings.ToLower(p)] = p
	}
	for _, p := range rels {
		base := p
		if i := strings.LastIndex(p, "/"); i >= 0 {
			base = p[i+1:]
		}
		if !strings.HasSuffix(base, ".sol") {
			continue
		}
		stem := base[:len(base)-len(".sol")]
		if !strings.HasSuffix(strings.ToLower(stem), "_exp") {
			continue
		}
		stem = stem[:len(stem)-len("_exp")]
		key := NormalizeName(validation.VStr(stem))
		idx.Stems[key] = append(idx.Stems[key], p)
	}
	return idx
}

// lessPathParts is Python's Path ordering: compare the tuple of path parts
// (never the joined string — "2024-03/x" sorts before "2024-03-01/y" as
// parts, the opposite of the string order).
func lessPathParts(a, b string) bool {
	as, bs := strings.Split(a, "/"), strings.Split(b, "/")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] != bs[i] {
			return as[i] < bs[i]
		}
	}
	return len(as) < len(bs)
}

// contractVariants is _contract_variants: candidate repo-relative paths for a
// Contract field value, covering the observed drift (recon §10.3): a leading
// /, a missing _exp suffix (EverValueCoin), a wrong .sol name
// (Gangsterfinance.sol vs Gangsterfinance_exp.sol). Order is most-literal
// first so an exact hit always wins over a repaired one.
func contractVariants(contract string) []string {
	raw := strings.TrimLeft(pyStrip(contract), "/")
	if raw == "" {
		return nil
	}
	out := []string{raw}
	if !strings.HasSuffix(raw, ".sol") {
		raw += ".sol"
		out = append(out, raw)
	}
	stem := raw[:len(raw)-len(".sol")]
	if !strings.HasSuffix(strings.ToLower(stem), "_exp") {
		out = append(out, stem+"_exp.sol")
	}
	return out
}

// ResolvePoc is resolve_poc: resolve one incident to its PoC repo-relative
// path (or nil). Priority (recon §2): the Contract field (with drift-tolerant
// variants, exact then case-insensitive), the RCA pocLink path, then the
// normalized-name stem fallback. The first hit wins; ties in the stem index
// resolve to the sorted-first path.
func ResolvePoc(incident validation.Value, rca *validation.Value, idx PocIndex) *string {
	for _, candidate := range contractVariants(pyStrOrEmpty(at(incident, "Contract"))) {
		if idx.Files[candidate] {
			c := candidate
			return &c
		}
		if hit, ok := idx.Lower[strings.ToLower(candidate)]; ok {
			h := hit
			return &h
		}
	}
	if rca != nil {
		_, linkPath, _ := ExtractPocLink(at(*rca, "pocLink"))
		if linkPath != nil && *linkPath != "" {
			if idx.Files[*linkPath] {
				return linkPath
			}
			if hit, ok := idx.Lower[strings.ToLower(*linkPath)]; ok {
				h := hit
				return &h
			}
		}
	}
	matches := idx.Stems[NormalizeName(at(incident, "name"))]
	if len(matches) > 0 {
		sorted := append([]string{}, matches...)
		sort.Strings(sorted)
		m := sorted[0]
		return &m
	}
	return nil
}

// FindRCA is find_rca: join an incident name to its RCA record by normalized
// name. The 29 normalized-key collision groups (Paribus/Paribus_, ...) resolve
// deterministically to the FIRST key in file order (documented choice — either
// record describes the same protocol's exploit family). nil when nothing
// matches (154 incidents).
func FindRCA(name validation.Value, rcaData validation.Value) *validation.Value {
	target := NormalizeName(name)
	if target == "" {
		return nil
	}
	if rcaData.Kind != validation.Obj {
		return nil
	}
	for _, p := range rcaData.O {
		if p.V.Kind != validation.Obj {
			continue
		}
		if NormalizeName(validation.VStr(p.K)) == target {
			v := p.V
			return &v
		}
	}
	return nil
}

// lossText is _loss_text: Lost is a magnitude, never a severity.
func lossText(incident validation.Value) string {
	lost := at(incident, "Lost")
	lossType := pyStrOrEmpty(at(incident, "lossType"))
	if lossType == "" {
		lossType = "unknown units"
	}
	if lost.Kind == validation.Bool || lost.Kind == validation.Null {
		return "unknown loss (" + lossType + ")"
	}
	return validation.PyStr(lost) + " " + lossType
}

// rcaProse is `str(rca.get("rootCause") or "").strip()`.
func rcaProse(rca *validation.Value) string {
	if rca == nil {
		return ""
	}
	return pyStrip(pyStrOrEmpty(at(*rca, "rootCause")))
}

// ComposeDescription is compose_description: the 20-10000 char description —
// RCA prose, else fallback composed from name+type+chain+date+loss.
func ComposeDescription(incident validation.Value, rca *validation.Value) string {
	prose := rcaProse(rca)
	if runeLen(prose) >= 20 {
		return ClipText(prose, DescriptionMax)
	}
	name := pyStrOrEmpty(at(incident, "name"))
	if name == "" {
		name = "Unknown protocol"
	}
	inctype := pyStrOrEmpty(at(incident, "type"))
	if inctype == "" {
		inctype = "an unspecified vulnerability"
	}
	chain := "an unknown chain"
	if c := NormalizeChain(at(incident, "chain")); c != nil {
		chain = *c
	}
	date := pyStrOrEmpty(at(incident, "date"))
	if date == "" {
		date = "an unknown date"
	}
	text := fmt.Sprintf("%s (%s, %s) was exploited via %s. "+
		"Reported loss: %s.", name, date, chain, inctype, lossText(incident))
	for runeLen(text) < 20 {
		text += " The incident was confirmed as an on-chain exploit."
	}
	return ClipText(text, DescriptionMax)
}

// ComposeRootCause is compose_root_cause: the 10-2000 char root cause (brief
// pin, recon §9). RCA prose, sentence/paragraph-clipped to 2000 (126 records
// exceed it); else the RCA type label when it fits; else a composed
// name+type sentence (a bare "unavailable" would violate the schema minimum).
func ComposeRootCause(incident validation.Value, rca *validation.Value) string {
	prose := rcaProse(rca)
	if runeLen(prose) >= RootCauseMin {
		return ClipText(prose, RootCauseMax)
	}
	if rca != nil {
		label := pyStrip(pyStrOrEmpty(at(*rca, "type")))
		if n := runeLen(label); n >= RootCauseMin && n <= RootCauseMax {
			return label
		}
	}
	name := pyStrOrEmpty(at(incident, "name"))
	if name == "" {
		name = "Unknown protocol"
	}
	inctype := pyStrOrEmpty(at(incident, "type"))
	if inctype == "" {
		inctype = "an unspecified vulnerability"
	}
	date := pyStrOrEmpty(at(incident, "date"))
	if date == "" {
		date = "an unknown date"
	}
	text := fmt.Sprintf("%s (%s) was exploited via %s.", name, date, inctype)
	for runeLen(text) < RootCauseMin {
		text += " Loss of funds was confirmed on-chain."
	}
	return ClipText(text, RootCauseMax)
}

// ComposePattern is compose_pattern: the prior pattern as stable-joined atomic
// type labels. RCA type is comma-joined multi-label — split into atoms;
// without RCA the incident type is the single atom. Sorted unique join on
// "; " (stable regardless of source order). Short joins are extended with the
// incident identity so the memory schema's 15-char minimum always holds; long
// joins clip at an atom boundary to 500.
func ComposePattern(incident validation.Value, rca *validation.Value) string {
	pattern := strings.Join(dedupeSorted(patternAtoms(incident, rca)), "; ")
	if runeLen(pattern) < 15 {
		pattern = widenPattern(pattern, incident)
	}
	if runeLen(pattern) > 500 {
		pattern = clampPattern(pattern)
	}
	for runeLen(pattern) < 15 {
		pattern += " exploit pattern"
	}
	return pattern
}

// patternAtoms is compose_pattern's label source: the RCA type list, else the
// incident type, else "unknown".
func patternAtoms(incident validation.Value, rca *validation.Value) []string {
	var atoms []string
	if rca != nil {
		for _, a := range strings.Split(pyStrOrEmpty(at(*rca, "type")), ",") {
			if a = pyStrip(a); a != "" {
				atoms = append(atoms, a)
			}
		}
	}
	if len(atoms) == 0 {
		t := pyStrip(pyStrOrEmpty(at(incident, "type")))
		if t == "" {
			t = "unknown"
		}
		atoms = []string{t}
	}
	return atoms
}

// dedupeSorted is compose_pattern's case-insensitive first-wins dedupe, sorted
// by the lowercased key.
func dedupeSorted(atoms []string) []string {
	seen := map[string]string{}
	for _, atom := range atoms {
		key := strings.ToLower(atom)
		if _, ok := seen[key]; !ok {
			seen[key] = atom
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, seen[k])
	}
	return parts
}

// widenPattern is compose_pattern's <15-char widening.
func widenPattern(pattern string, incident validation.Value) string {
	name := pyStrOrEmpty(at(incident, "name"))
	if name == "" {
		name = "unknown protocol"
	}
	inctype := pyStrOrEmpty(at(incident, "type"))
	if inctype == "" {
		inctype = "unspecified vulnerability"
	}
	date := pyStrOrEmpty(at(incident, "date"))
	if date == "" {
		date = "undated"
	}
	return fmt.Sprintf("%s; %s (%s) %s exploit pattern", pattern, name, date,
		inctype)
}

// clampPattern is compose_pattern's >500-char atom-aware clamp.
func clampPattern(pattern string) string {
	parts := strings.Split(pattern, "; ")
	var kept []string
	total := 0
	for _, part := range parts {
		add := runeLen(part)
		if len(kept) > 0 {
			add += 2
		}
		if len(kept) > 0 && total+add > 497 {
			break
		}
		kept = append(kept, part)
		total += add
	}
	if len(kept) > 0 {
		pattern = strings.Join(kept, "; ")
	} else {
		pattern = runeSlice(parts[0], 0, 500)
	}
	if runeLen(pattern) > 500 {
		pattern = runeSlice(pattern, 0, 500)
	}
	return pattern
}

// BuildRecord is build_record: one common-shape record (pinned mapping, brief
// §Task 4). recordID comes from AssignIDs (collision-aware slug); rca from
// FindRCA; pocPath from ResolvePoc. Pinned points: url is pocLink > blob/main
// URL > None (no README-anchor fallback — the pin lists exactly three levels);
// program from name/chain; bug_class_label is the raw incident type (the
// taxonomy map's input, never pre-mapped); outcome confirmed-exploitable;
// severity None (Lost is a magnitude, not a severity); prior=True (real
// executed exploits are capability priors) with the atomic-label pattern;
// partition is set later by AssignPartitions (build_record stamps "dev" as the
// pre-partition placeholder).
func BuildRecord(incident validation.Value, recordID string, rca *validation.Value,
	pocPath *string) validation.Value {
	name := pyStrOrEmpty(at(incident, "name"))
	if name == "" {
		name = "Unknown protocol"
	}
	inctype := pyStrOrEmpty(at(incident, "type"))
	if inctype == "" {
		inctype = "Unknown"
	}
	date := pyStrOrEmpty(at(incident, "date"))
	platform := NormalizeChain(at(incident, "chain"))
	chainDisplay := "Unknown chain"
	if platform != nil {
		chainDisplay = *platform
	}
	var linkURL, linkCommit *string
	if rca != nil {
		linkURL, _, linkCommit = ExtractPocLink(at(*rca, "pocLink"))
	}
	url := validation.VNull()
	if linkURL != nil {
		url = validation.VStr(*linkURL)
	} else if pocPath != nil {
		url = validation.VStr(RepoURL + "/blob/main/" + *pocPath)
	}
	commit := CloneHead
	if linkCommit != nil {
		commit = *linkCommit
	}
	technique := inctype
	if rca != nil {
		if t := pyStrip(pyStrOrEmpty(at(*rca, "type"))); t != "" {
			technique = t
		}
	}
	title := recordTitle(name, inctype, chainDisplay, date, recordID)
	locations, codeFiles, exploitPath := pocPointers(pocPath)
	return validation.VObj(
		validation.KV{K: "id", V: validation.VStr(recordID)},
		validation.KV{K: "dataset", V: validation.VStr(Dataset)},
		validation.KV{K: "url", V: url},
		validation.KV{K: "program", V: recordProgram(name, platform)},
		validation.KV{K: "title", V: validation.VStr(title)},
		validation.KV{K: "description", V: validation.VStr(
			ComposeDescription(incident, rca))},
		validation.KV{K: "bug_class_label", V: validation.VStr(inctype)},
		validation.KV{K: "outcome", V: validation.VStr("confirmed-exploitable")},
		validation.KV{K: "severity", V: validation.VNull()},
		validation.KV{K: "negative", V: validation.VBool(false)},
		validation.KV{K: "prior", V: validation.VBool(true)},
		validation.KV{K: "pattern", V: validation.VStr(
			ComposePattern(incident, rca))},
		validation.KV{K: "root_cause", V: validation.VStr(
			ComposeRootCause(incident, rca))},
		validation.KV{K: "locations", V: locations},
		validation.KV{K: "code", V: validation.VObj(
			validation.KV{K: "repo", V: validation.VStr(RepoURL)},
			validation.KV{K: "commit", V: validation.VStr(commit)},
			validation.KV{K: "files", V: codeFiles})},
		validation.KV{K: "exploit", V: validation.VObj(
			validation.KV{K: "poc_path", V: exploitPath},
			validation.KV{K: "technique", V: validation.VStr(technique)})},
		validation.KV{K: "partition", V: validation.VStr("dev")},
	)
}

// recordTitle is build_record's title: "<name> - <type> (<chain>, <date>)"
// clipped to 500, padded to 5 with the record id.
func recordTitle(name, inctype, chainDisplay, date, recordID string) string {
	title := ClipText(fmt.Sprintf("%s - %s (%s, %s)", name, inctype,
		chainDisplay, date), 500)
	for runeLen(title) < 5 {
		title += " " + recordID
	}
	return title
}

// recordProgram is build_record's program block: platform/chains carry the
// normalized chain only when one is known.
func recordProgram(name string, platform *string) validation.Value {
	program := validation.VObj(
		validation.KV{K: "program", V: validation.VStr(name)},
		validation.KV{K: "platform", V: validation.VNull()},
		validation.KV{K: "chains", V: validation.VArr()})
	if platform == nil {
		return program
	}
	program = setKey(program, "platform", validation.VStr(*platform))
	return setKey(program, "chains",
		validation.VArr(validation.VStr(*platform)))
}

// pocPointers is build_record's PoC-derived triple: locations, code.files,
// exploit.poc_path.
func pocPointers(pocPath *string) (validation.Value, validation.Value,
	validation.Value) {
	if pocPath == nil {
		return validation.VArr(), validation.VArr(), validation.VNull()
	}
	return validation.VArr(validation.VObj(
			validation.KV{K: "file", V: validation.VStr(*pocPath)})),
		validation.VArr(validation.VStr(*pocPath)),
		validation.VStr(*pocPath)
}

// AssignIDs is assign_ids: the stable defihacklabs-<date>-<norm-name> slugs.
// 26 collision groups share a base slug (recon §7: 44 normalized-name dupes).
// The brief pins +chain on collision; 21 groups are identical even with the
// chain (exact duplicate rows), so the rule extends deterministically: within a
// group, members sort by (type, Contract, chain, full JSON) — the first keeps
// the bare slug, the rest take <slug>-<norm-chain> ("unknown" for null chains),
// then -<norm-type>, then -2/-3… until unique. Pure function of the incident
// list (no wall clock, no disk).
func AssignIDs(incidents []validation.Value) []string {
	bases := make([]string, len(incidents))
	for i, inc := range incidents {
		bases[i] = "defihacklabs-" + validation.PyStr(at(inc, "date")) + "-" +
			NormalizeName(at(inc, "name"))
	}
	groups := map[string][]int{}
	var order []string
	for i, base := range bases {
		if _, ok := groups[base]; !ok {
			order = append(order, base)
		}
		groups[base] = append(groups[base], i)
	}
	sortKey := func(idx int) [4]string {
		inc := incidents[idx]
		return [4]string{
			pyStrOrEmpty(at(inc, "type")),
			pyStrOrEmpty(at(inc, "Contract")),
			pyStrOrEmpty(at(inc, "chain")),
			validation.Canon(inc, false),
		}
	}
	ids := make([]string, len(incidents))
	for _, base := range order {
		members := groups[base]
		if len(members) == 1 {
			ids[members[0]] = base
			continue
		}
		ordered := append([]int{}, members...)
		sort.SliceStable(ordered, func(i, j int) bool {
			a, b := sortKey(ordered[i]), sortKey(ordered[j])
			for k := 0; k < 4; k++ {
				if a[k] != b[k] {
					return a[k] < b[k]
				}
			}
			return false
		})
		used := map[string]bool{base: true}
		ids[ordered[0]] = base
		for _, idx := range ordered[1:] {
			inc := incidents[idx]
			chainPart := NormalizeName(at(inc, "chain"))
			if chainPart == "" {
				chainPart = "unknown"
			}
			candidate := base + "-" + chainPart
			if used[candidate] {
				typePart := NormalizeName(at(inc, "type"))
				if typePart == "" {
					typePart = "notype"
				}
				candidate = candidate + "-" + typePart
			}
			suffix := 2
			for used[candidate] {
				candidate = base + "-" + chainPart + "-" + strconv.Itoa(suffix)
				suffix++
			}
			used[candidate] = true
			ids[idx] = candidate
		}
	}
	return ids
}

// AssignPartitions is assign_partitions: stamp the leakage partition —
// date-ascending, recent ceil(30%) held-out. Pure function of (date, id)
// order — ties break on the unique record id, so the cut is deterministic even
// when many incidents share a date. Operates in place, returns records.
func AssignPartitions(records []validation.Value, dates []string) []validation.Value {
	total := len(records)
	heldOut := int(math.Ceil(float64(total) * HeldOutRatio))
	order := make([]int, total)
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		i, j := order[a], order[b]
		if dates[i] != dates[j] {
			return dates[i] < dates[j]
		}
		return validation.PyStr(at(records[i], "id")) < validation.PyStr(at(records[j], "id"))
	})
	heldOutIdx := map[int]bool{}
	if heldOut > 0 {
		for _, idx := range order[total-heldOut:] {
			heldOutIdx[idx] = true
		}
	}
	for i := range records {
		part := "dev"
		if heldOutIdx[i] {
			part = "held-out"
		}
		records[i] = setKey(records[i], "partition", validation.VStr(part))
	}
	return records
}

// LoadRecords is load_records: load the explorer + PoC clones into
// common-shape records. Pure file reads (never writes to the clones). Returns
// a *CloneAbsentError when a clone is absent — integration tests skip on the
// directories, so the suite never requires the data. Returns one record per
// incident (930), file order, partitioned per AssignPartitions.
func LoadRecords(explorerDir, pocRoot *string) ([]validation.Value, error) {
	explorer := ExplorerDir
	if explorerDir != nil {
		explorer = *explorerDir
	}
	poc := PocRoot
	if pocRoot != nil {
		poc = *pocRoot
	}
	incidentsPath := filepath.Join(explorer, "incidents.json")
	rootcausePath := filepath.Join(explorer, "rootcause_data.json")
	if !isFile(incidentsPath) {
		return nil, &CloneAbsentError{Path: incidentsPath}
	}
	if !isFile(rootcausePath) {
		return nil, &CloneAbsentError{Path: rootcausePath}
	}
	incidents, err := validation.ReadJson(incidentsPath)
	if err != nil {
		return nil, err
	}
	rcaData, err := validation.ReadJson(rootcausePath)
	if err != nil {
		return nil, err
	}
	if incidents.Kind != validation.Arr {
		return nil, fmt.Errorf("%s must be a JSON array", incidentsPath)
	}
	if rcaData.Kind != validation.Obj {
		return nil, fmt.Errorf("%s must be a JSON object", rootcausePath)
	}
	index := BuildPocIndex(poc)
	recordIDs := AssignIDs(incidents.A)
	records := make([]validation.Value, 0, len(incidents.A))
	for i, incident := range incidents.A {
		rca := FindRCA(at(incident, "name"), rcaData)
		pocPath := ResolvePoc(incident, rca, index)
		records = append(records, BuildRecord(incident, recordIDs[i], rca, pocPath))
	}
	dates := make([]string, len(incidents.A))
	for i, inc := range incidents.A {
		dates[i] = pyStrOrEmpty(at(inc, "date"))
	}
	return AssignPartitions(records, dates), nil
}

// IngestOptions are ingest's keyword arguments.
type IngestOptions struct {
	Records    *[]validation.Value
	Maps       *validation.Value
	ProgramKey *string
	Tier       string
}

// Ingest is ingest: load, ingest_record each, publish. Every record becomes an
// eval case (the held-out slice is the incident benchmark); records with a
// resolvable PoC additionally yield campaign seeds (the Phase A launch list).
// Memory rows materialize only for taxonomy-mapped priors on the dev slice —
// publish_ingested holds held-out rows eval-only. tier selects the publish
// target (tests must NEVER call this against the real stores).
func Ingest(opts IngestOptions) (validation.Value, error) {
	records := opts.Records
	if records == nil {
		loaded, err := LoadRecords(nil, nil)
		if err != nil {
			return validation.VNull(), err
		}
		records = &loaded
	}
	maps := opts.Maps
	if maps == nil {
		m, err := taxonomy.LoadMaps([]string{"defihacklabs"})
		if err != nil {
			return validation.VNull(), err
		}
		maps = &m
	}
	programKey := ProgramKey
	if opts.ProgramKey != nil {
		programKey = *opts.ProgramKey
	}
	tier := opts.Tier
	if tier == "" {
		tier = "global"
	}
	results := make([]ingest.Result, 0, len(*records))
	for _, record := range *records {
		res, err := ingest.IngestRecord(record, maps)
		if err != nil {
			return validation.VNull(), err
		}
		results = append(results, res)
	}
	var seeds []validation.Value
	for i, res := range results {
		rec := (*records)[i]
		if at(at(rec, "exploit"), "poc_path").Kind == validation.Null {
			continue
		}
		if res.CampaignSeed != nil {
			seeds = append(seeds, *res.CampaignSeed)
		}
	}
	summary, err := ingest.PublishIngested(results, Dataset, &programKey, tier)
	if err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		validation.KV{K: "records", V: validation.VArr(*records...)},
		validation.KV{K: "results", V: validation.VArr(resultValues(results)...)},
		validation.KV{K: "campaign_seeds", V: validation.VArr(seeds...)},
		validation.KV{K: "publish", V: summary.Value()},
	), nil
}

// resultValues renders the ingest results as Python's list of dicts.
func resultValues(results []ingest.Result) []validation.Value {
	out := make([]validation.Value, len(results))
	for i, r := range results {
		out[i] = r.Value()
	}
	return out
}

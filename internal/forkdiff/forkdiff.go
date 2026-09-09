// Package forkdiff is a 1:1 port of webv2/forkdiff.py: how far is this
// target from known-good reference protocols? A target that differs from a
// battle-tested baseline by a handful of selectors is where critical bugs
// hide: the diff is the search space. The fingerprint is built on the SAME
// parser as the structural index (one parser, no drift), and baselines are
// operator-supplied, version-pinned trees with content hashes — nothing here
// fetches them at runtime.
//
// Verdicts are advisory (strong/partial/none): they order attention, they do
// not gate findings. Baseline drift is an audit failure, because a drifted
// reference silently corrupts every diff.
package forkdiff

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"websec/internal/audit/sections"
	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

// RepoRoot is REPO_ROOT: the tree the baselines directory hangs off. Python
// derives it from __file__ (an ABSOLUTE source-relative path); a Go binary
// has no source-relative root, so it defaults to the ABSOLUTE working
// directory — absolute so that the paths in diagnostics ("baseline source
// X overlaps the destination Y") render the same shape as Python's, and
// settable by the CLI/embedder.
var RepoRoot = "."

// BaselinesDir is BASELINES_DIR (REPO_ROOT/baselines).
var BaselinesDir = filepath.Join(RepoRoot, "baselines")

func init() {
	if wd, err := os.Getwd(); err == nil {
		RepoRoot = wd
		BaselinesDir = filepath.Join(wd, "baselines")
	}
}

// SetRepoRoot repoints REPO_ROOT and the derived baselines directory.
func SetRepoRoot(root string) {
	if root == "" {
		root = "."
	}
	RepoRoot = root
	BaselinesDir = filepath.Join(root, "baselines")
}

// SetBaselinesDir points the baselines directory at an explicit path.
func SetBaselinesDir(dir string) {
	if dir == "" {
		dir = filepath.Join(RepoRoot, "baselines")
	}
	BaselinesDir = dir
}

var (
	nameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,40}$`)
	strong  = 0.6
	partial = 0.4
)

// FingerprintTree is fingerprint_tree: the content-addressable shape of a
// source tree, from the T0 parser.
func FingerprintTree(root string) (validation.Value, error) {
	tree, err := structidx.IndexTreeValue(root)
	if err != nil {
		return validation.VNull(), err
	}
	nodes := objListAt(tree, "nodes")
	contracts, selectors, stateVars, modifiers, deleg := []string{},
		[]string{}, []string{}, []string{}, []string{}
	selSeen := map[string]bool{}
	for _, n := range nodes {
		switch objStr(n, "kind") {
		case "contract", "interface", "library":
			contracts = append(contracts, objStr(n, "name"))
		case "function":
			if s := objStr(n, "selector"); s != "" && !selSeen[s] {
				selSeen[s] = true
				selectors = append(selectors, s)
			}
			if len(objListAt(n, "delegatecalls")) > 0 {
				deleg = append(deleg, objStr(n, "id"))
			}
		case "state-variable":
			stateVars = append(stateVars, objStr(n, "name"))
		case "modifier":
			modifiers = append(modifiers, objStr(n, "name"))
		}
	}
	sort.Strings(contracts)
	sort.Strings(selectors)
	sort.Strings(stateVars)
	sort.Strings(modifiers)
	sort.Strings(deleg)
	inherits := []string{}
	for _, e := range objListAt(tree, "edges") {
		if objStr(e, "rel") != "inherits" {
			continue
		}
		from := objStr(e, "from")
		to := objStr(e, "to")
		if i := strings.Index(from, "#"); i >= 0 {
			from = from[i+1:]
		}
		if i := strings.Index(to, "#"); i >= 0 {
			to = to[i+1:]
		}
		inherits = append(inherits, from+"->"+to)
	}
	sort.Strings(inherits)
	return validation.VObj(
		validation.KV{K: "contracts", V: strArr(contracts)},
		validation.KV{K: "selectors", V: strArr(selectors)},
		validation.KV{K: "state_vars", V: strArr(stateVars)},
		validation.KV{K: "modifiers", V: strArr(modifiers)},
		validation.KV{K: "delegatecall_functions", V: strArr(deleg)},
		validation.KV{K: "inherits", V: strArr(inherits)},
	), nil
}

// FingerprintSha256 is fingerprint_sha256: canonical JSON + sha256. The
// canonical dump is ensure_ascii, so the utf-8 encoding is the identity.
func FingerprintSha256(fp validation.Value) string {
	return validation.Sha256Hex([]byte(validation.CanonCompact(fp)))
}

// jaccard is _jaccard: set intersection over union; two empty sets are
// identical surface, not dissimilar.
func jaccard(a, b []string) float64 {
	A, B := map[string]bool{}, map[string]bool{}
	for _, x := range a {
		A[x] = true
	}
	for _, x := range b {
		B[x] = true
	}
	inter, union := 0, 0
	for k := range A {
		if B[k] {
			inter++
		}
	}
	seen := map[string]bool{}
	for k := range A {
		seen[k] = true
	}
	for k := range B {
		seen[k] = true
	}
	union = len(seen)
	if union == 0 {
		return 1.0
	}
	return float64(inter) / float64(union)
}

// Match is match: weighted Jaccard against one baseline.
//
//	score = 0.5*J(selectors) + 0.3*J(state_vars) + 0.1*J(modifiers)
//	      + 0.1*J(contracts); strong >= 0.6, partial >= 0.4.
func Match(targetFP, baselineFP validation.Value, name string) validation.Value {
	js := jaccard(strs(targetFP, "selectors"), strs(baselineFP, "selectors"))
	jv := jaccard(strs(targetFP, "state_vars"), strs(baselineFP, "state_vars"))
	jm := jaccard(strs(targetFP, "modifiers"), strs(baselineFP, "modifiers"))
	jc := jaccard(strs(targetFP, "contracts"), strs(baselineFP, "contracts"))
	score := validation.PyRound(0.5*js+0.3*jv+0.1*jm+0.1*jc, 4)
	verdict := "none"
	if score >= strong {
		verdict = "strong"
	} else if score >= partial {
		verdict = "partial"
	}
	extra := difference(strs(targetFP, "selectors"), strs(baselineFP, "selectors"))
	missing := difference(strs(baselineFP, "selectors"), strs(targetFP, "selectors"))
	return validation.VObj(
		validation.KV{K: "baseline", V: validation.VStr(name)},
		validation.KV{K: "jaccard", V: validation.VObj(
			validation.KV{K: "selectors", V: validation.VFloat(validation.PyRound(js, 4))},
			validation.KV{K: "state_vars", V: validation.VFloat(validation.PyRound(jv, 4))},
			validation.KV{K: "modifiers", V: validation.VFloat(validation.PyRound(jm, 4))},
			validation.KV{K: "contracts", V: validation.VFloat(validation.PyRound(jc, 4))},
		)},
		validation.KV{K: "score", V: validation.VFloat(score)},
		validation.KV{K: "verdict", V: validation.VStr(verdict)},
		validation.KV{K: "extra_selectors", V: strArr(extra)},
		validation.KV{K: "missing_selectors", V: strArr(missing)},
	)
}

func difference(a, b []string) []string {
	B := map[string]bool{}
	for _, x := range b {
		B[x] = true
	}
	seen := map[string]bool{}
	out := []string{}
	for _, x := range a {
		if B[x] || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	sort.Strings(out)
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

func strs(v validation.Value, key string) []string {
	x := objAt(v, key)
	if x.Kind != validation.Arr {
		return nil
	}
	out := make([]string, 0, len(x.A))
	for _, e := range x.A {
		if e.Kind == validation.Str {
			out = append(out, e.S)
		}
	}
	return out
}

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

func objStr(v validation.Value, key string) string {
	x := objAt(v, key)
	if x.Kind == validation.Str {
		return x.S
	}
	return ""
}

func objListAt(v validation.Value, key string) []validation.Value {
	x := objAt(v, key)
	if x.Kind != validation.Arr {
		return nil
	}
	return x.A
}

func strArr(xs []string) validation.Value {
	out := make([]validation.Value, 0, len(xs))
	for _, x := range xs {
		out = append(out, validation.VStr(x))
	}
	return validation.VArr(out...)
}

func nowIso() string {
	if v := os.Getenv("WEBV2_NOW"); v != "" {
		return v
	}
	return state.NowIso()
}

// checkName is _check_name.
func checkName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid baseline name %s "+
			"(expected [a-z0-9][a-z0-9-]{1,40})", validation.PyReprStr(name))
	}
	return nil
}

func manifestPath() string { return filepath.Join(BaselinesDir, "manifest.json") }

// loadManifest is _load_manifest: the absent manifest reads as empty.
func loadManifest() (validation.Value, error) {
	p := manifestPath()
	if _, err := os.Stat(p); err != nil {
		return validation.VObj(
			validation.KV{K: "baselines", V: validation.VArr()},
			validation.KV{K: "updated_at", V: validation.VNull()},
		), nil
	}
	return validation.ReadJson(p)
}

// AddBaseline is add_baseline: register a version-pinned baseline tree.
// Copies the source into baselines/<name>/src/ and records its fingerprint —
// the COPY is what gets matched against and drift-audited.
//
// The copy is staged in a temporary sibling directory and swapped over the
// live tree only after it (and its fingerprint) fully succeed, so a failed
// copy can never gut an existing baseline. A source that overlaps the
// destination tree is refused up front for the same reason.
func AddBaseline(name, srcPath string, sourceURL, licenseID *string) (validation.Value, error) {
	if err := checkName(name); err != nil {
		return validation.VNull(), err
	}
	st, err := os.Stat(srcPath)
	if err != nil || !st.IsDir() {
		return validation.VNull(), fmt.Errorf(
			"baseline source not a directory: %s", srcPath)
	}
	destRoot := filepath.Join(BaselinesDir, name)
	destSrc := filepath.Join(destRoot, "src")
	srcRes, err := filepath.Abs(srcPath)
	if err != nil {
		return validation.VNull(), err
	}
	if r, err := filepath.EvalSymlinks(srcRes); err == nil {
		srcRes = r
	}
	destRes, err := filepath.Abs(destRoot)
	if err != nil {
		return validation.VNull(), err
	}
	if r, err := filepath.EvalSymlinks(destRes); err == nil {
		destRes = r
	}
	if srcRes == destRes || isAncestor(srcRes, destRes) || isAncestor(destRes, srcRes) {
		return validation.VNull(), fmt.Errorf(
			"baseline source %s overlaps the destination %s: refusing a "+
				"self-referential add", srcPath, destSrc)
	}
	if err := os.MkdirAll(BaselinesDir, 0o755); err != nil {
		return validation.VNull(), err
	}
	if err := os.MkdirAll(destRoot, 0o755); err != nil {
		return validation.VNull(), err
	}
	staging, err := os.MkdirTemp(filepath.Dir(destRoot), "."+name+".tmp-")
	if err != nil {
		return validation.VNull(), err
	}
	defer os.RemoveAll(staging)
	stagedSrc := filepath.Join(staging, "src")
	if err := copyTree(srcPath, stagedSrc); err != nil {
		return validation.VNull(), err
	}
	fp, err := FingerprintTree(stagedSrc)
	if err != nil {
		return validation.VNull(), err
	}
	if _, err := os.Lstat(destSrc); err == nil {
		backup := filepath.Join(filepath.Dir(destRoot), "."+name+".bak")
		if _, err := os.Lstat(backup); err == nil {
			if err := os.RemoveAll(backup); err != nil {
				return validation.VNull(), err
			}
		}
		if err := os.Rename(destSrc, backup); err != nil {
			return validation.VNull(), err
		}
		if err := os.Rename(stagedSrc, destSrc); err != nil {
			_ = os.Rename(backup, destSrc) // restore the old tree
			return validation.VNull(), err
		}
		_ = os.RemoveAll(backup)
	} else {
		if err := os.Rename(stagedSrc, destSrc); err != nil {
			return validation.VNull(), err
		}
	}
	meta := validation.VObj(
		validation.KV{K: "name", V: validation.VStr(name)},
		validation.KV{K: "added_at", V: validation.VStr(nowIso())},
		validation.KV{K: "source_url", V: optStr(sourceURL)},
		validation.KV{K: "license", V: optStr(licenseID)},
		validation.KV{K: "fingerprint", V: fp},
		validation.KV{K: "fingerprint_sha256", V: validation.VStr(FingerprintSha256(fp))},
	)
	if err := validation.WriteJson(filepath.Join(destRoot, "baseline.json"),
		meta, ""); err != nil {
		return validation.VNull(), err
	}
	man, err := loadManifest()
	if err != nil {
		return validation.VNull(), err
	}
	names := strs(man, "baselines")
	found := false
	for _, n := range names {
		if n == name {
			found = true
		}
	}
	if !found {
		names = append(names, name)
	}
	man = setKey(man, "baselines", strArr(names))
	man = setKey(man, "updated_at", validation.VStr(nowIso()))
	if err := validation.WriteJson(manifestPath(), man, ""); err != nil {
		return validation.VNull(), err
	}
	return meta, nil
}

func optStr(s *string) validation.Value {
	if s == nil {
		return validation.VNull()
	}
	return validation.VStr(*s)
}

// setKey replaces or appends a key, preserving the original key order.
func setKey(v validation.Value, key string, val validation.Value) validation.Value {
	out := make([]validation.KV, 0, len(v.O)+1)
	replaced := false
	for _, kv := range v.O {
		if kv.K == key {
			out = append(out, validation.KV{K: key, V: val})
			replaced = true
			continue
		}
		out = append(out, kv)
	}
	if !replaced {
		out = append(out, validation.KV{K: key, V: val})
	}
	return validation.VObj(out...)
}

// isAncestor reports whether a is an ancestor directory of b (Python's
// `a in b.parents`).
func isAncestor(a, b string) bool {
	for p := filepath.Dir(b); ; p = filepath.Dir(p) {
		if p == a {
			return true
		}
		parent := filepath.Dir(p)
		if parent == p {
			return false
		}
	}
}

// copyTree is shutil.copytree with symlinks=False: directories are
// recreated, file symlinks are followed and their contents copied.
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(src, path)
		if rerr != nil {
			return rerr
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		info, ierr := os.Stat(path)
		if ierr != nil {
			return ierr
		}
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, oerr := os.Open(path)
		if oerr != nil {
			return oerr
		}
		defer in.Close()
		out, cerr := os.Create(target)
		if cerr != nil {
			return cerr
		}
		if _, werr := io.Copy(out, in); werr != nil {
			out.Close()
			return werr
		}
		if cerr := out.Close(); cerr != nil {
			return cerr
		}
		return os.Chmod(target, info.Mode().Perm())
	})
}

// ListBaselines is list_baselines: registered baselines, sorted by name.
func ListBaselines() ([]validation.Value, error) {
	man, err := loadManifest()
	if err != nil {
		return nil, err
	}
	out := []validation.Value{}
	for _, name := range strs(man, "baselines") {
		p := filepath.Join(BaselinesDir, name, "baseline.json")
		if _, err := os.Stat(p); err != nil {
			continue
		}
		m, err := validation.ReadJson(p)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return objStr(out[i], "name") < objStr(out[j], "name")
	})
	return out, nil
}

// RemoveBaseline is remove_baseline.
func RemoveBaseline(name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	root := filepath.Join(BaselinesDir, name)
	if _, err := os.Stat(root); err == nil {
		if err := os.RemoveAll(root); err != nil {
			return err
		}
	}
	man, err := loadManifest()
	if err != nil {
		return err
	}
	kept := []string{}
	for _, n := range strs(man, "baselines") {
		if n != name {
			kept = append(kept, n)
		}
	}
	man = setKey(man, "baselines", strArr(kept))
	man = setKey(man, "updated_at", validation.VStr(nowIso()))
	return validation.WriteJson(manifestPath(), man, "")
}

// ForkdiffReport is forkdiff_report: match the target tree against every
// registered baseline; write the fork_diff artifact (consumed by findings and
// the critic bundle).
func ForkdiffReport(c *state.Campaign, snapshotRoot string) (validation.Value, error) {
	fp, err := FingerprintTree(snapshotRoot)
	if err != nil {
		return validation.VNull(), err
	}
	baselines, err := ListBaselines()
	if err != nil {
		return validation.VNull(), err
	}
	matches := make([]validation.Value, 0, len(baselines))
	for _, b := range baselines {
		matches = append(matches, Match(fp, objAt(b, "fingerprint"),
			objStr(b, "name")))
	}
	var best validation.Value
	hasBest := false
	for _, m := range matches {
		if !hasBest || scoreOf(m) > scoreOf(best) {
			best, hasBest = m, true
		}
	}
	snap, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		return validation.VNull(), err
	}
	snapID := "unpinned"
	if snap != nil {
		snapID = *snap
	}
	var matchedBaseline validation.Value = validation.VNull()
	diffSummary := "no baselines registered"
	extraSel, missingSel := validation.VArr(), validation.VArr()
	if hasBest {
		extraSel = objAt(best, "extra_selectors")
		missingSel = objAt(best, "missing_selectors")
		diffSummary = fmt.Sprintf("score %s (%s) vs %s",
			pyFixed2(scoreOf(best)), objStr(best, "verdict"),
			objStr(best, "baseline"))
		if objStr(best, "verdict") != "none" {
			matchedBaseline = objAt(best, "baseline")
		}
	}
	report := validation.VObj(
		validation.KV{K: "generated_at", V: validation.VStr(nowIso())},
		validation.KV{K: "snapshot_id", V: validation.VStr(snapID)},
		validation.KV{K: "matched_baseline", V: matchedBaseline},
		validation.KV{K: "diff_summary", V: validation.VStr(diffSummary)},
		validation.KV{K: "extra_selectors", V: extraSel},
		validation.KV{K: "missing_selectors", V: missingSel},
		validation.KV{K: "all_matches", V: validation.VArr(matches...)},
	)
	out := filepath.Join(c.ArtifactsDir, "fork_diff.json")
	if err := validation.WriteJson(out, report, ""); err != nil {
		return validation.VNull(), err
	}
	if _, err := c.RegisterOrRefresh("fork-diff", out, "", nil, diffSummary); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		validation.KV{K: "matched_baseline", V: matchedBaseline},
		validation.KV{K: "baselines", V: validation.VInt(int64(len(matches)))},
	)
	if _, err := c.Log("forkdiff.computed", nil, &data); err != nil {
		return validation.VNull(), err
	}
	return report, nil
}

func scoreOf(m validation.Value) float64 {
	x := objAt(m, "score")
	if x.Kind == validation.Flt {
		return x.F
	}
	return 0
}

// pyFixed2 is Python's f"{x:.2f}".
func pyFixed2(f float64) string {
	return fmt.Sprintf("%.2f", f)
}

// Wire installs forkdiff into the audit's baselines section (section 10),
// which owns the drift check: a baseline whose src/ no longer matches its
// recorded fingerprint is an audit problem. Python has no wiring step — the
// section imports forkdiff directly — so this is the Go spelling of that
// import edge.
func Wire() {
	sections.SetForkdiff(seam{})
}

// seam implements sections.ForkdiffAPI over this package's globals.
type seam struct{}

// BaselinesDir is FD.BASELINES_DIR.
func (seam) BaselinesDir(*state.Campaign) string { return BaselinesDir }

// FingerprintTree is FD.fingerprint_tree.
func (seam) FingerprintTree(root string) (validation.Value, error) {
	return FingerprintTree(root)
}

// shapes.go: PoC call-shape extraction, the pinned shape cache and the
// target matcher (plan Tasks 8/9). param_types goes through
// structidx.ParamTypes — the SAME normalization the target side uses — so a
// PoC shape and a target selector are directly comparable. Regex-only, no
// model calls, no compiler: same file bytes -> byte-identical shape list.
package corpus

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"websec/internal/archetypes"
	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

// NEAR_MISS_THRESHOLD is the shape matcher's fuzzy-name floor. Named constant
// here, NOT an import of archetypes': call-shape matching is a different
// domain. Calibrated (Task 12) at 0.25 against the sharevault fixture.
const NEAR_MISS_THRESHOLD = 0.25

// pocShapesFile is the derived artifact cache name.
const pocShapesFile = "poc_shapes.json"

// Shape is one extracted call site.
type Shape struct {
	Callee       string
	ParamTypes   string
	ReceiverHint string
}

// Value renders the shape's JSON object in Python's insertion order.
func (s Shape) Value() validation.Value {
	return validation.VObj(
		validation.KV{K: "callee", V: validation.VStr(s.Callee)},
		validation.KV{K: "param_types", V: validation.VStr(s.ParamTypes)},
		validation.KV{K: "receiver_hint", V: validation.VStr(s.ReceiverHint)},
	)
}

// ShapeIndex is {repo_rel_path: [shapes]}. Ordering is imposed at render
// time (sorted keys), so a map is safe.
type ShapeIndex map[string][]Shape

// SortedFiles is sorted(shapes_by_file).
func (si ShapeIndex) SortedFiles() []string {
	out := make([]string, 0, len(si))
	for k := range si {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Value renders the index as an ordered object with sorted file keys.
func (si ShapeIndex) Value() validation.Value {
	kvs := make([]validation.KV, 0, len(si))
	for _, rel := range si.SortedFiles() {
		shapes := make([]validation.Value, 0, len(si[rel]))
		for _, s := range si[rel] {
			shapes = append(shapes, s.Value())
		}
		kvs = append(kvs, validation.KV{K: rel, V: validation.VArr(shapes...)})
	}
	return validation.VObj(kvs...)
}

// ShapeIndexFromValue reads an index back out of a JSON/YAML Value.
func ShapeIndexFromValue(v validation.Value) ShapeIndex {
	out := ShapeIndex{}
	if v.Kind != validation.Obj {
		return out
	}
	for _, kv := range v.O {
		if kv.V.Kind != validation.Arr {
			continue
		}
		shapes := make([]Shape, 0, len(kv.V.A))
		for _, e := range kv.V.A {
			shapes = append(shapes, Shape{
				Callee:       objStr(e, "callee"),
				ParamTypes:   objStr(e, "param_types"),
				ReceiverHint: objStr(e, "receiver_hint"),
			})
		}
		out[kv.K] = shapes
	}
	return out
}

// ShapeDoc is the cached/indexed shape document.
type ShapeDoc struct {
	DatasetHead string
	PocCount    int64
	GeneratedAt string
	Shapes      ShapeIndex
}

// Value renders the doc in load_or_build_poc_shapes' key order.
func (d ShapeDoc) Value() validation.Value {
	return validation.VObj(
		validation.KV{K: "dataset_head", V: validation.VStr(d.DatasetHead)},
		validation.KV{K: "poc_count", V: validation.VInt(d.PocCount)},
		validation.KV{K: "generated_at", V: validation.VStr(d.GeneratedAt)},
		validation.KV{K: "shapes", V: d.Shapes.Value()},
	)
}

// callRe is _CALL_RE: (CastType)(args).callee( | receiver.callee( — the cast
// type name (one nesting level deep) becomes the receiver hint, else the
// receiver variable name. Lowercase-first casts are admitted: Solidity only
// admits a TYPE as the receiver of an Ident(...).callee( site, so widening
// the identifier class to [A-Za-z] cannot over-match function calls.
var callRe = regexp.MustCompile(`(?:\b([A-Za-z][A-Za-z0-9_]*)\s*\(\s*(?:[^();]|\([^()]*\))*?\)\s*\.\s*|([A-Za-z_]\w*)\s*\.\s*)([A-Za-z_]\w*)\s*\(`)

// ExtractCallShapes is extract_call_shapes: deterministic call-shape
// extraction from one Solidity file. Interface declarations and zero-arg calls
// are skipped; an unbalanced tail is skipped rather than guessed.
func ExtractCallShapes(source string) []Shape {
	shapes := []Shape{}
	for _, loc := range callRe.FindAllStringSubmatchIndex(source, -1) {
		castType, receiver, callee := group(source, loc, 1), group(source, loc, 2),
			group(source, loc, 3)
		// the match always ends at callee's "(": pull the balanced args
		openIdx := loc[1] - 1
		depth, i := 0, openIdx
		for i < len(source) {
			if source[i] == '(' {
				depth++
			} else if source[i] == ')' {
				depth--
				if depth == 0 {
					break
				}
			}
			i++
		}
		if i >= len(source) {
			continue // unbalanced tail — not a complete call site
		}
		paramsText := strings.TrimSpace(source[openIdx+1 : i])
		if paramsText == "" {
			continue // zero-arg call or a declaration artifact
		}
		hint := castType
		if hint == "" {
			hint = receiver
		}
		shapes = append(shapes, Shape{
			Callee:       callee,
			ParamTypes:   structidx.ParamTypes(paramsText),
			ReceiverHint: hint,
		})
	}
	return shapes
}

// group reads submatch n's text ("" when the alternative did not match).
func group(source string, loc []int, n int) string {
	start, end := loc[2*n], loc[2*n+1]
	if start < 0 || end < 0 {
		return ""
	}
	return source[start:end]
}

// expFileList is _exp_file_list: sorted repo-relative paths of every
// *_exp.sol under src/test/ (helper files excluded — the adapter's same stem
// rule).
func expFileList(root string) []string {
	testDir := filepath.Join(root, "src", "test")
	if !isDir(testDir) {
		return []string{}
	}
	out := []string{}
	_ = filepath.WalkDir(testDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".sol") ||
			!strings.HasSuffix(strings.ToLower(name), "_exp.sol") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(out)
	return out
}

func isDir(p string) bool {
	if p == "" {
		p = "."
	}
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// readPocText is Path.read_text(encoding="utf-8", errors="replace").
func readPocText(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if utf8.Valid(raw) {
		return string(raw), nil
	}
	return strings.ToValidUTF8(string(raw), "\uFFFD"), nil
}

// BuildPocShapeIndex is build_poc_shape_index: the uncached, always-fresh
// extraction.
func BuildPocShapeIndex(pocRoot string) (ShapeIndex, error) {
	out := ShapeIndex{}
	for _, rel := range expFileList(pocRoot) {
		text, err := readPocText(filepath.Join(pocRoot, rel))
		if err != nil {
			return nil, err
		}
		out[rel] = ExtractCallShapes(text)
	}
	return out, nil
}

// GitHead is git_head: `git rev-parse HEAD` of the dataset checkout, or nil
// when it is not a resolvable git checkout (absent, non-git, or corrupt).
func GitHead(pocRoot string) *string {
	cmd := exec.Command("git", "-C", pocRoot, "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	head := strings.TrimSpace(string(out))
	return &head
}

// LoadOrBuildPocShapes is load_or_build_poc_shapes: the shape index pinned to
// the dataset's git head + file list. Cache-first: only the cheap file list
// is computed before consulting the cache, so a hit never re-parses the PoCs.
// A non-git checkout fails loud — guessing staleness is worse than stopping.
func LoadOrBuildPocShapes(c *state.Campaign, pocRoot *string) (ShapeDoc, error) {
	root := PocRoot
	if pocRoot != nil {
		root = *pocRoot
	}
	head := GitHead(root)
	if head == nil {
		return ShapeDoc{}, fmt.Errorf("PoC dataset at %s is not a git checkout "+
			"— cannot pin the shape cache; refusing to guess staleness", root)
	}
	files := expFileList(root)
	cachePath := filepath.Join(c.ArtifactsDir, pocShapesFile)
	if _, err := os.Stat(cachePath); err == nil {
		cached, rerr := validation.ReadJson(cachePath)
		if rerr == nil {
			cachedShapes := ShapeIndexFromValue(objAt(cached, "shapes"))
			if objStr(cached, "dataset_head") == *head &&
				sameFiles(cachedShapes.SortedFiles(), files) {
				return ShapeDoc{
					DatasetHead: objStr(cached, "dataset_head"),
					PocCount:    intAt(cached, "poc_count"),
					GeneratedAt: objStr(cached, "generated_at"),
					Shapes:      cachedShapes,
				}, nil
			}
		}
	}
	shapes := ShapeIndex{}
	for _, rel := range files {
		text, err := readPocText(filepath.Join(root, rel))
		if err != nil {
			return ShapeDoc{}, err
		}
		shapes[rel] = ExtractCallShapes(text)
	}
	doc := ShapeDoc{DatasetHead: *head, PocCount: int64(len(files)),
		GeneratedAt: nowIso(), Shapes: shapes}
	if err := validation.WriteJson(cachePath, doc.Value(), ""); err != nil {
		return ShapeDoc{}, err
	}
	data := validation.VObj(
		validation.KV{K: "head", V: validation.VStr(firstNStr(*head, 12))},
		validation.KV{K: "count", V: validation.VInt(int64(len(files)))},
	)
	if _, err := c.Log("corpus_surface.poc_shapes", nil, &data); err != nil {
		return ShapeDoc{}, err
	}
	return doc, nil
}

func sameFiles(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TargetSurfaceKeys is _target_surface_keys: (fn_name, param_types) for every
// exported function, parsed from the selector.
func TargetSurfaceKeys(index validation.Value) (map[[2]string]bool, []string) {
	keys := map[[2]string]bool{}
	names := map[string]bool{}
	for _, n := range structidx.ExternalSurface(index) {
		sel := objStr(n, "selector")
		if sel == "" {
			continue
		}
		name, ptypes := partition(sel, "(")
		ptypes = strings.TrimRight(ptypes, ")")
		keys[[2]string{name, ptypes}] = true
		names[name] = true
	}
	return keys, sortedKeys(names)
}

// partition is str.partition("("): the part before, and the part after.
func partition(s, sep string) (string, string) {
	if i := strings.Index(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):]
	}
	return s, ""
}

// MatchShapes is match_shapes: exact hits and fuzzy near-misses against the
// target's exported surface. Files with no signal are omitted; ordering is
// deterministic throughout.
func MatchShapes(index validation.Value, shapesByFile ShapeIndex) []validation.Value {
	keys, names := TargetSurfaceKeys(index)
	out := []validation.Value{}
	for _, rel := range shapesByFile.SortedFiles() {
		exact := []validation.Value{}
		near := []validation.Value{}
		seenExact := map[[2]string]bool{}
		for _, s := range shapesByFile[rel] {
			key := [2]string{s.Callee, s.ParamTypes}
			if keys[key] {
				if !seenExact[key] {
					exact = append(exact, s.Value())
					seenExact[key] = true
				}
				continue
			}
			bestScore, bestTarget := 0.0, ""
			for _, t := range names {
				if sc := archetypes.Jaccard(s.Callee, t); sc > bestScore {
					bestScore, bestTarget = sc, t
				}
			}
			if bestTarget != "" && bestScore >= NEAR_MISS_THRESHOLD {
				near = append(near, validation.VObj(
					validation.KV{K: "callee", V: validation.VStr(s.Callee)},
					validation.KV{K: "param_types", V: validation.VStr(s.ParamTypes)},
					validation.KV{K: "nearest_target", V: validation.VStr(bestTarget)},
					validation.KV{K: "score", V: validation.VFloat(
						validation.PythonRound(bestScore, 4))},
				))
			}
		}
		if len(exact) == 0 && len(near) == 0 {
			continue
		}
		sort.SliceStable(exact, func(i, j int) bool {
			a := [2]string{objStr(exact[i], "callee"), objStr(exact[i], "param_types")}
			b := [2]string{objStr(exact[j], "callee"), objStr(exact[j], "param_types")}
			return a[0] < b[0] || (a[0] == b[0] && a[1] < b[1])
		})
		sort.SliceStable(near, func(i, j int) bool {
			si, sj := floatAt(near[i], "score"), floatAt(near[j], "score")
			if si != sj {
				return si > sj
			}
			return objStr(near[i], "callee") < objStr(near[j], "callee")
		})
		if len(near) > 10 {
			near = near[:10]
		}
		out = append(out, validation.VObj(
			validation.KV{K: "file", V: validation.VStr(rel)},
			validation.KV{K: "exact_hits", V: validation.VArr(exact...)},
			validation.KV{K: "near_misses", V: validation.VArr(near...)},
		))
	}
	return out
}

// firstNStr is firstN for a string prefix.
func firstNStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

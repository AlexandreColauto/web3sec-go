// docscan.go: documented_invariants / intent_claims / documented_ref /
// reconcile — the doc grep of the pinned snapshot tree (webv2/invariants.py).
package invariants

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"websec/internal/state"
	"websec/internal/validation"
)

// docSuffixes is _DOC_SUFFIXES.
var docSuffixes = []string{".md", ".rst", ".adoc", ".txt"}

// nowIso is state.now_iso: UTC with 6-digit microseconds and +00:00, with
// the WEBV2_NOW golden-suite pin honored verbatim (the recipe pins the clock
// so a replay emits byte-identical artifacts).
func nowIso() string {
	if v := os.Getenv("WEBV2_NOW"); v != "" {
		return v
	}
	now := time.Now().UTC()
	return fmt.Sprintf("%s.%06d+00:00",
		now.Format("2006-01-02T15:04:05"), now.Nanosecond()/1000)
}

// ---- documented set ------------------------------------------------------

// DocumentedInvariants is documented_invariants: a grep of the pinned
// snapshot tree for “INV-<n>“. snapshotID nil means the active snapshot;
// no snapshot (or no tree) is the empty dict, never an error.
func DocumentedInvariants(c *state.Campaign, snapshotID *string) (validation.Value, error) {
	sid := ""
	if snapshotID != nil {
		sid = *snapshotID
	} else {
		id, err := c.ActiveSnapshotIDOrNone()
		if err != nil {
			return validation.VNull(), err
		}
		if id != nil {
			sid = *id
		}
	}
	if sid == "" {
		return validation.VObj(), nil
	}
	root := filepath.Join(c.Dir, "snapshots", sid)
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return validation.VObj(), nil
	}
	files, err := docFiles(root)
	if err != nil {
		return validation.VNull(), err
	}
	out := validation.VObj()
	for _, rel := range files {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			continue // Python swallows OSError here
		}
		for i, line := range pySplitLines(decodeUTF8Replace(raw)) {
			for _, raw := range invDocMatches(line) {
				iid := NormalizeInvID(raw) // Python: f"INV-{int(digits)}"
				if hasKey(out, iid) {
					continue
				}
				out.O = append(out.O, pair(iid, validation.VObj(
					pair("file", validation.VStr(rel)),
					pair("line", validation.VInt(int64(i+1))),
					pair("context", validation.VStr(pyHead(pyStrip(line), 200))),
				)))
			}
		}
	}
	return out, nil
}

// docFiles is sorted(root.rglob("*")) filtered to readable doc candidates:
// regular files (symlinks followed) whose pathlib suffix is a doc suffix.
// The sort is over the whole relative path, exactly as Python sorts the
// full paths it collected.
func docFiles(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		fi, serr := os.Stat(p)
		if serr != nil || fi.IsDir() {
			return nil
		}
		if !inList(docSuffixes, strings.ToLower(pySuffix(d.Name()))) {
			return nil
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return pyPathLess(out[i], out[j]) })
	return out, nil
}

// pyPathLess is pathlib's PurePath ordering (CPython 3.14 compares the
// _parts_normcase tuples): part-by-part, not the raw string. This is why
// "a/b.md" sorts before "a.md" — the same order Python's sorted(rglob) uses.
func pyPathLess(a, b string) bool {
	pa, pb := strings.Split(a, "/"), strings.Split(b, "/")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return len(pa) < len(pb)
}

// pySuffix is pathlib's PurePath(name).suffix (CPython 3.14): leading dots
// are not part of the name's suffix ("..md" and ".md" have none), a trailing
// dot is one ("a." → ".").
func pySuffix(name string) string {
	if name == "" {
		return ""
	}
	lead := 0
	for lead < len(name) && name[lead] == '.' {
		lead++
	}
	if lead == len(name) {
		return ""
	}
	i := strings.LastIndexByte(name, '.')
	if i < lead {
		return ""
	}
	return name[i:]
}

// invDocMatches is _INV_DOC_RE.finditer with CPython's Unicode \b and
// leftmost non-overlapping scanning.
func invDocMatches(line string) []string {
	s := []rune(line)
	var out []string
	for i := 0; i+4 <= len(s); {
		if !(s[i] == 'I' && s[i+1] == 'N' && s[i+2] == 'V' && s[i+3] == '-') {
			i++
			continue
		}
		if i > 0 && pyWordChar(s[i-1]) {
			i++
			continue
		}
		start := i + 4
		k := start
		for k < len(s) && s[k] >= '0' && s[k] <= '9' {
			k++
		}
		if k == start {
			i++
			continue
		}
		if k-start > 4 || (k < len(s) && pyWordChar(s[k])) {
			i = k
			continue
		}
		out = append(out, "INV-"+string(s[start:k]))
		i = k
	}
	return out
}

// pyWordChar is Python's \w: letters, any numeric category, underscore.
func pyWordChar(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r)
}

// ---- intent claims -------------------------------------------------------

// intentLiterals is the fixed-literal alternatives of _INTENT_RE (the ones
// without internal boundaries).
var intentLiterals = []string{
	"as intended", "expected behavior", "expected outcome",
	"accrue", "accrual", "designed to", "meant to", "meant for",
}

// IntentClaims is intent_claims: documented invariants whose statement or
// its ±3-line context carries intent language.
func IntentClaims(c *state.Campaign, snapshotID *string) (validation.Value, error) {
	sid := ""
	if snapshotID != nil {
		sid = *snapshotID
	} else {
		id, err := c.ActiveSnapshotIDOrNone()
		if err != nil {
			return validation.VNull(), err
		}
		if id != nil {
			sid = *id
		}
	}
	if sid == "" {
		return validation.VObj(), nil
	}
	root := filepath.Join(c.Dir, "snapshots", sid)
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return validation.VObj(), nil
	}
	files, err := docFiles(root)
	if err != nil {
		return validation.VNull(), err
	}
	out := validation.VObj()
	for _, rel := range files {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			continue
		}
		lines := pySplitLines(decodeUTF8Replace(raw))
		for i, line := range lines {
			for _, raw := range invDocMatches(line) {
				iid := NormalizeInvID(raw) // Python: f"INV-{int(digits)}"
				if hasKey(out, iid) {
					continue
				}
				lo := i - 3
				if lo < 0 {
					lo = 0
				}
				hi := i + 3
				if hi > len(lines) {
					hi = len(lines)
				}
				for _, wl := range lines[lo:hi] {
					if !intentSearch(wl) {
						continue
					}
					out.O = append(out.O, pair(iid, validation.VObj(
						pair("file", validation.VStr(rel)),
						pair("line", validation.VInt(int64(i+1))),
						pair("context", validation.VStr(pyHead(pyStrip(line), 200))),
						pair("intent_line", validation.VStr(pyHead(pyStrip(wl), 200))),
					)))
					break
				}
			}
		}
	}
	return out, nil
}

// intentSearch is _INTENT_RE.search with CPython's Unicode \b semantics.
func intentSearch(line string) bool {
	s := []rune(line)
	for i := range s {
		if i > 0 && pyWordChar(s[i-1]) {
			continue
		}
		if !pyWordChar(s[i]) {
			continue
		}
		if intentAt(s, i) {
			return true
		}
	}
	return false
}

// intentAt tries every alternative anchored at s[i] (whose leading \b the
// caller already checked).
func intentAt(s []rune, i int) bool {
	for _, lit := range intentLiterals {
		if matchLit(s, i, lit) && boundAfter(s, i+len([]rune(lit))) {
			return true
		}
	}
	if matchLit(s, i, "by design") && boundAfter(s, i+9) {
		return true
	}
	if matchLit(s, i, "by-design") && boundAfter(s, i+9) {
		return true
	}
	if matchLit(s, i, "intentional") {
		if matchLit(s, i+11, "ly") && boundAfter(s, i+13) {
			return true
		}
		if boundAfter(s, i+11) {
			return true
		}
	}
	if matchLit(s, i, "not a ") {
		for _, w := range []string{"bug", "vulnerability", "concern"} {
			if matchLit(s, i+6, w) && boundAfter(s, i+6+len([]rune(w))) {
				return true
			}
		}
	}
	return donationAt(s, i)
}

// donationAt is the `donation(?:s)?\b.{0,40}\b(?:accrue|staker)` branch.
func donationAt(s []rune, i int) bool {
	if !matchLit(s, i, "donation") {
		return false
	}
	q := i + 8
	var starts []int
	if q < len(s) && (s[q] == 's' || s[q] == 'S') && boundAfter(s, q+1) {
		starts = append(starts, q+1)
	}
	if boundAfter(s, q) {
		starts = append(starts, q)
	}
	for _, r := range starts {
		for m := r; m <= r+40 && m <= len(s); m++ {
			if m == 0 || pyWordChar(s[m-1]) {
				continue
			}
			if matchLit(s, m, "accrue") && boundAfter(s, m+6) {
				return true
			}
			if matchLit(s, m, "staker") && boundAfter(s, m+6) {
				return true
			}
		}
	}
	return false
}

// matchLit is a case-insensitive literal match at s[i] (simple folding, the
// same relation CPython's re.IGNORECASE uses for these ASCII literals).
func matchLit(s []rune, i int, lit string) bool {
	l := []rune(lit)
	if i < 0 || i+len(l) > len(s) {
		return false
	}
	for j, r := range l {
		if !foldEq(s[i+j], r) {
			return false
		}
	}
	return true
}

// foldEq is Unicode simple case folding equality.
func foldEq(a, b rune) bool {
	if a == b {
		return true
	}
	for r := unicode.SimpleFold(a); r != a; r = unicode.SimpleFold(r) {
		if r == b {
			return true
		}
	}
	return false
}

// boundAfter is `\b` at index j: end of text or a non-word character next.
func boundAfter(s []rune, j int) bool {
	return j >= len(s) || !pyWordChar(s[j])
}

// ---- anchors and reconciliation ------------------------------------------

// DocumentedRef is documented_ref: the canonical “file#Lline“ anchor for a
// documented invariant id, or nil.
func DocumentedRef(c *state.Campaign, invariantID string,
	snapshotID *string) (*string, error) {
	doc, err := DocumentedInvariants(c, snapshotID)
	if err != nil {
		return nil, err
	}
	entry := objAt(doc, NormalizeInvID(invariantID))
	if entry.Kind != validation.Obj || len(entry.O) == 0 {
		return nil, nil
	}
	ref := objStr(entry, "file") + "#L" +
		strconv.FormatInt(objAt(entry, "line").I, 10)
	return &ref, nil
}

// Reconcile is reconcile: cross-check the model's invariants against the
// protocol's OWN documentation and log the divergence.
func Reconcile(c *state.Campaign, model validation.Value) (validation.Value, error) {
	doc, err := DocumentedInvariants(c, nil)
	if err != nil {
		return validation.VNull(), err
	}
	modelIDs := map[string]struct{}{}
	for _, inv := range objAt(model, "invariants").A {
		idV, ok := fieldAt(inv, "id")
		if !ok {
			return validation.VNull(), fmt.Errorf("'id'")
		}
		modelIDs[NormalizeInvID(pyStr(idV))] = struct{}{}
	}
	docIDs := keySet(doc)
	missing := sortedDiff(docIDs, modelIDs)
	extra := sortedDiff(modelIDs, docIDs)
	note := "model covers every documented invariant id"
	if len(missing) > 0 {
		note = "the model should inherit the protocol's documented invariant " +
			"ids (INV-1..N) so findings and the spec point at the same invariant"
	}
	rep := validation.VObj(
		pair("documented", strArr(sortedKeys(docIDs))),
		pair("in_model", strArr(sortedKeys(modelIDs))),
		pair("missing_from_model", strArr(missing)),
		pair("extra_in_model", strArr(extra)),
		pair("documentation", doc),
		pair("note", validation.VStr(note)),
	)
	data := validation.VObj(
		pair("documented", strArr(sortedKeys(docIDs))),
		pair("missing_from_model", strArr(missing)),
		pair("extra_in_model", strArr(extra)),
	)
	if _, err := c.Log("invariants.reconciled", nil, &data); err != nil {
		return validation.VNull(), err
	}
	return rep, nil
}

func keySet(v validation.Value) map[string]struct{} {
	out := map[string]struct{}{}
	for _, e := range v.O {
		out[e.K] = struct{}{}
	}
	return out
}

func sortedKeys(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedDiff(a, b map[string]struct{}) []string {
	out := []string{}
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// ---- text helpers --------------------------------------------------------

// pySplitLines is str.splitlines(): every Unicode line boundary, and no
// trailing empty string after a final break.
func pySplitLines(s string) []string {
	var out []string
	var cur []rune
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == '\r':
			if i+1 < len(rs) && rs[i+1] == '\n' {
				i++
			}
			out = append(out, string(cur))
			cur = nil
		case r == '\n' || r == '\v' || r == '\f' || r == '\x1c' ||
			r == '\x1d' || r == '\x1e' || r == '\x85' ||
			r == '\u2028' || r == '\u2029':
			out = append(out, string(cur))
			cur = nil
		default:
			cur = append(cur, r)
		}
	}
	if len(cur) > 0 {
		out = append(out, string(cur))
	}
	return out
}

// pySpace is str.isspace(): Unicode whitespace plus the C0 separators
// \x1c..\x1f that unicode.IsSpace does not cover.
func pySpace(r rune) bool {
	return r == '\x1c' || r == '\x1d' || r == '\x1e' || r == '\x1f' ||
		unicode.IsSpace(r)
}

// pyStrip is str.strip().
func pyStrip(s string) string { return strings.TrimFunc(s, pySpace) }

// pyHead is s[:n] (a code-point slice, never splitting a rune).
func pyHead(s string, n int) string {
	if n <= 0 {
		return ""
	}
	i := 0
	for k := range s {
		if i == n {
			return s[:k]
		}
		i++
	}
	return s
}

// decodeUTF8Replace is bytes.decode("utf-8", errors="replace") using the
// Unicode maximal-subpart rule (one U+FFFD per invalid subsequence, exactly
// as CPython reports it).
func decodeUTF8Replace(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); {
		r, size := utf8.DecodeRune(b[i:])
		if r != utf8.RuneError || size > 1 {
			sb.WriteRune(r)
			i += size
			continue
		}
		sb.WriteRune(utf8.RuneError)
		i += maximalSubpart(b[i:])
	}
	return sb.String()
}

// maximalSubpart is the number of bytes of an invalid UTF-8 sequence that
// belong to one replacement character.
func maximalSubpart(b []byte) int {
	if len(b) == 0 {
		return 1
	}
	b0 := b[0]
	var need int
	var lo, hi byte = 0x80, 0xbf
	switch {
	case b0 >= 0xc2 && b0 <= 0xdf:
		need = 1
	case b0 >= 0xe0 && b0 <= 0xef:
		need = 2
		if b0 == 0xe0 {
			lo = 0xa0
		}
		if b0 == 0xed {
			hi = 0x9f
		}
	case b0 >= 0xf0 && b0 <= 0xf4:
		need = 3
		if b0 == 0xf0 {
			lo = 0x90
		}
		if b0 == 0xf4 {
			hi = 0x8f
		}
	default:
		return 1
	}
	n := 1
	for ; n <= need && n < len(b); n++ {
		c := b[n]
		if c < lo || c > hi {
			return n
		}
		lo, hi = 0x80, 0xbf
	}
	return n
}

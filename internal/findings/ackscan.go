// ackscan.go: A2 — in-code acknowledgement matcher.
//
// A finding that lives in code the owner has already acknowledged
// ("// TODO", "not implemented", a stub, a placeholder) is less likely to be
// accepted as a bounty: the acknowledgement is evidence the behavior is known
// and intended (for now). ScanInCodeAck scans the pinned source around every
// anchor of the finding (the affected file/function/lines and the
// exploit_sequence call sites, resolved through the structural index artifact
// when present) for such phrases and, on a hit, records
// finding.dedup_meta.in_code_ack {file, line, phrase, window} — the data the
// gate advisory, the A3 acceptance score and the report quote all read.
//
// The scan is deterministic and model-free. A clean no-hit is a successful
// scan (hit=false): RecordAckScan then CLEARS a previously stored record, so
// a re-scan is idempotent. A scan that could not run at all (no source pin,
// missing snapshot, no resolvable anchor) returns an error and leaves the
// finding untouched.
package findings

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// AckWindow is the ±N lines scanned around each anchor (A2 spec: 12).
const AckWindow = 12

// ackPhrases is the acknowledgement vocabulary (case-insensitive,
// word-bounded). Order matters: for one line the FIRST matching phrase wins,
// so the multi-word, most specific phrases come first.
var ackPhrases = []string{
	"not implemented", "pending impl", "unimplemented",
	"for testing", "not yet",
	"stub", "placeholder", "todo", "fixme", "hack",
	"simplified", "temporary",
}

// ackPatterns is ackPhrases pre-compiled with word boundaries ("hackathon"
// must not match "hack", "todos" must not match "todo").
var ackPatterns = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(ackPhrases))
	for _, p := range ackPhrases {
		out = append(out, regexp.MustCompile(
			`(?i)\b`+regexp.QuoteMeta(p)+`\b`))
	}
	return out
}()

// AckRecord is the in_code_ack value stored on finding.dedup_meta.
func AckRecord(file string, line int, phrase string, window int) validation.Value {
	return validation.VObj(
		validation.KV{K: "file", V: validation.VStr(file)},
		validation.KV{K: "line", V: validation.VInt(int64(line))},
		validation.KV{K: "phrase", V: validation.VStr(phrase)},
		validation.KV{K: "window", V: validation.VStr(strconv.Itoa(window))},
	)
}

type ackAnchor struct {
	file string // relative to the snapshot root (or absolute)
	line int    // 1-based
}

// ScanInCodeAck scans the pinned source for in-code acknowledgements around
// the finding's anchors. Returns (hit, ack, err): hit=true with the ack
// record on a hit; hit=false with ack Null on a clean scan; err (with
// hit=false, ack Null) when no scan could run — the caller then records
// nothing.
func ScanInCodeAck(c *state.Campaign, f validation.Value) (bool,
	validation.Value, error) {
	root, err := ackSourceRoot(c, f)
	if err != nil {
		return false, validation.VNull(), err
	}
	anchors := ackCollectAnchors(c, f, root)
	if len(anchors) == 0 {
		return false, validation.VNull(), fmt.Errorf(
			"no scannable anchor (need affected[].lines, or a function " +
				"resolvable in the pin)")
	}
	for _, a := range anchors {
		hit, ack := ackScanFile(root, a)
		if hit {
			return true, ack, nil
		}
	}
	return false, validation.VNull(), nil
}

// RecordAckScan is the scan-and-record half: it runs ScanInCodeAck, stamps
// the finding.ack_scanned event, and — when the result differs from the
// stored record — updates finding.dedup_meta.in_code_ack (a hit replaces it,
// a clean no-hit clears it). A scan that cannot run returns its error and
// touches neither the finding nor the log.
func RecordAckScan(c *state.Campaign, findingID string) (bool, error) {
	f, err := LoadFinding(c, findingID)
	if err != nil {
		return false, err
	}
	hit, ack, err := ScanInCodeAck(c, f)
	if err != nil {
		return false, err
	}
	if hit {
		if _, ok := fieldAt(objAt(f, "dedup_meta"), "in_code_ack"); !ok {
			dm := objAt(f, "dedup_meta")
			if dm.Kind != validation.Obj {
				dm = validation.VObj()
			}
			dm.O = setOrAppend(dm.O, "in_code_ack", ack)
			f.O = setOrAppend(f.O, "dedup_meta", dm)
		} else {
			dm := objAt(f, "dedup_meta")
			dm.O = setOrAppend(dm.O, "in_code_ack", ack)
			f.O = setOrAppend(f.O, "dedup_meta", dm)
		}
	} else if cur, ok := fieldAt(objAt(f, "dedup_meta"), "in_code_ack"); ok &&
		cur.Kind != validation.Null {
		dm := objAt(f, "dedup_meta")
		kept := make([]validation.KV, 0, len(dm.O))
		for _, kv := range dm.O {
			if kv.K != "in_code_ack" {
				kept = append(kept, kv)
			}
		}
		dm.O = kept
		f.O = setOrAppend(f.O, "dedup_meta", dm)
	}
	if err := SaveFinding(c, &f); err != nil {
		return false, err
	}
	data := validation.VObj(
		validation.KV{K: "finding_id", V: validation.VStr(findingID)},
		validation.KV{K: "hit", V: validation.VBool(hit)},
		validation.KV{K: "ack", V: ack},
	)
	if _, err := c.Log("finding.ack_scanned", &findingID, &data); err != nil {
		return false, err
	}
	return hit, nil
}

// ackSourceRoot resolves the pinned source root for the finding's source
// snapshot id.
func ackSourceRoot(c *state.Campaign, f validation.Value) (string, error) {
	sid := objStr(objAt(f, "snapshot_ids"), "source")
	if sid == "" || sid == "unpinned" {
		return "", fmt.Errorf("finding has no source pin")
	}
	snapPath := filepath.Join(c.Dir, "snapshots", sid, "snapshot.json")
	snap, err := validation.ReadJson(snapPath)
	if err != nil {
		return "", fmt.Errorf("source pin %s not readable: %v", sid, err)
	}
	root := objStr(objAt(snap, "source"), "root")
	if root == "" {
		return "", fmt.Errorf("source pin %s has no root", sid)
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("source pin %s root missing: %s", sid, root)
	}
	return root, nil
}

// ackCollectAnchors gathers the scan anchors in a deterministic order: the
// affected file/function/lines first (entry order, line order), then the
// exploit_sequence call sites — "Contract.function" strings resolved through
// the structural index artifact when one is present. Duplicate file:line
// anchors are dropped.
func ackCollectAnchors(c *state.Campaign, f validation.Value,
	root string) []ackAnchor {
	var out []ackAnchor
	seen := map[string]struct{}{}
	add := func(file, function string, lines []int64) {
		if file == "" {
			return
		}
		if len(lines) == 0 {
			ln := ackFunctionLine(root, file, function)
			if ln == 0 {
				return
			}
			lines = []int64{int64(ln)}
		}
		for _, ln := range lines {
			if ln < 1 {
				continue
			}
			key := file + ":" + strconv.FormatInt(ln, 10)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, ackAnchor{file: file, line: int(ln)})
		}
	}
	aff := objAt(f, "affected")
	if aff.Kind == validation.Arr {
		for _, item := range aff.A {
			var lines []int64
			if lv := objAt(item, "lines"); lv.Kind == validation.Arr {
				for _, v := range lv.A {
					lines = append(lines, v.I)
				}
			}
			add(objStr(item, "path"), objStr(item, "function"), lines)
		}
	}
	if idx := ackIndexContracts(c); len(idx) > 0 {
		seq := objAt(f, "exploit_sequence")
		if seq.Kind == validation.Arr {
			for _, step := range seq.A {
				calls := objAt(step, "calls")
				if calls.Kind != validation.Arr {
					continue
				}
				for _, cv := range calls.A {
					call := cv.S
					i := strings.LastIndex(call, ".")
					if i <= 0 || i == len(call)-1 {
						continue
					}
					contract, fn := call[:i], call[i+1:]
					if path, ok := idx[contract]; ok {
						add(path, fn, nil)
					}
				}
			}
		}
	}
	return out
}

// ackIndexContracts loads the structural index artifact (when present) as a
// contract-name → file-path map (first definition wins, in artifact order).
func ackIndexContracts(c *state.Campaign) map[string]string {
	raw, err := os.ReadFile(
		filepath.Join(c.ArtifactsDir, "structural_index.json"))
	if err != nil {
		return nil
	}
	var doc struct {
		Nodes []struct {
			Kind string `json:"kind"`
			Name string `json:"name"`
			Path string `json:"path"`
		} `json:"nodes"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	out := map[string]string{}
	for _, n := range doc.Nodes {
		if n.Kind == "contract" && n.Name != "" && n.Path != "" {
			if _, ok := out[n.Name]; !ok {
				out[n.Name] = n.Path
			}
		}
	}
	return out
}

// ackFunctionLine finds the definition line of function in root/file —
// `function name(` (Solidity) or `def name(` (Python) — or 0 when absent.
func ackFunctionLine(root, file, function string) int {
	if function == "" {
		return 0
	}
	p := file
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	// [ \t]* (not \s*): the indent must not cross a newline, or the match
	// start — and the counted line — would drift to the previous line.
	re := regexp.MustCompile(`(?m)^[ \t]*(?:function\s+|def\s+)` +
		regexp.QuoteMeta(function) + `[ \t]*\(`)
	loc := re.FindIndex(raw)
	if loc == nil {
		return 0
	}
	return strings.Count(string(raw)[:loc[0]], "\n") + 1
}

// ackScanFile scans the ±AckWindow window around a.line in the anchor file
// (absolute or relative to the snapshot root). Returns (true, ack) for the
// first matching line; a file missing from the pin is a clean no-hit (the
// anchor is unresolvable, not a failure).
func ackScanFile(root string, a ackAnchor) (bool, validation.Value) {
	p := a.file
	if !filepath.IsAbs(p) {
		p = filepath.Join(root, p)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return false, validation.VNull()
	}
	lines := strings.Split(string(raw), "\n")
	lo := a.line - AckWindow
	if lo < 1 {
		lo = 1
	}
	hi := a.line + AckWindow
	if hi > len(lines) {
		hi = len(lines)
	}
	for i := lo; i <= hi; i++ {
		line := lines[i-1]
		for j, re := range ackPatterns {
			if re.MatchString(line) {
				return true, AckRecord(ackRelPath(root, p), i,
					ackPhrases[j], AckWindow)
			}
		}
	}
	return false, validation.VNull()
}

// ackRelPath renders the hit file relative to the pin root when it is under
// it, absolute otherwise.
func ackRelPath(root, p string) string {
	if rel, err := filepath.Rel(root, p); err == nil &&
		!strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return p
}

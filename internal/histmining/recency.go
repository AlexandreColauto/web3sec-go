// recency.go: recency-weighted prioritization — fresh + exposed files first.
// Advisory only (K1): it never gates a finding.
package histmining

import (
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"websec/internal/state"
	"websec/internal/validation"
)

var assetVarRe = regexp.MustCompile(
	`(?i)\b(balance|reserve|total(supply|assets)|share|price|fee)\b`)

// LogCap is _LOG_CAP: how many most-recent commits are scanned for file
// mtimes.
const LogCap = 300

// RecencyWindowDays is _RECENCY_WINDOW_DAYS: the scoring horizon in days.
// Files last touched outside the horizon score 0.0; files beyond the commit
// cap are indistinguishable from never-tracked (both score 0.0).
const RecencyWindowDays = 90

// IndexAPI is the seam to webv2.structural_index (P3). recency_scores calls
// exactly two of its functions:
//
//	EnsureFreshIndex  ensure_fresh_index(campaign, snapshot_root) -> index
//	SinkFunctions    sink_functions(index) -> value-moving function nodes
//
// The default is the absent-module behavior: an explicit error. Python has
// no "module missing" path, so the honest feature-absent behavior is to fail
// loudly instead of scoring a phantom file set.
type IndexAPI struct {
	EnsureFreshIndex func(c *state.Campaign, snapshotRoot string) (validation.Value, error)
	SinkFunctions    func(index validation.Value) []validation.Value
	// WritersOf is C0's reconciled writer list (the parser's writes_storage
	// omits statement-level writes); nil restores the absent-module default.
	WritersOf func(index, node validation.Value) []string
}

func notWiredIndex(*state.Campaign, string) (validation.Value, error) {
	return validation.VNull(), errIndexNotWired
}

func notWiredSinks(validation.Value) []validation.Value { return nil }

// rawWriters is the pre-C0 writer list (the parser's writes_storage, untouched).
// It is the default when a caller wires the index but not the C0
// reconciliation, so an incompletely wired IndexAPI keeps the reference
// behaviour instead of silently reporting that nothing writes storage.
func rawWriters(_ validation.Value, n validation.Value) []string {
	out := []string{}
	for _, v := range objAt(n, "writes_storage").A {
		if v.Kind == validation.Str {
			out = append(out, v.S)
		}
	}
	return out
}

var indexAPI = IndexAPI{
	EnsureFreshIndex: notWiredIndex,
	SinkFunctions:    notWiredSinks,
	WritersOf:        rawWriters,
}

// SetIndexAPI installs the structural_index implementation (the P3 structidx
// port wires this). A nil argument — or a nil field — restores the
// absent-module default.
func SetIndexAPI(api IndexAPI) {
	if api.EnsureFreshIndex == nil {
		api.EnsureFreshIndex = notWiredIndex
	}
	if api.SinkFunctions == nil {
		api.SinkFunctions = notWiredSinks
	}
	if api.WritersOf == nil {
		api.WritersOf = rawWriters
	}
	indexAPI = api
}

// errIndexNotWired is the absent-module error.
var errIndexNotWired = notWiredError(
	"structural_index module not wired: cannot score recency")

// RecencyScores is recency_scores: score every source file in the snapshot
// tree by (days since last change) x (exposure weight). Writes the recency
// artifact. A stale stored index is rebuilt first (ensure_fresh_index), so
// the file set — and every downstream score — tracks the active pin.
// recencyLogFormat is git log's pretty format for the recency walk.
const recencyLogFormat = `--pretty=format:@%H%x00%ad`

func RecencyScores(c *state.Campaign, target, snapshotRoot string) (
	validation.Value, error) {
	idx, err := indexAPI.EnsureFreshIndex(c, snapshotRoot)
	if err != nil {
		return validation.VNull(), err
	}
	var fns []validation.Value
	for _, n := range objAt(idx, "nodes").A {
		if objStr(n, "kind") == "function" {
			fns = append(fns, n)
		}
	}
	sinkFiles := map[string]bool{}
	for _, s := range indexAPI.SinkFunctions(idx) {
		sinkFiles[strings.SplitN(objStr(s, "function_id"), "#", 2)[0]] = true
	}
	assetWriterFiles := map[string]bool{}
	for _, n := range fns {
		// C0: reconciled writers (the raw writes_storage omits statement writes).
		for _, v := range indexAPI.WritersOf(idx, n) {
			if assetVarRe.MatchString(v) {
				assetWriterFiles[strings.SplitN(objStr(n, "id"), "#", 2)[0]] = true
				break
			}
		}
	}
	entryFiles := map[string]bool{}
	for _, n := range fns {
		if truthy(objAt(n, "is_entry_point")) {
			entryFiles[objStr(n, "path")] = true
		}
	}

	// one pass over the git log: file -> most recent commit date
	raw := Git(target, "log", "-n", strconv.Itoa(LogCap), recencyLogFormat,
		"--date=short", "--name-only")
	lastChanged := map[string]string{}
	curDate := ""
	for _, line := range splitLines(raw) {
		if strings.HasPrefix(line, "@") {
			parts := strings.SplitN(line[1:], "\x00", 2)
			if len(parts) == 2 {
				curDate = parts[1]
			} else {
				curDate = ""
			}
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && curDate != "" {
			if _, seen := lastChanged[trimmed]; !seen {
				lastChanged[trimmed] = curDate
			}
		}
	}

	now := time.Now().UTC()
	paths := []string{}
	seenPath := map[string]bool{}
	for _, n := range objAt(idx, "nodes").A {
		p := objStr(n, "path")
		if p == "" || seenPath[p] {
			continue
		}
		seenPath[p] = true
		paths = append(paths, p)
	}
	sort.Strings(paths)
	filesOut := []validation.Value{}
	changedInWindow := int64(0)
	for _, path := range paths {
		weight := 0.25
		if sinkFiles[path] || assetWriterFiles[path] {
			weight = 1.0
		} else if entryFiles[path] {
			weight = 0.5
		}
		changed, hasChanged := lastChanged[path]
		var daysAgo *int64
		score := 0.0
		if hasChanged {
			if d, err := time.Parse("2006-01-02", changed); err == nil {
				days := int64(now.Sub(d).Hours() / 24)
				daysAgo = &days
				score = validation.PythonRound(weight*maxF(0,
					1-float64(days)/RecencyWindowDays), 4)
				if days <= RecencyWindowDays {
					changedInWindow++
				}
			}
		}
		var changedV validation.Value = validation.VNull()
		if hasChanged {
			changedV = validation.VStr(changed)
		}
		var daysV validation.Value = validation.VNull()
		if daysAgo != nil {
			daysV = validation.VInt(*daysAgo)
		}
		filesOut = append(filesOut, validation.VObj(
			validation.KV{K: "path", V: validation.VStr(path)},
			validation.KV{K: "last_changed", V: changedV},
			validation.KV{K: "days_ago", V: daysV},
			validation.KV{K: "exposure_weight", V: validation.VFloat(weight)},
			validation.KV{K: "score", V: validation.VFloat(score)},
		))
	}
	sort.SliceStable(filesOut, func(i, j int) bool {
		si, sj := floatField(filesOut[i], "score"), floatField(filesOut[j], "score")
		if si != sj {
			return si > sj
		}
		return objStr(filesOut[i], "path") < objStr(filesOut[j], "path")
	})
	hot := filesOut
	if len(hot) > 25 {
		hot = hot[:25]
	}
	snapID, err := c.ActiveSnapshotIDOrNone()
	if err != nil {
		return validation.VNull(), err
	}
	snapV := "unpinned"
	if snapID != nil {
		snapV = *snapID
	}
	report := validation.VObj(
		validation.KV{K: "generated_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "snapshot_id", V: validation.VStr(snapV)},
		validation.KV{K: "target", V: validation.VStr(target)},
		validation.KV{K: "files", V: validation.VArr(filesOut...)},
		validation.KV{K: "hot_files", V: validation.VArr(hot...)},
		validation.KV{K: "stats", V: validation.VObj(
			validation.KV{K: "files", V: validation.VInt(int64(len(filesOut)))},
			validation.KV{K: "changed_in_window",
				V: validation.VInt(changedInWindow)},
			validation.KV{K: "scanned_commits", V: validation.VInt(LogCap)})},
	)
	out := filepath.Join(c.ArtifactsDir, "recency.json")
	if err := validation.WriteJson(out, report, ""); err != nil {
		return validation.VNull(), err
	}
	reason := strconv.Itoa(len(filesOut)) + " files scored"
	if _, err := c.RegisterOrRefresh("recency", out, "", nil, reason); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(validation.KV{K: "files",
		V: validation.VInt(int64(len(filesOut)))})
	if _, err := c.Log("recency.scored", nil, &data); err != nil {
		return validation.VNull(), err
	}
	return report, nil
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// truthy is Python's bool() for the JSON scalars the index holds.
func truthy(v validation.Value) bool {
	switch v.Kind {
	case validation.Bool:
		return v.B
	case validation.Str:
		return v.S != ""
	case validation.Int:
		return v.I != 0
	case validation.Flt:
		return v.F != 0
	case validation.Arr:
		return len(v.A) > 0
	case validation.Obj:
		return len(v.O) > 0
	}
	return false
}

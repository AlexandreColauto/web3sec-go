package cli

// hints.go — B9: the capped, suppressible write-time hygiene note.
//
// WHAT IT IS. On a SUCCESSFUL write that carries a finding payload (`ingest
// --json-file`, `mint`), the payload's affected[] files are resolved onto the
// campaign's canonical model paths through internal/anchorlink (the §B7
// read-side join — this file consumes that seam, it never re-derives it), and
// every UNDISPOSITIONED surface row and OPEN plan priority sharing one of
// those anchors is named on stderr: at most THREE lines, ranked by
// specificity, so the operator learns at write time that the code they just
// filed a finding about still carries an unanswered machine question. The
// round-1 near-miss is the counterfactual: a finding filed pre-reveal cited
// the same functions as an undispositioned tier-0 row and nothing said so.
//
// RANKING (most specific first):
//
//	tier 0  a surface row whose consumer/asserter IS the affected entry's
//	        function on the same path — an exact path#function match;
//	tier 1  a row or an open priority matching the PATH only, while the
//	        affected entry named a function (the payload is function-level,
//	        the store is not);
//	tier 2  a row or an open priority matching the PATH only, and the
//	        affected entry named no function either.
//
// Priorities can never reach tier 0: a plan priority carries components[]
// (contract names / lifecycle ids), no function coordinate.
//
// Within a tier rows come before priorities — a row is a concrete probe
// result, a priority is a question about one — ordered by the row's own
// surface tier, then rank, then row_id; priorities follow in id order. A
// priority that CLAIMS a row the note already names (probe.row_id) is not
// printed again: the row's line already ends in that priority's own `answered`
// command, so a second line would spend one of the three slots on the same
// obligation.
//
// SILENCE IS THE DEFAULT AND THE CONTRACT. Zero matches prints NOTHING, and so
// does an absent or unreadable protocol_model.json / probe_surface.json /
// campaign_plan.json: a hint never fails, blocks or rewrites a successful
// write, and the bytes of a hint-free run are exactly the bytes the same run
// printed before B9 (pinned by TestB9HintsSilentPathBytesUnchanged).
//
// SUPPRESSION. `--no-hints` on ingest and mint, or WEBV2_NO_HINTS=1 in the
// environment. The env switch honours the literal value 1 ONLY — "0", "true"
// and the empty string all leave the note on, because a learned-to-ignore note
// is worse than no note and the operator should be able to tell the two apart
// by reading the value they set. Both switches are documented in the verbs'
// help.
//
// STREAMS. Every line rides stderr, after the success bytes: stdout (the
// finding-id line, the --json document, the minted line) is untouched — the
// additive convention the rest of this CLI is pinned to. Exit codes are
// untouched too: the note cannot turn a successful write into a failure.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/anchorlink"
	"websec/internal/probes"
	"websec/internal/state"
	"websec/internal/validation"
)

// hintMaxLines is the cap: an uncapped file-level match floods (empirically a
// Rollup payload matches 7 rows + 12 priorities), and a flood is what the
// operator learns to ignore.
const hintMaxLines = 3

// hintWhyWidth is the "~60 chars" the row's why (or the priority's question)
// is truncated to, so one match is one line.
const hintWhyWidth = 60

// hintNoHintsEnv is the environment suppression switch and hintNoHintsValue
// the ONLY value that suppresses it.
const (
	hintNoHintsEnv   = "WEBV2_NO_HINTS"
	hintNoHintsValue = "1"
)

// The three specificity tiers (see the ranking table above).
const (
	hintTierFunction = iota
	hintTierPathWithFn
	hintTierPathNoFn
)

// The two store kinds a line may name.
const (
	hintRow      = "row"
	hintPriority = "priority"
)

// hintsSuppressed reports whether the note is off: the flag, or the
// environment switch set to exactly 1.
func hintsSuppressed(noHints bool) bool {
	return noHints || os.Getenv(hintNoHintsEnv) == hintNoHintsValue
}

// hintCandidate is one row/priority the note may name. tier is the
// specificity rank (lowest = most specific); claimID is the priority that
// claims a row through probe.row_id ("" when nothing claims it), which is
// both the row's acting command and the subsumption key.
type hintCandidate struct {
	kind    string
	id      string
	tier    int
	claimID string
	row     validation.Value
	prio    validation.Value
}

// emitWriteHints is the single entry point every write-time caller uses: it
// renders the capped note for the findings a successful write just produced,
// or prints nothing at all. It is void by design — a hint can never fail a
// write that already succeeded.
func emitWriteHints(c *state.Campaign, written []validation.Value,
	noHints bool, w io.Writer) {
	if hintsSuppressed(noHints) || len(written) == 0 {
		return
	}
	rows, prios, store, ok := hintJoin(c)
	if !ok {
		return
	}
	byKey := map[string]hintCandidate{}
	for _, f := range written {
		hintCollectFinding(store, rows, prios, f, byKey)
	}
	for _, line := range hintLines(c, byKey) {
		fmt.Fprintln(w, line)
	}
}

// hintJoin builds the anchorlink store over the campaign's three stores. ok is
// false — the whole note is skipped silently — when any of them is absent,
// unreadable, or not the shape anchorlink can index: a hint is never allowed
// to fail (or even to complain about) a write that succeeded.
func hintJoin(c *state.Campaign) (rows, prios []validation.Value,
	store *anchorlink.Store, ok bool) {
	model, err := validation.ReadJson(filepath.Join(c.ArtifactsDir,
		"protocol_model.json"))
	if err != nil {
		return nil, nil, nil, false
	}
	store, err = anchorlink.Open(model)
	if err != nil {
		return nil, nil, nil, false
	}
	surface, err := probes.CampaignSurface(c)
	if err != nil || surface == nil {
		return nil, nil, nil, false
	}
	plan, err := validation.ReadJson(filepath.Join(c.ArtifactsDir,
		"campaign_plan.json"))
	if err != nil {
		return nil, nil, nil, false
	}
	rows = t14List(*surface, "rows").A
	prios = t14List(plan, "priorities").A
	// The findings store is not indexed: the note compares the payload against
	// the surface and the plan only (the payload IS the finding under test).
	store.Index(rows, prios, nil)
	return rows, prios, store, true
}

// hintCollectFinding folds one finding's affected[] entries into byKey,
// keeping the most specific tier seen for each row/priority. Each entry is
// queried twice: path-only (which reaches rows and OPEN priorities alike) and,
// when the entry names a function, path#function (which reaches only the rows
// that anchor that function as their consumer/asserter).
func hintCollectFinding(store *anchorlink.Store, rows, prios []validation.Value,
	f validation.Value, byKey map[string]hintCandidate) {
	for _, a := range t14List(f, "affected").A {
		raw := validation.ObjStr(a, "path")
		if raw == "" {
			raw = validation.ObjStr(a, "file")
		}
		if raw == "" {
			continue
		}
		fn := validation.ObjStr(a, "function")
		pathTier := hintTierPathNoFn
		if fn != "" {
			pathTier = hintTierPathWithFn
		}
		path := store.Query(raw)
		for _, m := range path.Rows {
			if m.Dispositioned {
				continue // an answered row is not a hygiene note
			}
			hintRecord(byKey, hintRow, m.RowID, pathTier, rows, prios)
		}
		for _, id := range path.Priorities {
			hintRecord(byKey, hintPriority, id, pathTier, rows, prios)
		}
		if fn == "" {
			continue
		}
		for _, m := range store.Query(raw + "#" + fn).Rows {
			if m.Dispositioned {
				continue
			}
			hintRecord(byKey, hintRow, m.RowID, hintTierFunction, rows, prios)
		}
	}
}

// hintRecord keeps the most specific tier seen for one row/priority; a tie
// keeps the first sighting, so the note is deterministic.
func hintRecord(byKey map[string]hintCandidate, kind, id string, tier int,
	rows, prios []validation.Value) {
	if id == "" {
		return
	}
	key := kind + ":" + id
	if cur, seen := byKey[key]; seen && cur.tier <= tier {
		return
	}
	cand := hintCandidate{kind: kind, id: id, tier: tier}
	if kind == hintRow {
		cand.row = hintRowValue(rows, id)
		cand.claimID = hintClaimID(prios, id)
	} else {
		cand.prio = hintPriorityValue(prios, id)
	}
	byKey[key] = cand
}

// hintLines ranks, dedupes and caps the candidates, then renders them. The
// result holds at most hintMaxLines lines.
func hintLines(c *state.Campaign, byKey map[string]hintCandidate) []string {
	cands := make([]hintCandidate, 0, len(byKey))
	claimed := map[string]bool{}
	for _, cand := range byKey {
		cands = append(cands, cand)
		if cand.kind == hintRow && cand.claimID != "" {
			claimed[cand.claimID] = true
		}
	}
	// Subsumption: the row's line already names the priority that claims it.
	kept := cands[:0]
	for _, cand := range cands {
		if cand.kind == hintPriority && claimed[cand.id] {
			continue
		}
		kept = append(kept, cand)
	}
	sort.Slice(kept, func(i, j int) bool { return hintLess(kept[i], kept[j]) })
	if len(kept) > hintMaxLines {
		kept = kept[:hintMaxLines]
	}
	lines := make([]string, 0, len(kept))
	for _, cand := range kept {
		lines = append(lines, hintLine(c, cand))
	}
	return lines
}

// hintLess is the ranking order: specificity tier, then rows before
// priorities, then the row's own surface tier/rank/id (priorities by id).
func hintLess(a, b hintCandidate) bool {
	if a.tier != b.tier {
		return a.tier < b.tier
	}
	if a.kind != b.kind {
		return a.kind == hintRow
	}
	if a.kind == hintRow {
		if at, bt := objInt(a.row, "tier"), objInt(b.row, "tier"); at != bt {
			return at < bt
		}
		if ar, br := objInt(a.row, "rank"), objInt(b.row, "rank"); ar != br {
			return ar < br
		}
	}
	return a.id < b.id
}

// hintLine renders one match: the row/priority id, the one-line why, and the
// SMALLEST acting command. A row no priority claims is not yet a plan
// obligation — its smallest acting command is the emit that turns the surface
// into one; a claimed row is dispositioned through its claiming priority
// (which is where the required --anchor lives); a priority is closed directly.
// The placeholders are the ones the CLI's own refusals use (cmd_ingest_helpers'
// precheck names --anchor <field> the same way).
func hintLine(c *state.Campaign, cand hintCandidate) string {
	if cand.kind == hintRow {
		cmd := fmt.Sprintf("webv2 probes %s run --emit", c.CampaignID)
		if cand.claimID != "" {
			cmd = fmt.Sprintf("webv2 answered %s %s answered --reason '<why>' "+
				"--anchor <field>", c.CampaignID, cand.claimID)
		}
		return fmt.Sprintf("hint: row %s: %s — %s", cand.id, hintWhy(cand), cmd)
	}
	return fmt.Sprintf("hint: priority %s: %s — webv2 answered %s %s "+
		"answered --reason '<why>'", cand.id, hintWhy(cand), c.CampaignID, cand.id)
}

// hintWhy is the one-line why: the row's own `why` field, or the priority's
// question (falling back to its components), whitespace-collapsed and cut to
// hintWhyWidth runes.
func hintWhy(cand hintCandidate) string {
	var s string
	if cand.kind == hintPriority {
		s = validation.ObjStr(cand.prio, "question")
		if s == "" {
			s = t14Join(validation.ObjAt(cand.prio, "components"))
		}
		if s == "" {
			s = "(no question recorded)"
		}
	} else {
		s = validation.ObjStr(cand.row, "why")
		if s == "" {
			s = "(no why recorded)"
		}
	}
	return hintTrunc(s, hintWhyWidth)
}

// hintTrunc collapses runs of whitespace (a row's why is a sentence and may
// wrap) and cuts to width RUNES, so a multi-byte character is never split.
func hintTrunc(s string, width int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	return string(r[:width]) + "…"
}

// hintRowValue is the surface row with this row_id (the zero Value when the
// surface does not carry it — the note still names the id).
func hintRowValue(rows []validation.Value, rowID string) validation.Value {
	for _, row := range rows {
		if validation.ObjStr(row, "row_id") == rowID {
			return row
		}
	}
	return validation.VNull()
}

// hintPriorityValue is the plan priority with this id.
func hintPriorityValue(prios []validation.Value, id string) validation.Value {
	for _, p := range prios {
		if validation.ObjStr(p, "id") == id {
			return p
		}
	}
	return validation.VNull()
}

// hintClaimID is the FIRST priority claiming the row through probe.row_id —
// the same rule anchorlink's rowDisposition and probes.RowDispositions use.
func hintClaimID(prios []validation.Value, rowID string) string {
	for _, p := range prios {
		prov := validation.ObjAt(p, "probe")
		if prov.Kind == validation.Obj &&
			validation.ObjStr(prov, "row_id") == rowID {
			return validation.ObjStr(p, "id")
		}
	}
	return ""
}

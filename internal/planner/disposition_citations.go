// disposition_citations.go: the B4 v3 structural layer — the citation
// rule (a dismissal must name something checkable) and its converse
// duty (every cited record must exist).
package planner

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// v3: the structural layer. v2 catches the WORDS a dismissal uses; v3 catches
// the case it generalises over — a high-risk row closed by prose that names
// nothing a reader can check. The row's own surface entry is the citation
// source: its contract, the consumer/function it is about, the base it
// inherits, the siblings it is symmetric to, the forward path it pays into.
// A reason that quotes one of those is falsifiable (go read the function); a
// reason that quotes none of them, and cites no refutation that runs, is the
// G-01 failure with better manners.
//
// The second half of v3 is the converse duty: an id the reason CITES must
// exist. A dismissal that "rests on F-1a2b3c4d5e6f" is either citing a real
// finding or inventing one, and the framework can tell the difference.
// ---------------------------------------------------------------------------

// rowSymbolKeys are the row fields that name something in the tree, in the
// order a refusal message should offer them (most specific first). Only
// strings and string lists are read; a missing field is simply absent.
var rowSymbolKeys = []string{
	"contract", "consumer", "base", "asserter", "custody",
	"concept_keys", "forward", "siblings", "members",
}

// genericSymbols are tokens a row carries that name no code: a custody verb or
// a boolean says nothing a reader can go and look at, so matching one is not a
// citation. Kept deliberately tiny — the point is to avoid a rubber stamp, not
// to second-guess an author's vocabulary.
var genericSymbols = map[string]bool{
	"true": true, "false": true,
	"burns": true, "mints": true, "forwards": true,
}

// RowSymbols is the checkable identity of a surface row: every contract,
// function, concept and sibling the row is about, in row order, deduplicated
// (case-insensitively) and with the empties dropped. A row with no symbols at
// all returns an empty list, and callers must then NOT enforce the citation
// rule — an unclosable row would be worse than an unverified one.
func RowSymbols(row validation.Value) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || len(v) < 3 || genericSymbols[strings.ToLower(v)] {
			return
		}
		key := strings.ToLower(v)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, v)
	}
	for _, key := range rowSymbolKeys {
		v := validation.ObjAt(row, key)
		switch v.Kind {
		case validation.Str:
			add(v.S)
		case validation.Arr:
			for _, e := range v.A {
				switch e.Kind {
				case validation.Str:
					add(e.S)
				case validation.Obj:
					add(validation.ObjStr(e, "contract"))
					add(validation.ObjStr(e, "name"))
				}
			}
		}
	}
	return out
}

// namesSymbol reports which row symbol the reason quotes ("" when none). The
// match is a case-insensitive substring: "L1ReverseCustomGateway" inside prose
// about L1ReverseCustomGateway is the citation we want, and demanding a
// formatting convention would only teach authors to game it.
func namesSymbol(reason string, symbols []string) string {
	low := strings.ToLower(reason)
	for _, sym := range symbols {
		if strings.Contains(low, strings.ToLower(sym)) {
			return sym
		}
	}
	return ""
}

var (
	findingIDPattern = regexp.MustCompile(`\bF-[0-9a-f]{12}\b`)
	execRefPattern   = regexp.MustCompile(`\bEXEC-[0-9a-f]{10}\b`)
	invRefPattern    = regexp.MustCompile(`\bINV-[0-9]+\b`)
)

// ghostCitation is the v3 converse duty: every finding/exec/invariant id the
// reason mentions must exist. It returns the first id that does not ("" when
// every citation resolves), so a dismissal cannot rest on a record that was
// never written — by typo or by invention.
func ghostCitation(campaign *state.Campaign, reason string) (string, error) {
	for _, id := range findingIDPattern.FindAllString(reason, -1) {
		if _, err := os.Stat(filepath.Join(campaign.FindingsDir,
			id+".json")); err != nil {
			return id, nil
		}
	}
	for _, id := range execRefPattern.FindAllString(reason, -1) {
		if _, err := os.Stat(filepath.Join(campaign.ExecsDir, id,
			"exec_record.json")); err != nil {
			return id, nil
		}
	}
	for _, id := range invRefPattern.FindAllString(reason, -1) {
		if !invariantRegistered(campaign, id) {
			return id, nil
		}
	}
	return "", nil
}

// checkCitedRecords is v3's converse duty at the closure seam: whatever the
// reason or the ref CITES must exist. It runs for every closing disposition
// (not only high-risk probe rows) because a citation that resolves to nothing
// is wrong at every tier — and because "rests on F-1a2b3c4d5e6f" is a claim
// the framework can actually check. Refutation-backed refs are covered by the
// same scan (refutationBacked is the positive form of it).
func checkCitedRecords(campaign *state.Campaign, priorityID, outcome string,
	opts AnsweredOpts) error {
	closing := outcome == "answered" || outcome == "not-applicable" ||
		outcome == "deprioritized" || outcome == "blocked"
	if !closing {
		return nil
	}
	fields := []struct {
		what string
		text *string
	}{{"closure reason", opts.Reason}, {"--ref", opts.Ref}}
	for _, f := range fields {
		if f.text == nil {
			continue
		}
		ghost, err := ghostCitation(campaign, *f.text)
		if err != nil {
			return err
		}
		if ghost != "" {
			return errValue("priority " + priorityID + ": the " + f.what +
				" cites " + ghost + ", which does not exist in this " +
				"campaign — a disposition may rest on a real finding, exec " +
				"record or registered invariant, never on a citation that " +
				"was invented or mistyped")
		}
	}
	return nil
}

// invariantRegistered is refutationBacked's invariant half, factored out so
// the citation scan and the refutation check cannot disagree about what
// "registered" means.
func invariantRegistered(campaign *state.Campaign, id string) bool {
	links, err := invariants.LoadLinks(campaign)
	if err != nil {
		return false
	}
	reg := validation.ObjAt(links, "invariants")
	return reg.Kind == validation.Obj && hasKey(reg, id)
}

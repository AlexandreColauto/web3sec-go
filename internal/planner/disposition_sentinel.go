// disposition_sentinel.go: the B4 v3 sentinel-form rule — a closing
// disposition of a sentinel-guarded row must name the value that passes
// the check, held to a shared plausibility floor.
package planner

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---------------------------------------------------------------------------
// B4 v3: the sentinel-form rule. v2 catches the WORDS; the citation layer
// catches prose that names nothing; this catches the one closure that is
// checkable and still wrong: "the row is safe because an assertion exists"
// when the guard is a zero-check. `stateRoot != bytes32(0)` cannot express the
// truth of the root — every non-zero value passes it — so a closing
// disposition of such a row has to name the value that DOES pass the check.
// ---------------------------------------------------------------------------

// checkPassesValue is FIX-E's always-on half of the --passes rule: whenever
// the flag is supplied — on any priority, any status, sentinel row or not —
// the value is shape-validated through the SAME plausibility floor the
// sentinel gate uses (passesPlausible), so the two paths cannot disagree
// about what a plausible value is. It runs AFTER checkSentinelPassesRow, so
// the sentinel gate's row-symbol refusal keeps firing on the rows it covers;
// this is the backstop on every route that gate stands down. A short value
// is a REFUSAL naming the >= 3 floor, never closePriority's silent drop;
// junk is refused naming the legal shapes. The value is read against the row
// the disposition points at where one resolves (the citation shape needs
// it); elsewhere the literal shapes and the junk lexicon are still enforced.
func checkPassesValue(campaign *state.Campaign, priorityID string,
	prov validation.Value, hasProv bool, opts AnsweredOpts) error {
	if opts.PassesValue == nil {
		return nil
	}
	v := strings.TrimSpace(*opts.PassesValue)
	var row validation.Value
	if hasProv {
		if surface, err := PB().CampaignSurface(campaign); err == nil &&
			surface != nil {
			row, _ = findRow(*surface, validation.ObjStr(prov, "row_id"))
		}
	}
	if passesPlausible(row, v) {
		return nil
	}
	head := "priority " + priorityID + ": --passes " +
		validation.PyReprStr(*opts.PassesValue) + " "
	if len(v) < 3 {
		return errValue(head + "is below the 3-character floor a passing " +
			"value has to clear — a placeholder is not a value the closure " +
			"record can re-check: name the value that passes the row's " +
			"check, or drop --passes")
	}
	return errValue(head + "is not a plausible value for the check — " +
		"either quote something the row's own surface entry names, or give " +
		"a concrete literal the closure record can re-check (a decimal " +
		"integer, a hex number or Ethereum-style address 0x…, " +
		"bytes32(0x…), a boolean, or an honest quoted string) — or drop " +
		"--passes")
}

// checkSentinelPasses is the B4 v3 rule: a closing disposition of a
// sentinel-guarded row (own_form=sentinel) must name the value that passes
// the check. Existence of an assertion is not correctness; the disposition
// has to be falsifiable. FIX-C adds the plausibility floor the flag needed:
// a >= 3-character string is not yet a value — "zzz", "TBD", "n/a" pass the
// length floor and record nothing checkable. The supplied value must either
// (a) name a symbol that exists on the row's own surface entry (the same
// citation muscle the v3 citation rule uses — RowSymbols/namesSymbol), or
// (b) be a concrete, machine-checkable literal: a decimal integer, a hex
// number or Ethereum-style address (0x…), a bytes32(0x…) literal, a boolean,
// or a quoted string literal. A hex literal is trusted as a CLAIMED value:
// the falsifiability comes from it being recorded on the closure and
// re-checkable by any reader, matching the framework's record-not-answer
// philosophy — the gate forces the question onto the record, it never
// pretends to evaluate the answer. The family escape hatch
// (--override-dismissal with --override-reason) stays the only way around
// the rule — see checkSentinelPassesRow.
func checkSentinelPasses(row validation.Value, outcome string,
	opts AnsweredOpts) error {
	if outcome != "answered" && outcome != "not-applicable" {
		return nil
	}
	if validation.ObjStr(row, "own_form") != "sentinel" {
		return nil
	}
	given := opts.PassesValue != nil
	if given && passesPlausible(row, *opts.PassesValue) {
		return nil
	}
	if !given || len(strings.TrimSpace(*opts.PassesValue)) < 3 {
		return errValue("sentinel-guarded probe row " + validation.ObjStr(row, "row_id") +
			": a closing disposition must name the value that passes its check " +
			"(--passes VALUE) — or override explicitly (--override-dismissal " +
			"--override-reason R)")
	}
	// A value was given and cleared the length floor but is neither a row
	// citation nor a concrete literal: refused, naming both legal shapes.
	syms := RowSymbols(row)
	shape := "either quote something the row's own surface entry names"
	if len(syms) > 0 {
		shape += " (" + strings.Join(syms, ", ") + ")"
	} else {
		shape += " — this row names no symbols, so a citation shape is not " +
			"available here"
	}
	return errValue("sentinel-guarded probe row " + validation.ObjStr(row, "row_id") +
		": --passes " + validation.PyReprStr(*opts.PassesValue) + " is not a " +
		"plausible value for the check — " + shape + ", or give a concrete " +
		"literal the closure record can re-check (a decimal integer, a hex " +
		"number or Ethereum-style address 0x…, bytes32(0x…), a boolean, or " +
		"a quoted string) — or override explicitly (--override-dismissal " +
		"--override-reason R)")
}

// junkPassesValues is the FIX-E junk lexicon, shared by both halves of the
// --passes floor: bare junk and the quoted-string arm of the literal
// alternation are held to the same standard, so `"TBD"` cannot smuggle the
// value in under quotes (round-3 chief item 5, problem 1). Whole-value,
// case-insensitive: an honest quoted literal that merely CONTAINS one of
// these words ("3 days of unresolved withdrawals") stays legal.
var junkPassesValues = map[string]bool{
	"tbd": true, "n/a": true, "na": true, "none": true, "unknown": true,
	"whatever": true, "asdf": true, "zzz": true, "xxx": true,
	"foo": true, "bar": true, "baz": true,
}

// passesLiteralRe is the FIX-C literal half of the --passes plausibility
// floor: the concrete, machine-checkable shapes a sentinel value may take
// without naming a row symbol. A literal is trusted as a claimed value (see
// checkSentinelPasses) — recorded, re-checkable, never evaluated here. The
// quoted-string arm is additionally excluded by junkPassesValues (see
// passesPlausible): a quoted junk word is a placeholder, not a value.
var passesLiteralRe = regexp.MustCompile(
	`(?i)^(?:-?[0-9]+|0[xX][0-9a-fA-F]+|bytes32\(0[xX][0-9a-fA-F]{64}\)|` +
		`true|false|"[^"]+"|'[^']+')$`)

// passesPlausible is the --passes floor, the ONE check both consumers share
// (FIX-E problem 2): the sentinel gate's acceptance and the always-on
// validation of a --passes supplied anywhere else must never disagree about
// what a plausible value is. A value is plausible when it names a symbol on
// the row's own surface entry (case-insensitive substring, the namesSymbol
// muscle), is a concrete literal (passesLiteralRe, junk-quoted forms
// excluded), or — on a row that names no symbols at all — is any honest
// literal; the >= 3 length floor is the caller's. A row with no symbols at
// all stays closable through the literal shapes — an unclosable row would be
// worse than an unverified one.
func passesPlausible(row validation.Value, v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < 3 {
		return false
	}
	if namesSymbol(v, RowSymbols(row)) != "" {
		return true
	}
	if !passesLiteralRe.MatchString(v) {
		return false
	}
	// The quoted arms pass the regex by shape; a quoted junk word is
	// refused with the bare forms (the lexicon is whole-value, so a quoted
	// sentence that contains a junk word is untouched).
	quoted := len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0]
	if quoted && junkPassesValues[strings.ToLower(v[1:len(v)-1])] {
		return false
	}
	return true
}

// checkSentinelPassesRow is the closure-seam half: it resolves the surface row
// the disposition points at and applies the rule to it. A probe disposition
// whose surface row cannot be resolved (no surface, or the row was re-emitted
// away) is skipped — the anchor path reports that more usefully, and a row
// nobody can look up must never become unclosable. The family escape hatch
// (--override-dismissal) answers a refusal here under the dismissal gate's
// own contract, never as a bare flag: the override carries its justification
// and is recorded as probe.dismissal_overridden (see overrideSentinelPasses).
func checkSentinelPassesRow(campaign *state.Campaign, priorityID,
	outcome string, prov validation.Value, hasProv bool, opts AnsweredOpts,
	dry bool) error {
	if !hasProv || !slices.Contains([]string{"answered", "not-applicable"}, outcome) {
		return nil
	}
	surface, err := PB().CampaignSurface(campaign)
	if err != nil {
		return err
	}
	if surface == nil {
		return nil
	}
	row, ok := findRow(*surface, validation.ObjStr(prov, "row_id"))
	if !ok {
		// FIX-3: the skip is announced, not silent (see
		// checkDismissalGateInner).
		if opts.SkipNotice != nil {
			*opts.SkipNotice = gateSkipNotice(priorityID,
				validation.ObjStr(prov, "row_id"), "sentinel-guard")
		}
		return nil
	}
	err = checkSentinelPasses(row, outcome, opts)
	if err == nil || !opts.OverrideDismissal {
		return err
	}
	return overrideSentinelPasses(campaign, priorityID, row,
		validation.ObjStr(prov, "row_id"), opts, dry)
}

// overrideSentinelPasses is the sentinel rule's override arm: the same
// contract checkDismissalGateInner applies on a high-risk row — the override
// carries its own justification, and the decision is recorded as
// probe.dismissal_overridden with the same provenance (row, tier, gap,
// actor, phrases, both reasons). dry (the batch pre-flight) validates the
// justification but records nothing, so a refused batch leaves zero events
// behind. One closure, one override event: on a HIGH-risk row the dismissal
// gate — which runs after this gate in runAnsweredGates, with the same opts
// — records the identical event, so the sentinel arm stays silent there and
// lets it.
func overrideSentinelPasses(campaign *state.Campaign, priorityID string,
	row validation.Value, rowID string, opts AnsweredOpts, dry bool) error {
	head := "priority " + priorityID + " (probe row " + rowID +
		", tier " + strconv.FormatInt(rowInt(row, "tier"), 10) +
		", assertion_gap " +
		strconv.FormatInt(rowInt(row, "assertion_gap"), 10) + ")"
	if opts.OverrideReason == nil ||
		strings.TrimSpace(*opts.OverrideReason) == "" {
		return errValue(head + ": --override-dismissal needs " +
			"--override-reason — the justification is logged with the " +
			"override (probe.dismissal_overridden)")
	}
	if HighRiskRow(row) && opts.Reason != nil {
		// the dismissal gate records the event — see the comment above.
		return nil
	}
	// FIX-8 dedupe, restated: a non-high-risk row is recorded HERE (the
	// dismissal gate's low-risk arm yields to this one for sentinel rows),
	// a high-risk row with a closure reason is recorded by the dismissal
	// gate (which runs after it with the same opts). The phrase list is the
	// closure reason's dismissal vocabulary — empty for a reason-less
	// override.
	phrases := []string{}
	if opts.Reason != nil {
		phrases = DismissalHits(*opts.Reason)
	}
	return recordOverrideEvent(campaign, priorityID, row, rowID,
		phrases, opts, dry)
}

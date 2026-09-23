package regression

import (
	"fmt"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// unmappedClass is the class Classify returns when no rule fires, and the key
// the label file's counts object carries for those rows. It is a legitimate
// value, not a failure: it is the bucket a human reviews (Step 7), which is
// why the review is recorded rather than implied.
const unmappedClass = "unmapped"

// LabelRule is one classification rule: a canonical class and the phrases
// whose presence in title+description assigns it. Phrases are matched
// case-folded, on word boundaries. The winner is the LONGEST matching phrase,
// and an EQUAL-LENGTH TIE GOES TO THE EARLIEST RULE IN THE TABLE — so a
// specific phrase beats a generic one only when it is strictly longer, and THE
// TABLE'S ORDER IS LOAD-BEARING: reordering two rules can silently change a
// committed label file. The case is reachable, not theoretical: "round down"
// (precision-rounding) and "spot price" (oracle-manipulation) are both ten
// bytes, so "Incorrect round down of the spot price in share math" takes
// oracle-manipulation only because that rule sits earlier.
// TestClassifyTieBreakFollowsTableOrder pins that outcome, so a reorder of
// those two rules goes red. Do not reorder this table casually — the order is
// part of the classification, and Task 4's selection consumes its output.
type LabelRule struct {
	Class   string
	Phrases []string
}

// LabelRules is §3a's derived bucketing, as data. It is deliberately a
// starting table: ScaBench's snapshot carries no labels, so the classification
// is ours and a named source of error (Part 10).
//
// THE TABLE CANNOT PRODUCE EIGHT CANONICAL CLASSES, and that is the property
// to know before trusting a label file: authorization, centralization-risk,
// chain-freeze, donation, frontend-injection, infra-boundary, sequencer-halt
// and share-price-accounting have no rule here. A row belonging to one of them
// is therefore never labelled with its own class, and when a neighbouring
// rule's phrase also fits its text it is bucketed into that class instead —
// so it does not even reach the `unmapped` bucket: "Sequencer halt ..." fires
// "halt" and lands in liveness although the taxonomy has a distinct
// sequencer-halt; "donation attack" lands in share-price-inflation although
// "donation" is canonical; "no authorization" and "anyone can call" land in
// access-control although "authorization" is canonical; chain-freeze is
// reachable only through liveness's "stuck"/"frozen funds". Step 7's review
// reads the `unmapped` bucket, which can only show MISSES — it cannot show
// this CONFLATION. The per-row `rule` key is the only way to audit it: it
// records the phrase that fired, so "donation attack -> share-price-inflation"
// is visible in the committed file even though the class is wrong. Review by
// rule, not only by unmapped bucket.
//
// TestLabelRulesCannotProduceTheUncoveredCanonicalClasses pins that set as a
// literal, so taxonomy drift — a class renamed, removed or added — forces a
// human back to this table rather than passing silently.
//
// The vocabulary pin lives in the TEST, not here:
// TestLabelRulesNameOnlyCanonicalClasses reads this table and
// taxonomy.CanonicalClasses() and fails on any Class the framework does not
// have — importing taxonomy from this file would only be for the doc
// reference, and an unused import does not compile.
//
// Extend it by reviewing the `unmapped` bucket in a labels file (Task 3 Step 7)
// and adding the phrases the review found — never by guessing at scale.
var LabelRules = []LabelRule{
	{Class: "reentrancy", Phrases: []string{
		"reentran", "re-entran", "read-only reentrancy", "callback reenters"}},
	{Class: "oracle-manipulation", Phrases: []string{
		"oracle manipul", "price manipul", "stale price", "stale oracle",
		"spot price", "twap manipulation"}},
	{Class: "share-price-inflation", Phrases: []string{
		"share inflation", "first depositor", "donation attack",
		"inflate the share", "exchange rate manipulation"}},
	{Class: "precision-rounding", Phrases: []string{
		"rounding", "round down", "precision loss", "truncat", "integer division",
		"off-by-one in the accounting"}},
	{Class: "access-control", Phrases: []string{
		"missing access control", "missing onlyowner", "unprotected function",
		"anyone can call", "no authorization", "permissionless call"}},
	{Class: "liquidation-logic", Phrases: []string{
		"liquidation", "bad debt", "insolven", "underwater position",
		"health factor"}},
	{Class: "cross-chain-replay", Phrases: []string{
		"replay", "message replay", "same signature", "nonce reuse",
		"cross-chain replay"}},
	{Class: "signature-replay", Phrases: []string{
		"signature malleab", "ecrecover", "permit replay"}},
	{Class: "unchecked-external-call", Phrases: []string{
		"unchecked call", "unchecked return", "ignores the return value",
		"low-level call"}},
	{Class: "dos-griefing", Phrases: []string{
		"denial of service", "grief", "block the withdrawal", "revert the loop",
		"unbounded loop"}},
	{Class: "liveness", Phrases: []string{
		"liveness", "stuck", "cannot withdraw", "frozen funds", "halt"}},
	{Class: "upgrade-initializer", Phrases: []string{
		"initializ", "uninitialized", "upgrade", "implementation slot"}},
	{Class: "bridge-message", Phrases: []string{
		"bridge", "cross-chain message", "message verification",
		"relayer", "merkle proof verification"}},
	{Class: "economic-invariant", Phrases: []string{
		"economic invariant", "invariant broken", "accounting mismatch",
		"supply mismatch"}},
	{Class: "flash-loan", Phrases: []string{"flash loan", "flashloan"}},
	{Class: "token-integration", Phrases: []string{
		"fee-on-transfer", "rebasing token", "erc20 with fee", "weird token"}},
	{Class: "logic-error", Phrases: []string{
		"wrong variable", "incorrect comparison", "logic error",
		"incorrect state update"}},
}

// Classify assigns one canonical class from title+description. It returns the
// class and the phrase that fired ("unmapped" when nothing did) so a label is
// always explainable. Longest phrase wins, then the earliest table position —
// a total order, so the result does not depend on map iteration.
func Classify(title, description string) (string, string) {
	hay := strings.ToLower(title + "\n" + description)
	bestClass, bestPhrase := "", ""
	for _, rule := range LabelRules {
		for _, p := range rule.Phrases {
			lp := strings.ToLower(strings.TrimSpace(p))
			if lp == "" || !containsWord(hay, lp) {
				continue
			}
			if len(lp) > len(bestPhrase) {
				bestClass, bestPhrase = rule.Class, p
			}
		}
	}
	if bestClass == "" {
		return unmappedClass, unmappedClass
	}
	return bestClass, bestPhrase
}

// containsWord reports whether needle occurs in hay at a WORD START: the byte
// before the match must not be a letter.
//
// The RIGHT edge is deliberately open, and that is not sloppiness: every phrase
// in LabelRules is a stem ("reentran", "re-entran", "truncat", "initializ",
// "manipul", "insolven", "grief", "halt"), and a stem's whole point is to match
// its own inflections ("reentrancy", "truncated", "initialization"). Closing the
// right edge — which an earlier draft of this function did — makes every stem
// unmatchable, so "Reentrancy in withdraw()" classifies as unmapped and the
// whole rule table silently stops firing. Closing the LEFT edge is what keeps a
// stem out of an unrelated token: "grounding" does not contain "rounding" and
// "asphalt" does not contain "halt".
func containsWord(hay, needle string) bool {
	for i := 0; ; {
		j := strings.Index(hay[i:], needle)
		if j < 0 {
			return false
		}
		start := i + j
		if start == 0 || !isLetter(hay[start-1]) {
			return true
		}
		i = start + 1
	}
}

func isLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// labelRowFields is the dataset's four fields verbatim (§3a: "exactly four
// fields per vulnerability") plus the project the extractor joins in, which
// selection needs. A row missing any of them is refused rather than classified.
var labelRowFields = []string{"finding_id", "project", "severity", "title", "description"}

// checkLabelRow refuses a row that does not carry every dataset field, so a
// schema drift in the snapshot surfaces here rather than as silently-unmapped
// rows.
func checkLabelRow(row validation.Value, i int) error {
	for _, k := range labelRowFields {
		if validation.ObjStr(row, k) == "" {
			return fmt.Errorf(
				"row %d is missing %s — ScaBench's curated snapshot has exactly "+
					"finding_id, severity, title, description (plus the project the "+
					"extractor joins in); anything else is a different dataset or a "+
					"different snapshot", i, k)
		}
	}
	return nil
}

// requireHighSeverity enforces the label file's scope: the snapshot's HIGH
// findings and nothing else. §3a's set-cover is over the 114 gold findings, so
// a medium row in here would inflate `gold_findings` and the coverage
// arithmetic. The snapshot's real severity vocabulary is
// high|medium|low|informational (114/237/184/20) — informational is NOT a typo
// and is the reason this guard cannot say "high|medium|low only".
func requireHighSeverity(row validation.Value, i int) error {
	sev := validation.ObjStr(row, "severity")
	if sev == "high" {
		return nil
	}
	return fmt.Errorf(
		"row %d (%s) has severity %q; this label file covers the snapshot's "+
			"high findings only — the 114 gold findings §3a's set-cover is "+
			"over. The snapshot's other rows (237 medium, 184 low, 20 "+
			"informational) are not labelled here; filter the extraction to "+
			"severity == \"high\"", i, validation.ObjStr(row, "finding_id"), sev)
}

// labelRow classifies one already-checked row into the label file's row shape:
// the dataset's fields plus the class and the rule that fired.
func labelRow(row validation.Value) validation.Value {
	class, rule := Classify(validation.ObjStr(row, "title"),
		validation.ObjStr(row, "description"))
	return validation.VObj(
		kv("finding_id", validation.VStr(validation.ObjStr(row, "finding_id"))),
		kv("project", validation.VStr(validation.ObjStr(row, "project"))),
		kv("severity", validation.VStr(validation.ObjStr(row, "severity"))),
		kv("class", validation.VStr(class)),
		kv("rule", validation.VStr(rule)),
	)
}

// classCounts is the ordered per-class tally: a class's FIRST appearance fixes
// its position, so the counts object is deterministic (and a rewrite of the
// same rows is byte-identical) without a sort or a map iteration.
type classCounts struct {
	order []string
	n     map[string]int
}

func (c *classCounts) add(class string) {
	if _, ok := c.n[class]; !ok {
		c.order = append(c.order, class)
	}
	c.n[class]++
}

// obj renders the tally as the label file's counts object, in first-appearance
// order.
func (c *classCounts) obj() validation.Value {
	out := make([]validation.KV, 0, len(c.order))
	for _, class := range c.order {
		out = append(out, validation.KV{K: class,
			V: validation.VInt(int64(c.n[class]))})
	}
	return validation.VObj(out...)
}

// DeriveLabels classifies every row of one snapshot. It refuses a row that
// does not carry the dataset's four fields verbatim (§3a: "exactly four fields
// per vulnerability") plus the project the extractor joined in, and it refuses
// any severity but "high" — the label file is the 114 gold findings, nothing
// else.
func DeriveLabels(rows []validation.Value, dataset, snapshotDate string) (validation.Value, error) {
	if dataset == "" || snapshotDate == "" {
		return validation.VNull(), fmt.Errorf(
			"DeriveLabels needs the dataset name and snapshot date — a label file " +
				"whose provenance is blank cannot be re-derived")
	}
	out := make([]validation.Value, 0, len(rows))
	counts := &classCounts{n: map[string]int{}}
	for i, row := range rows {
		if err := checkLabelRow(row, i); err != nil {
			return validation.VNull(), err
		}
		if err := requireHighSeverity(row, i); err != nil {
			return validation.VNull(), err
		}
		labelled := labelRow(row)
		out = append(out, labelled)
		counts.add(validation.ObjStr(labelled, "class"))
	}
	return validation.VObj(
		kv("dataset", validation.VStr(dataset)),
		kv("snapshot_date", validation.VStr(snapshotDate)),
		kv("created_at", validation.VStr(state.NowIso())),
		kv("rows", validation.VArr(out...)),
		kv("counts", counts.obj()),
		kv("schema_version", validation.VInt(1)),
	), nil
}

// LabelCounts is the per-class row count from a label file.
func LabelCounts(labels validation.Value) map[string]int {
	out := map[string]int{}
	for _, kvp := range validation.ObjAt(labels, "counts").O {
		out[kvp.K] = int(kvp.V.I)
	}
	return out
}

// UnmappedCount is the size of the bucket a human must review.
func UnmappedCount(labels validation.Value) int { return LabelCounts(labels)[unmappedClass] }

// LoadLabels reads a label file and verifies its sidecar.
func LoadLabels(path string) (validation.Value, error) { return ReadRepoRecord(path) }

package regression

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"websec/internal/taxonomy"
	"websec/internal/validation"
)

// TestLabelRulesNameOnlyCanonicalClasses is the realism law applied to the
// vocabulary: the rule table and taxonomy.CanonicalClasses() are two
// vocabularies that must agree, so the test reads BOTH and pins them equal.
// It also records the live size — framework-plan-v1.6 §3a says "23-class
// taxonomy" and the live set is larger, so this assertion is where that
// discrepancy would bite.
//
// The pin is ONE-DIRECTIONAL, and that is a real limit: it iterates LabelRules
// and checks each rule's Class against the taxonomy, so it catches a rule that
// names a class the framework does not have — it cannot catch a canonical
// class that NO rule names (removing "donation" from the taxonomy leaves this
// test green, because no rule names it). The other direction is pinned by
// TestLabelRulesCannotProduceTheUncoveredCanonicalClasses below, which is what
// catches drift in the uncovered set.
func TestLabelRulesNameOnlyCanonicalClasses(t *testing.T) {
	canonical := taxonomy.CanonicalClasses()
	if len(canonical) == 0 {
		t.Fatal("taxonomy.CanonicalClasses() is empty — the pin would be vacuous")
	}
	if len(LabelRules) == 0 {
		t.Fatal("LabelRules is empty — a classifier with no rules maps everything " +
			"to unmapped and the set-cover has nothing to cover")
	}
	for _, rule := range LabelRules {
		if _, ok := canonical[rule.Class]; !ok {
			t.Errorf("LabelRule %q names class %q, which is not in the canonical "+
				"taxonomy — the labels would not join to anything downstream",
				rule.Phrases[0], rule.Class)
		}
		if len(rule.Phrases) == 0 {
			t.Errorf("LabelRule for %q has no phrases", rule.Class)
		}
		for _, p := range rule.Phrases {
			if strings.TrimSpace(p) == "" || len(strings.Fields(p)) == 0 {
				t.Errorf("LabelRule for %q carries an empty phrase", rule.Class)
			}
		}
	}
}

// uncoveredCanonicalClasses is the exact set of canonical classes NO rule in
// LabelRules can produce, as a sorted literal. It is the pin the vocabulary
// test above cannot be: that test reads the table and asks "is every rule
// canonical?", which stays green when a canonical class loses its rule or the
// taxonomy renames, removes or adds one. This literal makes any of those a
// failure that forces a human to re-read the table — which is the only
// defence for the rows the table conflates into a neighbouring class (see the
// LabelRules doc comment).
//
// It is a literal on purpose: deriving it from LabelRules would be the same
// self-reference the pin exists to break.
var uncoveredCanonicalClasses = []string{
	"authorization", "centralization-risk", "chain-freeze", "donation",
	"frontend-injection", "infra-boundary", "sequencer-halt",
	"share-price-accounting",
}

// TestLabelRulesCannotProduceTheUncoveredCanonicalClasses pins the OTHER
// direction of the vocabulary law: which canonical classes this table cannot
// label. Rows for those classes are bucketed into a neighbouring class (or
// fall through to unmapped), so they are invisible to a review that reads only
// the `unmapped` bucket — the set must be stated, not inferred.
func TestLabelRulesCannotProduceTheUncoveredCanonicalClasses(t *testing.T) {
	named := map[string]bool{}
	for _, rule := range LabelRules {
		named[rule.Class] = true
	}
	got := []string{}
	for class := range taxonomy.CanonicalClasses() {
		if !named[class] {
			got = append(got, class)
		}
	}
	sort.Strings(got)
	if !slices.Equal(got, uncoveredCanonicalClasses) {
		t.Fatalf("the canonical classes LabelRules cannot produce are\n got %q\n"+
			"want %q\nthe taxonomy or the table moved: re-read the LabelRules doc "+
			"comment and decide whether each newly-covered class needs a rule, and "+
			"whether each newly-uncovered one is a conflation a Step 7 review can "+
			"no longer see", got, uncoveredCanonicalClasses)
	}
}

// TestClassifyTieBreakFollowsTableOrder pins the tie-break the LabelRule doc
// comment warns about: "round down" (precision-rounding, table index 3) and
// "spot price" (oracle-manipulation, table index 1) are both ten bytes, so the
// EARLIEST rule wins and the table's order is load-bearing. Swapping those two
// rules changes this row's class — and therefore a committed label file —
// without touching a phrase, which is exactly why this is pinned.
func TestClassifyTieBreakFollowsTableOrder(t *testing.T) {
	const title = "Incorrect round down of the spot price in share math"
	class, rule := Classify(title, "")
	if class != "oracle-manipulation" || rule != "spot price" {
		t.Fatalf("Classify(%q) = (%q, %q), want (oracle-manipulation, spot price): "+
			"the equal-length tie is decided by table position, so reordering "+
			"LabelRules silently changes committed labels", title, class, rule)
	}
}

func TestClassifyIsDeterministicAndCaseInsensitive(t *testing.T) {
	class, rule := Classify("Reentrancy in withdraw()", "the callback re-enters before the balance is written")
	if class == unmappedClass {
		t.Fatalf("the reentrancy rule did not fire (rule=%q) — either the rule "+
			"table lost its entry or Classify's matching broke", rule)
	}
	again, againRule := Classify("Reentrancy in withdraw()", "the callback re-enters before the balance is written")
	if class != again || rule != againRule {
		t.Fatalf("Classify is not deterministic: (%q,%q) then (%q,%q)",
			class, rule, again, againRule)
	}
	upper, _ := Classify("REENTRANCY IN WITHDRAW()", "THE CALLBACK RE-ENTERS")
	if upper != class {
		t.Fatalf("case changed the class: %q vs %q", upper, class)
	}
	if got, _ := Classify("Deposit works as documented", "nothing unusual"); got != unmappedClass {
		t.Fatalf("an unmatched row = %q, want unmapped", got)
	}
}

func TestDeriveLabelsRefusesARowMissingTheDatasetsFields(t *testing.T) {
	good := validation.VObj(
		kv("finding_id", validation.VStr("S-1")),
		kv("project", validation.VStr("acme-vault")),
		kv("severity", validation.VStr("high")),
		kv("title", validation.VStr("Reentrancy in withdraw")),
		kv("description", validation.VStr("the callback re-enters before the write")),
	)
	// §3a: the snapshot has "exactly four fields per vulnerability" — plus the
	// project the extractor joins in (the row's own file), which selection needs.
	for _, missing := range []string{
		"finding_id", "project", "severity", "title", "description",
	} {
		assertMissingFieldRefused(t, good, missing)
	}
	labels, err := DeriveLabels([]validation.Value{good}, "scabench", "2025-08-18")
	if err != nil {
		t.Fatal(err)
	}
	counts := validation.ObjAt(labels, "counts")
	if len(counts.O) == 0 {
		t.Fatal("counts is empty")
	}
	if got := validation.ObjAt(labels, "rows").A[0]; validation.ObjStr(got, "class") != "reentrancy" {
		t.Fatalf("class = %q, want reentrancy", validation.ObjStr(got, "class"))
	}
}

// assertMissingFieldRefused drops one dataset field from the good row and
// asserts DeriveLabels refuses it BY NAME: a row that ingests as a silently
// unmapped label is exactly the schema drift the guard exists to catch.
func assertMissingFieldRefused(t *testing.T, good validation.Value, missing string) {
	t.Helper()
	bad := validation.VObj()
	for _, kvp := range good.O {
		if kvp.K != missing {
			bad.O = append(bad.O, kvp)
		}
	}
	_, err := DeriveLabels([]validation.Value{bad}, "scabench", "2025-08-18")
	if err == nil || !strings.Contains(err.Error(), missing) {
		t.Errorf("missing %s: err = %v, want a refusal naming it", missing, err)
	}
}

// TestRepoRecordRoundTripsWithItsSidecar: the label file and its sha256
// sidecar are written together, and a hand edit is detectable.
func TestRepoRecordRoundTripsWithItsSidecar(t *testing.T) {
	path, doc := writeLabelRecord(t)
	back, err := ReadRepoRecord(path)
	if err != nil {
		t.Fatal(err)
	}
	if validation.CanonSpaced(back) != validation.CanonSpaced(doc) {
		t.Fatal("the record did not round-trip")
	}
	assertSidecarCatchesAHandEdit(t, path)
}

// TestRepoRecordRefusesAMissingSidecar: ReadRepoRecord's own contract is that
// an unverifiable record is REFUSED, not warned about — the sidecar is what
// makes a committed answer key checkable, so a reader that tolerates its
// absence accepts a file nobody can verify. LoadLabels is the same reader on
// the labels path, so both are asserted.
func TestRepoRecordRefusesAMissingSidecar(t *testing.T) {
	path, _ := writeLabelRecord(t)
	if err := os.Remove(path + ".sha256"); err != nil {
		t.Fatal(err)
	}
	_, err := ReadRepoRecord(path)
	assertNoSidecarRefusal(t, "ReadRepoRecord", err)
	_, err = LoadLabels(path)
	assertNoSidecarRefusal(t, "LoadLabels", err)
}

// assertNoSidecarRefusal checks that a reader refused a record whose sidecar is
// gone, BY NAME: the sidecar-MISMATCH error is a different refusal, and a bare
// err != nil would be satisfied by a parse error or by the wrong one.
func assertNoSidecarRefusal(t *testing.T, reader string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s accepted a record with no sha256 sidecar — an unverifiable "+
			"record must be refused", reader)
	}
	if !strings.Contains(err.Error(), "has no sha256 sidecar") {
		t.Fatalf("%s refused the record with %q, want the missing-sidecar refusal",
			reader, err)
	}
}

// assertSidecarCatchesAHandEdit appends a newline to a written record — a
// JSON-PRESERVING edit, so the document still parses and only its bytes differ
// — and asserts the read refuses it BY NAME. The edit must not break the
// document: an earlier version of this helper truncated the closing brace, so
// ReadRepoRecord failed with a PARSE error and the assertion was satisfied by
// the wrong failure entirely (deleting the sidecar mismatch check left it
// green).
func assertSidecarCatchesAHandEdit(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := validation.ReadJson(path); err != nil {
		t.Fatalf("the hand edit broke the JSON (%v) — the test would then pass on "+
			"a parse error instead of on the sidecar mismatch", err)
	}
	_, err = ReadRepoRecord(path)
	if err == nil {
		t.Fatal("ReadRepoRecord accepted a hand-edited file (sidecar mismatch)")
	}
	if !strings.Contains(err.Error(), "has been edited since it was written") {
		t.Fatalf("the refusal %q does not name the sidecar mismatch — a bare "+
			"err != nil would accept a parse error here", err)
	}
}

// writeLabelRecord writes one valid label record with its sidecar into a temp
// dir and returns the path and the document, so the sidecar tests spend their
// lines on the refusal rather than on the plumbing.
func writeLabelRecord(t *testing.T) (string, validation.Value) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "labels.json")
	doc, err := DeriveLabels([]validation.Value{labelTestRow("S-1",
		"Oracle price is stale", "the stale oracle price is read")},
		"scabench", "2025-08-18")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteRepoRecord(path, doc, "regression_labels"); err != nil {
		t.Fatal(err)
	}
	return path, doc
}

// testProject is the project id the extractor joins into every row, shared by
// the fixtures below so the literal appears once.
const testProject = "acme-vault"

// labelTestRow is one snapshot row in the extractor's shape: the dataset's
// four fields, plus the project the extractor joins in.
func labelTestRow(id, title, description string) validation.Value {
	return labelTestRowSeverity(id, "high", title, description)
}

// labelTestRowSeverity is labelTestRow with the severity spelled out, so a
// test can hand the classifier a row the dataset would never mark high.
func labelTestRowSeverity(id, severity, title, description string) validation.Value {
	return validation.VObj(
		kv("finding_id", validation.VStr(id)),
		kv("project", validation.VStr(testProject)),
		kv("severity", validation.VStr(severity)),
		kv("title", validation.VStr(title)),
		kv("description", validation.VStr(description)),
	)
}

// TestDeriveLabelsRefusesEverySeverityButHigh is the scope guard's own test.
// The snapshot's vocabulary is high|medium|low|informational, and the label
// file is the 114 `high` rows and nothing else: a medium row in here would be
// counted as gold and inflate the set-cover's coverage arithmetic.
func TestDeriveLabelsRefusesEverySeverityButHigh(t *testing.T) {
	for _, sev := range []string{"medium", "low", "informational", "HIGH"} {
		doc, err := DeriveLabels([]validation.Value{
			labelTestRowSeverity("S-2", sev, "Reentrancy in withdraw",
				"the callback re-enters before the write")}, "scabench", "2025-08-18")
		if err == nil {
			t.Fatalf("severity %q was labelled — a non-high row is not gold", sev)
		}
		for _, want := range []string{"high findings only", "S-2", sev} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("severity %q: the refusal %q does not name %q", sev, err, want)
			}
		}
		if doc.Kind != validation.Null {
			t.Errorf("severity %q: refused, but returned a %v document", sev, doc.Kind)
		}
	}
}

// TestLabelFileRecordsTheRuleThatFired: the `rule` key is the whole reason the
// label file is reviewable — a class nobody can re-derive is an opinion. The
// test asserts the attribution is not merely present but the LONGEST phrase of
// the recorded class that occurs in the row's own text (the documented
// tie-break), so the right class with the wrong reason still fails.
func TestLabelFileRecordsTheRuleThatFired(t *testing.T) {
	cases := []struct{ id, title, desc, class string }{
		{"S-1", "Reentrancy in withdraw()",
			"the callback re-enters before the balance is written", "reentrancy"},
		{"S-2", "Stale oracle price",
			"the stale oracle price is read without a freshness check", "oracle-manipulation"},
		{"S-3", "Missing access control on setFee",
			"anyone can call setFee; there is no authorization", "access-control"},
		{"S-4", "Deposit works as documented", "nothing unusual", unmappedClass},
	}
	rows := make([]validation.Value, 0, len(cases))
	for _, tc := range cases {
		rows = append(rows, labelTestRow(tc.id, tc.title, tc.desc))
	}
	labels, err := DeriveLabels(rows, "scabench", "2025-08-18")
	if err != nil {
		t.Fatal(err)
	}
	for i, tc := range cases {
		row := validation.ObjAt(labels, "rows").A[i]
		class, rule := validation.ObjStr(row, "class"), validation.ObjStr(row, "rule")
		if class != tc.class {
			t.Errorf("%q: class = %q, want %q", tc.title, class, tc.class)
			continue
		}
		assertRuleIsTheLongestMatch(t, class, rule, tc.title, tc.desc)
	}
}

// assertRuleIsTheLongestMatch is the attribution check: the recorded rule must
// be a phrase of the recorded class, must occur in the row's own title or
// description, and must be the longest such phrase (or "unmapped" when the
// class is unmapped). A classifier that returned the class name, or another
// class's phrase, fails here.
func assertRuleIsTheLongestMatch(t *testing.T, class, rule, title, desc string) {
	t.Helper()
	hay := strings.ToLower(title + "\n" + desc)
	if class == unmappedClass {
		if rule != unmappedClass {
			t.Fatalf("unmapped row records rule %q, want unmapped", rule)
		}
		return
	}
	longest := ""
	for _, r := range LabelRules {
		if r.Class != class {
			continue
		}
		for _, p := range r.Phrases {
			lp := strings.ToLower(strings.TrimSpace(p))
			if strings.Contains(hay, lp) && len(lp) > len(longest) {
				longest = p
			}
		}
	}
	if longest == "" {
		t.Fatalf("class %q has no phrase in %q — the row cannot carry it", class, hay)
	}
	if rule != longest {
		t.Fatalf("class %q recorded rule %q, want the longest matching phrase %q",
			class, rule, longest)
	}
}

// TestLabelCountsAreTheRowTally pins the counts object's VALUES, not only the
// unmapped bucket the CLI test reads: Task 4 weights the set-cover by
// gold-finding count, so a count that is not the number of rows carrying the
// class silently reweights the pick. sum(counts) == len(rows) catches a dropped
// or double-counted row; the per-class check catches a count that is right in
// aggregate and wrong per class.
func TestLabelCountsAreTheRowTally(t *testing.T) {
	rows := []validation.Value{
		labelTestRow("S-1", "Reentrancy in withdraw()", "the callback re-enters"),
		labelTestRow("S-2", "Reentrancy in deposit()", "another re-entrancy"),
		labelTestRow("S-3", "Stale oracle price", "the stale oracle price is read"),
		labelTestRow("S-4", "Deposit works as documented", "nothing unusual"),
	}
	labels, err := DeriveLabels(rows, "scabench", "2025-08-18")
	if err != nil {
		t.Fatal(err)
	}
	counts := LabelCounts(labels)
	sum := 0
	for _, n := range counts {
		sum += n
	}
	if sum != len(rows) {
		t.Fatalf("sum(counts) = %d, want %d — one count per row", sum, len(rows))
	}
	assertCountsAreTheRowTally(t, labels, counts)
}

// assertCountsAreTheRowTally checks every class's count against the rows that
// carry it, and pins the two classes this fixture produces.
func assertCountsAreTheRowTally(t *testing.T, labels validation.Value, counts map[string]int) {
	t.Helper()
	byClass := map[string]int{}
	for _, row := range validation.ObjAt(labels, "rows").A {
		byClass[validation.ObjStr(row, "class")]++
	}
	for class, want := range byClass {
		if got := counts[class]; got != want {
			t.Errorf("counts[%q] = %d, but %d row(s) carry that class", class, got, want)
		}
	}
	if got := counts["reentrancy"]; got != 2 {
		t.Errorf("counts[reentrancy] = %d, want 2", got)
	}
	if got := counts[unmappedClass]; got != 1 {
		t.Errorf("counts[%s] = %d, want 1", unmappedClass, got)
	}
}

// TestDeriveLabelsHonoursThePinnedClock: created_at comes from state.NowIso,
// the repo's deterministic-time seam (WEBV2_NOW, which the golden recipe pins).
// A record stamped with a raw time.Now() cannot be re-derived byte-for-byte,
// which is the property the label file exists to have.
func TestDeriveLabelsHonoursThePinnedClock(t *testing.T) {
	const pinned = "2026-09-21T00:00:00.000000+00:00"
	t.Setenv("WEBV2_NOW", pinned)
	labels, err := DeriveLabels([]validation.Value{labelTestRow("S-1",
		"Oracle price is stale", "the stale oracle price is read")},
		"scabench", "2025-08-18")
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(labels, "created_at"); got != pinned {
		t.Fatalf("created_at = %q, want the pinned clock %q — the record is not "+
			"re-derivable", got, pinned)
	}
}

// TestWriteRepoRecordValidatesTheWritePath: the schema is enforced where the
// file is written, not only where it is read. additionalProperties is false,
// so an unknown key is a schema edit plus a validation change — never a free
// ride — and the optional review flags the operator sets in Step 7 are legal.
func TestWriteRepoRecordValidatesTheWritePath(t *testing.T) {
	_, doc := writeLabelRecord(t)
	dir := t.TempDir()
	extra := withExtraKey(doc, "surprise", validation.VStr("x"))
	if err := WriteRepoRecord(filepath.Join(dir, "extra.json"), extra, "regression_labels"); err == nil {
		t.Fatal("WriteRepoRecord accepted a document with an unknown key")
	}
	if _, err := os.Stat(filepath.Join(dir, "extra.json")); !os.IsNotExist(err) {
		t.Fatal("a refused write left the label file behind")
	}
	reviewed := withExtraKey(doc, "unmapped_reviewed", validation.VBool(false))
	reviewed = withExtraKey(reviewed, "reviewed_by", validation.VStr("operator"))
	if err := WriteRepoRecord(filepath.Join(dir, "reviewed.json"), reviewed, "regression_labels"); err != nil {
		t.Fatalf("the review flags the operator sets in Step 7 were rejected: %v", err)
	}
	if _, err := LoadLabels(filepath.Join(dir, "reviewed.json")); err != nil {
		t.Fatalf("LoadLabels refused a reviewed label file: %v", err)
	}
}

// withExtraKey copies a document's KV list and appends one key, so a test can
// probe the schema without aliasing the document it probes.
func withExtraKey(doc validation.Value, k string, v validation.Value) validation.Value {
	out := append([]validation.KV{}, doc.O...)
	return validation.VObj(append(out, kv(k, v))...)
}

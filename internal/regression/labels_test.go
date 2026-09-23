package regression

import (
	"os"
	"path/filepath"
	"reflect"
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

// TestContainsWordKeepsTheLeftEdgeStrictAndTheRightEdgeOpen pins both edges of
// the matcher, which the doc comment argues for and nothing observed: the RIGHT
// edge is OPEN so a stem matches its own inflections, the LEFT edge is STRICT so
// a stem cannot ride inside an unrelated token. Closing the right edge (which
// the plan's Step 5 did) makes "reentran" miss "Reentrancy" and the whole table
// go unmapped; dropping the left check turns "grounding" into
// precision-rounding and "asphalt" into liveness.
func TestContainsWordKeepsTheLeftEdgeStrictAndTheRightEdgeOpen(t *testing.T) {
	if !containsWord("reentrancy in withdraw()", "reentran") {
		t.Error(`the right edge is closed: the stem "reentran" did not match its ` +
			`own inflection "reentrancy", which disables the whole rule table`)
	}
	for _, tc := range []struct{ hay, needle string }{
		{"grounding the invariants", "rounding"},
		{"asphalt of the vault", "halt"},
	} {
		if containsWord(tc.hay, tc.needle) {
			t.Errorf("%q matched inside %q: the left edge is not strict, so a stem "+
				"rides inside an unrelated token", tc.needle, tc.hay)
		}
	}
	if got, _ := Classify("Grounding the invariants", ""); got != unmappedClass {
		t.Errorf("Classify(\"Grounding the invariants\") = %q, want unmapped — a "+
			"left-open matcher reads it as precision-rounding", got)
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

// withRows replaces a label document's rows, so a test can hand the schema a
// row shape DeriveLabels itself would never write.
func withRows(doc validation.Value, rows ...validation.Value) validation.Value {
	out := append([]validation.KV{}, doc.O...)
	return validation.VObj(validation.SetOrAppend(out, "rows", validation.VArr(rows...))...)
}

// codebaseKey is defined in labels.go and reused here, so the production
// writer, its guard and these tests can never disagree about the wire name.

// testCodebase is the codebase id the tests join in, in the dataset's own
// shape — the key exists because one project (Starknet Perpetual) carries two
// codebases and the commit lives on the codebase, not the project.
const testCodebase = "starknet-perpetual_main"

// labelTestRowCodebase is labelTestRow with the checkout key the extractor
// joins in when the project carries more than one codebase. It is appended
// rather than re-spelled so the fixture stays one shape.
func labelTestRowCodebase(codebase, title, description string) validation.Value {
	return withExtraKey(labelTestRow("S-1", title, description), codebaseKey,
		validation.VStr(codebase))
}

// TestLabelRowCarriesCodebaseIDWhenPresent is the round trip: a row that
// carries the checkout key must survive DeriveLabels, the schema write and the
// reload with the SAME value. Dropping it at labelRow would silently lose the
// only bridge back to the tree a label's finding was reported against.
func TestLabelRowCarriesCodebaseIDWhenPresent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labels.json")
	labels, err := DeriveLabels([]validation.Value{
		labelTestRowCodebase(testCodebase, "Oracle price is stale",
			"the stale oracle price is read")}, "scabench", "2025-08-18")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteRepoRecord(path, labels, "regression_labels"); err != nil {
		t.Fatalf("a label file whose row carries codebase_id was refused: %v", err)
	}
	back, err := LoadLabels(path)
	if err != nil {
		t.Fatal(err)
	}
	row := validation.ObjAt(back, "rows").A[0]
	if !validation.HasKey(row, codebaseKey) {
		t.Fatal("the written row dropped codebase_id — the checkout key the " +
			"extractor joined in never reaches the label file")
	}
	if got := validation.ObjStr(row, codebaseKey); got != testCodebase {
		t.Fatalf("codebase_id = %q, want %q", got, testCodebase)
	}
}

// TestLabelRowOmitsCodebaseIDWhenAbsent is the load-bearing half of the
// optionality: a row WITHOUT the key must be written with the key ABSENT, not
// with an empty string. A present-but-blank id is a different claim (it says
// the extractor looked and found a blank codebase) and would defeat the
// "optional otherwise" rule; it would also be the only value the schema's
// minLength:1 could never accept.
func TestLabelRowOmitsCodebaseIDWhenAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labels.json")
	labels, err := DeriveLabels([]validation.Value{
		labelTestRow("S-1", "Oracle price is stale", "the stale oracle price is read")},
		"scabench", "2025-08-18")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteRepoRecord(path, labels, "regression_labels"); err != nil {
		t.Fatalf("a row without a codebase_id was refused: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), codebaseKey) {
		t.Fatal("a row that carried no codebase_id was written WITH the key — " +
			"an absent key and a present-but-empty id are different claims")
	}
	back, err := LoadLabels(path)
	if err != nil {
		t.Fatal(err)
	}
	if row := validation.ObjAt(back, "rows").A[0]; validation.HasKey(row, codebaseKey) {
		t.Fatal("the reloaded row carries codebase_id, want the key absent")
	}
}

// TestLabelSchemaStillRejectsAnUnknownRowKey keeps the row's
// additionalProperties:false honest while the new key is added: the point of
// adding codebase_id is that an unagreed claim on a row is still refused, so
// this is the guard against widening the row to whatever the extractor emits.
func TestLabelSchemaStillRejectsAnUnknownRowKey(t *testing.T) {
	labels, err := DeriveLabels([]validation.Value{
		labelTestRow("S-1", "Oracle price is stale", "the stale oracle price is read")},
		"scabench", "2025-08-18")
	if err != nil {
		t.Fatal(err)
	}
	row := validation.ObjAt(labels, "rows").A[0]
	bad := withRows(labels, withExtraKey(row, "surprise", validation.VStr("x")))
	if err := WriteRepoRecord(filepath.Join(t.TempDir(), "bad.json"), bad,
		"regression_labels"); err == nil {
		t.Fatal("the row schema accepted an unknown key — additionalProperties:false " +
			"is the reason a label row cannot carry an unagreed claim")
	}
}

// TestCodebaseIDChangesNothingButTheCheckoutKey: the checkout key is
// provenance, not input to the classifier. The same row with and without it
// must classify identically and tally identically, or the key would be a
// second, invisible axis of the label file.
func TestCodebaseIDChangesNothingButTheCheckoutKey(t *testing.T) {
	const title = "Oracle price is stale"
	const desc = "the stale oracle price is read"
	with, err := DeriveLabels([]validation.Value{
		labelTestRowCodebase(testCodebase, title, desc)}, "scabench", "2025-08-18")
	if err != nil {
		t.Fatal(err)
	}
	without, err := DeriveLabels([]validation.Value{
		labelTestRow("S-1", title, desc)}, "scabench", "2025-08-18")
	if err != nil {
		t.Fatal(err)
	}
	a := validation.ObjAt(with, "rows").A[0]
	b := validation.ObjAt(without, "rows").A[0]
	for _, k := range []string{"finding_id", "project", "severity", "class", "rule"} {
		if validation.ObjStr(a, k) != validation.ObjStr(b, k) {
			t.Errorf("%s = %q with a codebase_id and %q without — the checkout "+
				"key must not move the classification", k, validation.ObjStr(a, k),
				validation.ObjStr(b, k))
		}
	}
	if !reflect.DeepEqual(validation.ObjAt(with, "counts"), validation.ObjAt(without, "counts")) {
		t.Fatalf("counts = %v with a codebase_id and %v without",
			validation.ObjAt(with, "counts"), validation.ObjAt(without, "counts"))
	}
}

// writtenRow derives a one-row label file from row, writes it through the real
// schema and returns the row as it reloads from disk — the round trip every
// checkout-key test below asserts on.
func writtenRow(t *testing.T, row validation.Value) validation.Value {
	t.Helper()
	path := filepath.Join(t.TempDir(), "labels.json")
	labels, err := DeriveLabels([]validation.Value{row}, "scabench", "2025-08-18")
	if err != nil {
		t.Fatalf("DeriveLabels refused the row: %v", err)
	}
	if err := WriteRepoRecord(path, labels, "regression_labels"); err != nil {
		t.Fatalf("WriteRepoRecord refused the row: %v", err)
	}
	back, err := LoadLabels(path)
	if err != nil {
		t.Fatalf("LoadLabels: %v", err)
	}
	return validation.ObjAt(back, "rows").A[0]
}

// TestLabelRowDropsWhitespaceOnlyCodebaseID is D1: a whitespace-only
// codebase_id carries no id, so it is written ABSENT — never as a present key
// holding "   ". "Present but blank" is a third state (it says the extractor
// looked and found a blank codebase) and it is the only string value the
// schema's minLength/pattern refuse, so the writer must not produce it.
func TestLabelRowDropsWhitespaceOnlyCodebaseID(t *testing.T) {
	row := writtenRow(t, labelTestRowCodebase("   ",
		"Whitespace checkout key", "the blank id must be dropped"))
	if validation.HasKey(row, codebaseKey) {
		t.Fatalf("a whitespace-only codebase_id round-tripped as a present key "+
			"holding %q — blank must drop to absent",
			validation.ObjStr(row, codebaseKey))
	}
}

// TestLabelRowDropsEmptyCodebaseID is D1's empty-string case: "" is absent, not
// a present key holding nothing. minLength:1 would refuse the latter, so the
// writer must not be able to produce it.
func TestLabelRowDropsEmptyCodebaseID(t *testing.T) {
	row := writtenRow(t, labelTestRowCodebase("",
		"Empty checkout key", "the empty id must be dropped"))
	if validation.HasKey(row, codebaseKey) {
		t.Fatal("an empty codebase_id round-tripped as a present key, want absent")
	}
}

// TestLabelRowTrimsPaddedCodebaseID is D1's other half: a padded REAL id is
// trimmed, so "  <id>  " round-trips as the id the target record carries
// instead of as a value that silently fails the picker's join.
func TestLabelRowTrimsPaddedCodebaseID(t *testing.T) {
	row := writtenRow(t, labelTestRowCodebase("  "+testCodebase+"  ",
		"Padded checkout key", "the padded id must be trimmed"))
	if got := validation.ObjStr(row, codebaseKey); got != testCodebase {
		t.Fatalf("codebase_id = %q, want the trimmed %q", got, testCodebase)
	}
}

// TestLabelRowRefusesNonStringCodebaseID is D5's type rule: a present but
// non-string key (42, null, {}, []) is REFUSED, matching checkLabelRow's
// refuse-don't-drop law for the required fields. Dropping it would read as
// "this project has no checkout key" — a claim the producer never made.
func TestLabelRowRefusesNonStringCodebaseID(t *testing.T) {
	for _, tc := range []struct {
		name string
		val  validation.Value
	}{
		{"number", validation.VInt(42)},
		{"null", validation.VNull()},
		{"object", validation.VObj()},
		{"array", validation.VArr()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DeriveLabels([]validation.Value{withExtraKey(
				labelTestRow("S-1", "Typed checkout key", "the type must be checked"),
				codebaseKey, tc.val)}, "scabench", "2025-08-18")
			if err == nil {
				t.Fatalf("a %s codebase_id was silently dropped, want a refusal",
					tc.name)
			}
		})
	}
}

// TestLabelSchemaRefusesAMalformedCodebaseID is the schema half of D1 and D5:
// a hand-crafted rows file — the only route that reaches the schema without
// DeriveLabels' trim/type guard — must be refused for a whitespace-only value
// (without "pattern": "\\S", three spaces satisfy minLength:1 and validate) and
// for a non-string one (type:string is the hand-edit half of the guard).
func TestLabelSchemaRefusesAMalformedCodebaseID(t *testing.T) {
	labels, err := DeriveLabels([]validation.Value{labelTestRow("S-1",
		"Schema checkout key", "the schema must refuse a malformed id")},
		"scabench", "2025-08-18")
	if err != nil {
		t.Fatal(err)
	}
	base := validation.ObjAt(labels, "rows").A[0]
	for _, tc := range []struct {
		name string
		val  validation.Value
	}{
		{"blank", validation.VStr("   ")},
		{"number", validation.VInt(42)},
		{"null", validation.VNull()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := withExtraKey(base, codebaseKey, tc.val)
			if err := WriteRepoRecord(filepath.Join(t.TempDir(), "bad.json"),
				withRows(labels, row), "regression_labels"); err == nil {
				t.Fatalf("the row schema accepted a %s codebase_id", tc.name)
			}
		})
	}
}

// TestCodebaseIDGuardsAreDeclared pins the checkout key's schema guards BY
// NAME. The behavioral tests above cover type:string (a numeric id is refused)
// and pattern:\S (a blank id is refused); minLength:1 is NOT behaviorally
// observable once pattern:\S is present, because \S already rejects the empty
// string, so removing minLength changes no verdict anywhere in this package.
// This pin is therefore the only test that can kill that mutation, and it is a
// contract assertion rather than a mirror of the file: the key's guards are
// part of the schema's public shape, and D5 exists because nothing read them.
func TestCodebaseIDGuardsAreDeclared(t *testing.T) {
	raw, err := validation.ReadSchemaFile("regression_labels")
	if err != nil {
		t.Fatalf("ReadSchemaFile(regression_labels): %v", err)
	}
	doc, err := validation.ParseOrdered(raw)
	if err != nil {
		t.Fatal(err)
	}
	items := validation.ObjAt(validation.ObjAt(validation.ObjAt(doc, "properties"),
		"rows"), "items")
	prop := validation.ObjAt(validation.ObjAt(items, "properties"), codebaseKey)
	if prop.Kind != validation.Obj {
		t.Fatalf("the schema declares no rows[].%s property", codebaseKey)
	}
	if got := validation.ObjStr(prop, "type"); got != "string" {
		t.Errorf("%s.type = %q, want \"string\"", codebaseKey, got)
	}
	if got := validation.ObjAt(prop, "minLength").I; got != 1 {
		t.Errorf("%s.minLength = %d, want 1", codebaseKey, got)
	}
	if got := validation.ObjStr(prop, "pattern"); got != `\S` {
		t.Errorf(`%s.pattern = %q, want "\\S"`, codebaseKey, got)
	}
}

package cli

// T14 cmd_ingest tests: the --example payload/legend contract, the
// CPython-compatible JSON error text, the shape-swap hint, and the two
// ingest output shapes. Vectors generated from the live Python CLI
// (CPython 3.14 json.loads + webv2.validation.schema_enum_legend).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// generated from CPython 3.14 json.loads (see .scratch/t14/jsonerr.json)
var t14JSONErrVectors = []struct{ doc, want string }{
	{"", "Expecting value: line 1 column 1 (char 0)"},
	{" ", "Expecting value: line 1 column 2 (char 1)"},
	{"{", "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)"},
	{"}", "Expecting value: line 1 column 1 (char 0)"},
	{"[", "Expecting value: line 1 column 2 (char 1)"},
	{"]", "Expecting value: line 1 column 1 (char 0)"},
	{"{not json}", "Expecting property name enclosed in double quotes: line 1 column 2 (char 1)"},
	{"nope", "Expecting value: line 1 column 1 (char 0)"},
	{"tru", "Expecting value: line 1 column 1 (char 0)"},
	{"fals", "Expecting value: line 1 column 1 (char 0)"},
	{"nul", "Expecting value: line 1 column 1 (char 0)"},
	{"{\"a\"}", "Expecting ':' delimiter: line 1 column 5 (char 4)"},
	{"{\"a\":}", "Expecting value: line 1 column 6 (char 5)"},
	{"{\"a\":1,}", "Illegal trailing comma before end of object: line 1 column 7 (char 6)"},
	{"{\"a\":1,,\"b\":2}", "Expecting property name enclosed in double quotes: line 1 column 8 (char 7)"},
	{"{\"a\" 1}", "Expecting ':' delimiter: line 1 column 6 (char 5)"},
	{"{\"a\":1 \"b\":2}", "Expecting ',' delimiter: line 1 column 8 (char 7)"},
	{"{\"a\":1,\"b\":2,}", "Illegal trailing comma before end of object: line 1 column 13 (char 12)"},
	{"[1,]", "Illegal trailing comma before end of array: line 1 column 3 (char 2)"},
	{"[1 2]", "Expecting ',' delimiter: line 1 column 4 (char 3)"},
	{"[,1]", "Expecting value: line 1 column 2 (char 1)"},
	{"[1,,2]", "Expecting value: line 1 column 4 (char 3)"},
	{"[1,2", "Expecting ',' delimiter: line 1 column 5 (char 4)"},
	{"{\"a\":1", "Expecting ',' delimiter: line 1 column 7 (char 6)"},
	{"\"unterminated", "Unterminated string starting at: line 1 column 1 (char 0)"},
	{"\"bad\\x\"", "Invalid \\escape: line 1 column 5 (char 4)"},
	{"\"bad\\uZZZZ\"", "Invalid \\uXXXX escape: line 1 column 6 (char 5)"},
	{"\"bad\\u12\"", "Invalid \\uXXXX escape: line 1 column 6 (char 5)"},
	{"[1] extra", "Extra data: line 1 column 5 (char 4)"},
	{"{} {}", "Extra data: line 1 column 4 (char 3)"},
	{"01", "Extra data: line 1 column 2 (char 1)"},
	{"1.", "Extra data: line 1 column 2 (char 1)"},
	{"+1", "Expecting value: line 1 column 1 (char 0)"},
	{".5", "Expecting value: line 1 column 1 (char 0)"},
	{"Infinity", ""},
	{"NaN", ""},
	{"-Infinity", ""},
	{"{\"a\": tru}", "Expecting value: line 1 column 7 (char 6)"},
	{"[true false]", "Expecting ',' delimiter: line 1 column 7 (char 6)"},
	{"{\"a\": null,}", "Illegal trailing comma before end of object: line 1 column 11 (char 10)"},
	{"  {  }  ", ""},
	{"{\"a\": \"b\"}\n\nx", "Extra data: line 3 column 1 (char 12)"},
	{"[{\"a\": 1},]", "Illegal trailing comma before end of array: line 1 column 10 (char 9)"},
	{"\"\\\"\"", ""},
	{"{\"\":}", "Expecting value: line 1 column 5 (char 4)"},
	{"{\"a\":[1,2,]}", "Illegal trailing comma before end of array: line 1 column 10 (char 9)"},
	{"{\"a\":{\"b\":}}", "Expecting value: line 1 column 11 (char 10)"},
	{"1 2", "Extra data: line 1 column 3 (char 2)"},
	{"[ ] x", "Extra data: line 1 column 5 (char 4)"},
	{"{\"a\":\"\\\"}", "Unterminated string starting at: line 1 column 6 (char 5)"},
	{"'x'", "Expecting value: line 1 column 1 (char 0)"},
	{"\"a\\tb\"", ""},
	{"\"a\nb\"", "Invalid control character at: line 1 column 3 (char 2)"},
	{"[1,\n2,\n]", "Illegal trailing comma before end of array: line 2 column 2 (char 5)"},
	{"{\"a\":1,\n\"b\":2,\n}", "Illegal trailing comma before end of object: line 2 column 6 (char 13)"},
}

var t14FindingLegend = []string{
	"status: HYPOTHESIS|NEEDS_RESEARCH|PROVISIONALLY_VALID|POSSIBLE|CONFIRMED|DISPROVED|DUPLICATE|OUT_OF_SCOPE|INFORMATIONAL|CHAIN",
	"trajectory: code|economic|state-machine|attacker|historical|integration|drift|lifecycle|chain|model",
	"assumptions[]/type: reachability|authority|control|state|invariant|economic|environment|temporal|cross_domain",
	"assumptions[]/status: UNKNOWN|SUPPORTED|REFUTED",
	"preconditions[]/kind: state|external|time|privilege|market|configuration",
	"preconditions[]/enforced_by_poc: true|false|unknown|null",
	"evidence[]/level: E0|E1|E2|E3|E4|E5|E6|E7",
	"evidence[]/type: reasoning|static-analysis|reachability|unit-test|foundry-test|fuzz|invariant-test|symbolic-witness|fork-test|trace|balance-delta|differential|historical-analog|manual",
	"economic_impact/blast_radius: single-user|subset-of-users|all-users|protocol-solvency|bridge-canonical",
	"reported_severity: low|medium|high|critical",
	"fork_diff/verdict: strong|partial|none",
	"maximization/disposition: open|complete|waived|null",
	"risk/validated/band: critical|high|medium|low|informational",
	"risk/impact_vector/asset_exposure: none|lt_100k|100k_1m|1m_10m|gt_10m",
	"risk/impact_vector/privilege_class: unprivileged|semi-privileged|role|owner",
	"risk/impact_vector/recoverability: unknown|low|medium|high",
	"risk/impact_vector/insolvency_risk: low|medium|high",
	"risk/reversibility: irreversible|trusted-party|reversible",
	"dedup/candidate_verdicts/additionalProperties: same|distinct",
	"verification/reproduction/tier_reached: none|T0|T1|T2|T3|T4",
	"verification/reproduction/status: not_attempted|attempted|reproduced|failed|blocked|falsified",
	"verification/reproduction/attempts[]/outcome: reproduced|failed|blocked|falsified",
	"verification/reproduction/attempts[]/failure_class: environment|setup|logic|precondition-unmet|hypothesis-wrong|unknown|null",
	"verification/critic_verdict: pending|confirmed|possible|disproved|duplicate|out_of_scope|informational",
	"verification/independent_reproduction/status: not_attempted|matches|differs|failed|contradicts",
	"bounty/policy_checks[]/result: pass|fail|unknown|human-review",
	"provenance/memory_checks[]/mode: negative|comparative",
	"provenance/memory_checks[]/relevance/basis[]: bug_class|capability|cwe",
}

func TestIngestExampleStdoutIsPureJSON(t *testing.T) {
	root := mkroot(t)
	code, out, errS := run(t, "--root", root, "ingest", "--example")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "{\n  \"title\":") {
		t.Fatalf("stdout is not the payload: %q", out[:60])
	}
	if !strings.HasSuffix(out, "}\n") {
		t.Fatalf("payload must end with a single newline: %q", out[len(out)-8:])
	}
	// stdout is pipeable: exactly one JSON document, no prose.
	if strings.Contains(out, "This payload IS") {
		t.Fatalf("contract prose leaked to stdout")
	}
	if !strings.Contains(errS, "This payload IS the ingest schema contract") {
		t.Fatalf("contract statement missing from stderr: %q", errS)
	}
	if !strings.Contains(errS, "closed-enum fields (auto-generated from "+
		"schema/finding.schema.json — every allowed value):") {
		t.Fatalf("legend header missing: %q", errS)
	}
	if !strings.Contains(errS, "\n  status: HYPOTHESIS|NEEDS_RESEARCH|") {
		t.Fatalf("legend lines missing: %q", errS)
	}
}

func TestIngestExampleLegendMatchesSchema(t *testing.T) {
	legend, err := validation.SchemaEnumLegend("finding")
	if err != nil {
		t.Fatalf("legend: %v", err)
	}
	if len(legend) != len(t14FindingLegend) {
		t.Fatalf("legend has %d lines, want %d", len(legend),
			len(t14FindingLegend))
	}
	for i, want := range t14FindingLegend {
		if legend[i] != want {
			t.Fatalf("legend[%d] = %q, want %q", i, legend[i], want)
		}
	}
	if !strings.Contains(strings.Join(legend, "\n"),
		"dedup/candidate_verdicts/additionalProperties: same|distinct") {
		t.Fatalf("map-valued enums must be walked: %v", legend)
	}
}

func TestPyJSONErrorMatchesCPython(t *testing.T) {
	if len(t14JSONErrVectors) < 50 {
		t.Fatalf("vector table too small: %d", len(t14JSONErrVectors))
	}
	for _, v := range t14JSONErrVectors {
		if got := t14PyJSONError(v.doc); got != v.want {
			t.Errorf("t14PyJSONError(%q) = %q, want %q", v.doc, got, v.want)
		}
	}
}

func TestIngestShapeHint(t *testing.T) {
	pre := "campaign_plan validation failed at assumptions/0: additional " +
		"property 'kind' is not allowed"
	got := t14IngestShapeHint(pre)
	if !strings.HasPrefix(got, "did you use the preconditions shape "+
		"for an assumption?") {
		t.Fatalf("precondition-shape hint = %q", got)
	}
	if !strings.Contains(got, "see `webv2 ingest --example`") {
		t.Fatalf("hint must point at the example: %q", got)
	}
	assum := "finding validation failed at preconditions/1: additional " +
		"property 'model_belief' is not allowed"
	got = t14IngestShapeHint(assum)
	if !strings.HasPrefix(got, "did you use the assumptions shape "+
		"for a precondition?") {
		t.Fatalf("assumption-shape hint = %q", got)
	}
	if t14IngestShapeHint("some unrelated error") != "" {
		t.Fatalf("unrelated error must get no shape hint")
	}
}

func TestIngestExamplePipeRoundTrip(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	payload := filepath.Join(root, "payload.json")
	if err := os.WriteFile(payload, []byte(t14ExamplePayload), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", payload)
	if code != 0 {
		t.Fatalf("ingest exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "ingested F-") ||
		!strings.Contains(out, "[HYPOTHESIS] (class share-price-inflation)") {
		t.Fatalf("ingest output = %q", out)
	}
	if errS != "" {
		t.Fatalf("ingest stderr = %q", errS)
	}
	// a re-ingested payload is a NEW finding flagged as a possible
	// duplicate (dedup does not silently merge) — Python parity
	code, out2, _ := run(t, "--root", root, "ingest", cid,
		"--json-file", payload)
	if code != 0 {
		t.Fatalf("second ingest exit %d", code)
	}
	if !strings.Contains(out2, "[HYPOTHESIS]") {
		t.Fatalf("second ingest = %q", out2)
	}
	if out2 == out {
		t.Fatalf("second ingest reused the first finding id: %q", out2)
	}
}

func TestIngestShapeSwapHint(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	// an assumption written with the preconditions shape: the CLI must name
	// the offending field AND offer the shape-swap hint on stderr
	bad := t14TestWrite(t, root, "bad.json", `{"title":"ShareVault deposit `+
		`inflates the share price for later depositors","root_cause":`+
		`{"class":"share-price-inflation","description":"The first depositor `+
		`sets the share price with a single wei, so all later depositors buy `+
		`shares at a price the attacker chose.","mechanism":"deposit() mints `+
		`shares at total_assets/total_shares"},"affected":[{"path":`+
		`"src/ShareVault.sol","contract":"ShareVault","function":"deposit",`+
		`"lines":[42,60],"entry_point":true}],"attacker":{"profile":`+
		`"arbitrary EOA","capabilities":["deposit"]},"evidence":[],`+
		`"invariant":{"id":"INV-1","statement":"a depositor's share may not `+
		`decrease"},"assumptions":[{"kind":"state","description":"vault is `+
		`empty","satisfied_by":"be the first depositor"}],"preconditions":[],`+
		`"exploit_sequence":[{"step":1,"actor":"attacker","action":`+
		`"deposit(1 wei)"}]}`)
	code, out, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", bad)
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.HasPrefix(errS, "ingest failed: finding validation failed "+
		"at assumptions/0: ") {
		t.Fatalf("stderr = %q", errS)
	}
	if !strings.Contains(errS, "\nhint: did you use the preconditions shape "+
		"for an assumption? assumptions need {id, type, claim, status, "+
		"model_belief, blocking}; preconditions need {kind, description, "+
		"satisfied_by, enforced_by_poc} — see `webv2 ingest --example`\n") {
		t.Fatalf("stderr missing shape hint: %q", errS)
	}
}

func TestIngestMissingFileAndBadJSON(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, _, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", filepath.Join(root, "nope.json"))
	if code != 1 {
		t.Fatalf("missing file exit %d: %q", code, errS)
	}
	if !strings.Contains(errS, "[Errno 2] No such file or directory: ") {
		t.Fatalf("missing file error = %q", errS)
	}
	bad := filepath.Join(root, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json}"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errS = run(t, "--root", root, "ingest", cid, "--json-file", bad)
	if code != 1 {
		t.Fatalf("bad json exit %d: %q", code, errS)
	}
	want := "error: Expecting property name enclosed in double quotes: " +
		"line 1 column 2 (char 1)\n"
	if errS != want {
		t.Fatalf("bad json error = %q, want %q", errS, want)
	}
}

func TestIngestPriorityOutcomeNeedsAnswers(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "ingest", cid,
		"--priority-outcome", "answered", "--json-file", "x.json")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if errS != "--priority-outcome requires --answers-priority (there is "+
		"no plan priority to close without it)\n" {
		t.Fatalf("stderr = %q", errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
}

func TestIngestRefusesProbeRowPriority(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	// a plan with one probe row: ingest cannot supply the --anchor a probe
	// disposition requires, so it must refuse BEFORE writing the finding
	artifacts := filepath.Join(root, "campaigns", cid, "artifacts")
	if err := os.MkdirAll(artifacts, 0o755); err != nil {
		t.Fatal(err)
	}
	plan := `{"campaign_id":"` + cid + `","created_at":` +
		`"2026-09-10T00:00:00.000000+00:00","snapshot_id":"unpinned",` +
		`"strategy_note":"fixture","priorities":[{"id":"Q-005",` +
		`"question":"a question long enough to satisfy the schema",` +
		`"risk":0.5,"status":"open","components":[],"invariant_ids":[],` +
		`"required_context":[],"trajectories":[],"recommended_stages":[],` +
		`"budget_class":"standard","probe":{"row_id":"81dfad6492",` +
		`"probe_id":"assertion-strength","axis":"enforcement-timing",` +
		`"surface_sha":"4649be945ad02d2b81067a4dc64798537b948163e5516a8a1768458058ca6908",` +
		`"shape_sha":"6f498a3270b53c6e","risk_band":"high"}}],"lenses":[]}`
	if err := os.WriteFile(filepath.Join(artifacts, "campaign_plan.json"),
		[]byte(plan), 0o644); err != nil {
		t.Fatal(err)
	}
	payload := t14TestWrite(t, root, "payload.json", t14TestHypothesisJSON)
	code, out, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", payload, "--answers-priority", "Q-005")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	want := "ingest failed: priority Q-005 is probe row '81dfad6492' — a " +
		"probe disposition must name the field it claims is safe (--anchor), " +
		"which `ingest` cannot supply: ingest the finding WITHOUT " +
		"--answers-priority, then close the row with `webv2 answered " + cid +
		" Q-005 answered --reason <why> --actor <you> --anchor <field>`\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestIngestCorruptPlanIsReportedNotATraceback(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	artifacts := filepath.Join(root, "campaigns", cid, "artifacts")
	if err := os.MkdirAll(artifacts, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifacts, "campaign_plan.json"),
		[]byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	payload := t14TestWrite(t, root, "payload.json", t14TestHypothesisJSON)
	code, out, errS := run(t, "--root", root, "ingest", cid,
		"--json-file", payload, "--answers-priority", "Q-001")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	want := "ingest failed: cannot read the campaign plan (Expecting " +
		"property name enclosed in double quotes: line 1 column 2 " +
		"(char 1))\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestIngestUnrecognizedArgument(t *testing.T) {
	root := mkroot(t)
	code, _, errS := run(t, "--root", root, "ingest", "--bogus")
	if code != 2 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if !strings.HasSuffix(errS, "webv2: error: unrecognized arguments: "+
		"--bogus\n") {
		t.Fatalf("stderr = %q", errS)
	}
	if !strings.HasPrefix(errS, "usage: webv2 [-h] [--root ROOT]\n") {
		t.Fatalf("usage prefix = %q", errS)
	}
}

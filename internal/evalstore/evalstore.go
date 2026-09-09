// Package evalstore ports webv2.eval_store: the repo-level evaluation store.
//
// WHY: the cases belong to the FRAMEWORK, not to one campaign — so the store
// is repo-level (eval/cases.json), never campaign-level, and it is
// tamper-evident: a sha256 sidecar (eval/cases.sha256, one hex line) turns any
// hand edit into detectable drift, the same posture as the shared store's
// manifest (a hand edit is not an operation; AddCase is).
//
// Every write validates against schema/evaluation_case.schema.json via
// validation.Validate — a case that fails validation is a bug in the caller,
// never something to paper over with a warning. VerifyEvalStore re-validates
// every stored case and re-checks the sidecar hash, and reports problems
// without raising (mirroring sharedmem.VerifySharedStore).
package evalstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"websec/internal/state"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

// Names and partitions (CASES_NAME / SIDECAR_NAME / PARTITIONS).
const (
	CasesName   = "cases.json"
	SidecarName = "cases.sha256"
)

// Partitions is PARTITIONS.
var Partitions = []string{"dev", "held-out", "training"}

// EvalDir is EVAL_DIR. Python resolves it against the repo root
// (REPO_ROOT/eval); a Go binary has no source-relative root, so the default
// is the same path relative to the process working directory, and the
// WEBV2_EVAL_DIR seam (the golden harness / operators) overrides it.
func EvalDir() string {
	if dirOverride != nil {
		return *dirOverride
	}
	if v := os.Getenv("WEBV2_EVAL_DIR"); v != "" {
		return v
	}
	return "eval"
}

var dirOverride *string

// SetEvalDir points the store at dir (tests and operators).
func SetEvalDir(dir string) { dirOverride = &dir }

// ResetEvalDir restores the WEBV2_EVAL_DIR / cwd-relative default.
func ResetEvalDir() { dirOverride = nil }

// CasesPath is _cases_path.
func CasesPath() string { return filepath.Join(EvalDir(), CasesName) }

// SidecarPath is _sidecar_path.
func SidecarPath() string { return filepath.Join(EvalDir(), SidecarName) }

// NewCaseID is new_case_id: “CASE-<12 hex>“ — the schema's case_id shape.
//
// Python draws a RAW uuid.uuid4() here (not state.new_id); the id is opaque
// and never cross-compared, so the port uses state.NewID's pin-aware stream.
func NewCaseID() string {
	return state.NewID("CASE", 12)
}

// LoadCases is _load_cases: the stored cases, or [] when nothing has been
// ingested yet.
func LoadCases() ([]validation.Value, error) {
	p := CasesPath()
	if _, err := os.Stat(p); err != nil {
		return nil, nil
	}
	data, err := validation.ReadJson(p)
	if err != nil {
		return nil, err
	}
	if data.Kind != validation.Arr {
		return nil, fmt.Errorf(
			"%s must be a JSON list of evaluation cases", CasesName)
	}
	return data.A, nil
}

// writeCases is _write_cases: rewrite cases.json (atomic tmp+replace, house
// style) and refresh the sidecar so the hash always describes the file just
// written.
func writeCases(cases []validation.Value) error {
	out := CasesPath()
	if err := validation.WriteJson(out, validation.VArr(cases...), ""); err != nil {
		return err
	}
	digest, err := validation.Sha256File(out)
	if err != nil {
		return err
	}
	return os.WriteFile(SidecarPath(), []byte(digest+"\n"), 0o644)
}

// AddCase is add_case: validate + append one evaluation case, then rewrite
// both files. Stamps the framework-owned fields the caller may omit.
func AddCase(caseDoc validation.Value) (validation.Value, error) {
	if caseDoc.Kind != validation.Obj {
		return validation.VNull(), errors.New("an evaluation case must be a dict")
	}
	c := copyObj(caseDoc)
	c.O = setDefault(c.O, "case_id", validation.VStr(NewCaseID()))
	c.O = setDefault(c.O, "partition", validation.VStr("dev"))
	c.O = setDefault(c.O, "schema_version", validation.VInt(2))
	c.O = setDefault(c.O, "created_at", validation.VStr(state.NowIso()))

	if err := checkGoldClass(c); err != nil {
		return validation.VNull(), err
	}
	if err := validation.Validate(c, "evaluation_case", 1); err != nil {
		return validation.VNull(), err
	}
	cases, err := LoadCases()
	if err != nil {
		return validation.VNull(), err
	}
	cid := objStr(c, "case_id")
	for _, existing := range cases {
		if objStr(existing, "case_id") == cid {
			return validation.VNull(), fmt.Errorf(
				"eval case %s already exists — case ids are unique per store; "+
					"mint a new one instead of overwriting gold", cid)
		}
	}
	cases = append(cases, c)
	if err := writeCases(cases); err != nil {
		return validation.VNull(), err
	}
	return c, nil
}

// checkGoldClass is the gold taxonomy contract on top of the schema:
// gold.bug_class is a canonical class or the literal 'unmapped' — never a raw
// dataset label.
func checkGoldClass(c validation.Value) error {
	bugClass := objAt(objAt(c, "gold"), "bug_class")
	if bugClass.Kind == validation.Str && bugClass.S == taxonomy.UNMAPPED {
		return nil
	}
	if bugClass.Kind == validation.Str {
		if _, ok := taxonomy.CanonicalClasses()[bugClass.S]; ok {
			return nil
		}
	}
	return fmt.Errorf("gold.bug_class %s is neither a canonical class nor %s; "+
		"resolve raw dataset labels through taxonomy.normalize_class first",
		validation.PyRepr(bugClass), validation.PyReprStr(taxonomy.UNMAPPED))
}

// ListCases is list_cases, optionally filtered. A nil filter is Python's None.
func ListCases(partition, dataset, program *string) ([]validation.Value, error) {
	cases, err := LoadCases()
	if err != nil {
		return nil, err
	}
	out := make([]validation.Value, 0, len(cases))
	for _, c := range cases {
		if partition != nil && orDefault(objStr(c, "partition"), "dev") != *partition {
			continue
		}
		if dataset != nil &&
			objStr(objAt(c, "source"), "dataset") != *dataset {
			continue
		}
		if program != nil {
			got := strings.ToLower(strings.TrimSpace(
				objStr(objAt(c, "program"), "program")))
			if got != strings.ToLower(strings.TrimSpace(*program)) {
				continue
			}
		}
		out = append(out, c)
	}
	return out, nil
}

// LoadCase is load_case: one case by id; an error when absent (a missing gold
// label is a hard error for whoever asked, not an empty answer).
func LoadCase(caseID string) (validation.Value, error) {
	cases, err := LoadCases()
	if err != nil {
		return validation.VNull(), err
	}
	for _, c := range cases {
		if objStr(c, "case_id") == caseID {
			return c, nil
		}
	}
	return validation.VNull(), fmt.Errorf("no eval case %s",
		validation.PyReprStr(caseID))
}

// VerifyResult is verify_eval_store's report dict.
type VerifyResult struct {
	OK       bool
	Count    int
	Problems []string
}

// Value renders the report as the JSON object Python returns.
func (r VerifyResult) Value() validation.Value {
	problems := make([]validation.Value, 0, len(r.Problems))
	for _, p := range r.Problems {
		problems = append(problems, validation.VStr(p))
	}
	return validation.VObj(
		validation.KV{K: "ok", V: validation.VBool(r.OK)},
		validation.KV{K: "count", V: validation.VInt(int64(r.Count))},
		validation.KV{K: "problems", V: validation.VArr(problems...)})
}

// VerifyEvalStore is verify_eval_store: re-validate every case and re-check
// the sidecar hash. Report-never-raise: problems collects every finding, ok is
// false the moment anything is off. A store that does not exist yet is not a
// problem — nothing has been ingested.
func VerifyEvalStore() VerifyResult {
	casesPath, sidecarPath := CasesPath(), SidecarPath()
	problems := []string{}
	var cases []validation.Value
	exists := fileExists(casesPath)

	if exists {
		data, err := validation.ReadJson(casesPath)
		if err != nil {
			problems = append(problems,
				fmt.Sprintf("%s is not readable JSON: %v", CasesName, err))
		} else if data.Kind != validation.Arr {
			problems = append(problems,
				fmt.Sprintf("%s must be a JSON list of cases", CasesName))
		} else {
			cases = data.A
		}
	}
	seen := map[string]struct{}{}
	for i, c := range cases {
		if err := validation.Validate(c, "evaluation_case", 1); err != nil {
			problems = append(problems,
				fmt.Sprintf("%s[%d]: %v", CasesName, i, err))
		}
		cid := objStr(c, "case_id")
		if cid != "" {
			if _, dup := seen[cid]; dup {
				problems = append(problems, fmt.Sprintf(
					"%s[%d]: duplicate case_id %s", CasesName, i, cid))
			}
			seen[cid] = struct{}{}
		}
	}
	problems = append(problems, sidecarProblems(casesPath, sidecarPath, exists)...)
	return VerifyResult{OK: len(problems) == 0, Count: len(cases),
		Problems: problems}
}

// sidecarProblems is verify_eval_store's sidecar leg: a missing sidecar, a
// drifted hash, or a sidecar without a store.
func sidecarProblems(casesPath, sidecarPath string, casesExist bool) []string {
	var problems []string
	if casesExist {
		digest, err := validation.Sha256File(casesPath)
		if err != nil {
			problems = append(problems,
				fmt.Sprintf("%s is not readable: %v", CasesName, err))
			return problems
		}
		if !fileExists(sidecarPath) {
			problems = append(problems, fmt.Sprintf(
				"%s is missing — the store's tamper-evidence sidecar was removed",
				SidecarName))
			return problems
		}
		raw, err := os.ReadFile(sidecarPath)
		if err != nil {
			problems = append(problems,
				fmt.Sprintf("%s is not readable: %v", SidecarName, err))
			return problems
		}
		if strings.TrimSpace(string(raw)) != digest {
			problems = append(problems, fmt.Sprintf(
				"%s does not match %s — the store was modified outside add_case",
				SidecarName, CasesName))
		}
		return problems
	}
	if fileExists(sidecarPath) {
		problems = append(problems, fmt.Sprintf(
			"%s present without %s", SidecarName, CasesName))
	}
	return problems
}

// ---- helpers -------------------------------------------------------------

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func copyObj(v validation.Value) validation.Value {
	return validation.Value{Kind: validation.Obj,
		O: append([]validation.KV(nil), v.O...)}
}

// setDefault is dict.setdefault (key order: an absent key is appended).
func setDefault(o []validation.KV, key string, v validation.Value) []validation.KV {
	for _, kv := range o {
		if kv.K == key {
			return o
		}
	}
	return append(o, validation.KV{K: key, V: v})
}

func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

func objStr(v validation.Value, key string) string {
	x := objAt(v, key)
	if x.Kind == validation.Str {
		return x.S
	}
	return ""
}

// orDefault is `c.get("partition") or "dev"`.
func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

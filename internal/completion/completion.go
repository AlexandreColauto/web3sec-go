// Package completion is the artifact-based completion proofs (port of
// src/webv2/completion.py): a stage is DONE because artifacts prove it, not
// because someone wrote `done` into the state file.
//
// Completion is DERIVED: each stage declares a deterministic predicate over
// the campaign's own artifacts; Pipeline.run() auto-completes a blocked model
// stage whose proof holds, and halts — with the EXACT missing items — only on
// stages that are genuinely open. A `waive()` records a named actor, a
// written reason and a logged event; waived subjects satisfy the proof.
//
// Proof scope: MODEL stages carry authoritative proofs. Mixed/deterministic
// stages carry ADVISORY proofs — their builtins legitimately "run" without
// per-finding completion, so their proofs drive `next_actions` guidance,
// never audit failures.
package completion

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"websec/internal/findings"
	"websec/internal/pipeline"
	"websec/internal/state"
	"websec/internal/validation"
)

// OpenStatuses are the finding statuses that still await operator/model work.
var OpenStatuses = []string{"HYPOTHESIS", "NEEDS_RESEARCH",
	"PROVISIONALLY_VALID", "POSSIBLE"}

// TerminalStatuses are the finding statuses the learning proof tracks.
var TerminalStatuses = []string{"CONFIRMED", "DISPROVED", "DUPLICATE",
	"OUT_OF_SCOPE", "INFORMATIONAL", "CHAIN", "SUPERSEDED"}

// AllAxes is ALL_AXES: the maximal-exploitation variant axes.
var AllAxes = []string{"capital-minimization", "precondition-removal",
	"role-conflation", "ordering-permutation", "cap-saturation"}

// ---------------------------------------------------------------------------
// waivers — recorded dispositions, never silent skips
// ---------------------------------------------------------------------------

// WaiversPath is _waivers_path.
func WaiversPath(c *state.Campaign) string {
	return filepath.Join(campaignDir(c), "waivers.jsonl")
}

// Waivers is waivers(): the recorded waiver rows, optionally filtered by
// stage ("" = no filter).
//
// r40c P2-3: the frame is the file's OWN frame — one row per "\n"-delimited
// physical line, blanks decided by state.BlankLine, THE one framing
// predicate — exactly what state.readWaiverRowsR12 (the reader verify and
// the audit use) does. Before this the reader used CPython's
// str.splitlines(), which counts U+2028/U+2029/U+0085 as row breaks: the
// writer's raw separator split the row in half, the first fragment died
// with a bare "unexpected EOF" naming no file/line, the proof read "open"
// while verify said ok:true, and the recorded waiver was never consulted.
// The writer no longer emits those raw (pyjson.go escapes them), and rows
// written BEFORE that fix — the ones already on disk — now read here the
// same way the audit reader reads them: as the single valid JSON row their
// bytes are. The alternative — teaching this reader the exotic separators —
// would leave the two readers disagreeing on everything a hypothetical
// third writer emits; there is one frame now, and it is the physical line.
func Waivers(c *state.Campaign, stage string) ([]validation.Value, error) {
	raw, err := os.ReadFile(WaiversPath(c))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	rows := []validation.Value{}
	for i, ln := range strings.Split(string(raw), "\n") {
		// state.BlankLine, never a local copy: r38's finding was two
		// packages answering "blank" differently about the same bytes (a
		// U+00A0-only line is a RECORD here, as it is for every other
		// JSONL reader in the tree).
		if state.BlankLine(ln) {
			continue
		}
		row, err := validation.ParseOrdered([]byte(ln))
		if err != nil {
			// r13: a bare JSON error makes the operator diff the file by
			// eye — name the file and the physical line.
			return nil, fmt.Errorf("waivers.jsonl line %d: %v", i+1, err)
		}
		if stage != "" && validation.ObjStr(row, "stage") != stage {
			continue
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// Waive is waive(): waive one proof subject ('*' waives the whole stage).
// Requires a named actor and a written reason; logged, append-only.
func Waive(c *state.Campaign, stage, subject, reason, actor string) (validation.Value, error) {
	if reason == "" || pyLen(pyStrip(reason)) < 10 {
		return validation.VNull(), fmt.Errorf("%s", "a waiver needs a written "+
			"reason (>=10 chars): the point is the audit trail, not the bypass")
	}
	if actor == "" {
		return validation.VNull(), fmt.Errorf("%s", "a waiver needs a named actor")
	}
	subj := subject
	if subj == "" {
		subj = "*"
	}
	trimmed := pyStrip(reason)
	row := validation.VObj(
		kv("stage", validation.VStr(stage)),
		kv("subject", validation.VStr(subj)),
		kv("reason", validation.VStr(trimmed)),
		kv("actor", validation.VStr(actor)),
		kv("at", validation.VStr(state.NowIso())),
	)
	// r13: the waiver row and its completion.waived event are ONE unit
	// (VerifyLog cross-checks them both directions). Another process
	// must not observe or interleave half of it: hold the campaign lock
	// across the append AND the Log. A hard crash between the two still
	// burns red loudly — that residue is inherent to a two-store pair
	// without a shared commit, and the red is honest.
	// r38 P2-2: a REFUSED Log is that shape's sibling and must not leave
	// the waiver half-landed — pre-r38 the row was appended first and the
	// Log error returned with the row still on disk, so a truncated
	// ledger (mirror longer than the log) recorded a waiver the ledger
	// never did: VerifyLog red-lines "a waiver without its event" and the
	// retry appended a SECOND row. state.AppendJsonlThenLog is the shared
	// r36 unwind-on-refusal dance (snapshot -> append -> log -> restore
	// the exact pre-write bytes on refusal), the same one the cost pair
	// and learning's JSONL writers use.
	ref := stage
	data := validation.VObj(
		kv("subject", validation.VStr(subj)),
		kv("actor", validation.VStr(actor)),
		kv("reason", validation.VStr(trimmed)),
	)
	if err := state.AppendJsonlThenLog(c, WaiversPath(c), pyJSONDumps(row),
		func() error {
			_, lerr := c.Log("completion.waived", &ref, &data)
			return lerr
		}); err != nil {
		return validation.VNull(), err
	}
	return row, nil
}

// waiverMap is _waiver_map: subject -> row for one stage.
func waiverMap(c *state.Campaign, stage string) (map[string]validation.Value, error) {
	rows, err := Waivers(c, stage)
	if err != nil {
		return nil, err
	}
	out := map[string]validation.Value{}
	for _, w := range rows {
		out[validation.ObjStr(w, "subject")] = w
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// helpers shared by proofs
// ---------------------------------------------------------------------------

// liveFindings is _live_findings (findings.load_all_findings).
func liveFindings(c *state.Campaign) ([]validation.Value, error) {
	return findings.LoadAllFindings(c)
}

// findingsWith is _findings_with: the live findings in one of statuses.
func findingsWith(c *state.Campaign, statuses []string) ([]validation.Value, error) {
	live, err := liveFindings(c)
	if err != nil {
		return nil, err
	}
	out := []validation.Value{}
	for _, f := range live {
		st := validation.ObjStr(f, "status")
		for _, want := range statuses {
			if st == want {
				out = append(out, f)
				break
			}
		}
	}
	return out, nil
}

// proofItem is one (subject_id, what_is_missing) pair.
type proofItem struct {
	subject string
	missing string
}

// unwaived is _unwaived: missing strings, dropping subjects covered by a
// stage-wide ('*') or per-subject waiver.
func unwaived(items []proofItem, waived map[string]validation.Value,
	format func(subject, missing string) string) []string {
	if _, ok := waived["*"]; ok {
		return []string{}
	}
	out := []string{}
	for _, it := range items {
		if _, ok := waived[it.subject]; ok {
			continue
		}
		out = append(out, format(it.subject, it.missing))
	}
	return out
}

// proofResult builds {"done":…, "missing":…, "note":…} in Python key order.
func proofResult(done bool, missing []string, note string) validation.Value {
	return validation.VObj(
		kv("done", validation.VBool(done)),
		kv("missing", validation.StrArr(missing)),
		kv("note", validation.VStr(note)),
	)
}

// ---------------------------------------------------------------------------
// proof registry and the public API
// ---------------------------------------------------------------------------

// ProofFunc evaluates one stage's proof. It returns Python's proof dict; an
// error is Python's raised exception (proof_status turns it into the
// "proof raised" bundle, so a proof can never crash the scheduler).
type ProofFunc func(c *state.Campaign) (validation.Value, error)

// Proofs is PROOFS: stage id -> proof builder.
var Proofs = map[string]ProofFunc{
	"protocol-model":           proofProtocolModel,
	"campaign-planning":        proofCampaignPlanning,
	"discovery":                proofDiscovery,
	"dedup":                    proofDedup,
	"hostile-review":           proofHostileReview,
	"reproduction":             proofReproduction,
	"maximal-exploitation":     proofMaximalExploitation,
	"independent-verification": proofIndependentVerification,
	"risk-calibration":         proofRiskCalibration,
	"mainnet-fork-poc":         proofMainnetForkPoc,
	"bounty-gate":              proofBountyGate,
	"report":                   proofReport,
	"learning":                 proofLearning,
}

// proofOrder is PROOFS' insertion order (Python dicts are ordered; Go maps
// are not, and the audit + all_proof_status iterate in this order).
var proofOrder = []string{
	"protocol-model", "campaign-planning", "discovery", "dedup",
	"hostile-review", "reproduction", "maximal-exploitation",
	"independent-verification", "risk-calibration", "mainnet-fork-poc",
	"bounty-gate", "report", "learning",
}

// stageKind is _KIND: stage id -> kind from the pipeline STAGES table.
func stageKind(stage string) string {
	for _, s := range pipeline.Stages {
		if s.ID == stage {
			return s.Kind
		}
	}
	return ""
}

// HasProof is has_proof.
func HasProof(stage string) bool {
	_, ok := Proofs[stage]
	return ok
}

// ProofStatus is proof_status: evaluate one stage's proof. Null = the stage
// declares no proof (Python's None).
func ProofStatus(c *state.Campaign, stage string) (validation.Value, error) {
	fn, ok := Proofs[stage]
	if !ok {
		return validation.VNull(), nil
	}
	out, err := fn(c)
	if err != nil { // a proof must never crash the scheduler
		out = proofResult(false, []string{"proof error: " + err.Error()},
			"proof raised")
	}
	out.O = append(out.O,
		kv("stage", validation.VStr(stage)),
		kv("authoritative", validation.VBool(stageKind(stage) == "model")))
	return out, nil
}

// AllProofStatus is all_proof_status: every stage's proof, in PROOFS order.
func AllProofStatus(c *state.Campaign) (validation.Value, error) {
	kvs := make([]validation.KV, 0, len(proofOrder))
	for _, sid := range proofOrder {
		pr, err := ProofStatus(c, sid)
		if err != nil {
			return validation.VNull(), err
		}
		kvs = append(kvs, kv(sid, pr))
	}
	return validation.VObj(kvs...), nil
}

// AuditStageLedger is audit_stage_ledger: MODEL stages the ledger marks done
// while their proof fails. The paper-over detector — a raw set_stage('done')
// can still schedule the DAG, but it cannot survive the audit.
func AuditStageLedger(c *state.Campaign) ([]string, error) {
	problems := []string{}
	st, err := c.State()
	if err != nil {
		return nil, err
	}
	stages := orEmpty(validation.ObjAt(st, "stages"))
	for _, sid := range proofOrder {
		if stageKind(sid) != "model" {
			continue
		}
		entry := orEmpty(validation.ObjAt(stages, sid))
		if validation.ObjStr(entry, "status") != "done" {
			continue
		}
		pr, err := ProofStatus(c, sid)
		if err != nil {
			return nil, err
		}
		if pr.Kind == validation.Obj && !pyTruthyBigNonEmpty(validation.ObjAt(pr, "done")) {
			missing := strList(validation.ObjAt(pr, "missing"))
			head := missing
			if len(head) > 5 {
				head = head[:5]
			}
			msg := fmt.Sprintf("stage %s is marked done but its completion "+
				"proof fails: %s", validation.PyReprStr(sid),
				strings.Join(head, "; "))
			if len(missing) > 5 {
				msg += " (+more)"
			}
			problems = append(problems, msg)
		}
	}
	return problems, nil
}

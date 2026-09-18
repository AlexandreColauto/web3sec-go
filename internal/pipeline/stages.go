// Pipeline stages — the canonical STAGES table and its per-stage metadata accessors (split from pipeline.go; pure structural move).

package pipeline

// Stage is one row of STAGES: (stage id, kind, campaign phase it advances).
//
//	deterministic — code performs it
//	model         — a model stage; the runner halts unless a handler is given
//	mixed         — code bootstraps it, a model may refine it
type Stage struct {
	ID    string
	Kind  string
	Phase string
}

// Stages is the canonical STAGES table, transcribed verbatim from the Python
// constants (golden-tested against the Python twin).
var Stages = []Stage{
	{"scope", "deterministic", "SCOPE"},
	{"snapshot", "deterministic", "SNAPSHOT"},
	{"structural-index", "deterministic", "STRUCTURAL_INDEX"},
	{"protocol-model", "model", "PROTOCOL_INTELLIGENCE"},
	{"campaign-planning", "mixed", "CAMPAIGN_PLANNING"},
	{"discovery", "model", "DISCOVERY"},
	{"dedup", "mixed", "CANDIDATE_INTEL"},
	{"hostile-review", "model", "HOSTILE_REVIEW"},
	{"reproduction", "mixed", "REPRODUCTION"},
	{"chaining", "deterministic", "CHAINING"},
	{"maximal-exploitation", "model", "MAXIMAL_EXPLOITATION"},
	{"independent-verification", "model", "INDEPENDENT_VERIFICATION"},
	{"risk-calibration", "deterministic", "RISK_CALIBRATION"},
	{"mainnet-fork-poc", "model", "MAINNET_FORK_POC"},
	{"bounty-gate", "deterministic", "BOUNTY_GATE"},
	{"report", "deterministic", "REPORTING"},
	{"learning", "model", "LEARNING"},
}

// StageIDs is STAGE_IDS.
var StageIDs = stageIDs()

func stageIDs() []string {
	out := make([]string, len(Stages))
	for i, s := range Stages {
		out[i] = s.ID
	}
	return out
}

func stageByID(sid string) (Stage, bool) {
	for _, s := range Stages {
		if s.ID == sid {
			return s, true
		}
	}
	return Stage{}, false
}

// StageKind is stage_kind.
func StageKind(sid string) string {
	s, _ := stageByID(sid)
	return s.Kind
}

// StagePhase is _PHASE[sid].
func StagePhase(sid string) string {
	s, _ := stageByID(sid)
	return s.Phase
}

func isStageID(sid string) bool {
	_, ok := stageByID(sid)
	return ok
}

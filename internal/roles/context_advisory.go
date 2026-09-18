// context_advisory.go: advisory context helpers split out of context.go —
// sequence requirements, the simulation directive, benign-actor audit flags
// and the finding summary projection.
package roles

import (
	"fmt"
	"sort"
	"websec/internal/findings"
	"websec/internal/playbooks"
	"websec/internal/sequencepoc"
	"websec/internal/state"
	"websec/internal/validation"
)

// sequenceRequirements is _sequence_requirements: live findings whose
// declared exploit_sequence needs a multi-tx PoC. ONE helper consumed by BOTH
// bundles — parity is test-pinned. Advisory only.
func sequenceRequirements(campaign *state.Campaign) ([]validation.Value, error) {
	live, err := findings.LoadLiveFindings(campaign)
	if err != nil {
		return nil, err
	}
	out := []validation.Value{}
	for _, f := range live {
		if !sequencepoc.IsSequenceRequired(f) {
			continue
		}
		seq := validation.ObjAt(f, "exploit_sequence")
		steps := 0
		actorSet := map[string]bool{}
		if seq.Kind == validation.Arr {
			steps = len(seq.A)
			for _, s := range seq.A {
				if s.Kind != validation.Obj {
					continue
				}
				if a := validation.ObjAt(s, "actor"); a.Kind == validation.Str &&
					a.S != "" {
					actorSet[a.S] = true
				}
			}
		}
		actors := make([]string, 0, len(actorSet))
		for a := range actorSet {
			actors = append(actors, a)
		}
		sort.Strings(actors)
		note := fmt.Sprintf("declared exploit_sequence has %d steps / %d "+
			"actor(s) — a single-call PoC cannot cover it; attempt T4 with "+
			"`webv2 sequence run`", steps, len(actors))
		out = append(out, validation.VObj(
			validation.KV{K: "finding_id", V: validation.ObjAt(f, "finding_id")},
			validation.KV{K: "steps", V: validation.VInt(int64(steps))},
			validation.KV{K: "actors", V: validation.StrArr(actors)},
			validation.KV{K: "note", V: validation.VStr(note)}))
	}
	return out, nil
}

// simulationDirectiveBlock is _simulation_directive_block: the
// simulation-mode prior for per-class proposer passes (spec 3.2 §4.2).
func simulationDirectiveBlock(playbook validation.Value) validation.Value {
	if playbook.Kind != validation.Obj {
		return validation.VNull()
	}
	if validation.ObjStr(playbook, "investigation_mode") != "adversarial-simulation" {
		return validation.VNull()
	}
	sim := validation.ObjAt(playbook, "simulation")
	if sim.Kind != validation.Obj {
		return validation.VNull()
	}
	ref := validation.ObjAt(sim, "expectation_violated")
	statement := ""
	if invs := validation.ObjAt(playbook, "invariants"); invs.Kind == validation.Arr {
		for _, i := range invs.A {
			if i.Kind == validation.Obj && sameScalar(validation.ObjAt(i, "id"), ref) {
				statement = validation.ObjStr(i, "statement")
				break
			}
		}
	}
	return validation.VObj(
		validation.KV{K: "mode", V: validation.VStr("adversarial-simulation")},
		validation.KV{K: "stage_prompt",
			V: validation.VStr("prompts/50_adversarial_simulation.md")},
		validation.KV{K: "simulation", V: sim},
		validation.KV{K: "expectation", V: validation.VObj(
			validation.KV{K: "id", V: ref},
			validation.KV{K: "statement", V: validation.VStr(statement)})},
		validation.KV{K: "note", V: validation.VStr("this class is hunted as " +
			"a game-theoretic simulation, not code reading: model the cast, " +
			"their capital and rationality, the ordering freedoms, and " +
			"propose strategy profiles that violate the documented " +
			"expectation; exploit_sequence steps must be attributed to " +
			"named actors")})
}

// benignActorAuditBlock is _benign_actor_audit_block: advisory value-echo
// flags for findings whose class has a simulation-mode playbook.
func benignActorAuditBlock(campaign *state.Campaign,
	finding validation.Value) validation.Value {
	cls := validation.ObjStr(validation.ObjAt(finding, "root_cause"), "class")
	if cls == "" {
		return validation.VNull()
	}
	pb, found, err := playbooks.PlaybookForClass(cls)
	if err != nil || !found {
		return validation.VNull()
	}
	sim := validation.ObjAt(pb, "simulation")
	if sim.Kind != validation.Obj {
		return validation.VNull()
	}
	cast := map[string]string{}
	if actors := validation.ObjAt(sim, "actors"); actors.Kind == validation.Arr {
		for _, a := range actors.A {
			if a.Kind != validation.Obj {
				continue
			}
			if name := validation.ObjAt(a, "name"); name.Kind == validation.Str {
				cast[name.S] = validation.ObjStr(a, "behavior_class")
			}
		}
	}
	flags := sequencepoc.BenignActorAudit(validation.ObjAt(finding, "exploit_sequence"), cast)
	if len(flags) == 0 {
		return validation.VNull()
	}
	return validation.VArr(flags...)
}

// findingSummary is _finding_summary: the only shape of an existing finding
// a role other than its owner ever sees.
func findingSummary(f validation.Value) validation.Value {
	levels := []validation.Value{}
	if ev := validation.ObjAt(f, "evidence"); ev.Kind == validation.Arr {
		for _, e := range ev.A {
			levels = append(levels, validation.ObjAt(e, "level"))
		}
	}
	return validation.VObj(
		validation.KV{K: "finding_id", V: validation.ObjAt(f, "finding_id")},
		validation.KV{K: "title", V: validation.ObjAt(f, "title")},
		validation.KV{K: "status", V: validation.ObjAt(f, "status")},
		validation.KV{K: "trajectory", V: validation.ObjAt(f, "trajectory")},
		validation.KV{K: "bug_class", V: validation.ObjAt(validation.ObjAt(f, "root_cause"), "class")},
		validation.KV{K: "evidence_levels", V: validation.VArr(levels...)})
}

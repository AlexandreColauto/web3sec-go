// Context-bundle concern: build_context() and its bounded block builder —
// the exact artifacts a stage's prompt gets, under a character budget.
package adapter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// structuredOutputs is the stable map of ingest functions a model must use.
func structuredOutputs() validation.Value {
	return validation.VObj(
		validation.KV{K: "hypotheses", V: validation.VStr("findings.ingest_hypothesis(campaign, payload, trajectory=...)")},
		// D4: the callable surface, not the Python function name. The setters
		// have no dispatch entry, so a model told to "call
		// dedup.set_root_cause_signature" had nothing to call and the only way
		// a campaign got a tier-2/3 signature was a hand-written 16-hex.
		validation.KV{K: "dedup_signatures", V: validation.VStr("webv2 dedup-signature <campaign> <finding> --root-cause 'target-agnostic root-cause sentence'   (or: --economic 'target-agnostic economic-effect sentence'; the tool derives the 16-hex signature from the sentence)")},
		validation.KV{K: "drifts", V: validation.VStr("learning.record_drifts(campaign, snapshot_id, drifts)")},
		validation.KV{K: "memory", V: validation.VStr("learning.queue_memory(...)")},
		validation.KV{K: "evidence", V: validation.VStr("findings.add_evidence(campaign, finding_id, item)")},
		validation.KV{K: "critic_verdict", V: validation.VStr("findings.set_critic_verdict(campaign, finding_id, verdict, reasoning)")},
		validation.KV{K: "repro_attempt", V: validation.VStr("reproduction.record_attempt(campaign, finding_id, outcome, ...)")},
		validation.KV{K: "exploitability", V: validation.VStr("webv2 exploit <campaign> <finding> --paid --arg 'who pays, and why the bug makes them pay (>= 200 chars)'   (or: --unpaid --arg 'why the finding is not payable')")},
		validation.KV{K: "adversarial_game", V: validation.VStr("webv2 adversarial-game <campaign> <finding> --who-profit 'who profits from the freeze' --mechanism 'how the profit works' --interplay 'why the challenge path does not undo it'   (liveness findings only; each field >= 20 chars; the bounty gate check15 re-validates)")},
		validation.KV{K: "chain", V: validation.VStr("webv2 chain <campaign> <finding> <finding> [...] [--title 'chain title'] [--note 'narrative'] [--unproven]   (without --unproven every member must be CONFIRMED/CHAIN on one shared source pin and a CHAIN super-finding is written; --unproven materializes a HYPOTHESIS-level LEAD: provenance unproven, per-link evidence levels, NO super-finding — never counted as confirmed)")},
	)
}

// blockBuilder accumulates context blocks against a character budget; once
// the budget is spent further blocks are dropped (never truncated to empty).
type blockBuilder struct {
	budget int64
	blocks []validation.Value
}

// add appends one block, truncating its text to the remaining budget.
// The budget is counted in CHARACTERS, exactly like the reference
// (`text = text[:budget]; budget -= len(text)`), so a multi-byte rune
// straddling the boundary must not shorten the block (or drain extra budget).
func (b *blockBuilder) add(title, text string) {
	if b.budget <= 0 {
		return
	}
	runes := []rune(text)
	if int64(len(runes)) > b.budget {
		runes = runes[:b.budget]
	}
	b.budget -= int64(len(runes))
	text = string(runes)
	b.blocks = append(b.blocks, validation.VObj(
		validation.KV{K: "title", V: validation.VStr(title)},
		validation.KV{K: "text", V: validation.VStr(text)}))
}

// BuildContext is build_context(): the bounded context bundle a stage needs.
func BuildContext(c *state.Campaign, stage string, maxChars int64,
	extraPaths []string) (validation.Value, error) {
	if maxChars == 0 {
		maxChars = 60000
	}
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	bb := &blockBuilder{budget: maxChars}
	if err := gatherContextBlocks(c, st, stage, extraPaths, bb); err != nil {
		return validation.VNull(), err
	}
	promptPath, err := PromptPath(stage)
	if err != nil {
		return validation.VNull(), err
	}
	promptText, err := PromptText(mustRel(stage))
	if err != nil {
		return validation.VNull(), err
	}
	budgetClass, _, err := StageConfig(stage)
	if err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		validation.KV{K: "stage", V: validation.VStr(stage)},
		validation.KV{K: "prompt_path", V: validation.VStr(promptPath)},
		validation.KV{K: "prompt", V: validation.VStr(promptText)},
		validation.KV{K: "budget_class", V: validation.VStr(budgetClass)},
		validation.KV{K: "blocks", V: validation.VArr(bb.blocks...)},
		validation.KV{K: "structured_outputs", V: structuredOutputs()},
	), nil
}

// addArtifactBlocks is the three artifact texts build_context injects, each
// capped, in order: protocol model, campaign plan, coverage.
func addArtifactBlocks(c *state.Campaign, bb *blockBuilder) error {
	for _, b := range []struct {
		title string
		file  string
		cap   int
	}{
		{"protocol_model", "protocol_model.json", 20000},
		{"campaign_plan", "campaign_plan.json", 8000},
		{"coverage", "coverage.json", 6000},
	} {
		text, err := readTextIfExists(filepath.Join(c.ArtifactsDir, b.file))
		if err != nil {
			return err
		}
		if text != nil {
			bb.add(b.title, truncate(*text, b.cap))
		}
	}
	return nil
}

// gatherContextBlocks fills the budget in build_context's order: the campaign
// header, the pinned snapshot, the structural index stats, the three artifact
// texts, the boundary matrix for boundary stages, the finding index, then the
// operator's extra paths.
func gatherContextBlocks(c *state.Campaign, st validation.Value, stage string,
	extraPaths []string, bb *blockBuilder) error {
	phase := validation.ObjAt(st, "phase")
	program := validation.ObjAt(st, "program")
	activeSnapshot := validation.ObjAt(st, "active_snapshot_id")
	pass := validation.ObjAt(validation.ObjAt(st, "budget"), "pass")
	bb.add("campaign", fmt.Sprintf("campaign_id: %s\nprogram: %s\nphase: %s\n"+
		"active_snapshot: %s\npass: %s", c.CampaignID, scalarStr(program),
		scalarStr(phase), scalarStr(activeSnapshot), scalarStr(pass)))
	if sid := scalarStr(activeSnapshot); sid != "None" {
		snap := filepath.Join(c.Dir, "snapshots", sid, "snapshot.json")
		if text, err := readTextIfExists(snap); err != nil {
			return err
		} else if text != nil {
			bb.add("snapshot", truncate(*text, 4000))
		}
	}
	idx := filepath.Join(c.ArtifactsDir, "structural_index.json")
	if text, err := readTextIfExists(idx); err != nil {
		return err
	} else if text != nil {
		ix, err := validation.ParseOrdered([]byte(*text))
		if err != nil {
			return err
		}
		bb.add("structural_index_stats",
			validation.DumpsOrdered(validation.ObjAt(ix, "stats"), true))
	}
	if err := addArtifactBlocks(c, bb); err != nil {
		return err
	}
	if boundaryStages[stage] {
		bb.add("boundary_matrix", BoundaryMatrix())
	}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return err
	}
	if len(all) > 0 {
		lines := []string{}
		for i, f := range all {
			if i >= 80 {
				break
			}
			lines = append(lines, findingIndexLine(f))
		}
		bb.add("finding_index", strings.Join(lines, "\n"))
	}
	for _, p := range extraPaths {
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			continue
		}
		text, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		bb.add(filepath.Base(p), string(text))
	}
	return nil
}

// findingIndexLine is one finding_index JSON line (Python json.dumps).
func findingIndexLine(f validation.Value) string {
	levels := validation.VArr()
	for _, e := range validation.ObjAt(f, "evidence").A {
		levels.A = append(levels.A, validation.ObjAt(e, "level"))
	}
	line := validation.VObj(
		validation.KV{K: "finding_id", V: validation.ObjAt(f, "finding_id")},
		validation.KV{K: "title", V: validation.ObjAt(f, "title")},
		validation.KV{K: "status", V: validation.ObjAt(f, "status")},
		validation.KV{K: "trajectory", V: validation.ObjAt(f, "trajectory")},
		validation.KV{K: "bug_class", V: validation.ObjAt(validation.ObjAt(f, "root_cause"), "class")},
		validation.KV{K: "evidence_levels", V: levels},
	)
	return validation.DumpsOrdered(line, true)
}

// truncate is Python's `s[:n]`: a CHARACTER slice (the reference caps block
// text with `[:cap]` before the budget clip).
func truncate(s string, n int) string {
	if runes := []rune(s); len(runes) > n {
		return string(runes[:n])
	}
	return s
}

func readTextIfExists(path string) (*string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	s := string(raw)
	return &s, nil
}

// scalarStr renders a scalar the way Python's str() would inside an f-string.
func scalarStr(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return v.S
	case validation.Null:
		return "None"
	case validation.Bool:
		if v.B {
			return "True"
		}
		return "False"
	case validation.Int:
		return validation.IntText(v)
	case validation.Flt:
		return validation.PythonFloat(v.F)
	}
	return ""
}

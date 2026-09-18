// Pipeline builtins — model bundle assembly, ladder paths/findings and the built-in stage handlers (split from pipeline.go; pure structural move).

package pipeline

import (
	"errors"
	"fmt"

	"path/filepath"
	"websec/internal/findings"
	"websec/internal/validation"
)

// modelBundle is _model_bundle: the bounded context a model stage needs. The
// runner never calls a model; it hands over exactly what the operator does.
func (p *Pipeline) modelBundle(sid string) (validation.Value, error) {
	stage := sid
	if mapped, ok := ModelStagePrompt[sid]; ok {
		stage = mapped
	}
	proof, err := completionImpl.ProofStatus(p.C, sid)
	if err != nil {
		return validation.VNull(), err
	}
	missing := validation.VArr()
	if proof.Kind == validation.Obj {
		missing = validation.ObjAt(proof, "missing")
	}
	bundle := validation.VObj(
		kvOf("stage", validation.VStr(sid)),
		kvOf("completion_missing", missing),
	)
	extra, err := p.ladderPaths(stage)
	if err != nil {
		return validation.VNull(), err
	}
	ctx, err := adapterImpl.BuildContext(p.C, stage, extra)
	if err != nil {
		if isAdapterAbsent(err) {
			bundle.O = append(bundle.O,
				kvOf("adapter_stage", validation.VStr(stage)),
				kvOf("prompt_path", validation.VStr("unmapped")),
				kvOf("error", validation.VStr(err.Error())))
			return bundle, nil
		}
		return validation.VNull(), err
	}
	for _, key := range []string{"prompt_path", "budget_class"} {
		if !validation.HasKey(ctx, key) {
			return adapterKeyError(bundle, stage, key), nil
		}
	}
	blocksVal := validation.ObjAt(ctx, "blocks")
	if blocksVal.Kind != validation.Arr {
		return validation.VNull(), errors.New("adapter context blocks is not a list")
	}
	blocks := []validation.Value{}
	for _, b := range blocksVal.A {
		if !validation.HasKey(b, "title") {
			return adapterKeyError(bundle, stage, "title"), nil
		}
		blocks = append(blocks, validation.ObjAt(b, "title"))
	}
	if !validation.HasKey(ctx, "structured_outputs") {
		return adapterKeyError(bundle, stage, "structured_outputs"), nil
	}
	bundle.O = append(bundle.O,
		kvOf("adapter_stage", validation.VStr(stage)),
		kvOf("prompt_path", validation.ObjAt(ctx, "prompt_path")),
		kvOf("budget_class", validation.ObjAt(ctx, "budget_class")),
		kvOf("blocks", validation.VArr(blocks...)),
		kvOf("how_to_feed_back", validation.ObjAt(ctx, "structured_outputs")))
	return bundle, nil
}

// adapterKeyError is Python's `except KeyError`: str(KeyError(key)) is the
// repr of the missing key, and the bundle degrades to prompt_path "unmapped".
func adapterKeyError(bundle validation.Value, stage, key string) validation.Value {
	bundle.O = append(bundle.O,
		kvOf("adapter_stage", validation.VStr(stage)),
		kvOf("prompt_path", validation.VStr("unmapped")),
		kvOf("error", validation.VStr(validation.PyReprStr(key))))
	return bundle
}

// ladderPaths is _model_bundle's extra list: the working artifact for both
// verification stages (the maximizer extends it, the verifier attacks it).
func (p *Pipeline) ladderPaths(stage string) ([]string, error) {
	extra := []string{}
	if stage != "maximal-exploitation" && stage != "independent-verification" {
		return extra, nil
	}
	ladders, err := p.ladderFindings()
	if err != nil {
		return nil, err
	}
	for _, f := range ladders {
		fid := validation.ObjStr(f, "finding_id")
		lad, err := maximizationImpl.LoadLadder(p.C, fid)
		if err != nil {
			return nil, err
		}
		if lad.Kind != validation.Null {
			extra = append(extra, filepath.Join(p.C.Dir, "ladders", fid+".json"))
		}
	}
	return extra, nil
}

// ladderFindings is _ladder_findings: findings that carry a variant ladder.
func (p *Pipeline) ladderFindings() ([]validation.Value, error) {
	all, err := findings.LoadAllFindings(p.C)
	if err != nil {
		return nil, err
	}
	out := []validation.Value{}
	for _, f := range all {
		if validation.PyTruthy(validation.ObjAt(validation.ObjAt(f, "maximization"), "ladder_id")) {
			out = append(out, f)
		}
	}
	return out, nil
}

// builtin is _builtin: the default implementations for the deterministic and
// mixed stages, delegating to the orchestrator so there is one owner of each.
func (p *Pipeline) builtin(sid string) (validation.Value, error) {
	o := p.O
	if o == nil {
		o = defaultOrchestrator
	}
	if o == nil {
		return validation.VNull(), fmt.Errorf(
			"no orchestrator wired; cannot run stage %s", validation.PyReprStr(sid))
	}
	switch sid {
	case "scope":
		return o.Scope()
	case "structural-index":
		index, err := o.BuildStructuralIndex()
		if err != nil {
			return validation.VNull(), err
		}
		stats := validation.ObjAt(index, "stats")
		return validation.VObj(
			kvOf("solidity_files", objOr(stats, "solidity_files", validation.VInt(0))),
			kvOf("contracts", objOr(stats, "contracts", validation.VInt(0))),
			kvOf("functions", objOr(stats, "functions", validation.VInt(0))),
			kvOf("entry_points", objOr(stats, "entry_points", validation.VInt(0))),
			kvOf("entry_count", objOr(index, "entry_count", validation.VInt(0))),
			kvOf("artifact", validation.VStr("artifacts/structural_index.json")),
		), nil
	case "dedup":
		return o.RunDedup()
	case "chaining":
		return o.Chaining()
	case "risk-calibration":
		return o.CalibrateAll()
	case "bounty-gate":
		return o.BountyGateAll()
	case "report":
		path, err := reportImpl.Generate(p.C)
		if err != nil {
			return validation.VNull(), err
		}
		return validation.VStr(path), nil
	case "campaign-planning":
		return p.builtinCampaignPlanning(o)
	case "snapshot":
		active, err := p.C.ActiveSnapshotIDOrNone()
		if err != nil {
			return validation.VNull(), err
		}
		if active != nil {
			return validation.VStr("already pinned: " + *active), nil
		}
		return validation.VNull(), errors.New("snapshot needs a target path: " +
			"call orchestrator.snapshot(target) or register a handler for the " +
			"'snapshot' stage")
	case "reproduction":
		return o.ReproductionQueue()
	}
	return validation.VNull(), fmt.Errorf("no builtin for stage %s; register a handler",
		validation.PyReprStr(sid))
}

// builtinCampaignPlanning is the campaign-planning builtin (B1/D1): a plan
// already on disk is the campaign's CONTRACT, so the stage reuses it instead
// of regenerating it. Returning the raw result would bury that in a capped
// JSON blob (state cap_note); the operator gets one line saying WHAT
// happened and HOW to regenerate.
func (p *Pipeline) builtinCampaignPlanning(
	o OrchestratorAPI) (validation.Value, error) {
	res, err := o.Plan()
	if err != nil {
		return validation.VNull(), err
	}
	if res.Kind == validation.Obj && validation.PyTruthy(validation.ObjAt(res, "read_only")) {
		return validation.VStr("existing plan reused read-only — " +
			"`webv2 plan " + p.C.CampaignID + " --rebuild` to regenerate"), nil
	}
	return res, nil
}

// ModelStagePrompt is _MODEL_STAGE_PROMPT: pipeline stage -> adapter stage id
// (the prompt to run for a model stage).
var ModelStagePrompt = map[string]string{
	"protocol-model":           "protocol-model",
	"discovery":                "discovery-specialist",
	"hostile-review":           "adversarial-critic",
	"maximal-exploitation":     "maximal-exploitation",
	"independent-verification": "independent-verification",
	"mainnet-fork-poc":         "mainnet-fork-poc",
	"learning":                 "reflection",
}

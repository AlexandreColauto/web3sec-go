package briefing

import (
	"os"
	"path/filepath"
	"regexp"

	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/structidx"
	"websec/internal/validation"
)

// criticalityBlock is build_brief's criticality section. ok=false means the
// section is omitted (Python's `except Exception: pass`).
//
// r45a: ok=false is the genuine-absence answer only. A protocol_model.json or
// structural_index.json that EXISTS but could not be read (chmod 000, EISDIR,
// ENOTDIR, a torn document) is a read failure: the old body folded it into
// "no model" (section silently gone) or into a fabricated EMPTY index, which
// ranked every component as uncovered from structure it never read. Both now
// return the `unreadable` disclosure, which BuildBrief names in the problems
// block; no ranking is computed from unread input.
func criticalityBlock(campaign *state.Campaign, all []validation.Value,
	plan validation.Value, planErr error) (validation.Value, bool, error) {
	m := critLoadModel(campaign)
	if m.omit {
		if m.disclo.Kind != validation.Null {
			return m.disclo, false, nil
		}
		return validation.VNull(), false, nil
	}
	ranked := structidx.CriticalityRank(m.model, m.index)
	compBlobs, findingBlobs, execBlobs, err := critBlobs(campaign, all,
		plan, planErr)
	if err != nil {
		return validation.VNull(), false, err
	}
	coverage, uncovered := critCoverage(ranked, compBlobs, findingBlobs,
		execBlobs)
	return validation.VObj(
		kv("ranking", validation.VArr(ranked...)),
		kv("coverage", validation.VObj(coverage...)),
		kv("uncovered_consensus_critical",
			validation.VArr(uncovered...))), true, nil
}

// critModel is the loaded model/index pair the criticality ranker needs.
// omit=true means the section is omitted: a genuine absence leaves disclo
// null, a read failure carries the `unreadable` disclosure instead.
type critModel struct {
	model  validation.Value
	index  validation.Value
	omit   bool
	disclo validation.Value
}

// critLoadModel reads protocol_model.json (required for the section) and
// structural_index.json (falling back to the documented empty default).
func critLoadModel(campaign *state.Campaign) critModel {
	modelPath := filepath.Join(campaign.ArtifactsDir, "protocol_model.json")
	if _, err := os.Stat(modelPath); err != nil {
		if os.IsNotExist(err) {
			return critModel{omit: true, disclo: validation.VNull()}
		}
		return critModel{omit: true,
			disclo: unreadableSection("protocol_model.json", err)}
	}
	model, err := validation.ReadJson(modelPath)
	if err != nil {
		return critModel{omit: true,
			disclo: unreadableSection("protocol_model.json", err)}
	}
	indexPath := filepath.Join(campaign.ArtifactsDir, "structural_index.json")
	var index validation.Value
	foundIndex := false
	if _, err := os.Stat(indexPath); err != nil {
		if !os.IsNotExist(err) {
			return critModel{omit: true,
				disclo: unreadableSection("structural_index.json", err)}
		}
		// genuinely absent: the empty default below is the documented shape
		// for a campaign that never wrote an index.
	} else {
		doc, rerr := validation.ReadJson(indexPath)
		if rerr != nil {
			return critModel{omit: true,
				disclo: unreadableSection("structural_index.json", rerr)}
		}
		index, foundIndex = doc, true
	}
	if !foundIndex {
		index = validation.VObj(kv("nodes", validation.VArr()),
			kv("edges", validation.VArr()))
	}
	return critModel{model: model, index: index}
}

// critBlobs gathers the three evidence pools criticality coverage matches
// against: the plan's declared components, the findings' affected contracts
// and paths, and the exec log's command surfaces.
func critBlobs(campaign *state.Campaign, all []validation.Value,
	plan validation.Value, planErr error) ([]string, []string, []string, error) {
	compBlobs := []string{}
	if planErr == nil && plan.Kind == validation.Obj {
		for _, p := range listAt(plan, "priorities") {
			if p.Kind != validation.Obj {
				continue
			}
			for _, c := range listAt(p, "components") {
				if c.Kind == validation.Str {
					compBlobs = append(compBlobs, c.S)
				} else {
					compBlobs = append(compBlobs, validation.PyRepr(c))
				}
			}
		}
	}
	findingBlobs := []string{}
	for _, f := range all {
		for _, a := range listAt(f, "affected") {
			if a.Kind != validation.Obj {
				continue
			}
			findingBlobs = append(findingBlobs, validation.ObjStr(a, "contract"))
			findingBlobs = append(findingBlobs, validation.ObjStr(a, "path"))
		}
	}
	execBlobs := []string{}
	// r44a: this used to be `if recs, err := ...; err == nil`, which swallowed
	// the whole error class. AllExecs folds a genuinely ABSENT execs/ store
	// into an empty list with a nil error, so the tolerant shape already
	// covers absence — and a non-nil error can only mean the store could not
	// be listed. Swallowing THAT would drop every exec blob and let the
	// coverage pass below assert components "uncovered" from evidence it
	// never read: a read error is a refusal, not "not found", so it
	// propagates (the caller renders it).
	recs, err := sandbox.AllExecs(campaign)
	if err != nil {
		return nil, nil, nil, err
	}
	{
		for _, rec := range recs {
			if rec.Kind != validation.Obj {
				continue
			}
			for _, key := range []string{"command", "workdir", "finding_id",
				"artifact_id"} {
				v := validation.ObjAt(rec, key)
				if v.Kind == validation.Str {
					execBlobs = append(execBlobs, v.S)
				} else {
					execBlobs = append(execBlobs, "")
				}
			}
		}
	}
	return compBlobs, findingBlobs, execBlobs, nil
}

// critCoverage marks each ranked component covered or not against the pooled
// evidence blobs, and collects the consensus-critical uncovered names.
func critCoverage(ranked []validation.Value, compBlobs, findingBlobs,
	execBlobs []string) ([]validation.KV, []validation.Value) {
	coverage := []validation.KV{}
	uncovered := []validation.Value{}
	seen := map[string]bool{}
	for _, r := range ranked {
		name := validation.ObjStr(r, "contract")
		if !seen[name] {
			seen[name] = true
			covered := false
			pool := append(append(append([]string{}, compBlobs...),
				findingBlobs...), execBlobs...)
			for _, b := range pool {
				if hitName(name, b) {
					covered = true
					break
				}
			}
			coverage = append(coverage, validation.KV{K: name,
				V: validation.VBool(covered)})
			if validation.ObjStr(r, "tier") == "consensus-critical" && !covered {
				uncovered = append(uncovered, validation.VStr(name))
			}
		}
	}
	return coverage, uncovered
}

func hitName(name, blob string) bool {
	if name == "" {
		return false
	}
	re, err := regexp.Compile(`(?i)\b` + regexp.QuoteMeta(name) + `\b`)
	if err != nil {
		return false
	}
	idx := re.FindStringIndex(blob)
	if idx == nil {
		return false
	}
	_ = idx
	return true
}

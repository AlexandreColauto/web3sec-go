// Package roles is the port of webv2/roles.py: role-specific context
// builders (proposer / critic / reproducer).
//
// The architecture law this module enforces: the critic (and the reproducer)
// are STRUCTURALLY independent of the proposer. That is built, not promised —
// each builder is a pure projection of deterministic campaign state onto an
// EXPLICIT allow-list of fields. Defense in depth: after projection, every
// bundle is re-checked at every nesting depth for a per-role set of forbidden
// field names; if the allow-list regresses, the builder raises instead of
// leaking.
package roles

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// Roles is ROLES, in order.
var Roles = []string{"proposer", "critic", "reproducer"}

// NegativeStatuses is NEGATIVE_STATUSES: memory row statuses that are "known
// non-issues".
var NegativeStatuses = []string{
	"DISPROVED", "DUPLICATE", "OUT_OF_SCOPE", "INTENDED_BEHAVIOR",
	"UNREACHABLE", "NON-ECONOMIC", "TEST-HARNESS-ONLY",
}

// ForbiddenKeys is FORBIDDEN_KEYS: keys that must never appear in a role's
// serialized bundle, checked at every depth by AssertClean.
var ForbiddenKeys = map[string][]string{
	"proposer": {
		"critic_reasoning", "critic_verdict", "shield_adjudication",
		"bounty", "patch_verified", "provenance", "dedup_meta",
	},
	"critic": {
		// proposer narrative / chain-of-thought
		"mechanism", "exploit_sequence", "confidence",
		// hidden verdicts + downstream adjudications
		"critic_reasoning", "critic_verdict", "shield_adjudication",
		"bounty", "patch_verified", "independent_reproduction",
		// narrative containers
		"provenance", "dedup_meta", "risk", "history",
	},
	"reproducer": {
		"critic_reasoning", "critic_verdict", "shield_adjudication",
		"bounty", "patch_verified", "provenance", "dedup_meta",
		"risk", "history",
	},
}

// PolicyKeys is _POLICY_KEYS.
var PolicyKeys = []string{"program", "program_url", "chains", "scope",
	"severity_rules", "poc_requirements"}

// AssertClean is _assert_clean: no forbidden FIELD NAME exists anywhere in
// the bundle (every dict key at every depth, lists included).
func AssertClean(bundle validation.Value, role string) error {
	forbidden, ok := ForbiddenKeys[role]
	if !ok {
		return fmt.Errorf("unknown role %s", validation.PyReprStr(role))
	}
	set := map[string]bool{}
	for _, k := range forbidden {
		set[k] = true
	}
	leaked := map[string]bool{}
	var walk func(validation.Value)
	walk = func(node validation.Value) {
		switch node.Kind {
		case validation.Obj:
			for _, kv := range node.O {
				if set[kv.K] {
					leaked[kv.K] = true
				}
				walk(kv.V)
			}
		case validation.Arr:
			for _, item := range node.A {
				walk(item)
			}
		}
	}
	walk(bundle)
	if len(leaked) > 0 {
		names := make([]string, 0, len(leaked))
		for k := range leaked {
			names = append(names, k)
		}
		sort.Strings(names)
		return fmt.Errorf("role %s context bundle contains forbidden key(s) "+
			"%s — the allow-list has regressed; refusing to build",
			role, pyListRepr(names))
	}
	return nil
}

// boundedJSON is _bounded_json: parse a JSON artifact into the bundle; fall
// back to a truncated raw text marker when it does not fit the budget. Never
// raises on absence.
func boundedJSON(path string, maxChars int) (validation.Value, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return validation.VNull(), nil
	}
	text := string(raw)
	if len(text) > maxChars {
		return truncatedMarker(text, maxChars), nil
	}
	data, err := validation.ParseOrdered(raw)
	if err != nil {
		return truncatedMarker(text, maxChars), nil
	}
	return data, nil
}

func truncatedMarker(text string, maxChars int) validation.Value {
	if len(text) > maxChars {
		text = text[:maxChars]
	}
	return validation.VObj(
		validation.KV{K: "_truncated", V: validation.VBool(true)},
		validation.KV{K: "text", V: validation.VStr(text)})
}

// snapshotBlock is _snapshot_block.
func snapshotBlock(campaign *state.Campaign) (validation.Value, error) {
	snap, err := campaign.ActiveSnapshot()
	if err != nil {
		return validation.VNull(), err
	}
	if snap.Kind == validation.Null {
		return validation.VNull(), nil
	}
	sid, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil {
		return validation.VNull(), err
	}
	source := objAt(snap, "source")
	if source.Kind != validation.Obj {
		source = validation.VObj()
	}
	return validation.VObj(
		validation.KV{K: "snapshot_id", V: nullableStr(sid)},
		validation.KV{K: "source", V: source},
		validation.KV{K: "deployment", V: objAt(snap, "deployment")},
		validation.KV{K: "chain", V: objAt(snap, "chain")},
		validation.KV{K: "pinned_at", V: objAt(snap, "pinned_at")},
	), nil
}

// campaignPolicy is _campaign_policy.
func campaignPolicy(campaign *state.Campaign) (validation.Value, error) {
	policy, err := boundedJSON(filepath.Join(campaign.Dir, "bounty_policy.json"),
		20000)
	if err != nil {
		return validation.VNull(), err
	}
	if policy.Kind != validation.Obj {
		return validation.VNull(), nil
	}
	out := validation.VObj()
	for _, k := range PolicyKeys {
		if v := objAt(policy, k); v.Kind != validation.Null {
			out.O = append(out.O, validation.KV{K: k, V: v})
		}
	}
	return out, nil
}

// artifactRerun is _ARTIFACT_RERUN (shared with briefing._stale_artifacts).
var artifactRerun = [][2]string{
	{"structural_index.json", "webv2 index <campaign> --src <target>"},
	{"value_flow.json", "webv2 sinks <campaign> --src <target>"},
	{"archetype_prescreen.json", "webv2 prescreen <campaign> --src <target>"},
	{"fork_diff.json", "webv2 forkdiff <campaign> --src <target>"},
	{"recency.json", "webv2 recency <campaign> --target <git> --src <target>"},
}

// freshArtifact is _fresh_artifact: serve a registered analysis artifact to a
// model role ONLY while fresh (recorded snapshot_id == active pin).
func freshArtifact(campaign *state.Campaign, name string,
	maxChars int) (validation.Value, error) {
	p := filepath.Join(campaign.ArtifactsDir, name)
	if _, err := os.Stat(p); err != nil {
		return validation.VNull(), nil
	}
	data, err := validation.ReadJson(p)
	if err != nil {
		return validation.VNull(), nil
	}
	if data.Kind != validation.Obj {
		return validation.VNull(), nil
	}
	active, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil {
		return validation.VNull(), err
	}
	if !nullableStrEqual(objAt(data, "snapshot_id"), active) {
		return validation.VNull(), nil
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return validation.VNull(), nil
	}
	if len(raw) > maxChars {
		return truncatedMarker(string(raw), maxChars), nil
	}
	return data, nil
}

// freshIndexStats is _fresh_index_stats.
func freshIndexStats(campaign *state.Campaign,
	maxChars int) (validation.Value, error) {
	data, err := freshArtifact(campaign, "structural_index.json", maxChars)
	if err != nil {
		return validation.VNull(), err
	}
	if data.Kind != validation.Obj {
		return validation.VNull(), nil
	}
	return objAt(data, "stats"), nil
}

// StaleArtifacts is _stale_artifacts: analysis artifacts that exist but
// predate the active pin — the brief tells the operator which re-run command
// restores each.
func StaleArtifacts(campaign *state.Campaign) ([]validation.Value, error) {
	out := []validation.Value{}
	active, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil {
		return nil, err
	}
	for _, pair := range artifactRerun {
		p := filepath.Join(campaign.ArtifactsDir, pair[0])
		if _, err := os.Stat(p); err != nil {
			continue
		}
		data, err := validation.ReadJson(p)
		if err != nil {
			continue
		}
		if data.Kind == validation.Obj &&
			!nullableStrEqual(objAt(data, "snapshot_id"), active) {
			out = append(out, validation.VObj(
				validation.KV{K: "artifact", V: validation.VStr(pair[0])},
				validation.KV{K: "stale_snapshot", V: objAt(data, "snapshot_id")},
				validation.KV{K: "re_run", V: validation.VStr(pair[1])}))
		}
	}
	return out, nil
}

// ArtifactRerun exposes the re-run table (briefing shares it).
func ArtifactRerun() [][2]string { return artifactRerun }

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

func nullableStr(s *string) validation.Value {
	if s == nil {
		return validation.VNull()
	}
	return validation.VStr(*s)
}

func nullableStrEqual(v validation.Value, s *string) bool {
	if v.Kind == validation.Null || s == nil {
		return v.Kind == validation.Null && s == nil
	}
	return v.Kind == validation.Str && v.S == *s
}

func pyListRepr(xs []string) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = validation.PyReprStr(x)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func objStr(v validation.Value, key string) string {
	x := objAt(v, key)
	if x.Kind == validation.Str {
		return x.S
	}
	return ""
}

// Package privileged is the bounded privileged-role attacker track (3.1):
// a 1:1 port of webv2/privileged.py (port-era provenance; twin retired 2026-09-09).
//
// A bounded role is an explicit baseline — {"call_any_entry_point"} plus the
// role_<role> capability label. Nothing else: capital is a cost, never a
// capability (chain_engine law). The track is structurally separate: the EOA
// baseline never holds a role label, so a role-required finding is
// unreachable from the EOA terminal report unless a CONFIRMED
// EOA-reachable finding grants the label. No model calls; deterministic.
package privileged

import (
	"os"
	"path/filepath"
	"sort"

	"websec/internal/capabilities"
	"websec/internal/chainengine"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// Note is NOTE: the track's read-only separation statement.
const Note = "separate attacker track: each bounded role is an explicit " +
	"baseline; the unprivileged-EOA terminal report is unaffected " +
	"by this view"

// BlastOrder is the blast-radius ladder, same order as chain_engine.
var BlastOrder = []string{"single-user", "subset-of-users", "all-users",
	"protocol-solvency", "bridge-canonical"}

func blastRank(b string) int {
	for i, x := range BlastOrder {
		if x == b {
			return i
		}
	}
	return -1
}

// listOf is `d.get(key) or []`.
func listOf(v validation.Value, key string) validation.Value {
	if f := validation.ObjAt(v, key); f.Kind == validation.Arr {
		return f
	}
	return validation.VArr()
}

func kvOf(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// PrivilegeEntries is _privilege_entries: the model's privilege table as
// dict entries only. A hand-edited artifact may hold a non-list `privileges`
// value or junk entries; malformed shapes are dropped, never raised on.
func PrivilegeEntries(model validation.Value) []validation.Value {
	if model.Kind != validation.Obj {
		return nil
	}
	privs := validation.ObjAt(model, "privileges")
	if privs.Kind != validation.Arr {
		return nil
	}
	out := []validation.Value{}
	for _, p := range privs.A {
		if p.Kind == validation.Obj {
			out = append(out, p)
		}
	}
	return out
}

// PrivilegedRoles is privileged_roles: normalized distinct roles, sorted.
func PrivilegedRoles(model validation.Value) []string {
	seen := map[string]struct{}{}
	for _, p := range PrivilegeEntries(model) {
		if role := validation.ObjStr(p, "role"); role != "" {
			seen[capabilities.NormalizeLabel(role)] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// RoleBaseline is role_baseline: entry points + the role label, sorted (the
// frozenset's iteration order is sorted where Python prints it).
func RoleBaseline(role string) []string {
	return []string{"call_any_entry_point", capabilities.RoleLabel(role)}
}

// LoadProtocolModel is load_protocol_model: the protocol model artifact, or
// nil when it has not been saved. Fail-soft like the sibling readers: a
// corrupt (unparseable) or unreadable artifact yields nil — the empty track
// — never an exception.
func LoadProtocolModel(c *state.Campaign) *validation.Value {
	p := filepath.Join(c.ArtifactsDir, "protocol_model.json")
	if _, err := os.Stat(p); err != nil {
		return nil
	}
	// Fail-soft: unreadable, unparseable and absent all mean "no model yet"
	// (the empty track). The corrupt-vs-absent distinction this used to
	// discriminate with errors.As returned nil from both arms anyway.
	model, err := validation.ReadJson(p)
	if err != nil {
		return nil
	}
	return &model
}

// PrivilegedTerminalReport is privileged_terminal_report: terminal search
// from one role's baseline, plus role identity.
func PrivilegedTerminalReport(c *state.Campaign,
	role string) (validation.Value, error) {
	base := RoleBaseline(role)
	rep, err := chainengine.TerminalReport(c, &base)
	if err != nil {
		return validation.VNull(), err
	}
	out := validation.Value{Kind: validation.Obj,
		O: append([]validation.KV(nil), rep.O...)}
	out.O = append(out.O,
		kvOf("role", validation.VStr(role)),
		kvOf("role_label", validation.VStr(capabilities.RoleLabel(role))))
	return out, nil
}

// PathConstraints is path_constraints: the recorded privilege entries for
// one normalized role, sorted by capability.
func PathConstraints(model validation.Value, role string) []validation.Value {
	want := capabilities.NormalizeLabel(role)
	out := []validation.Value{}
	for _, p := range PrivilegeEntries(model) {
		r := validation.ObjStr(p, "role")
		if r != "" && capabilities.NormalizeLabel(r) == want {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return validation.ObjStr(out[i], "capability") < validation.ObjStr(out[j], "capability")
	})
	return out
}

// ExposureBand is exposure_band: timelocked (any entry) beats
// multi-signatory (threshold >= 3) beats unconstrained.
func ExposureBand(constraints []validation.Value) string {
	for _, c := range constraints {
		if v := validation.ObjAt(c, "timelocked"); v.Kind == validation.Bool && v.B {
			return "timelocked"
		}
	}
	for _, c := range constraints {
		t := validation.ObjAt(c, "multisig_threshold")
		if t.Kind == validation.Bool {
			continue
		}
		switch t.Kind {
		case validation.Int:
			if t.I >= 3 {
				return "multi-signatory"
			}
		case validation.Flt:
			if t.F >= 3 {
				return "multi-signatory"
			}
		}
	}
	return "unconstrained"
}

// pathBlastRadius is _path_blast_radius: the max recorded blast_radius over
// the path's member findings.
func pathBlastRadius(c *state.Campaign, path validation.Value) string {
	best := ""
	for _, fid := range listOf(path, "path").A {
		if fid.Kind != validation.Str {
			continue
		}
		m, err := findings.LoadFinding(c, fid.S)
		if err != nil {
			continue
		}
		b := validation.ObjStr(validation.ObjAt(m, "economic_impact"), "blast_radius")
		if blastRank(b) >= 0 && (best == "" || blastRank(b) > blastRank(best)) {
			best = b
		}
	}
	return best
}

// pathExtractable is _path_extractable: the max RECORDED
// economic_impact.extractable_usd over the path's members; 0 when none.
func pathExtractable(c *state.Campaign, path validation.Value) float64 {
	best := 0.0
	for _, fid := range listOf(path, "path").A {
		if fid.Kind != validation.Str {
			continue
		}
		m, err := findings.LoadFinding(c, fid.S)
		if err != nil {
			continue
		}
		v := validation.ObjAt(validation.ObjAt(m, "economic_impact"), "extractable_usd")
		if v.Kind == validation.Bool {
			continue
		}
		var f float64
		switch v.Kind {
		case validation.Int:
			f = float64(v.I)
		case validation.Flt:
			f = v.F
		default:
			continue
		}
		if f > best {
			best = f
		}
	}
	return best
}

// enrichPaths is _enrich_paths: shallow-copied path dicts carrying
// constraints, band and blast radius, sorted per spec D3 (blast rank
// descending, extractable descending, path tuple).
func enrichPaths(c *state.Campaign, paths []validation.Value,
	constraints []validation.Value, band string) []validation.Value {
	enriched := []validation.Value{}
	for _, p := range paths {
		q := validation.Value{Kind: validation.Obj,
			O: append([]validation.KV(nil), p.O...)}
		q.O = append(q.O,
			kvOf("constraints", validation.VArr(constraints...)),
			kvOf("exposure_band", validation.VStr(band)),
			kvOf("blast_radius", blastValue(pathBlastRadius(c, p))))
		enriched = append(enriched, q)
	}
	sort.SliceStable(enriched, func(i, j int) bool {
		ri, rj := sortRank(enriched[i]), sortRank(enriched[j])
		if ri != rj {
			return ri < rj
		}
		ei, ej := pathExtractable(c, enriched[i]), pathExtractable(c, enriched[j])
		if ei != ej {
			return ei > ej
		}
		return pathKey(enriched[i]) < pathKey(enriched[j])
	})
	return enriched
}

// blastValue renders the blast radius (`None` when unrecorded).
func blastValue(b string) validation.Value {
	if b == "" {
		return validation.VNull()
	}
	return validation.VStr(b)
}

// sortRank is -_BLAST_RANK.get(blast, -1): unrecorded sorts last.
func sortRank(p validation.Value) int {
	b := validation.ObjAt(p, "blast_radius")
	if b.Kind != validation.Str {
		return 1
	}
	r := blastRank(b.S)
	if r < 0 {
		return 1
	}
	return -r
}

// pathKey is `tuple(p.get("path") or [])` flattened.
func pathKey(p validation.Value) string {
	out := ""
	for _, f := range listOf(p, "path").A {
		out += f.S + "\x00"
	}
	return out
}

// PrivilegedExposure is privileged_exposure: one entry per role in the
// recorded privilege table. READ-ONLY over campaign state — nothing here
// logs or saves, so a model without privileges leaves the report
// byte-identical.
func PrivilegedExposure(c *state.Campaign) (validation.Value, error) {
	empty := validation.VObj(
		kvOf("track", validation.VStr("privileged")),
		kvOf("note", validation.VStr(Note)),
		kvOf("roles", validation.VArr()))
	modelPtr := LoadProtocolModel(c)
	if modelPtr == nil {
		return empty, nil
	}
	model := *modelPtr
	privs := PrivilegeEntries(model)
	if len(privs) == 0 {
		return empty, nil
	}
	roles := []validation.Value{}
	for _, r := range PrivilegedRoles(model) {
		rep, err := PrivilegedTerminalReport(c, r)
		if err != nil {
			return validation.VNull(), err
		}
		constraints := PathConstraints(model, r)
		band := ExposureBand(constraints)
		rolePrivs := []validation.Value{}
		for _, p := range privs {
			if capabilities.NormalizeLabel(validation.ObjStr(p, "role")) == r {
				rolePrivs = append(rolePrivs, p)
			}
		}
		sort.SliceStable(rolePrivs, func(i, j int) bool {
			return validation.ObjStr(rolePrivs[i], "capability") <
				validation.ObjStr(rolePrivs[j], "capability")
		})
		roles = append(roles, validation.VObj(
			kvOf("role", validation.VStr(r)),
			kvOf("role_label", validation.VStr(capabilities.RoleLabel(r))),
			kvOf("baseline", validation.StrArr(RoleBaseline(r))),
			kvOf("privileges", validation.VArr(rolePrivs...)),
			kvOf("constraints", validation.VArr(constraints...)),
			kvOf("exposure_band", validation.VStr(band)),
			kvOf("direct", validation.VArr(enrichPaths(c,
				listOf(rep, "direct").A, constraints, band)...)),
			kvOf("terminal_chains", validation.VArr(enrichPaths(c,
				listOf(rep, "terminal_chains").A, constraints, band)...)),
			kvOf("shortest_by_terminal", validation.VArr(enrichPaths(c,
				listOf(rep, "shortest_by_terminal").A, constraints, band)...)),
		))
	}
	return validation.VObj(
		kvOf("track", validation.VStr("privileged")),
		kvOf("note", validation.VStr(Note)),
		kvOf("roles", validation.VArr(roles...)),
	), nil
}

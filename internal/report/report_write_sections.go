// Opening report sections: state header, protocol economics, chain
// assumptions, coverage, component surfaces and the privileged/probe
// surface sections, in the order Generate emits them.
package report

import (
	"fmt"
	"path/filepath"
	"strings"
	"websec/internal/coverage"
	"websec/internal/economics"
	"websec/internal/validation"
)

// writeProtocolEconomics renders the economic-model section from the
// protocol model artifact, presence-gated on the artifact file.
func (r *reportBuilder) writeProtocolEconomics() error {
	modelPath := filepath.Join(r.campaign.ArtifactsDir, "protocol_model.json")
	if fileExists(modelPath) {
		model, err := validation.ReadJson(modelPath)
		if err != nil {
			return err
		}
		econ := economics.EconomicSummary(model)
		r.L = append(r.L, "## Protocol economics")
		r.L = append(r.L, "")
		if gaps := listAt(econ, "equation_gaps"); len(gaps) > 0 {
			r.L = append(r.L, "| equation | missing |")
			r.L = append(r.L, "|---|---|")
			shown := gaps
			if len(shown) > 12 {
				shown = shown[:12]
			}
			for _, g := range shown {
				eq := []rune(validation.ObjStr(g, "equation"))
				if len(eq) > 60 {
					eq = eq[:60]
				}
				r.L = append(r.L, fmt.Sprintf("| `%s` | %s |", string(eq),
					strings.Join(strList(validation.ObjAt(g, "missing")), ", ")))
			}
			r.L = append(r.L, "")
		}
		if risky := listAt(econ, "risky_assets"); len(risky) > 0 {
			names := []string{}
			shown := risky
			if len(shown) > 6 {
				shown = shown[:6]
			}
			for _, a := range shown {
				names = append(names, validation.ObjStr(a, "asset"))
			}
			r.L = append(r.L, fmt.Sprintf("- risky assets "+
				"(fee-on-transfer/rebasing/odd-decimals): %d — %s", len(risky),
				strings.Join(names, ", ")))
		}
		gaps := len(listAt(econ, "equation_gaps"))
		r.L = append(r.L, fmt.Sprintf("> %d equation(s) with no enforcement or "+
			"no known break path — the economic model is unfinished, not safe",
			gaps))
		r.L = append(r.L, "")
	}
	return nil
}

// G10 assumption table (Task 4): the per-hop declared table plus
// ASSUMPTION GAP lines, beside the economics model section.
// Presence-gated (the additive convention) — a chains-only legacy
// campaign gains no bytes.
func (r *reportBuilder) writeChainAssumptions() {
	r.L = append(r.L, chainAssumptionsBlock(r.campaign)...)
}

// writeCoverage renders the coverage summary table and the thin-coverage
// subsection from the coverage.json artifact, presence-gated on the file
// and on a non-empty summary object.
func (r *reportBuilder) writeCoverage() error {
	covPath := filepath.Join(r.campaign.ArtifactsDir, "coverage.json")
	if fileExists(covPath) {
		cov, err := validation.ReadJson(covPath)
		if err != nil {
			return err
		}
		s := validation.AsObj(validation.ObjAt(cov, "summary"))
		if len(s.O) > 0 {
			r.L = append(r.L, "## Coverage")
			r.L = append(r.L, "")
			r.L = append(r.L, "| metric | value |")
			r.L = append(r.L, "|---|---|")
			for _, k := range s.O {
				if k.K == "unknown_note" {
					continue
				}
				r.L = append(r.L, fmt.Sprintf("| %s | %s |",
					strings.ReplaceAll(k.K, "_", " "), validation.PyStr(k.V)))
			}
			r.L = append(r.L, "")
			note := "unknown ≠ secure"
			if v := validation.ObjAt(s, "unknown_note"); v.Kind != validation.Null {
				note = validation.PyStr(v)
			}
			r.L = append(r.L, "> "+note)
			r.L = append(r.L, "")
			thin, err := coverage.ThinCoverage(r.campaign, 2)
			if err != nil {
				return err
			}
			if len(thin) > 0 {
				r.L = append(r.L, "### Thin coverage (fewer than 2 trajectories)")
				r.L = append(r.L, "")
				shown := thin
				if len(shown) > 20 {
					shown = shown[:20]
				}
				for _, t := range shown {
					trajs := strings.Join(strList(validation.ObjAt(t, "trajectories")), ", ")
					if trajs == "" {
						trajs = "none"
					}
					r.L = append(r.L, fmt.Sprintf("- `%s` — status %s, "+
						"trajectories: %s", validation.ObjStr(t, "path"),
						validation.ObjStr(t, "status"), trajs))
				}
				r.L = append(r.L, "")
			}
		}
	}
	return nil
}

// G9 opaque surfaces (Task 6): the tracked-but-opaque component
// block, beside the Coverage scope section. Presence-gated (the
// additive convention) — a component-free campaign gains no bytes.
func (r *reportBuilder) writeComponentSurfaces() {
	r.L = append(r.L, componentSurfacesBlock(r.campaign)...)
}

// writePrivilegedAndProbeSurfaces appends the privileged-actor track and
// the probe-surface section, both section helpers over the campaign.
func (r *reportBuilder) writePrivilegedAndProbeSurfaces() error {
	priv, err := PrivilegedSection(r.campaign)
	if err != nil {
		return err
	}
	r.L = append(r.L, priv...)
	ps, err := ProbeSurfaceSection(r.campaign)
	if err != nil {
		return err
	}
	r.L = append(r.L, ps...)
	return nil
}

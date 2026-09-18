// Package report is webv2.report: the deterministic markdown report — a
// VIEW over the finding IR. The report is generated FROM the finding
// objects, never the reverse: edit findings, regenerate the report.
//
// I1: the ONE sanctioned mutation is generate() re-running the bounty gate
// (a stale submission_ready flag is a stale claim) and registering the
// report artifact + logging report.generated. Everything else reads.
package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"websec/internal/bounty"
	"websec/internal/findings"
	"websec/internal/learning"
	"websec/internal/state"
	"websec/internal/validation"
)

// reportBuilder carries the shared context of one Generate run — the
// campaign, its loaded inputs (state, policy, findings, chains, memory,
// events) and the output line slice — so every report section is a short
// method appending to L in the same order the monolith did.
type reportBuilder struct {
	campaign       *state.Campaign
	st             validation.Value
	policy         validation.Value
	all            []validation.Value
	provenChains   []validation.Value
	unprovenChains []validation.Value
	mem            []validation.Value
	evts           []validation.Value
	confirmed      []validation.Value
	chainF         []validation.Value
	ready          []validation.Value
	disproved      int
	duplicates     int
	outOfScope     int
	L              []string
}

// Generate is generate(): write report.md, register/refresh the artifact and
// log report.generated. Returns the report path.
func Generate(campaign *state.Campaign) (string, error) {
	r := &reportBuilder{campaign: campaign}
	st, err := campaign.State()
	if err != nil {
		return "", err
	}
	r.st = st
	if err := r.runBountyGate(); err != nil {
		return "", err
	}
	if err := r.loadInputs(); err != nil {
		return "", err
	}
	r.writeHeader()
	if err := r.writeProtocolEconomics(); err != nil {
		return "", err
	}
	r.writeChainAssumptions()
	if err := r.writeCoverage(); err != nil {
		return "", err
	}
	r.writeComponentSurfaces()
	if err := r.writePrivilegedAndProbeSurfaces(); err != nil {
		return "", err
	}
	r.classifyFindings()
	r.writeResults()
	r.writeCostAttribution()
	r.writeAllFindingsTable()
	r.writeAnswerQuality()
	if err := r.writeRootCauseClusters(); err != nil {
		return "", err
	}
	if err := r.writeHypothesisLenses(); err != nil {
		return "", err
	}
	r.writeLivenessFindings()
	if err := r.writeConfirmedSections(); err != nil {
		return "", err
	}
	r.writeProvenChains()
	r.writeUnprovenChains()
	r.writeDismissed()
	r.writeDismissedWithReach()
	r.writeDispositionReview()
	r.writeLearningQueue()
	return r.persist()
}

// runBountyGate re-runs the bounty gate over every CONFIRMED/CHAIN finding
// when a policy is configured, storing the policy for the Results section.
func (r *reportBuilder) runBountyGate() error {
	policyPath := validation.ObjStr(r.st, "policy_path")
	// policy is hoisted out of the if-block: the Results section's precision
	// block (A3) reads its submission_budget even when the gate re-run above
	// had nothing to do.
	var policy validation.Value
	if policyPath != "" && fileExists(policyPath) {
		p, err := bounty.LoadPolicy(policyPath)
		if err != nil {
			return err
		}
		policy = p
		all, err := findings.LoadAllFindings(r.campaign)
		if err != nil {
			return err
		}
		for _, f := range all {
			status := validation.ObjStr(f, "status")
			if status != "CONFIRMED" && status != "CHAIN" {
				continue
			}
			if _, err := bounty.EvaluateBountyGate(r.campaign,
				validation.ObjStr(f, "finding_id"), policy, true); err != nil {
				return err
			}
		}
	}
	r.policy = policy
	return nil
}

// loadInputs loads the findings, the chain store (split by provenance), the
// learning memory and the event log.
func (r *reportBuilder) loadInputs() error {
	all, err := findings.LoadAllFindings(r.campaign)
	if err != nil {
		return err
	}
	r.all = all
	// r43a: a report renders "no materialized chains" only when the chain
	// store really is empty; an unreadable store refuses, naming the path.
	chainPaths, err := validation.ListPrefixedOptional(r.campaign.ChainsDir,
		"CHAIN-", ".json")
	if err != nil {
		return fmt.Errorf("the chain store %s cannot be listed: %v",
			r.campaign.ChainsDir, err)
	}
	sort.Strings(chainPaths)
	chains := []validation.Value{}
	for _, p := range chainPaths {
		doc, err := validation.ReadJson(p)
		if err != nil {
			return err
		}
		chains = append(chains, doc)
	}
	// B3: a chain doc is either evidence-confirmed (the materialization hard
	// gate) or hypothesis-level ("unproven"). The split is by field
	// presence: pre-B3 docs carry no provenance key at all and stay proven.
	r.provenChains, r.unprovenChains = splitChainsByProvenance(chains)
	mem, err := learning.AllMemory(r.campaign)
	if err != nil {
		return err
	}
	r.mem = mem
	evts, err := r.campaign.Events()
	if err != nil {
		return err
	}
	r.evts = evts
	return nil
}

// writeHeader emits the state-head marker and the campaign banner.
func (r *reportBuilder) writeHeader() {
	var headHash validation.Value = validation.VNull()
	if len(r.evts) > 0 {
		if h := validation.ObjAt(r.evts[len(r.evts)-1], "event_hash"); h.Kind != validation.Null {
			headHash = h
		}
	}
	r.L = append(r.L, "<!-- state-head: "+validation.PyStr(headHash)+" -->")
	r.L = append(r.L, "# Security Research Report — "+validation.ObjStr(r.st, "program"))
	r.L = append(r.L, "")
	r.L = append(r.L, fmt.Sprintf("- campaign: `%s`", validation.ObjStr(r.st, "campaign_id")))
	r.L = append(r.L, fmt.Sprintf("- phase: **%s** (pass %s)", validation.ObjStr(r.st, "phase"),
		validation.PyStr(validation.ObjAt(validation.AsObj(validation.ObjAt(r.st, "budget")), "pass"))))
	r.L = append(r.L, fmt.Sprintf("- active snapshot: `%s`",
		validation.PyStr(validation.ObjAt(r.st, "active_snapshot_id"))))
	r.L = append(r.L, fmt.Sprintf("- generated: %s", state.NowIso()))
	r.L = append(r.L, "")
}

// persist writes report.md, registers/refreshes the artifact and logs
// report.generated, returning the report path.
func (r *reportBuilder) persist() (string, error) {
	out := filepath.Join(r.campaign.Dir, "report.md")
	if err := os.WriteFile(out, []byte(strings.Join(r.L, "\n")+"\n"), 0o644); err != nil {
		return "", err
	}
	if _, err := r.campaign.RegisterOrRefresh("report", out, "", nil,
		"report regenerated (view over current findings)"); err != nil {
		return "", err
	}
	data := validation.VObj(kv("path", validation.VStr(out)))
	if _, err := r.campaign.Log("report.generated", nil, &data); err != nil {
		return "", err
	}
	return out, nil
}

// splitChainsByProvenance is the B3 split: a chain doc whose provenance is
// "unproven" is a hypothesis-level lead, everything else (including every
// pre-B3 doc, which carries no provenance key at all) is evidence-confirmed.
func splitChainsByProvenance(chains []validation.Value) (proven,
	unproven []validation.Value) {
	for _, ch := range chains {
		if validation.ObjStr(ch, "provenance") == "unproven" {
			unproven = append(unproven, ch)
		} else {
			proven = append(proven, ch)
		}
	}
	return proven, unproven
}

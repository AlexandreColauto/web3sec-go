// Package report — G18 immunefi export (Task 25): GenerateImmunefi writes
// one file per submission-ready finding (report-immunefi-<FINDING-ID>.md),
// shaped for immunefi's one-form-per-bug intake. Generate is untouched:
// the default md path is byte-identical with or without the --format flag.
//
// submission_ready is read from the SAME stored gate output the md report's
// bounty section reads (the submission_ready predicate below mirrors
// Generate's ready-row collection verbatim) — never re-derived by a
// parallel rule. The gate itself is refreshed first, exactly as Generate
// does, so a stale flag is never exported.
//
// Field map (zero new surface — every field already exists on the finding
// IR, the policy, or the campaign state):
//
//	Summary        title + campaign program key + gate state string
//	Impact         root_cause.mechanism/description + economic_impact
//	Severity       bounty.SeverityFor vs policy severity_rules + G12 alias
//	PoC            evidence items (type + EXEC artifact links + G15 reruns /
//	               fork_stale advisories, verbatim line shape)
//	Recommendation verification.recommendation (the prose fix)
//	Related areas  affected entries + bounty.accepted_risk + in-code ack
//
// Fail-open law: an empty section renders the literal checklist line
// "- <Section>: MISSING (fill before submitting)" and the file opens with
// a checklist block naming every empty section. The file is still
// generated. Zero submission-ready findings is advisory, never a blocker:
// GenerateImmunefi returns no paths and the CLI prints
// "no submission-ready findings" with exit 0.
package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"websec/internal/bounty"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// immunefiSections is the fixed section order (the brief's order).
var immunefiSections = []string{"Summary", "Impact", "Severity", "PoC",
	"Recommendation", "Related areas"}

// immunefiMissing is the literal empty-section line (fail-open list law).
func immunefiMissing(section string) string {
	return "- " + section + ": MISSING (fill before submitting)"
}

// GenerateImmunefi writes one immunefi-shaped file per submission-ready
// finding into the campaign directory and returns the paths, sorted by
// finding id (the determinism law). Zero submission-ready findings yields
// no paths and no files — the CLI renders the honest advisory line.
func GenerateImmunefi(campaign *state.Campaign) ([]string, error) {
	st, err := campaign.State()
	if err != nil {
		return nil, err
	}
	// The gate refresh mirrors Generate's verbatim: a stale
	// submission_ready flag is a stale claim, and the export must read
	// the same gate the md report's bounty section reads.
	var policy validation.Value
	if policyPath := validation.ObjStr(st, "policy_path"); policyPath != "" &&
		fileExists(policyPath) {
		p, err := bounty.LoadPolicy(policyPath)
		if err != nil {
			return nil, err
		}
		policy = p
		all, err := findings.LoadAllFindings(campaign)
		if err != nil {
			return nil, err
		}
		for _, f := range all {
			status := validation.ObjStr(f, "status")
			if status != "CONFIRMED" && status != "CHAIN" {
				continue
			}
			if _, err := bounty.EvaluateBountyGate(campaign,
				validation.ObjStr(f, "finding_id"), policy, true); err != nil {
				return nil, err
			}
		}
	}
	all, err := findings.LoadAllFindings(campaign)
	if err != nil {
		return nil, err
	}
	// The row set mirrors Generate's ready collection verbatim
	// (report.go Results section): the stored bounty.submission_ready
	// flag, re-read after the refresh above.
	ready := []validation.Value{}
	for _, f := range all {
		if pyTruthyInt64Only(validation.ObjAt(validation.AsObj(validation.ObjAt(f, "bounty")), "submission_ready")) {
			ready = append(ready, f)
		}
	}
	sort.SliceStable(ready, func(i, j int) bool {
		return validation.ObjStr(ready[i], "finding_id") < validation.ObjStr(ready[j], "finding_id")
	})
	program := validation.ObjStr(st, "program")
	paths := []string{}
	for _, f := range ready {
		fid := validation.ObjStr(f, "finding_id")
		lines := renderImmunefiFinding(f, policy, program)
		out := filepath.Join(campaign.Dir, "report-immunefi-"+fid+".md")
		if err := os.WriteFile(out,
			[]byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			return nil, err
		}
		// Kind "report" (the registry's report row is one row per
		// resolved path, so each export keeps its own row beside
		// report.md — never a collision, never a ghost).
		if _, err := campaign.RegisterOrRefresh("report", out, "", nil,
			"immunefi submission draft for "+fid); err != nil {
			return nil, err
		}
		paths = append(paths, out)
	}
	if len(paths) > 0 {
		data := validation.VObj(kv("paths",
			validation.Value{Kind: validation.Arr, A: strVals(paths)}))
		if _, err := campaign.Log("report.immunefi_generated", nil,
			&data); err != nil {
			return nil, err
		}
	}
	return paths, nil
}

// strVals renders paths as a JSON string array (the log payload).
func strVals(items []string) []validation.Value {
	out := make([]validation.Value, 0, len(items))
	for _, s := range items {
		out = append(out, validation.VStr(s))
	}
	return out
}

// immunefiSection is one rendered section: its body lines and whether it
// carried data (false renders the literal MISSING line instead).
type immunefiSection struct {
	name  string
	body  []string
	empty bool
}

// renderImmunefiFinding renders one file's lines: the header, the
// pre-submit checklist block (first, only when some section is empty),
// then the six sections in fixed order.
func renderImmunefiFinding(f, policy validation.Value,
	program string) []string {
	fid := validation.ObjStr(f, "finding_id")
	sections := []immunefiSection{}
	for _, name := range immunefiSections {
		switch name {
		case "Summary":
			sections = append(sections, immunefiSummary(f, program))
		case "Impact":
			sections = append(sections, immunefiImpact(f))
		case "Severity":
			sections = append(sections, immunefiSeverity(f, policy))
		case "PoC":
			sections = append(sections, immunefiPoC(f))
		case "Recommendation":
			sections = append(sections, immunefiRecommendation(f))
		case "Related areas":
			sections = append(sections, immunefiRelated(f))
		}
	}
	L := []string{fmt.Sprintf("# Immunefi submission — `%s`", fid), ""}
	L = append(L, fmt.Sprintf("- generated: %s", state.NowIso()))
	L = append(L, "")
	empties := []string{}
	for _, s := range sections {
		if s.empty {
			empties = append(empties, s.name)
		}
	}
	if len(empties) > 0 {
		L = append(L,
			fmt.Sprintf("> pre-submit checklist: %d section(s) MISSING — "+
				"fill before submitting", len(empties)))
		L = append(L, "")
		for _, name := range empties {
			L = append(L, immunefiMissing(name))
		}
		L = append(L, "")
	}
	for _, s := range sections {
		L = append(L, "## "+s.name)
		L = append(L, "")
		if s.empty {
			L = append(L, immunefiMissingBody(s.name))
		} else {
			L = append(L, s.body...)
		}
		L = append(L, "")
	}
	return L
}

// immunefiMissingBody is the in-section empty line: the literal checklist
// line everywhere, plus the "not drafted" prose fallback in
// Recommendation (the brief names both; the literal line stays greppable).
func immunefiMissingBody(section string) string {
	if section == "Recommendation" {
		return immunefiMissing(section) + " — not drafted"
	}
	return immunefiMissing(section)
}

// immunefiSummary is title + program + the gate state string already on
// the finding (the EvaluateBountyGate output the md report renders).
func immunefiSummary(f validation.Value, program string) immunefiSection {
	body := []string{}
	if title := validation.ObjStr(f, "title"); title != "" {
		body = append(body, "- title: "+title)
	}
	if program != "" {
		body = append(body, "- program: "+program)
	}
	if b := validation.AsObj(validation.ObjAt(f, "bounty")); len(b.O) > 0 {
		line := fmt.Sprintf("- bounty gate: eligible=%s, submission_ready=%s",
			pyStr(validation.ObjAt(b, "eligible")), pyStr(validation.ObjAt(b, "submission_ready")))
		if blockers := listAt(b, "blocking_reasons"); len(blockers) > 0 {
			line += ", blockers: " + strings.Join(strList(validation.ObjAt(b,
				"blocking_reasons")), "; ")
		}
		body = append(body, line)
	}
	return immunefiSection{name: "Summary", body: body,
		empty: len(body) == 0}
}

// immunefiImpact is the exploit mechanism (root_cause.mechanism, the
// finding IR's exploit_mechanism) plus the economic_impact record.
func immunefiImpact(f validation.Value) immunefiSection {
	body := []string{}
	rc := validation.AsObj(validation.ObjAt(f, "root_cause"))
	if mech := validation.ObjStr(rc, "mechanism"); mech != "" {
		body = append(body, "- exploit mechanism: "+mech)
	}
	if desc := validation.ObjStr(rc, "description"); desc != "" {
		body = append(body, "- root cause: "+desc)
	}
	ei := validation.AsObj(validation.ObjAt(f, "economic_impact"))
	if len(ei.O) > 0 {
		if ex := validation.ObjAt(ei, "extractable_usd"); ex.Kind != validation.Null {
			body = append(body, fmt.Sprintf("- extractable: $%s",
				pyCommaAuto(ex)))
		}
		if ml := validation.ObjAt(ei, "max_loss_usd"); ml.Kind != validation.Null {
			body = append(body, fmt.Sprintf("- max loss: $%s",
				pyCommaAuto(ml)))
		}
		if br := validation.ObjStr(ei, "blast_radius"); br != "" {
			body = append(body, "- blast radius: "+br)
		}
		if kind := validation.ObjStr(ei, "kind"); kind != "" {
			body = append(body, "- impact kind: "+kind)
		}
		if em := validation.ObjStr(ei, "mechanism"); em != "" {
			body = append(body, "- economic mechanism: "+em)
		}
		if conf := validation.ObjAt(ei, "confidence"); conf.Kind != validation.Null {
			body = append(body, fmt.Sprintf("- confidence: %s",
				pyStr(conf)))
		}
		if ceiling := validation.ObjStr(ei, "ceiling"); ceiling != "" {
			body = append(body, "- ceiling: "+ceiling)
		}
		if basis := validation.ObjStr(ei, "price_basis"); basis != "" {
			body = append(body, "- price basis: `"+basis+"`")
		}
	}
	return immunefiSection{name: "Impact", body: body,
		empty: len(body) == 0}
}

// immunefiSeverity is the program severity mapping (SeverityFor against
// the policy severity_rules) plus the G12 alias line when the class is
// mapped (presence-gated: unmapped classes render no alias, and an
// evaluated-but-unmatched mapping still renders its verdict, never
// silence).
func immunefiSeverity(f, policy validation.Value) immunefiSection {
	if policy.Kind != validation.Obj || len(policy.O) == 0 {
		return immunefiSection{name: "Severity", empty: true}
	}
	sev, why, err := bounty.SeverityFor(policy, f)
	body := []string{}
	if err != nil {
		body = append(body, "- program severity: unevaluated — "+err.Error())
	} else if sev != "" {
		body = append(body, fmt.Sprintf("- program severity: **%s** — %s",
			sev, why))
	} else {
		body = append(body, "- program severity: unmapped — "+why)
	}
	class := validation.ObjStr(validation.ObjAt(f, "root_cause"), "class")
	if class != "" {
		body = append(body, fmt.Sprintf("- class: `%s`%s", class,
			classAliasSuffixSpaced(class)))
	}
	if reported := validation.ObjAt(f, "reported_severity"); pyTruthyInt64Only(reported) {
		band := "n/a"
		if b := validation.AsObj(validation.ObjAt(validation.AsObj(validation.ObjAt(f, "risk")), "validated")); b.Kind == validation.Obj {
			if bv := validation.ObjAt(b, "band"); bv.Kind != validation.Null {
				band = pyStr(bv)
			}
		}
		body = append(body, fmt.Sprintf("- reported severity: **%s** — "+
			"computed band: **%s**", pyStr(reported), band))
	}
	return immunefiSection{name: "Severity", body: body, empty: false}
}

// immunefiPoC renders every evidence item verbatim: the findingSection
// line shape (level, type, description, sandbox, G15 reruns/fork_stale
// advisories) plus the EXEC link (artifact_id) the export shape requires.
func immunefiPoC(f validation.Value) immunefiSection {
	ev := listAt(f, "evidence")
	if len(ev) == 0 {
		return immunefiSection{name: "PoC", empty: true}
	}
	sorted := append([]validation.Value{}, ev...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return evidenceIndex(validation.ObjStr(sorted[i], "level")) <
			evidenceIndex(validation.ObjStr(sorted[j], "level"))
	})
	body := []string{}
	for _, e := range sorted {
		line := fmt.Sprintf("- %s [%s] %s", validation.ObjStr(e, "level"),
			validation.ObjStr(e, "type"), pyStr(validation.ObjAt(e, "description")))
		if validation.ObjStr(e, "sandbox_profile") != "" {
			line += " (sandbox: " + validation.ObjStr(e, "sandbox_profile") + ")"
		}
		if validation.ObjStr(e, "reruns") != "" {
			line += " [reruns " + validation.ObjStr(e, "reruns") + "]"
		}
		if validation.ObjStr(e, "fork_stale") != "" {
			line += " [fork stale]"
		}
		if aid := validation.ObjAt(e, "artifact_id"); aid.Kind != validation.Null &&
			pyStr(aid) != "" {
			line += " — artifact `" + pyStr(aid) + "`"
		}
		body = append(body, line)
	}
	return immunefiSection{name: "PoC", body: body, empty: false}
}

// immunefiRecommendation is the prose fix (verification.recommendation —
// the finding IR's fix field).
func immunefiRecommendation(f validation.Value) immunefiSection {
	if rec := validation.ObjStr(validation.AsObj(validation.ObjAt(f, "verification")), "recommendation"); rec != "" {
		return immunefiSection{name: "Recommendation",
			body: []string{"- fix: " + rec}}
	}
	return immunefiSection{name: "Recommendation", empty: true}
}

// immunefiRelated cites the adjacent surface: affected entries plus the
// program-acknowledged risks on the record (bounty.accepted_risk, the
// policy's accepted_risks entry check13 recorded) and in-code
// acknowledgements. Empty when none are cited.
func immunefiRelated(f validation.Value) immunefiSection {
	body := []string{}
	for _, a := range listAt(f, "affected") {
		parts := []string{}
		if p := validation.ObjStr(a, "path"); p != "" {
			parts = append(parts, "`"+p+"`")
		}
		if c := validation.ObjStr(a, "contract"); c != "" {
			parts = append(parts, "contract `"+c+"`")
		}
		if fn := validation.ObjStr(a, "function"); fn != "" {
			parts = append(parts, "function `"+fn+"`")
		}
		if len(parts) > 0 {
			body = append(body, "- related: "+strings.Join(parts, " "))
		}
	}
	if ar := validation.AsObj(validation.ObjAt(validation.AsObj(validation.ObjAt(f, "bounty")), "accepted_risk")); len(ar.O) > 0 {
		line := fmt.Sprintf("- accepted risk: **%s**", pyStr(validation.ObjAt(ar,
			"pattern")))
		if kind := validation.ObjStr(ar, "kind"); kind != "" {
			line += " (" + kind + ")"
		}
		if ref := validation.ObjStr(ar, "reference"); ref != "" {
			line += " — " + ref
		}
		if note := validation.ObjStr(ar, "note"); note != "" {
			line += " — " + note
		}
		body = append(body, line+" (documented by the program)")
	}
	if ack := validation.AsObj(validation.ObjAt(validation.ObjAt(f, "dedup_meta"), "in_code_ack")); len(ack.O) > 0 {
		body = append(body, fmt.Sprintf("- in-code ack: %s:%s — phrase %q",
			pyStr(validation.ObjAt(ack, "file")), pyStr(validation.ObjAt(ack, "line")),
			pyStr(validation.ObjAt(ack, "phrase"))))
	}
	return immunefiSection{name: "Related areas", body: body,
		empty: len(body) == 0}
}

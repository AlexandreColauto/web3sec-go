package cli

// cmd_ingest_print: ingest's output — the failure/hint line, the
// accepted-payload record, and the --example payload with its
// schema-walked legend (moved verbatim from cmd_ingest.go).
import (
	"fmt"
	"strings"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

// t14ExamplePayload is examples/hypothesis.example.json verbatim.
const t14ExamplePayload = `{
  "title": "ShareVault deposit inflates the share price for later depositors",
  "root_cause": {
    "class": "share-price-inflation",
    "description": "The first depositor sets the share price with a single wei, so all later depositors buy shares at a price the attacker chose, diluting their position.",
    "mechanism": "deposit() mints shares at total_assets/total_shares before any real assets are in the vault"
  },
  "affected": [
    {"path": "src/ShareVault.sol", "contract": "ShareVault",
     "function": "deposit", "lines": [42, 60], "entry_point": true}
  ],
  "attacker": {"profile": "arbitrary EOA", "capabilities": ["deposit"]},
  "evidence": [],
  "invariant": {
    "id": "INV-1",
    "statement": "a depositor's share of total assets may not decrease as a result of their own deposit"
  },
  "assumptions": [
    {
      "id": "A1",
      "type": "state",
      "claim": "the vault can be empty when the first deposit arrives",
      "status": "UNKNOWN",
      "model_belief": 0.9,
      "blocking": true
    }
  ],
  "preconditions": [
    {
      "kind": "state",
      "description": "vault is empty (total_shares == 0)",
      "satisfied_by": "be the first depositor"
    }
  ],
  "exploit_sequence": [
    {"step": 1, "actor": "attacker", "action": "deposit(1 wei) to set the share price"},
    {"step": 2, "actor": "victim", "action": "deposit(1 ETH) at the attacker-set price"}
  ]
}
`

// printIngestFailure is the stderr half of a rejected payload: the validation
// message plus the shape-contract hint (the shape-swap hint when the error
// names a known confusion).
func printIngestFailure(r *Runner, err error) {
	fmt.Fprintf(r.Err, "ingest failed: %s\n", err)
	if hint := t14IngestShapeHint(err.Error()); hint != "" {
		fmt.Fprintf(r.Err, "hint: %s\n", hint)
		return
	}
	// R2-4 (critic): the shape-contract hint is a SCHEMA hint. Budget,
	// ledger (exec_ref), gate and lie-detection refusals are not shape
	// problems — sending the operator to diff a payload that is fine is
	// its own kind of misleading hint.
	if strings.Contains(err.Error(), " validation failed at ") {
		fmt.Fprint(r.Err, "hint: the `webv2 ingest --example` payload is the "+
			"shape contract — diff yours against it (fields, nesting, value "+
			"types); the message above names the offending path\n")
	}
}

// printIngestResult is the accepted-payload output: the taxonomy advisory and
// intake warnings are part of the record, so they are printed with the id.
//
// Wave N, T6: the accepted line names the CONFIRMED floor the chosen class
// pins, because an ingest-time taxonomy choice silently sets it (G-02 filed an
// E4-reachable bug under an E6 class and sat evidence-saturated). The floor
// comes from findings.RequiredLevelForCampaign — the SAME lookup the CONFIRMED
// gate runs (findings.gateRun.evidenceFloor) — so the line can never disagree
// with the gate about what the class costs, instance floor overrides included.
func printIngestResult(r *Runner, campaign *state.Campaign, f validation.Value,
	asJSON bool) {
	cls := validation.ObjStr(validation.ObjAt(f, "root_cause"), "class")
	advisory := taxonomy.ClassAdvisory(&cls, campaign)
	warnings := findings.IntakeCheckpoint(f,
		objStrDefault(f, "trajectory", "code"), validation.ObjStr(f, "campaign_id"), campaign)
	if asJSON {
		t14PrintJSON(r.Out, validation.VObj(
			validation.KV{K: "finding", V: f},
			validation.KV{K: "confirmed_floor",
				V: validation.VStr(findings.RequiredLevelForCampaign(
					campaign, "CONFIRMED", cls))},
			validation.KV{K: "class_advisory", V: t14OrNull(advisory)},
			validation.KV{K: "intake_warnings", V: t14StrArr(warnings)},
		))
		return
	}
	shown := cls
	if shown == "" {
		shown = "?"
	}
	fmt.Fprintf(r.Out, "ingested %s [%s] (class %s, CONFIRMED floor %s)\n",
		validation.ObjStr(f, "finding_id"), validation.ObjStr(f, "status"), shown,
		findings.RequiredLevelForCampaign(campaign, "CONFIRMED", cls))
	if advisory != "" {
		fmt.Fprintf(r.Out, "  ADVISORY: %s\n", advisory)
	}
	for _, w := range warnings {
		if advisory != "" && w == advisory {
			// IntakeCheckpoint re-emits the advisory as a warning (data,
			// pinned by the golden); the ADVISORY line above already says
			// it — print once (critic I-8).
			continue
		}
		fmt.Fprintf(r.Out, "  warning: %s\n", w)
	}
}

// printIngestExample is the --example branch: the payload on stdout (pipeable),
// the contract statement and the schema-walked enum legend on stderr.
func printIngestExample(r *Runner) error {
	text := t14ExamplePayload
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	fmt.Fprint(r.Out, text)
	fmt.Fprint(r.Err, "This payload IS the ingest schema contract: the "+
		"fields, nesting and value types shown are exactly what "+
		"`webv2 ingest <campaign> --json-file` validates against — a "+
		"payload that differs in shape fails validation, and the error names "+
		"the offending field.\n")
	fmt.Fprint(r.Err, "save as payload.json, then: webv2 ingest <campaign> "+
		"--json-file payload.json\n(or pipe: webv2 ingest --example | "+
		"webv2 ingest <campaign> --json-file -)\n")
	// The fields alone do not tell a first pass what the closed enums may
	// say; the legend is WALKED from the schema at call time.
	legend, err := validation.SchemaEnumLegend("finding")
	if err != nil {
		return err
	}
	fmt.Fprint(r.Err, "closed-enum fields (auto-generated from "+
		"schema/finding.schema.json — every allowed value):\n")
	for _, line := range legend {
		fmt.Fprintf(r.Err, "  %s\n", line)
	}
	return nil
}

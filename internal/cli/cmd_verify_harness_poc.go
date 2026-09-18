package cli

// cmd_verify_harness_poc: the bridged sequence_poc artifact and the
// operator storage-layout sidecar it grounds on (moved verbatim from
// cmd_verify_harness.go; see that file's "The bridged PoC artifact").

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"websec/internal/harness"
	"websec/internal/state"
	"websec/internal/validation"
)

// harnessLayoutFile is the operator-provided storage-layout sidecar's
// basename: artifacts/harness/<INV>/layout.json beside the PoC it grounds.
const harnessLayoutFile = "layout.json"

// harnessPocFile is the bridged PoC's basename inside the invariant's
// harness dir. It names the invariant, not the exec: the file is a view of
// the invariant's latest counterexample rung, so a newer run replaces it
// rather than accumulating one file per run.
func harnessPocFile(invID string) string {
	return "poc-" + invID + ".json"
}

// pocSpecID is the sequence_poc `spec_id` a bridged PoC carries:
// "SEQ-<slug>-POC", where the slug is the invariant id uppercased with
// every non-alphanumeric byte dropped ("INV-1" -> "SEQ-INV1-POC"). The
// schema pins spec_id to ^SEQ-[A-Z0-9]+-[A-Za-z0-9]+$, and the id is a
// function of the INVARIANT alone — never of the exec or the witness — so
// the same invariant always claims the same spec_id and a re-verify
// overwrites one artifact instead of minting a second identity. (A
// hand-edited invariant id whose slug is empty yields an id the schema
// refuses; harnessWriteBridgedPoc validates the document before writing,
// so that lands as a named refusal, never as a schema-invalid file.)
func pocSpecID(invID string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(invID) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return "SEQ-" + b.String() + "-POC"
}

// harnessWriteBridgedPoc is the L4 consumption seam on the run path: on a
// minicertora counterexample rung, bridge the run's witness into a
// sequence_poc and land it as artifacts/harness/<INV>/poc-<INV>.json.
//
// It is total and never fails a mappable run: every refusal lane prints ONE
// stderr note and returns nil — the run's rung is already recorded and the
// derived artifact simply does not exist. The lanes:
//
//   - the layout sidecar (harnessLayoutSidecar) is malformed -> one note,
//     bridge layoutless;
//   - the bridge refuses the witness (no calls, an unbridgable step, a
//     symbolic sender, a non-wei value) -> "verify: poc for '<INV>' not
//     written: <the bridge's own refusal>";
//   - the bridged document fails the sequence_poc schema (a defect in the
//     bridge, or an invariant id with no alphanumerics) -> the same note
//     shape with the schema error, because a schema-invalid artifact under
//     artifacts/ is worse than no artifact.
//
// A clean bridge is SILENT: the harness-result print line is pinned, so the
// success record is the artifact registry row (kind sequence-poc) plus the
// file itself. A failed writer (I/O, registry) is a real error and does
// propagate.
func harnessWriteBridgedPoc(c *state.Campaign, invID string, raw []byte,
	ruleName string, r *Runner) error {
	layout, layoutNote := harnessLayoutSidecar(c, invID)
	if layoutNote != "" {
		fmt.Fprintln(r.Err, layoutNote)
	}
	doc, refusal := harness.BridgeWitnessLine(raw, ruleName, pocSpecID(invID),
		invID, layout)
	if refusal != "" {
		fmt.Fprintf(r.Err, "verify: poc for %s not written: %s\n",
			validation.PyReprStr(invID), refusal)
		return nil
	}
	if err := validation.Validate(doc, "sequence_poc", 1); err != nil {
		fmt.Fprintf(r.Err, "verify: poc for %s not written: bridged "+
			"document is not a sequence_poc: %s\n",
			validation.PyReprStr(invID), err)
		return nil
	}
	regNote := fmt.Sprintf("bridged counterexample witness for %s (%s)",
		invID, pocSpecID(invID))
	_, _, err := harnessArtifactWrite(c, invID, harnessPocFile(invID),
		[]byte(validation.CanonCompact(doc)), "sequence-poc", regNote,
		"bridged witness regenerated")
	return err
}

// harnessLayoutSidecar loads the operator's storage-layout sidecar for one
// invariant and reports why it was ignored, if it was. The shape is
// deliberately narrow: a JSON OBJECT whose every value is a STRING —
// "<Contract>.<var>" -> decimal slot, plus optional "<Contract>" -> 0x
// address companions (see the file comment). Anything else (absent-but-
// unreadable, not JSON, an array or scalar, a numeric slot) is malformed:
// the map is dropped and the note says which rule broke, so the operator
// sees a typo instead of silently losing final_assertions. A file that is
// merely absent — the normal case — is not a note: no sidecar is not a
// mistake, and a well-shaped sidecar that grounds nothing (an unknown
// contract, a symbolic reading) stays the BRIDGE's quiet skip, never this
// loader's complaint.
func harnessLayoutSidecar(c *state.Campaign, invID string) (map[string]string,
	string) {
	p := harnessArtifactFile(c, invID, harnessLayoutFile)
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ""
		}
		return nil, harnessLayoutNote(c, p,
			fmt.Sprintf("unreadable: %s", err))
	}
	v, err := validation.ParseOrdered(raw)
	if err != nil {
		return nil, harnessLayoutNote(c, p,
			fmt.Sprintf("not JSON: %s", err))
	}
	if v.Kind != validation.Obj {
		return nil, harnessLayoutNote(c, p, "top level must be an object "+
			"mapping \"<Contract>.<var>\" to a decimal slot string")
	}
	out := make(map[string]string, len(v.O))
	for _, kv := range v.O {
		if kv.V.Kind != validation.Str {
			return nil, harnessLayoutNote(c, p, fmt.Sprintf("key %s must "+
				"map to a string, got %s", validation.PyReprStr(kv.K),
				validation.CanonCompact(kv.V)))
		}
		out[kv.K] = kv.V.S
	}
	return out, ""
}

// harnessLayoutNote is the one-line stderr note for an ignored sidecar: the
// campaign-relative path (the spelling verifyScaffold prints for artifacts
// under the same dir) plus the reason.
func harnessLayoutNote(c *state.Campaign, p, why string) string {
	rel, err := filepath.Rel(c.Dir, p)
	if err != nil {
		rel = p
	}
	return fmt.Sprintf("verify: layout sidecar %s ignored: %s", rel, why)
}

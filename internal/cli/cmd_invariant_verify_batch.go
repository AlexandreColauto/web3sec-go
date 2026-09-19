package cli

// cmd_invariant_verify_batch: B6(b) — the `--invariants INV-1,INV-2,...` batch
// form of `invariant-verify`
// (docs/feedback-triage-morph-r2.md §B6(b), plan-review F7).
//
//	webv2 invariant-verify <campaign> --artifact ART-... --invariants INV-1,INV-2
//
// It is the single form's --artifact path repeated over a list, against ONE
// registered artifact, with the all-or-nothing discipline
// cmd_answered_batch.go established for the Q-* batch: EVERY per-invariant
// gate runs BEFORE any write, so a refused batch writes nothing and never
// prints an `attested` line for state that does not exist; when all gates pass
// every id is committed and only THEN does the run print one `<id>: attested`
// line per id, in ARGUMENT order. Events stay one-per-invariant
// (VerifyInvariantStatement logs invariant.verified once per call), because
// the hash chain and audit's per-attestation projection must never see a fused
// row. The audit projection counts attestations: a half-seen batch is the
// defect F7 exists to prevent.
//
// Exit codes are the verb's existing trichotomy: a refusal or a usage error is
// 2, a runtime (store) failure is 1, success is 0. The single-positional form
// is untouched — this file adds a flag and a route, and the absent case
// (no --invariants) still runs the original code path byte-for-byte
// (pinned by cmd_invariant_verify_test.go and by
// TestInvariantVerifySingleFormBytesUnchangedWithoutBatchFlag).
//
// Why the preflight is a read-only replica: VerifyInvariantStatement
// (internal/invariants/verify.go:76) runs its three gates and commits in ONE
// call, and the invariants package exports no dry-run seam. The gates are pure
// reads (registered artifact? registered invariant? do the artifact's bytes
// name the invariant or an applies_to target?), so this file replays them
// read-only — batchArtifactReferencesInvariant / batchReferenceTokens below
// mirror verify.go:123-173 line for line, and batchIrrelevantArtifactReason /
// the unknown-invariant reason mirror the message text those gates produce, so
// the batch refuses in the single form's own words. The duplication is
// deliberate and is guarded by TestInvariantVerifyBatchGateAgreesWithSingleForm
// (both directions: the batch's verdict and reason must match what the single
// form prints for the same fixture) — and it can never AUTHORIZE a write the
// authoritative gate would refuse, because the commit loop calls
// VerifyInvariantStatement itself and reports a mid-batch failure loudly
// rather than claiming nothing was written.

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// invariantVerifyBatchDisclosure is the stderr disclosure a successful batch
// appends ONCE (not per id): the recorded verdicts are operator attestations,
// not mechanically established proof — the same disclosure the single form
// prints, kept identical so a batch can never read as stronger evidence than
// the per-id verb it repeats.
const invariantVerifyBatchDisclosure = "invariant-verify: operator attestation " +
	"recorded; artifact attribution is not mechanical proof\n"

// runInvariantVerifyBatchRoute is the parse-time half of the batch form: the
// list hygiene and the conflicts argparse would raise before anything is
// opened, then state.Open, then the one-flag requirement. It is called from
// runInvariantVerify only when --invariants was passed, so the single form's
// bytes are untouched.
func runInvariantVerifyBatchRoute(root string, pos []string, artifact, execID,
	raw string, r *Runner) int {
	ids, code := batchInvariantIDs(r, raw)
	if code != 0 {
		return code
	}
	// Duplicates are a usage error (exit 2, the house argparse rendering): the
	// same id twice in one list is a typo the operator must see, never a
	// silently deduplicated batch — and never two attestations for one
	// invariant, which would make the audit's count disagree with the list.
	if dup := batchDuplicateID(ids); dup != "" {
		return r.fail(root, argErrf("invariant-verify",
			"argument --invariants: duplicate invariant id: %s",
			validation.PyReprStr(dup)))
	}
	// The batch attests every id against ONE --artifact. --exec mints (or
	// refreshes) an artifact per exec, so it cannot ride a list: the operator
	// who wants per-id exec citations runs the single form per id.
	if execID != "" {
		return r.fail(root, argErrf("invariant-verify",
			"argument --exec: not allowed with argument --invariants"))
	}
	// argparse's mutual-exclusion wording: the positional inv_id belongs to
	// the single form; the list IS the id list.
	if len(pos) > 1 {
		return r.fail(root, argErrf("invariant-verify",
			"argument inv_id: not allowed with argument --invariants"))
	}
	if len(pos) < 1 {
		return r.fail(root, requiredErrf("invariant-verify", "campaign"))
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return r.withErr(root, func() error { return err })
	}
	if artifact == "" {
		// The single form's "one is required" line is printed after Open too;
		// the batch narrows the requirement to --artifact and says why.
		fmt.Fprintln(r.Err, "invariant-verify: --invariants needs --artifact "+
			"ART-... — every id in the list is attested against that ONE "+
			"registered artifact (--exec cannot ride the batch: it mints an "+
			"artifact per exec)")
		return 2
	}
	return runInvariantVerifyBatch(c, ids, artifact, r)
}

// batchInvariantIDs splits the --invariants value and refuses the hygiene
// defects artifact-register's B2 check refuses in the same shape: one stderr
// line, the offending value repr-quoted, exit 2, before anything is opened or
// written. An empty string (`--invariants=`) and an empty element
// (`INV-1,,INV-2`, a trailing comma included) are both "an id that names
// nothing". Elements are otherwise taken VERBATIM — the registry key is what
// the operator typed, and a padded ` INV-1` is refused by the gate as the
// unknown invariant it is rather than silently trimmed into a different id.
func batchInvariantIDs(r *Runner, raw string) ([]string, int) {
	parts := strings.Split(raw, ",")
	ids := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			fmt.Fprintf(r.Err, "invariant-verify: --invariants: empty "+
				"invariant id: %s\n", validation.PyReprStr(raw))
			return nil, 2
		}
		ids = append(ids, p)
	}
	return ids, 0
}

// batchDuplicateID is the first id that appears twice in the list, or "".
func batchDuplicateID(ids []string) string {
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			return id
		}
		seen[id] = true
	}
	return ""
}

// runInvariantVerifyBatch is the batch body: GATE ALL, COMMIT ALL, THEN
// PRINT — F7's order, and the reason no `attested` line can ever describe
// state that does not exist.
func runInvariantVerifyBatch(c *state.Campaign, ids []string, artifact string,
	r *Runner) int {
	// One links read for the whole preflight. LoadLinks is the authoritative
	// read seam (it is what the commit path calls, read-time legacy migration
	// included); a malformed registry is a store failure — exit 1, the
	// verb's runtime code — not a per-invariant refusal, because no id has
	// been judged yet.
	links, err := invariants.LoadLinks(c)
	if err != nil {
		return r.withErr(c.Root, func() error { return err })
	}
	// Phase 1 — every per-invariant gate, read-only. The first refusal ends
	// the run: one line, exit 2, and NOTHING has been written (no registry
	// flip, no invariant.verified event) because no write has been attempted.
	for _, id := range ids {
		reason, ok := batchInvariantGate(c, id, artifact, links)
		if !ok {
			fmt.Fprintf(r.Err, "aborted: %s refused: %s; nothing written\n",
				id, reason)
			return 2
		}
	}
	// Phase 2 — commit every id. VerifyInvariantStatement re-runs the gates
	// it owns (the preflight above is a replica, never an authority) and logs
	// exactly one invariant.verified event per id.
	for _, id := range ids {
		if _, err := invariants.VerifyInvariantStatement(c, id, artifact); err != nil {
			// Unreachable while the preflight replica agrees with the gate;
			// if it ever happens (a concurrent writer, or a reworded gate),
			// say what actually landed instead of the preflight's promise.
			fmt.Fprintf(r.Err, "aborted: %s refused: %s; the ids before it "+
				"in this batch were already attested — re-run after fixing\n",
				id, err.Error())
			return 2
		}
	}
	// Phase 3 — only now the output: one line per id, in ARGUMENT order.
	for _, id := range ids {
		fmt.Fprintf(r.Out, "%s: attested\n", id)
	}
	fmt.Fprint(r.Err, invariantVerifyBatchDisclosure)
	return 0
}

// batchInvariantGate is the read-only preflight for one (invariant, artifact)
// pair: exactly the three checks VerifyInvariantStatement performs before it
// writes anything, in the same order, with the same words. It returns
// (reason, false) for a refusal and ("", true) when the pair would commit.
//
// It reports reasons, not errors: the batch must name the refused id in one
// line, and a store read failure is handled by the caller before the loop.
func batchInvariantGate(c *state.Campaign, invID, artifactID string,
	links validation.Value) (string, bool) {
	// 1. The artifact must be registered (verify.go:78). state's
	// UnknownArtifactError already renders the pinned "unknown artifact 'X'".
	a, err := c.Artifact(artifactID)
	if err != nil {
		return err.Error(), false
	}
	// 2. The invariant must be a registry key (verify.go:87) — the exact
	// spelling, no normalization, exactly as the single form checks it.
	reg := validation.ObjAt(links, "invariants")
	if !validation.HasKey(reg, invID) {
		return "unknown invariant " + validation.PyReprStr(invID), false
	}
	// 3. The artifact's BYTES must name the invariant or an applies_to target
	// (verify.go:91). This is ATTRIBUTION, not proof — the same relevance law
	// the single form applies.
	entry := validation.ObjAt(reg, invID)
	if !batchArtifactReferencesInvariant(c, a, invID, entry) {
		return batchIrrelevantArtifactReason(artifactID, invID), false
	}
	return "", true
}

// batchArtifactReferencesInvariant mirrors invariants.artifactReferencesInvariant
// (internal/invariants/verify.go:129) — word-boundary, case-insensitive
// matching over the artifact's bytes, failing closed when the bytes cannot be
// read. Kept in sync by TestInvariantVerifyBatchGateAgreesWithSingleForm.
func batchArtifactReferencesInvariant(c *state.Campaign, a validation.Value,
	invID string, entry validation.Value) bool {
	raw, err := os.ReadFile(c.ResolveArtifactPath(a))
	if err != nil {
		return false
	}
	text := string(raw)
	for _, tok := range batchReferenceTokens(invID, entry) {
		re, cerr := regexp.Compile(`(?i)\b` + regexp.QuoteMeta(tok) + `\b`)
		if cerr != nil {
			continue
		}
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

// batchReferenceTokens mirrors invariants.referenceTokens
// (internal/invariants/verify.go:154): the id in the registry's spelling and
// in NormalizeInvID's canonical spelling, plus every applies_to target in both
// spellings, deduplicated, empties dropped.
func batchReferenceTokens(invID string, entry validation.Value) []string {
	cands := []string{invID}
	for _, t := range validation.ObjAt(entry, "applies_to").A {
		if t.Kind == validation.Str {
			cands = append(cands, t.S)
		}
	}
	seen := map[string]bool{}
	out := []string{}
	for _, cand := range cands {
		for _, tok := range []string{cand, invariants.NormalizeInvID(cand)} {
			if tok == "" || seen[tok] {
				continue
			}
			seen[tok] = true
			out = append(out, tok)
		}
	}
	return out
}

// batchIrrelevantArtifactReason is invariants.irrelevantArtifact's message
// (internal/invariants/verify.go:177) verbatim, so the batch refuses a
// citation in the single form's own words and with its heal.
func batchIrrelevantArtifactReason(artifactID, invariantID string) string {
	return fmt.Sprintf("artifact %s does not reference %s (nor its "+
		"applies_to) — cite a check that names what it verifies "+
		"(invariant-verify with --exec <id> re-registers stdout as the "+
		"artifact)", artifactID, invariantID)
}

// invariantVerifyHelp is `webv2 invariant-verify -h`. Its first two lines are
// argparseUsageBlocks["invariant-verify"] byte-for-byte (read from that map,
// not retyped), so the help block and the usage error can never disagree about
// the single form's signature; the batch's own usage line follows, then the
// option that turns it on. The single form's usage ERROR is untouched — B6b
// adds help text, never a new byte on the pinned error path.
var invariantVerifyHelp = argparseUsageBlocks["invariant-verify"] +
	"       webv2 invariant-verify [-h] --artifact ARTIFACT --invariants IDS campaign\n" +
	`
positional arguments:
  campaign             the campaign whose invariant registry moves
  inv_id               the invariant to attest (single form; omit it with
                       --invariants)

options:
  -h, --help           show this help message and exit
  --artifact ARTIFACT  the registered artifact whose bytes name what it
                       verifies (required: exactly one of --artifact/--exec)
  --exec EXEC-*        register a finished exec's captured output as the check
                       artifact and cite it (single form only)
  --invariants IDS     batch form: a comma-separated id list (INV-1,INV-2,...)
                       attested against ONE --artifact. Every per-invariant
                       gate runs first: a refusal prints
                       'aborted: <id> refused: <reason>; nothing written' at
                       exit 2 and NOTHING is written; when all pass, every id
                       is committed (one invariant.verified event each) and
                       one '<id>: attested' line per id follows, in argument
                       order. Duplicate ids, an empty id and an empty list are
                       refused at exit 2; ids are taken verbatim. --exec cannot
                       ride the batch.
`

func init() {
	// Self-registration, the house pattern for per-verb surface (the map lives
	// in cli.go; every command already registers itself from its own file).
	verbHelpBlocks["invariant-verify"] = invariantVerifyHelp
}

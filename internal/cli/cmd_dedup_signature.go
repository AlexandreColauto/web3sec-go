package cli

// cmd_dedup_signature: `webv2 dedup-signature <campaign> <finding>
// {--root-cause SENTENCE [--cwe CWE] | --economic SENTENCE}` — record a
// tier-2/tier-3 dedup signature from the NORMALIZED SENTENCE, with the tool
// computing the hash (D4).
//
// Why: dedup.SetRootCauseSignature / SetEconomicSignature have always computed
// the 16-hex TextSignature themselves, but nothing in the CLI called them and
// the model-facing prompt only named the Python function, so in practice the
// only way a campaign got a tier-2/3 signature was a human hand-writing the hex
// into the finding JSON. The morph campaign's `dedup-normalization` sat at
// needs-model with no signatures set. The operator (or the model, through this
// verb) supplies the sentence; the hash is derived.
//
// The two signature kinds are mutually exclusive: a root-cause sentence answers
// "same cause?" and an economic sentence answers "same effect?", and recording
// one while believing the other is exactly the mistake the tiers exist to
// separate. Both may be set on one finding, via two calls.

import (
	"fmt"

	"websec/internal/dedup"
	"websec/internal/findings"
	"websec/internal/state"
)

const dedupSignatureUsage = "usage: webv2 dedup-signature [-h] " +
	"[--root-cause SENTENCE | --economic SENTENCE] [--cwe CWE] campaign " +
	"finding\n"

const dedupSignatureHelp = dedupSignatureUsage + `
record a tier-2 (root cause) or tier-3 (economic effect) dedup signature on a
finding. The sentence must be TARGET-AGNOSTIC — a statement about the bug
("attacker-controlled exchange rate creates unbacked withdrawal value"), not a
restatement of a file or function name; the tool hashes the sentence into the
16-hex signature, so the hash itself is never written by hand.

  --root-cause SENTENCE  tier-2: the normalized root cause
  --economic SENTENCE    tier-3: the normalized ultimate economic effect
  --cwe CWE              optional CWE for a root-cause signature

exactly one of --root-cause / --economic is required.

positional arguments:
  campaign              campaign id
  finding               finding id

options:
  -h, --help            show this help message and exit
`

func runDedupSignature(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return dedupSignatureCmd(root, args, r) })
}

func dedupSignatureCmd(root string, args []string, r *Runner) error {
	sp := &argSpec{
		prog:  "dedup-signature",
		usage: dedupSignatureUsage,
		vals:  []*valOpt{{name: "--root-cause"}, {name: "--economic"}, {name: "--cwe"}},
		pos:   []*posOpt{{name: "campaign"}, {name: "finding"}},
	}
	if err := sp.parse(args); err != nil {
		return err
	}
	if sp.helpSeen {
		fmt.Fprint(r.Out, dedupSignatureHelp)
		return nil
	}
	rootCause := sp.vals[0].val
	economic := sp.vals[1].val
	cwe := sp.vals[2].val
	switch {
	case rootCause == "" && economic == "":
		return t14ArgparseErr(dedupSignatureUsage, "dedup-signature",
			"one of --root-cause or --economic is required")
	case rootCause != "" && economic != "":
		return t14ArgparseErr(dedupSignatureUsage, "dedup-signature",
			"argument --economic: not allowed with argument --root-cause")
	case cwe != "" && rootCause == "":
		return t14ArgparseErr(dedupSignatureUsage, "dedup-signature",
			"argument --cwe: only meaningful with --root-cause")
	}
	c, err := state.Open(root, sp.pos[0].val)
	if err != nil {
		return err
	}
	fid := sp.pos[1].val
	if rootCause != "" {
		var cwePtr *string
		if cwe != "" {
			cwePtr = &cwe
		}
		f, err := dedup.SetRootCauseSignature(c, fid, rootCause, cwePtr)
		if err != nil {
			return err
		}
		fmt.Fprintf(r.Out, "%s: root_cause_signature %s\n", fid,
			objStr(objAt(f, "dedup"), "root_cause_signature"))
		if cwe != "" {
			fmt.Fprintf(r.Out, "  cwe %s\n", objStr(objAt(f, "root_cause"), "cwe"))
		}
		return nil
	}
	f, err := dedup.SetEconomicSignature(c, fid, economic)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "%s: economic_signature %s\n", fid,
		objStr(objAt(f, "dedup"), "economic_signature"))
	return nil
}

// dedupSignaturePreview is the sentence-to-signature mapping the verb promises,
// exposed for tests: the operator supplies the sentence and this is the hash
// the registry will hold.
func dedupSignaturePreview(sentence string) string {
	return findings.TextSignature(sentence)
}

func init() {
	register(command{ord: 76, name: "dedup-signature",
		line: "dedup-signature <campaign> <finding>  record a tier-2/3 dedup " +
			"signature from a normalized sentence",
		run: runDedupSignature})
}

package cli

// cmd_verify_harness_store: the invariant-links store helpers the
// harness bind reads and writes through (entry lookup, save, kind
// resolution, the linksThenLog atomic-landing forwarder; moved verbatim
// from cmd_verify_harness.go).

import (
	"strings"
	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// harnessField builds the verification.harness object in the brief's key
// order (kind, rung, exec, bounded_k int-or-null, summary, proof). The
// proof key rides ONLY when a sidecar object exists (an attributed
// minicertora line): every other kind — and every unattributed minicertora
// refusal — omits the key entirely rather than writing null.
func harnessField(kind harness.Kind, rung, exec string,
	boundedK *int, summary string, proof validation.Value) validation.KV {
	var bk validation.Value = validation.VNull()
	if boundedK != nil {
		bk = validation.VInt(int64(*boundedK))
	}
	kvs := []validation.KV{
		{K: "kind", V: validation.VStr(string(kind))},
		{K: "rung", V: validation.VStr(rung)},
		{K: "exec", V: validation.VStr(exec)},
		{K: "bounded_k", V: bk},
		{K: "summary", V: validation.VStr(summary)},
	}
	if proof.Kind == validation.Obj {
		kvs = append(kvs, validation.KV{K: "proof", V: proof})
	}
	return validation.KV{K: "harness", V: validation.VObj(kvs...)}
}

// harnessInvValue is the invariant value harness.Scaffold renders from: the
// registry entry plus the id the registry carries as its map KEY (Scaffold
// reads "id" off the record, so the key is passed in as that field). Both
// the scaffold command (verifyScaffold) and the Validate arm go through
// here on purpose: if the two inputs could drift, every bound run would be
// refused for bytes that never moved.
//
// r28b F3: the implementation moved to harness.InvValue so the audit's
// re-derivation builds the claim value the SAME way (one implementation,
// two callers); this is the package-local spelling its other call sites use.
func harnessInvValue(invID string, entry validation.Value) validation.Value {
	return harness.InvValue(invID, entry)
}

// harnessInvEntry is links["invariants"][invID] with presence.
func harnessInvEntry(links validation.Value, invID string) (validation.Value,
	bool) {
	if reg := validation.ObjAt(links, "invariants"); reg.Kind == validation.Obj {
		for _, kv := range reg.O {
			if kv.K == invID {
				return kv.V, true
			}
		}
	}
	return validation.VNull(), false
}

// harnessSaveEntry writes one entry back through the links store.
func harnessSaveEntry(c *state.Campaign, links validation.Value, invID string,
	entry validation.Value) error {
	reg := validation.ObjAt(links, "invariants")
	reg.O = validation.SetOrAppend(reg.O, invID, entry)
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	_, err := invariants.SaveLinks(c, links)
	return err
}

// harnessKindFor resolves the harness kind: --kind wins; otherwise the
// scaffold artifact id HARNESS-<INV>-<kind> read off the harness_scaffold
// events. Zero scaffolds (or two, one per skeleton) without --kind is
// exit 2 — the operator disambiguates, the tool never guesses.
func harnessKindFor(c *state.Campaign, invID, flag string) (harness.Kind,
	error) {
	if flag != "" {
		// r29b F1(c): the kind is CANONICALIZED at the source, so the ledger
		// cannot hold a spelling no mapper knows. argparse already refuses
		// any --kind outside {halmos, forge-fuzz, minicertora} (parseVerifyArgs,
		// byte-identical message), so this resolution is the belt to that
		// brace: should a caller reach here without that validation, an
		// unknown or mis-cased kind is refused instead of stored verbatim
		// (the audit would then have to burn the bind's own rung).
		k, ok := harness.NormalizeScaffoldKind(flag)
		if !ok {
			return "", t14ExitErr(2, "verify: unknown harness kind %s\n",
				validation.PyReprStr(flag))
		}
		return k, nil
	}
	events, err := c.Events()
	if err != nil {
		return "", err
	}
	prefix := "HARNESS-" + invID + "-"
	var kinds []string
	for _, ev := range events {
		if validation.ObjStr(validation.ObjAt(ev, "data"), "artifact_id") == "" ||
			validation.ObjStr(ev, "type") != "harness_scaffold" {
			continue
		}
		aid := validation.ObjStr(validation.ObjAt(ev, "data"), "artifact_id")
		if !strings.HasPrefix(aid, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(aid, prefix)
		if (suffix == string(harness.Halmos) ||
			suffix == string(harness.ForgeFuzz) ||
			suffix == string(harness.MiniCertora)) &&
			!containsStrCLI(kinds, suffix) {
			kinds = append(kinds, suffix)
		}
	}
	switch len(kinds) {
	case 1:
		return harness.Kind(kinds[0]), nil
	case 0:
		return "", t14ExitErr(2, "verify: no harness scaffold for %s "+
			"(scaffold it first with verify --scaffold "+
			"{halmos|forge-fuzz|minicertora} --invariant %s, or pass "+
			"--kind)\n",
			validation.PyReprStr(invID), validation.PyReprStr(invID))
	default:
		return "", t14ExitErr(2, "verify: %s has multiple harness "+
			"scaffolds; pass --kind {halmos|forge-fuzz|minicertora}\n",
			validation.PyReprStr(invID))
	}
}

// linksThenLog is the cli-side FORWARDING door onto the one implementation of
// the r20 F3 law for the INVARIANT_LINKS surface, invariants.LinksThenLog
// (r42 P3-b): the rung is campaign STATE (artifacts/invariant_links.json)
// exactly like a finding file is — a save that lands while its event is
// refused leaves the ledger asserting a verification nobody logged, and the
// half-landed rung is invisible to audit. The law's discipline (snapshot the
// file pre-write, hold the campaign process lock across the
// snapshot→save→log→restore window — the r21 F9 reason — and restore
// together on refusal) lives in the invariants package now. This name stays
// because this file's harness rungs and cmd_verify_autoprove.go's rung call
// it; it must remain a forwarder, never a second copy of the body.
func linksThenLog(c *state.Campaign, save func() error, log func() error) error {
	return invariants.LinksThenLog(c, save, log)
}

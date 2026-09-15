package probes

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"websec/internal/state"
	"websec/internal/validation"
)

// BlankReasonMin is BLANK_REASON_MIN.
const BlankReasonMin = 10

// surfaceAxis is _surface_axis.
func surfaceAxis(surface validation.Value, axisName string) *validation.Value {
	// Return the matching (filtered) element itself. Indexing the RAW list
	// with a filtered-list index would return the wrong axis whenever a
	// non-object precedes the match.
	for _, a := range vObjList(surface, "axes") {
		if vStr(a, "axis") == axisName {
			matched := a
			return &matched
		}
	}
	return nil
}

// axisBlindKeys is _axis_blind_keys.
func axisBlindKeys(surface validation.Value, axisName string) []string {
	out := []string{}
	ax := surfaceAxis(surface, axisName)
	if ax == nil {
		return out
	}
	for _, b := range vList(*ax, "blind") {
		if b.Kind == validation.Obj {
			out = append(out, vStr(b, "key"))
		}
	}
	return out
}

// resolveLensAxis is _resolve_lens_axis: a lens spelling is resolved by the
// CITED KEY.
func resolveLensAxis(surface validation.Value, scope *AxisScope,
	anchorBlind string) (AxisMeta, error) {
	reg := RegisteredAxes()
	hits := []string{}
	for _, name := range scope.Axes {
		if containsStr(axisBlindKeys(surface, name), anchorBlind) {
			hits = append(hits, name)
		}
	}
	if len(hits) == 1 {
		return reg[hits[0]], nil
	}
	if len(hits) > 0 {
		return AxisMeta{}, errf("%s is the LENS of %d probes and %s is "+
			"published by more than one of them (%s) — name the probe's axis",
			validation.PyReprStr(scope.Token), len(scope.Axes),
			validation.PyReprStr(anchorBlind), strings.Join(hits, ", "))
	}
	published := map[string]struct{}{}
	for _, name := range scope.Axes {
		for _, k := range axisBlindKeys(surface, name) {
			published[k] = struct{}{}
		}
	}
	return AxisMeta{}, errf("blank attestation cites %s, which no axis on %s "+
		"published; the lens's blind[] keys are %s",
		validation.PyReprStr(anchorBlind), validation.PyReprStr(scope.Token),
		validation.PyRepr(strArr(sortedStrSet(published))))
}

// blankReplaces is _blank_replaces: which prior attestation this one
// supersedes. Only the SAME probe axis.
func blankReplaces(entry validation.Value, resolved AxisMeta) bool {
	if pa := vStr(entry, "probe_axis"); pa != "" {
		return pa == resolved.Axis
	}
	if vStr(entry, "axis") != resolved.Lens {
		return false
	}
	scope := AxisScopeOf(resolved.Lens)
	return scope != nil && len(scope.Axes) == 1 && scope.Axes[0] == resolved.Axis
}

// SetBlank is set_blank: record (or replace) the blank attestation for one
// probe axis. Fail-loud on every way the decision could be unfalsifiable.
func SetBlank(c *state.Campaign, axis, anchorBlind, reason,
	actor string) (validation.Value, error) {
	reg := RegisteredAxes()
	resolved := ResolveAxis(axis)
	if resolved == nil {
		lenses := map[string]struct{}{}
		for _, meta := range reg {
			lenses[meta.Lens] = struct{}{}
		}
		return validation.VNull(), errf("unknown probe axis %s; registered: "+
			"%s (or their lens ids %s)", validation.PyReprStr(axis),
			strings.Join(sortedKeys(reg), ", "),
			strings.Join(sortedStrSet(lenses), ", "))
	}
	if strings.TrimSpace(actor) == "" {
		return validation.VNull(), errf("a blank attestation must name its " +
			"actor (who decided the probe saw nothing)")
	}
	// Count characters, not bytes (matches the complete-reason check): a
	// multibyte reason is >= N chars even when it is < N bytes.
	if utf8.RuneCountInString(strings.TrimSpace(reason)) < BlankReasonMin {
		return validation.VNull(), errf("a blank attestation requires a "+
			"written reason (>= %d chars): the point is the audit trail, not "+
			"the shrug", BlankReasonMin)
	}
	if strings.TrimSpace(anchorBlind) == "" {
		return validation.VNull(), errf("a blank attestation must cite one of " +
			"the probe's published blind[] keys (--anchor-blind)")
	}
	surface, err := CampaignSurface(c)
	if err != nil {
		return validation.VNull(), err
	}
	if surface == nil {
		return validation.VNull(), errf("no probe surface for %s — run "+
			"`webv2 probes %s run` first", c.CampaignID, c.CampaignID)
	}
	scope := AxisScopeOf(axis)
	if scope == nil {
		scope = &AxisScope{Token: axis, Lens: resolved.Lens,
			Axes: []string{resolved.Axis}}
	}
	if len(scope.Axes) > 1 {
		meta, err := resolveLensAxis(*surface, scope, anchorBlind)
		if err != nil {
			return validation.VNull(), err
		}
		resolved = &meta
	}
	ax := surfaceAxis(*surface, resolved.Axis)
	if ax == nil {
		return validation.VNull(), errf("the probe surface does not carry "+
			"axis %s (%s) — re-run `webv2 probes %s run`", resolved.Axis,
			resolved.Lens, c.CampaignID)
	}
	if vStr(*ax, "status") != "blind" {
		return validation.VNull(), errf("axis %s (%s) is not blind (status "+
			"%s) — a blank attestation says the probe rejected every site it "+
			"saw, but this axis has %d row(s) to work", resolved.Axis,
			resolved.Lens, validation.PyReprStr(vStr(*ax, "status")),
			vInt(*ax, "rows"))
	}
	keys := axisBlindKeys(*surface, resolved.Axis)
	if !containsStr(keys, anchorBlind) {
		return validation.VNull(), errf("blank attestation cites %s, which "+
			"is not in %s's published blind[] keys: %s",
			validation.PyReprStr(anchorBlind), resolved.Axis,
			validation.PyRepr(strArr(sortedStrings(keys))))
	}
	entry := validation.VObj(
		kv("axis", validation.VStr(resolved.Lens)),
		kv("probe_axis", validation.VStr(resolved.Axis)),
		kv("anchor_blind", validation.VStr(anchorBlind)),
		kv("reason", validation.VStr(strings.TrimSpace(reason))),
		kv("actor", validation.VStr(strings.TrimSpace(actor))),
		kv("at", validation.VStr(state.NowIso())),
	)
	// r14: load->save of probe_blanks is one read-modify-write unit; the
	// campaign lock spans the window (depth re-entry via SaveState).
	if err := c.LockProcess(); err != nil {
		return validation.VNull(), err
	}
	defer c.UnlockProcess()
	// r40e: the attestation lives in campaign_state (probe_blanks), and the
	// audit re-derives it from the ledger — blankProblems red-lines an
	// attested axis with no probes.blank event as "hand-edited". So the
	// pre-write state bytes are the snapshot of the r16 unwind law, taken
	// BEFORE the load-modify-write, and a refused probes.blank append puts
	// them back (state.RawState/UnwindState are the exported seam for
	// packages that compose a state write with their own Log).
	prevRaw, hadRaw := c.RawState()
	st, err := c.State()
	if err != nil {
		return validation.VNull(), err
	}
	prior := vObjList(st, "probe_blanks")
	kept := []validation.Value{}
	for _, e := range prior {
		if !blankReplaces(e, *resolved) {
			kept = append(kept, e)
		}
	}
	replaced := len(kept) != len(prior)
	kept = append(kept, entry)
	vSet(&st, "probe_blanks", validation.VArr(kept...))
	if err := saveStateFunc(c, st); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(
		kv("axis", validation.VStr(resolved.Axis)),
		kv("probe", validation.VStr(resolved.Probe)),
		kv("probe_axis", validation.VStr(resolved.Axis)),
		kv("anchor_blind", vGet(entry, "anchor_blind")),
		kv("actor", vGet(entry, "actor")),
		kv("reason", vGet(entry, "reason")),
		kv("replaced", validation.VBool(replaced)),
	)
	ref := resolved.Lens
	if _, err := c.Log("probes.blank", &ref, &data); err != nil {
		// r40e: the ledger refused — UNWIND the state write (the r16 law,
		// via the exported seam): an attestation the log never recorded is
		// exactly what the surface audit reads as a hand-edited blank.
		if uerr := c.UnwindState(prevRaw, hadRaw); uerr != nil {
			return validation.VNull(), fmt.Errorf("%w (UNWIND ALSO FAILED: "+
				"%v — campaign_state still holds a probe_blanks attestation "+
				"with no probes.blank event; repair by hand before "+
				"continuing)", err, uerr)
		}
		return validation.VNull(), err
	}
	return entry, nil
}

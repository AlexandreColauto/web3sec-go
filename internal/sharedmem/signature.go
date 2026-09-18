// Capability signature derivation (pure): from the explicit capability
// lists of a finding/chain.

package sharedmem

import (
	"sort"
	"strings"

	"websec/internal/capabilities"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- signature derivation (pure) -------------------------------------------

// terminalOf is _terminal_of: the first sorted granted terminal capability.
func terminalOf(granted []string) *string {
	sorted := append([]string{}, granted...)
	sort.Strings(sorted)
	for _, cap := range sorted {
		if capabilities.IsTerminal(cap) {
			return &cap
		}
	}
	return nil
}

// CodeSourced is code_sourced: the union of granted labels over every live
// finding in the campaign.
func CodeSourced(c *state.Campaign) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return nil, err
	}
	for _, f := range all {
		if s := validation.ObjStr(f, "status"); s == "DUPLICATE" || s == "OUT_OF_SCOPE" {
			continue
		}
		for _, lab := range capabilities.Granted(f) {
			out[lab] = struct{}{}
		}
	}
	return out, nil
}

// DeriveSignature is derive_signature: the capability-level signature of a
// finding/chain, from the EXPLICIT capability lists only.
func DeriveSignature(f validation.Value, key string, program validation.Value,
	campaignID string, codeSourced map[string]struct{}) validation.Value {
	caps := validation.ObjAt(f, "capabilities")
	if caps.Kind != validation.Obj {
		caps = validation.VObj()
	}
	granted := sortedStrings(capabilities.NormalizeLabels(
		strList(validation.ObjAt(caps, "granted"))))
	required := sortedStrings(capabilities.NormalizeLabels(
		strList(validation.ObjAt(caps, "required"))))
	codeSourcedRequired := []string{}
	for _, r := range required {
		if _, ok := codeSourced[r]; ok {
			codeSourcedRequired = append(codeSourcedRequired, r)
		}
	}
	terminal := terminalOf(granted)
	terminalStr := ""
	if terminal != nil {
		terminalStr = *terminal
	}
	csig := findings.TextSignature("sig|" + key + "|" + strings.Join(granted, ",") +
		"|" + strings.Join(required, ",") + "|" + terminalStr)
	class := "unknown"
	if rc := validation.ObjAt(f, "root_cause"); rc.Kind == validation.Obj {
		if c := validation.ObjStr(rc, "class"); c != "" {
			class = c
		}
	}
	return validation.VObj(
		kv("program_key", validation.VStr(key)),
		kv("program", program),
		kv("bug_class", validation.VStr(class)),
		kv("granted", validation.StrArr(granted)),
		kv("required", validation.StrArr(required)),
		kv("code_sourced_required", validation.StrArr(codeSourcedRequired)),
		kv("terminal", strOrNull(terminal)),
		kv("capability_signature", validation.VStr(csig)),
		kv("title", validation.ObjAt(f, "title")),
		kv("source", validation.VObj(
			kv("campaign_id", validation.VStr(campaignID)),
			kv("finding_id", validation.VStr(validation.ObjStr(f, "finding_id"))))))
}

// sigKey is _sig_key.
func sigKey(sig validation.Value) string {
	src := validation.ObjAt(sig, "source")
	return validation.ObjStr(sig, "program_key") + "\x00" +
		validation.ObjStr(sig, "capability_signature") + "\x00" +
		validation.ObjStr(src, "campaign_id") + "\x00" + validation.ObjStr(src, "finding_id")
}

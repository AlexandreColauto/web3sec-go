package defihacklabs

import (
	"fmt"
	"sort"
	"strings"

	"websec/internal/validation"
)

// lossText is _loss_text: Lost is a magnitude, never a severity.
func lossText(incident validation.Value) string {
	lost := at(incident, "Lost")
	lossType := pyStrOrEmpty(at(incident, "lossType"))
	if lossType == "" {
		lossType = "unknown units"
	}
	if lost.Kind == validation.Bool || lost.Kind == validation.Null {
		return "unknown loss (" + lossType + ")"
	}
	return validation.PyStr(lost) + " " + lossType
}

// rcaProse is `str(rca.get("rootCause") or "").strip()`.
func rcaProse(rca *validation.Value) string {
	if rca == nil {
		return ""
	}
	return pyStrip(pyStrOrEmpty(at(*rca, "rootCause")))
}

// ComposeDescription is compose_description: the 20-10000 char description —
// RCA prose, else fallback composed from name+type+chain+date+loss.
func ComposeDescription(incident validation.Value, rca *validation.Value) string {
	prose := rcaProse(rca)
	if runeLen(prose) >= 20 {
		return ClipText(prose, DescriptionMax)
	}
	name := pyStrOrEmpty(at(incident, "name"))
	if name == "" {
		name = "Unknown protocol"
	}
	inctype := pyStrOrEmpty(at(incident, "type"))
	if inctype == "" {
		inctype = "an unspecified vulnerability"
	}
	chain := "an unknown chain"
	if c := NormalizeChain(at(incident, "chain")); c != nil {
		chain = *c
	}
	date := pyStrOrEmpty(at(incident, "date"))
	if date == "" {
		date = "an unknown date"
	}
	text := fmt.Sprintf("%s (%s, %s) was exploited via %s. "+
		"Reported loss: %s.", name, date, chain, inctype, lossText(incident))
	for runeLen(text) < 20 {
		text += " The incident was confirmed as an on-chain exploit."
	}
	return ClipText(text, DescriptionMax)
}

// ComposeRootCause is compose_root_cause: the 10-2000 char root cause (brief
// pin, recon §9). RCA prose, sentence/paragraph-clipped to 2000 (126 records
// exceed it); else the RCA type label when it fits; else a composed
// name+type sentence (a bare "unavailable" would violate the schema minimum).
func ComposeRootCause(incident validation.Value, rca *validation.Value) string {
	prose := rcaProse(rca)
	if runeLen(prose) >= RootCauseMin {
		return ClipText(prose, RootCauseMax)
	}
	if rca != nil {
		label := pyStrip(pyStrOrEmpty(at(*rca, "type")))
		if n := runeLen(label); n >= RootCauseMin && n <= RootCauseMax {
			return label
		}
	}
	name := pyStrOrEmpty(at(incident, "name"))
	if name == "" {
		name = "Unknown protocol"
	}
	inctype := pyStrOrEmpty(at(incident, "type"))
	if inctype == "" {
		inctype = "an unspecified vulnerability"
	}
	date := pyStrOrEmpty(at(incident, "date"))
	if date == "" {
		date = "an unknown date"
	}
	text := fmt.Sprintf("%s (%s) was exploited via %s.", name, date, inctype)
	for runeLen(text) < RootCauseMin {
		text += " Loss of funds was confirmed on-chain."
	}
	return ClipText(text, RootCauseMax)
}

// ComposePattern is compose_pattern: the prior pattern as stable-joined atomic
// type labels. RCA type is comma-joined multi-label — split into atoms;
// without RCA the incident type is the single atom. Sorted unique join on
// "; " (stable regardless of source order). Short joins are extended with the
// incident identity so the memory schema's 15-char minimum always holds; long
// joins clip at an atom boundary to 500.
func ComposePattern(incident validation.Value, rca *validation.Value) string {
	pattern := strings.Join(dedupeSorted(patternAtoms(incident, rca)), "; ")
	if runeLen(pattern) < 15 {
		pattern = widenPattern(pattern, incident)
	}
	if runeLen(pattern) > 500 {
		pattern = clampPattern(pattern)
	}
	for runeLen(pattern) < 15 {
		pattern += " exploit pattern"
	}
	return pattern
}

// patternAtoms is compose_pattern's label source: the RCA type list, else the
// incident type, else "unknown".
func patternAtoms(incident validation.Value, rca *validation.Value) []string {
	var atoms []string
	if rca != nil {
		for _, a := range strings.Split(pyStrOrEmpty(at(*rca, "type")), ",") {
			if a = pyStrip(a); a != "" {
				atoms = append(atoms, a)
			}
		}
	}
	if len(atoms) == 0 {
		t := pyStrip(pyStrOrEmpty(at(incident, "type")))
		if t == "" {
			t = "unknown"
		}
		atoms = []string{t}
	}
	return atoms
}

// dedupeSorted is compose_pattern's case-insensitive first-wins dedupe, sorted
// by the lowercased key.
func dedupeSorted(atoms []string) []string {
	seen := map[string]string{}
	for _, atom := range atoms {
		key := strings.ToLower(atom)
		if _, ok := seen[key]; !ok {
			seen[key] = atom
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, seen[k])
	}
	return parts
}

// widenPattern is compose_pattern's <15-char widening.
func widenPattern(pattern string, incident validation.Value) string {
	name := pyStrOrEmpty(at(incident, "name"))
	if name == "" {
		name = "unknown protocol"
	}
	inctype := pyStrOrEmpty(at(incident, "type"))
	if inctype == "" {
		inctype = "unspecified vulnerability"
	}
	date := pyStrOrEmpty(at(incident, "date"))
	if date == "" {
		date = "undated"
	}
	return fmt.Sprintf("%s; %s (%s) %s exploit pattern", pattern, name, date,
		inctype)
}

// clampPattern is compose_pattern's >500-char atom-aware clamp.
func clampPattern(pattern string) string {
	parts := strings.Split(pattern, "; ")
	var kept []string
	total := 0
	for _, part := range parts {
		add := runeLen(part)
		if len(kept) > 0 {
			add += 2
		}
		if len(kept) > 0 && total+add > 497 {
			break
		}
		kept = append(kept, part)
		total += add
	}
	if len(kept) > 0 {
		pattern = strings.Join(kept, "; ")
	} else {
		pattern = runeSlice(parts[0], 0, 500)
	}
	if runeLen(pattern) > 500 {
		pattern = runeSlice(pattern, 0, 500)
	}
	return pattern
}

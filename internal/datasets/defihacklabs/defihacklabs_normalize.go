package defihacklabs

import (
	"strings"

	"websec/internal/validation"
)

// NormalizeName is normalize_name: lowercase + strip non-alphanumerics (recon
// §10.4 name chaos). "Hundred Finance" and "HundredFinance" (and "Paribus" /
// "Paribus_") are one key — which is exactly why RCA collision groups exist
// and why incident id slugs need the chain/type fallback.
func NormalizeName(name validation.Value) string {
	return nonAlnumRe.ReplaceAllString(strings.ToLower(pyStrOrEmpty(name)), "")
}

// NormalizeChain is normalize_chain: the noisy single-chain string to a
// display name. nil for raw chain ids, nulls, and the non-chain markers —
// the caller then emits platform=None + chains=[] (brief pin). Unknown-but-
// plausible names pass through stripped (never invent a mapping for a chain we
// have not seen).
func NormalizeChain(chain validation.Value) *string {
	if chain.Kind != validation.Str {
		return nil
	}
	text := pyStrip(chain.S)
	key := strings.ToLower(text)
	if noChain[key] || allDigitsRe.MatchString(key) {
		return nil
	}
	if v, ok := chainAliases[key]; ok {
		return &v
	}
	return &text
}

// ExtractPocLink is extract_poclink: split an RCA pocLink blob URL into
// (url, path, commit). The #L… line fragment is stripped (3 records carry
// one); commit is set only for a 40-hex pinned ref (24 records) — blob/main
// links carry no commit. Returns (nil, nil, nil) for empty input.
func ExtractPocLink(url validation.Value) (u, path, commit *string) {
	raw := pyStrip(pyStrOrEmpty(url))
	if raw == "" {
		return nil, nil, nil
	}
	urlClean := raw
	if i := strings.Index(urlClean, "#"); i >= 0 {
		urlClean = urlClean[:i]
	}
	m := pocLinkRefRe.FindStringSubmatch(urlClean)
	if m == nil {
		return &urlClean, nil, nil
	}
	ref, p := m[1], m[2]
	if fullSHARe.MatchString(ref) {
		return &urlClean, &p, &ref
	}
	return &urlClean, &p, nil
}

// ClipText is clip_text: truncate to limit chars at a paragraph/sentence
// boundary. Deterministic rule: hard-cut at limit, then back off to the last
// blank line, newline, sentence end, clause break, or word break — whichever
// is latest but keeps at least 10 chars (so the root-cause minimum survives
// clipping). A single over-long token with no break is hard-cut.
func ClipText(text string, limit int) string {
	text = pyStrip(text)
	if runeLen(text) <= limit {
		return text
	}
	cut := runeSlice(text, 0, limit)
	for _, sep := range []string{"\n\n", "\n", ". ", "; ", " "} {
		idx := lastIndexRunes(cut, sep)
		if idx < 10 {
			continue
		}
		end := idx
		if sep == ". " {
			end = idx + 1
		}
		clipped := pyStrip(runeSlice(cut, 0, end))
		if runeLen(clipped) >= 10 {
			return clipped
		}
	}
	return pyStrip(cut)
}

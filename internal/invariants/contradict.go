// Invariant contradiction — contradict_invariant_statement and invariant-ID normalization (split from invariants.go; pure structural move).

package invariants

import (
	"strconv"
	"strings"
	"unicode"

	"websec/internal/state"
	"websec/internal/validation"
)

// ContradictInvariantStatement is contradict_invariant_statement:
// CONTRADICTED with an evidence anchor (file#Lline or a registered artifact
// id). A finding that depends on a contradicted model invariant cannot
// advance.
func ContradictInvariantStatement(c *state.Campaign, invariantID,
	evidenceRef string) (validation.Value, error) {
	links, err := LoadLinks(c)
	if err != nil {
		return validation.VNull(), err
	}
	reg := regOf(links)
	if !validation.HasKey(reg, invariantID) {
		return validation.VNull(), unknownInvariant(invariantID)
	}
	entry := validation.ObjAt(reg, invariantID)
	entry.O = validation.SetOrAppend(entry.O, "status", validation.VStr("CONTRADICTED"))
	entry.O = validation.SetOrAppend(entry.O, "contradiction", validation.VStr(evidenceRef))
	entry.O = popKey(entry.O, "verified_by")
	entry.O = validation.SetOrAppend(entry.O, "modified_by", validation.VStr(state.NowIso()))
	entry.O = validation.SetOrAppend(entry.O, "updated_at", validation.VStr(state.NowIso()))
	reg.O = validation.SetOrAppend(reg.O, invariantID, entry)
	links = setObjKey(links, "invariants", reg)
	data := validation.VObj(pair("evidence", validation.VStr(evidenceRef)))
	// r40: a CONTRADICTED entry without its event blocks dependent
	// findings on state the ledger never recorded. Unwind on refusal.
	if err := LinksThenLog(c, func() error {
		_, serr := SaveLinks(c, links)
		return serr
	}, func() error {
		_, lerr := c.Log("invariant.contradicted", &invariantID, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return entry, nil
}

// ---- ids -----------------------------------------------------------------

// NormalizeInvID is normalize_inv_id: “INV-001“ → “INV-1“. Non-matching
// ids pass through unchanged. CPython's “\d“ and “$“ semantics are kept:
// Unicode decimal digits count, and one trailing newline still matches.
func NormalizeInvID(iid string) string {
	if !strings.HasPrefix(iid, "INV-") {
		return iid
	}
	body := iid[4:]
	if strings.HasSuffix(body, "\n") {
		body = body[:len(body)-1]
	}
	digits, ok := ndDigits(body)
	if !ok {
		return iid
	}
	trimmed := strings.TrimLeft(digits, "0")
	if trimmed == "" {
		trimmed = "0"
	}
	return "INV-" + trimmed
}

// ndDigits maps a non-empty run of Unicode decimal digits to its ASCII
// decimal text (Python int() accepts any Nd digit).
func ndDigits(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	var b strings.Builder
	for _, r := range s {
		d, ok := ndDigit(r)
		if !ok {
			return "", false
		}
		b.WriteByte(byte('0' + d))
	}
	return b.String(), true
}

// ndDigit is the decimal value of an Nd rune. Every unicode.Nd range is a
// stride-1 run of ten digits (verified against CPython's unicodedata), so
// (r - Lo) % 10 is the digit.
func ndDigit(r rune) (int, bool) {
	if r >= '0' && r <= '9' {
		return int(r - '0'), true
	}
	if !unicode.IsDigit(r) {
		return 0, false
	}
	for _, x := range unicode.Nd.R16 {
		if r >= rune(x.Lo) && r <= rune(x.Hi) {
			return int(r-rune(x.Lo)) % 10, true
		}
	}
	for _, x := range unicode.Nd.R32 {
		if r >= rune(x.Lo) && r <= rune(x.Hi) {
			return int(r-rune(x.Lo)) % 10, true
		}
	}
	return 0, false
}

// pyIntText is int(text) for a run of Unicode decimal digits (Python's
// `k[4:].isdigit()` then `int(...)` in seed_from_model).
func pyIntText(text string) (int, bool) {
	digits, ok := ndDigits(text)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(digits)
	if err != nil {
		return 0, false
	}
	return n, true
}

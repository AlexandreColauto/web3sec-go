// signatures.go: technical_signature / text_signature — the deterministic
// 16-hex dedup keys (webv2.findings).
package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"websec/internal/validation"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// pyLower is Python's str.lower(): the FULL Unicode case mapping, including
// U+0130 -> "i"+U+0307 and the Greek Final_Sigma rule ("ΑΣ" -> "ας").
// strings.ToLower is only the simple per-rune mapping and diverges on those
// characters, which would break the byte-exact signature contract. x/text
// was already an indirect dependency (jsonschema/v6); this promotes it to a
// direct one. Caser is safe for concurrent use.
var pyLower = cases.Lower(language.Und)

// TechnicalSignature is technical_signature: the deterministic 16-hex dedup
// key for a (bug class, path, function, invariant) tuple. The raw is
// "class|path|function|invariant" with each part stripped and lowercased
// (function/invariant empty when nil/empty, as Python's `or ”`), then
// sha256 hexdigest truncated to the first 16 hex chars. Byte-exact
// contract.
func TechnicalSignature(bugClass, path, function, invariantID string) string {
	raw := bugClass + "|" +
		pyStripLower(path) + "|" +
		pyStripLower(function) + "|" +
		pyStripLower(invariantID)
	return signatureHex16(raw)
}

// TextSignature is text_signature: the 16-hex sha256 of the whitespace-
// normalized text (" ".join(text.strip().lower().split())).
func TextSignature(text string) string {
	normalized := strings.Join(pyFields(pyLower.String(validation.PyStrip(text))), " ")
	return signatureHex16(normalized)
}

// pyStripLower is (s or "").strip().lower().
func pyStripLower(s string) string {
	return pyLower.String(validation.PyStrip(s))
}

// pyStrip is Python's str.strip() with no argument: trim str.isspace()
// characters from both ends.

// pyFields is Python's str.split() with no argument: split on runs of
// str.isspace() characters, dropping empty fields.
func pyFields(s string) []string {
	return strings.FieldsFunc(s, validation.PyIsSpace)
}

// pySpace is Py_UNICODE_ISSPACE: the Unicode White_Space property plus the
// ASCII file separators U+001C-U+001F (Python's str.isspace() says true
// there, unicode.IsSpace does not).

// signatureHex16 is sha256(data).hexdigest()[:16].
func signatureHex16(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:8])
}

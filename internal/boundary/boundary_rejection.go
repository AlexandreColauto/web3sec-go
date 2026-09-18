package boundary

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"websec/internal/state"
	"websec/internal/validation"
)

// RecordRejection is record_rejection: log a rejected generation as a
// first-class event and return the re-request message. The payload is
// recorded by hash only.
func RecordRejection(campaign *state.Campaign, role, kind string,
	payload validation.Value, err error) (string, error) {
	blob := validation.CanonSpaced(payload)
	data := validation.VObj(
		validation.KV{K: "role", V: validation.VStr(role)},
		validation.KV{K: "kind", V: validation.VStr(kind)},
		validation.KV{K: "error", V: validation.VStr(pyTrunc(err.Error(), 1000))},
		validation.KV{K: "payload_sha256", V: validation.VStr(sha256Hex(blob))},
		validation.KV{K: "action", V: validation.VStr(
			"re-request against the response contract; do not coerce")})
	if _, logErr := campaign.Log("model.rejected", nil, &data); logErr != nil {
		return "", logErr
	}
	return fmt.Sprintf("REJECTED (%s/%s): %s — re-request against "+
		"model_response.schema.json#definitions/%s", role, kind,
		pyTrunc(err.Error(), 300), kind), nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

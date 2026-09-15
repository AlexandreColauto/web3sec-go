// Section 1: event_log — sequence contiguity + hash chain + state tail.
// Delegates the whole verdict to campaign.verify_log (Task 7), surfaced
// message-for-message with the exact verify_log dict keys.
package sections

import (
	"websec/internal/state"
	"websec/internal/validation"
)

// EventLog is audit.py section 1: report["sections"]["event_log"] =
// campaign.verify_log().
//
// r42c P3: the delegation is the point, not a shortcut — the section owns no
// second copy of any ledger law. A torn tail (events.jsonl whose last byte
// is not a newline, the shape the write path's framing guard refuses) is
// therefore reported here as ok:false with the tail problem in `problems`,
// and the audit can no longer say PASS over a ledger its own writer calls
// unusable. Judging the tail here as well would be two implementations of
// one law, which is exactly how verify and audit would drift apart again.
func EventLog(c *state.Campaign) (validation.Value, error) {
	v, err := c.VerifyLog()
	if err != nil {
		return validation.Value{}, err
	}
	problems := make([]validation.Value, len(v.Problems))
	for i, p := range v.Problems {
		problems[i] = validation.VStr(p)
	}
	return validation.VObj(
		validation.KV{K: "events", V: validation.VInt(int64(v.Events))},
		validation.KV{K: "ok", V: validation.VBool(v.OK)},
		validation.KV{K: "problems", V: validation.VArr(problems...)},
		validation.KV{K: "chained", V: validation.VInt(int64(v.Chained))},
		validation.KV{K: "legacy_unchained", V: validation.VInt(int64(v.LegacyUnchained))},
		validation.KV{K: "malformed_lines", V: validation.VInt(int64(v.MalformedLines))},
	), nil
}

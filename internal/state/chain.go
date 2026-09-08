package state

import (
	"websec/internal/validation"
)

// GenesisHash anchors the first chained event (64 zeros).
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// eventHash is _event_hash: the canonical sha256 over every event field
// except event_hash itself. json.dumps(sort_keys=True, ensure_ascii=True)
// with default (spaced) separators; ASCII output makes the hash
// independent of non-ASCII line separators (U+2028 et al.) in
// attacker-controlled payloads, so log content can never alias or
// corrupt the chain.
func eventHash(event validation.Value) string {
	body := pickEventBody(event)
	return validation.Sha256Hex([]byte(validation.CanonSpaced(body)))
}

// legacyAnchor is _legacy_anchor: unchained legacy events are counted,
// and the chain anchors at the first chained event.
func legacyAnchor(last validation.Value) string {
	seq := "None"
	for _, kv := range last.O {
		if kv.K == "seq" {
			seq = validation.CanonCompact(kv.V)
			break
		}
	}
	return "legacy-seq-" + seq
}

// pickEventBody extracts the six hashed fields in schema order.
func pickEventBody(ev validation.Value) validation.Value {
	var kvs []validation.KV
	for _, k := range []string{"seq", "at", "type", "ref", "data", "prev_hash"} {
		var v validation.Value
		for _, kv := range ev.O {
			if kv.K == k {
				v = kv.V
				break
			}
		}
		if v.Kind == 0 {
			v = validation.VNull()
		}
		kvs = append(kvs, kv(k, v))
	}
	return validation.VObj(kvs...)
}

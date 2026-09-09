package probes

import (
	"websec/internal/validation"
)

// AxisSurfaceBlocker is axis_surface_blocker: the four-state surface closure.
// "" = no surface-level blocker (the emitted rows still have to be
// dispositioned by the caller); a string is the reason the axis may not close.
func AxisSurfaceBlocker(axis validation.Value, blank *validation.Value) string {
	// The seam contract is "nil when no attestation was persisted", but a
	// caller reading a Go map directly hands us a pointer to the zero Value for
	// a missing key. Python's `(blanks or {}).get(ax)` yields None there, so
	// normalize anything that is not an object back to "no attestation" — a
	// persisted attestation is always an object.
	if blank != nil && blank.Kind != validation.Obj {
		blank = nil
	}
	status := vStr(axis, "status")
	switch status {
	case "no-sites":
		return ""
	case "blind":
		if blank == nil {
			return sprintf("%s saw %d sites and rejected every one of them "+
				"(%d blind keys published) — close it with `webv2 probes blank "+
				"--axis %s --anchor-blind <key> --reason R --actor A`",
				vStr(axis, "probe"), vInt(axis, "sites"),
				len(vList(axis, "blind")), vStr(axis, "lens"))
		}
		keys := map[string]struct{}{}
		for _, b := range vList(axis, "blind") {
			keys[vStr(b, "key")] = struct{}{}
		}
		cited := vStr(*blank, "anchor_blind")
		if _, ok := keys[cited]; !ok {
			return sprintf("blank attestation cites %s, which is not in the "+
				"probe's blind[] keys: %s", validation.PyReprStr(cited),
				validation.PyRepr(strArr(sortedStrSet(keys))))
		}
		if !vTruthy(vGet(*blank, "reason")) || !vTruthy(vGet(*blank, "actor")) {
			return "blank attestation needs a written reason and an actor"
		}
		return ""
	case "under-filled":
		return sprintf("quota under-filled: %s produced %d rows, emitted %d — "+
			"raise --per-axis or disposition the tail", vStr(axis, "probe"),
			vInt(axis, "rows"), vInt(axis, "emitted"))
	}
	return ""
}

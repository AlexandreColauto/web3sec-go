// Section 8: floor policy — the projection (state['floor_policy']) must
// agree with the log. Each current entry needs the LAST floor_policy.set
// event for its class with a matching floor; a cleared class must be gone.
// A hand-edited policy is caught exactly like a hand-edited artifact hash —
// the override is data, and data is audited. Message-for-message with
// audit.py section 8, including the three distinct problem formats and the
// unconditional emission ('checked': len(pol) + len(floor_events)).
package sections

import (
	"fmt"

	"websec/internal/state"
	"websec/internal/validation"
)

// FloorPolicy is audit.py section 8: {checked, problems, ok}.
func FloorPolicy(c *state.Campaign) (validation.Value, error) {
	events, err := c.Events()
	if err != nil {
		return validation.Value{}, err
	}
	st, err := c.State()
	if err != nil {
		return validation.Value{}, err
	}
	pol := listOf(validation.ObjAt(st, "floor_policy"))
	var floorEvents []validation.Value
	for _, e := range events {
		switch validation.ObjStr(e, "type") {
		case "floor_policy.set", "floor_policy.cleared":
			floorEvents = append(floorEvents, e)
		}
	}
	var problems []validation.Value
	if len(pol) > 0 || len(floorEvents) > 0 {
		problems = floorPolicyProblems(pol, events)
	}
	return validation.VObj(
		KV("checked", validation.VInt(int64(len(pol)+len(floorEvents)))),
		KV("problems", validation.VArr(problems...)),
		KV("ok", validation.VBool(len(problems) == 0)),
	), nil
}

// floorPolicyProblems is the guarded body of section 8: replay the log into
// the current policy, then reconcile it against the projection in both
// directions.
func floorPolicyProblems(pol, events []validation.Value) []validation.Value {
	cur := newFloorCurrent()
	for _, e := range events { // log order = decision order
		switch validation.ObjStr(e, "type") {
		case "floor_policy.set":
			cur.set(validation.ObjAt(e, "ref"), validation.ObjAt(e, "data"))
		case "floor_policy.cleared":
			cur.clear(validation.ObjAt(e, "ref"))
		}
	}
	var problems []validation.Value
	for _, entry := range pol {
		cls := validation.ObjAt(entry, "class")
		d, ok := cur.get(cls)
		if !ok {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"floor_policy lists class %s (floor %s) with no "+
					"floor_policy.set event — the policy was hand-edited",
				validation.PyRepr(cls), pyStrValue(validation.ObjAt(entry, "floor")))))
			continue
		}
		if !pyEqual(validation.ObjAt(d, "floor"), validation.ObjAt(entry, "floor")) {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"floor_policy for %s is %s but the log's last set says %s — "+
					"projection drifted from the log",
				validation.PyRepr(cls), pyStrValue(validation.ObjAt(entry, "floor")),
				validation.PyRepr(validation.ObjAt(d, "floor")))))
		}
		// r14: the level was policed but the ATTRIBUTION was not — the
		// floor law ("the decision is data, attributed, reasoned and
		// logged") is only enforceable if the audit checks the actor and
		// the reason too. An unflocked era let a racing set rewrite the
		// live row's reason while its event said another (the replay
		// matched on floor and stayed green): WHO decided and WHY is now
		// compared like the level is. (Divergence from the ported
		// section, same family as the projection un-gating — the twin
		// checked less.)
		for _, field := range []struct{ key, what string }{
			{"actor", "who decided"},
			{"reason", "the written reason"},
		} {
			if !pyEqual(validation.ObjAt(d, field.key), validation.ObjAt(entry, field.key)) {
				problems = append(problems, validation.VStr(fmt.Sprintf(
					"floor_policy for %s records %s=%s but the log's "+
						"last set says %s — %s drifted from the ledger",
					validation.PyRepr(cls), field.key,
					pyStrValue(validation.ObjAt(entry, field.key)),
					validation.PyRepr(validation.ObjAt(d, field.key)), field.what)))
			}
		}
	}
	for _, k := range cur.order {
		if !polHasClass(pol, cur.ref[k]) {
			problems = append(problems, validation.VStr(fmt.Sprintf(
				"log records floor_policy.set for %s but the state "+
					"projection has no entry for it",
				validation.PyRepr(cur.ref[k]))))
		}
	}
	return problems
}

// polHasClass is Python `any(e["class"] == cls for e in pol)`.
func polHasClass(pol []validation.Value, cls validation.Value) bool {
	for _, e := range pol {
		if pyEqual(validation.ObjAt(e, "class"), cls) {
			return true
		}
	}
	return false
}

// floorCurrent is Python's `current` dict: ordered keys (first assignment
// wins the position, as CPython dicts do) mapping the event ref to its data.
type floorCurrent struct {
	order []string
	ref   map[string]validation.Value
	val   map[string]validation.Value
}

// newFloorCurrent is the empty dict.
func newFloorCurrent() *floorCurrent {
	return &floorCurrent{
		ref: map[string]validation.Value{},
		val: map[string]validation.Value{},
	}
}

// set is current[e.get("ref")] = e.get("data") or {}.
func (f *floorCurrent) set(ref, data validation.Value) {
	k := refKeyOf(ref)
	if _, seen := f.ref[k]; !seen {
		f.order = append(f.order, k)
	}
	f.ref[k] = ref
	if validation.PyTruthy(data) {
		f.val[k] = data
	} else {
		f.val[k] = validation.VObj()
	}
}

// clear is current.pop(e.get("ref"), None).
func (f *floorCurrent) clear(ref validation.Value) {
	k := refKeyOf(ref)
	if _, seen := f.ref[k]; !seen {
		return
	}
	delete(f.ref, k)
	delete(f.val, k)
	for i, key := range f.order {
		if key == k {
			f.order = append(f.order[:i], f.order[i+1:]...)
			break
		}
	}
}

// get is current.get(cls): the last set event's data, or ok=false.
func (f *floorCurrent) get(cls validation.Value) (validation.Value, bool) {
	v, ok := f.val[refKeyOf(cls)]
	return v, ok
}

// refKeyOf is Python's dict-key identity for a decoded JSON value: strings
// by text, None by a null marker, and numbers/bools by exact rational value
// (Python hashes True == 1 == 1.0 to one key).
func refKeyOf(v validation.Value) string {
	switch v.Kind {
	case validation.Null:
		return "null:"
	case validation.Str:
		return "str:" + v.S
	case validation.Bool:
		if v.B {
			return "num:1"
		}
		return "num:0"
	case validation.Int, validation.Flt:
		return "num:" + ratOf(v).RatString()
	}
	return "json:" + validation.CanonCompact(v)
}

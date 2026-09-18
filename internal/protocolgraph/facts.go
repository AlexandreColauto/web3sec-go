// facts.go: I4 (Wave I Task 8) — operator-supplied DNS/dependency facts on
// protocol_model.components[].
//
// A fact is a HUMAN ASSERTION: it names the component it is about, says who
// supplied it, and carries the date the operator observed it. The framework
// never invents either half. In particular there is NO DNS RESOLUTION PATH
// anywhere in this task: the only place a DNS fact can enter the system is
// an operator-supplied operator_facts JSON document, and its observed_at —
// like a dependency fact's — is either written by the operator or passed in
// by the operator for an offline manifest extraction. Nothing here reads a
// clock, and nothing opens a socket.
package protocolgraph

import (
	"fmt"

	"websec/internal/validation"
)

// FactCounts is the tally the CLI prints after a merge: how many facts were
// applied, split by kind, and how many distinct components received one.
type FactCounts struct {
	Applied    int
	DNS        int
	Dependency int
	Components int
}

// LoadFacts reads and schema-validates an operator_facts document. The
// document is the DNS half of I4: no other input can carry a DNS fact.
func LoadFacts(path string) (validation.Value, error) {
	doc, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), err
	}
	if err := validation.Validate(doc, "operator_facts", 1); err != nil {
		return validation.VNull(), err
	}
	return doc, nil
}

// ApplyFacts is the locked I4 join: attach each fact's dns/dependency
// sub-object to the ONE component it targets, preserving component order and
// every other field byte-for-byte.
//
// The join key is (kind, url) when the fact targets a url, else (kind, path)
// — the same two identity fields the model already uses. The join is
// fail-closed: a fact matching ZERO components is an error (a typo must not
// be dropped), a fact matching TWO is an error (an ambiguous join is a data
// defect), and a second dns/dependency fact for one component is an error
// (never merge two assertions silently). Applying the same document twice is
// a no-op: the sub-object is replaced in place, not accumulated.
//
// The input model is not mutated; a merged copy is returned.
func ApplyFacts(model, facts validation.Value) (validation.Value, error) {
	out, _, err := ApplyFactsCounted(model, facts)
	return out, err
}

// applyFactsSlot is the per-component attachment being assembled for this call.
type applyFactsSlot struct {
	dns, dep       validation.Value
	hasDNS, hasDep bool
}

// applyFactsState carries the merge state ApplyFactsCounted accumulates as it
// walks the fact list.
type applyFactsState struct {
	counts FactCounts
	slots  map[int]*applyFactsSlot
	comps  validation.Value
}

// ApplyFactsCounted is ApplyFacts plus the tally the CLI's summary line
// needs (the counts cannot be recovered from the merged model alone).
func ApplyFactsCounted(model, facts validation.Value) (validation.Value,
	FactCounts, error) {
	var counts FactCounts
	if model.Kind != validation.Obj {
		return validation.VNull(), counts,
			fmt.Errorf("operator facts: model is not an object")
	}
	if facts.Kind != validation.Obj {
		return validation.VNull(), counts,
			fmt.Errorf("operator facts: document is not an object")
	}
	factList := validation.ObjAt(facts, "facts")
	if factList.Kind != validation.Arr {
		return validation.VNull(), counts,
			fmt.Errorf("operator facts: document carries no facts list")
	}
	st := &applyFactsState{
		slots: map[int]*applyFactsSlot{},
		comps: validation.ObjAt(model, "components"),
	}
	for _, f := range factList.A {
		if f.Kind != validation.Obj {
			return validation.VNull(), st.counts,
				fmt.Errorf("operator facts: fact is not an object")
		}
		kind, field, identity, err := st.applyFactsTarget(f)
		if err != nil {
			return validation.VNull(), st.counts, err
		}
		matched, err := st.applyFactsMatch(kind, field, identity)
		if err != nil {
			return validation.VNull(), st.counts, err
		}
		if err := st.applyFactsAttach(matched, f, kind, field, identity); err != nil {
			return validation.VNull(), st.counts, err
		}
	}
	if len(st.slots) == 0 {
		// no facts: the model is returned verbatim (presence-gated callers
		// never see a byte move)
		return model, st.counts, nil
	}
	st.counts.Components = len(st.slots)
	return st.applyFactsRebuild(model), st.counts, nil
}

// applyFactsTarget resolves a fact's target: the (kind, url|path) identity
// the join keys on.
func (st *applyFactsState) applyFactsTarget(f validation.Value) (string,
	string, string, error) {
	target := validation.ObjAt(f, "target")
	kind := validation.ObjAt(target, "kind").S
	if url := validation.ObjAt(target, "url"); url.Kind == validation.Str && url.S != "" {
		return kind, "url", url.S, nil
	} else if path := validation.ObjAt(target, "path"); path.Kind == validation.Str &&
		path.S != "" {
		return kind, "path", path.S, nil
	}
	return kind, "", "", fmt.Errorf(
		"operator facts: target kind=%s carries neither url nor path",
		kind)
}

// applyFactsMatch locates the ONE component the identity targets; matching
// zero or two components is a data defect.
func (st *applyFactsState) applyFactsMatch(kind, field,
	identity string) (int, error) {
	matched, n := -1, 0
	if st.comps.Kind == validation.Arr {
		for i, c := range st.comps.A {
			if c.Kind != validation.Obj || validation.ObjAt(c, "kind").S != kind {
				continue
			}
			if v := validation.ObjAt(c, field); v.Kind != validation.Str ||
				v.S != identity {
				continue
			}
			matched, n = i, n+1
		}
	}
	if n == 0 {
		return -1, fmt.Errorf(
			"operator facts: no component matches kind=%s %s=%s",
			kind, field, identity)
	}
	if n > 1 {
		return matched, fmt.Errorf(
			"operator facts: target kind=%s %s=%s matches %d components",
			kind, field, identity, n)
	}
	return matched, nil
}

// applyFactsAttach attaches the fact's dns/dependency sub-objects to its
// component's slot, counting as it goes.
func (st *applyFactsState) applyFactsAttach(matched int, f validation.Value,
	kind, field, identity string) error {
	s := st.slots[matched]
	if s == nil {
		s = &applyFactsSlot{}
		st.slots[matched] = s
	}
	if dns, ok := lookup(f, "dns"); ok {
		if s.hasDNS {
			return fmt.Errorf(
				"operator facts: duplicate dns fact for component kind=%s %s=%s",
				kind, field, identity)
		}
		s.dns, s.hasDNS = dns, true
		st.counts.DNS++
	}
	if dep, ok := lookup(f, "dependency"); ok {
		if s.hasDep {
			return fmt.Errorf(
				"operator facts: duplicate dependency fact for component "+
					"kind=%s %s=%s", kind, field, identity)
		}
		s.dep, s.hasDep = dep, true
		st.counts.Dependency++
	}
	st.counts.Applied++
	return nil
}

// applyFactsRebuild rebuilds only components[]: the component order is the
// original array's order, every other top-level entry is reused verbatim, and
// inside a matched component only the two fact keys move (an existing key
// keeps its position, a new one is appended — that is what makes a second
// apply a no-op).
func (st *applyFactsState) applyFactsRebuild(
	model validation.Value) validation.Value {
	comps := st.comps
	newComps := make([]validation.Value, len(comps.A))
	copy(newComps, comps.A)
	for i, s := range st.slots {
		o := append([]validation.KV(nil), newComps[i].O...)
		if s.hasDNS {
			o = setKey(o, "dns", s.dns)
		}
		if s.hasDep {
			o = setKey(o, "dependency", s.dep)
		}
		newComps[i] = validation.VObj(o...)
	}
	top := append([]validation.KV(nil), model.O...)
	top = setKey(top, "components", validation.VArr(newComps...))
	return validation.VObj(top...)
}

// setKey is `o[key] = v`: replace in place when the key exists (position
// kept), append otherwise.
func setKey(o []validation.KV, key string, v validation.Value) []validation.KV {
	for i := range o {
		if o[i].K == key {
			o[i].V = v
			return o
		}
	}
	return append(o, validation.KV{K: key, V: v})
}

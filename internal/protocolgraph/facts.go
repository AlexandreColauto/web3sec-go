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
	factList := objAt(facts, "facts")
	if factList.Kind != validation.Arr {
		return validation.VNull(), counts,
			fmt.Errorf("operator facts: document carries no facts list")
	}

	// slot is the per-component attachment being assembled for this call.
	type slot struct {
		dns, dep       validation.Value
		hasDNS, hasDep bool
	}
	slots := map[int]*slot{}
	comps := objAt(model, "components")
	for _, f := range factList.A {
		if f.Kind != validation.Obj {
			return validation.VNull(), counts,
				fmt.Errorf("operator facts: fact is not an object")
		}
		target := objAt(f, "target")
		kind := objAt(target, "kind").S
		field, identity := "", ""
		if url := objAt(target, "url"); url.Kind == validation.Str && url.S != "" {
			field, identity = "url", url.S
		} else if path := objAt(target, "path"); path.Kind == validation.Str &&
			path.S != "" {
			field, identity = "path", path.S
		} else {
			return validation.VNull(), counts, fmt.Errorf(
				"operator facts: target kind=%s carries neither url nor path",
				kind)
		}
		matched, n := -1, 0
		if comps.Kind == validation.Arr {
			for i, c := range comps.A {
				if c.Kind != validation.Obj || objAt(c, "kind").S != kind {
					continue
				}
				if v := objAt(c, field); v.Kind != validation.Str ||
					v.S != identity {
					continue
				}
				matched, n = i, n+1
			}
		}
		if n == 0 {
			return validation.VNull(), counts, fmt.Errorf(
				"operator facts: no component matches kind=%s %s=%s",
				kind, field, identity)
		}
		if n > 1 {
			return validation.VNull(), counts, fmt.Errorf(
				"operator facts: target kind=%s %s=%s matches %d components",
				kind, field, identity, n)
		}
		s := slots[matched]
		if s == nil {
			s = &slot{}
			slots[matched] = s
		}
		if dns, ok := lookup(f, "dns"); ok {
			if s.hasDNS {
				return validation.VNull(), counts, fmt.Errorf(
					"operator facts: duplicate dns fact for component kind=%s %s=%s",
					kind, field, identity)
			}
			s.dns, s.hasDNS = dns, true
			counts.DNS++
		}
		if dep, ok := lookup(f, "dependency"); ok {
			if s.hasDep {
				return validation.VNull(), counts, fmt.Errorf(
					"operator facts: duplicate dependency fact for component "+
						"kind=%s %s=%s", kind, field, identity)
			}
			s.dep, s.hasDep = dep, true
			counts.Dependency++
		}
		counts.Applied++
	}
	if len(slots) == 0 {
		// no facts: the model is returned verbatim (presence-gated callers
		// never see a byte move)
		return model, counts, nil
	}
	counts.Components = len(slots)

	// Rebuild only components[]: the component order is the original array's
	// order, every other top-level entry is reused verbatim, and inside a
	// matched component only the two fact keys move (an existing key keeps
	// its position, a new one is appended — that is what makes a second
	// apply a no-op).
	newComps := make([]validation.Value, len(comps.A))
	copy(newComps, comps.A)
	for i, s := range slots {
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
	return validation.VObj(top...), counts, nil
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

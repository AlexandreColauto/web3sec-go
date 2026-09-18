// Invariant registry seeding — seed_from_model: fresh entries, source refresh and liveness seeding (split from invariants.go; pure structural move).

package invariants

import (
	"fmt"
	"strconv"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// SeedFromModel is seed_from_model: create registry entries for every
// invariant in the protocol model, refresh model→documented one way, and
// synthesize the liveness template when the model has state machines.
func SeedFromModel(c *state.Campaign, model validation.Value) (validation.Value, error) {
	links, err := LoadLinks(c)
	if err != nil {
		return validation.VNull(), err
	}
	reg := regOf(links)
	doc, err := DocumentedInvariants(c, nil)
	if err != nil {
		return validation.VNull(), err
	}
	invs := validation.ObjAt(model, "invariants")
	for _, inv := range invs.A {
		iidV, ok := fieldAt(inv, "id")
		if !ok {
			return validation.VNull(), fmt.Errorf("'id'")
		}
		iid := validation.PyStr(iidV)
		if !validation.HasKey(reg, iid) {
			stmt, ok := fieldAt(inv, "statement")
			if !ok {
				return validation.VNull(), fmt.Errorf("'statement'")
			}
			reg.O = append(reg.O, pair(iid, freshEntry(inv, stmt, iid, doc)))
			continue
		}
		reg = refreshSource(reg, iid, doc)
	}
	if err := seedLiveness(c, model, &reg, doc); err != nil {
		return validation.VNull(), err
	}
	links = setObjKey(links, "invariants", reg)
	count := validation.VObj(pair("count", validation.VInt(int64(len(invs.A)))))
	// r40: fresh registry entries are campaign state the audit reads; a
	// seeded registry without its invariants.seeded event is a half-land.
	if err := LinksThenLog(c, func() error {
		_, serr := SaveLinks(c, links)
		return serr
	}, func() error {
		_, lerr := c.Log("invariants.seeded", nil, &count)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return links, nil
}

// freshEntry is the seeding entry literal (exact Python key order).
func freshEntry(inv, stmt validation.Value, iid string, doc validation.Value) validation.Value {
	kvs := []validation.KV{
		pair("statement", stmt),
		pair("kind", getOr(inv, "kind", validation.VStr("security"))),
		pair("severity_if_broken",
			getOr(inv, "severity_if_broken", validation.VStr("high"))),
		pair("applies_to", getOr(inv, "applies_to", validation.VArr())),
		pair("test_status", validation.VStr("untested")),
		// the model's claimed status is DATA, never a verdict
		pair("status", validation.VStr("UNVERIFIED")),
		pair("model_belief", validation.ObjAt(inv, "model_belief")),
		pair("depends_on", getOr(inv, "depends_on", validation.VArr())),
		pair("modified_by", validation.ObjAt(inv, "modified_by")),
	}
	kvs = append(kvs, entrySource(iid, doc)...)
	kvs = append(kvs,
		pair("findings", validation.VArr()),
		pair("tests", validation.VArr()),
		pair("detectors", validation.VArr()),
		pair("updated_at", validation.VStr(state.NowIso())),
	)
	return validation.VObj(kvs...)
}

// refreshSource is the re-seed one-way flip model → documented.
func refreshSource(reg validation.Value, iid string, doc validation.Value) validation.Value {
	src, detail := deriveSource(iid, doc)
	e := validation.ObjAt(reg, iid)
	if src != "documented" || validation.ObjStr(e, "source") == "documented" {
		return reg
	}
	e.O = validation.SetOrAppend(e.O, "source", validation.VStr("documented"))
	if detail != nil {
		e.O = validation.SetOrAppend(e.O, "source_detail", validation.VStr(*detail))
	}
	e.O = validation.SetOrAppend(e.O, "modified_by",
		validation.VStr("source-refresh model->documented "+state.NowIso()))
	e.O = validation.SetOrAppend(e.O, "updated_at", validation.VStr(state.NowIso()))
	reg.O = validation.SetOrAppend(reg.O, iid, e)
	return reg
}

// seedLiveness is the liveness-template half of seed_from_model.
func seedLiveness(c *state.Campaign, model validation.Value, reg *validation.Value,
	doc validation.Value) error {
	var machines []string
	for _, sm := range validation.ObjAt(model, "state_machines").A {
		if name, ok := fieldAt(sm, "name"); ok && validation.PyTruthy(name) {
			machines = append(machines, validation.PyStr(name))
		}
	}
	if len(machines) == 0 {
		return nil
	}
	// Stage 37 demands one liveness invariant PER state machine, so coverage
	// is counted per machine, never by the mere presence of a liveness kind.
	// (The old global "any liveness entry exists" check let two covered
	// machines hide a third uncovered one — the G-01 gap.)
	covered := map[string]struct{}{}
	for _, e := range reg.O {
		if validation.PyStr(validation.ObjAt(e.V, "kind")) != "liveness" {
			continue
		}
		for _, a := range validation.ObjAt(e.V, "applies_to").A {
			covered[validation.PyStr(a)] = struct{}{}
		}
	}
	var uncovered []string
	for _, m := range machines {
		if _, ok := covered[m]; !ok {
			uncovered = append(uncovered, m)
		}
	}
	if len(uncovered) == 0 {
		return nil
	}
	if len(uncovered) < len(machines) {
		// Partial coverage: refuse BEFORE any write (no registry mutation, no
		// template event), so the caller's unwind discipline is not needed
		// here — SeedFromModel never reaches SaveLinks on this path.
		return fmt.Errorf("protocol model: state machine(s) %s have no "+
			"liveness invariant (one per machine — stage 37)",
			strings.Join(uncovered, ", "))
	}
	// Zero coverage: the synthesis path below, unchanged.
	nid := nextInvNum(*reg)
	stmt := "LIVENESS: every modeled state machine must be able to advance " +
		"to its terminal/finalized state; no reachable state may permanently " +
		"block finalize/withdraw/challenge/claim. Machines: " +
		strings.Join(machines, ", ")
	key := "INV-" + strconv.Itoa(nid)
	kvs := []validation.KV{
		pair("statement", validation.VStr(stmt)),
		pair("kind", validation.VStr("liveness")),
		pair("severity_if_broken", validation.VStr("critical")),
		pair("applies_to", validation.StrArr(machines)),
		pair("test_status", validation.VStr("untested")),
		pair("status", validation.VStr("UNVERIFIED")),
		pair("model_belief", validation.VNull()),
		pair("depends_on", validation.VArr()),
		pair("modified_by", validation.VNull()),
	}
	kvs = append(kvs, entrySource(key, doc)...)
	kvs = append(kvs,
		pair("findings", validation.VArr()),
		pair("tests", validation.VArr()),
		pair("detectors", validation.VArr()),
		pair("updated_at", validation.VStr(state.NowIso())),
		pair("synthesized", validation.VStr("liveness-template")),
	)
	reg.O = validation.SetOrAppend(reg.O, key, validation.VObj(kvs...))
	data := validation.VObj(
		pair("id", validation.VStr(key)),
		pair("machines", validation.StrArr(machines)),
	)
	if _, err := c.Log("invariants.liveness_template", nil, &data); err != nil {
		return err
	}
	return nil
}

// nextInvNum is max(int(k[4:]) for numeric INV-n keys) + 1 (1 when none).
func nextInvNum(reg validation.Value) int {
	best := 0
	for _, e := range reg.O {
		k := e.K
		if len(k) < 5 || !strings.HasPrefix(k, "INV-") {
			continue
		}
		if n, ok := pyIntText(k[4:]); ok && n > best {
			best = n
		}
	}
	return best + 1
}

// ---- linking -------------------------------------------------------------

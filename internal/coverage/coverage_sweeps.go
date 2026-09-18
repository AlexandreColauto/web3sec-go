// coverage_sweeps.go: record_sweep / record_surface — recording one
// specialist pass over a contract and the cross-cutting surface counts.
package coverage

import (
	"fmt"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// SweepOpts mirrors record_sweep's keyword defaults.
type SweepOpts struct {
	EntryPointsReviewed int64
	FunctionsReviewed   int64
	Complete            bool
}

// RecordSweep is record_sweep: record one specialist pass over a contract
// from one trajectory and return the updated contract row.
func RecordSweep(c *state.Campaign, contract, trajectory string,
	opts SweepOpts) (validation.Value, error) {
	cov, err := Load(c)
	if err != nil {
		return validation.VNull(), err
	}
	rows, err := reqKey(cov, "contracts")
	if err != nil {
		return validation.VNull(), err
	}
	for i := range rows.A {
		path, err := reqKey(rows.A[i], "path")
		if err != nil {
			return validation.VNull(), err
		}
		if !matchesContract(path.S, contract) {
			continue
		}
		row, err := sweepRow(rows.A[i], trajectory, opts)
		if err != nil {
			return validation.VNull(), err
		}
		rows.A[i] = row
		cov.O = validation.SetOrAppend(cov.O, "contracts", rows)
		data := validation.VObj(
			kv("contract", validation.VStr(contract)),
			kv("trajectory", validation.VStr(trajectory)),
			kv("complete", validation.VBool(opts.Complete)),
		)
		// r40e: the sweep row without its coverage.sweep event is a
		// disposition no later reader can see; unwind the ledger write on a
		// refused append.
		if err := saveThenLog(c, &cov, func() error {
			_, lerr := c.Log("coverage.sweep", nil, &data)
			return lerr
		}); err != nil {
			return validation.VNull(), err
		}
		return row, nil
	}
	inner := fmt.Sprintf("unknown contract %s in coverage ledger",
		validation.PyReprStr(contract))
	return validation.VNull(), fmt.Errorf("%s", validation.PyReprStr(inner))
}

// matchesContract is record_sweep's path predicate (the endswith("/"+contract)
// clause is subsumed by the plain endswith).
func matchesContract(path, contract string) bool {
	return strings.HasSuffix(path, contract) || path == contract ||
		strings.Contains(path, contract)
}

// sweepRow applies one sweep to a contract row. The min() cap keeps the
// Python quirk: a falsy entry_points_total caps at the ARGUMENT, not at 0.
func sweepRow(row validation.Value, trajectory string, opts SweepOpts) (validation.Value, error) {
	counts, err := reqKey(row, "trajectory_counts")
	if err != nil {
		return validation.VNull(), err
	}
	if counts.Kind != validation.Obj {
		counts = validation.VObj()
	}
	n := numOrZero(validation.ObjAt(counts, trajectory)).addInt(1)
	counts.O = validation.SetOrAppend(counts.O, trajectory, n.value())
	row.O = validation.SetOrAppend(row.O, "trajectory_counts", counts)

	epr := numOrZero(validation.ObjAt(row, "entry_points_reviewed")).addInt(opts.EntryPointsReviewed)
	eprCap := numInt(opts.EntryPointsReviewed)
	if validation.PyTruthy(validation.ObjAt(row, "entry_points_total")) {
		eprCap = numOf(validation.ObjAt(row, "entry_points_total"))
	}
	row.O = validation.SetOrAppend(row.O, "entry_points_reviewed", epr.min(eprCap).value())

	fr := numOrZero(validation.ObjAt(row, "functions_reviewed")).addInt(opts.FunctionsReviewed)
	frCap := numInt(opts.FunctionsReviewed)
	if validation.PyTruthy(validation.ObjAt(row, "functions_total")) {
		frCap = numOf(validation.ObjAt(row, "functions_total"))
	}
	row.O = validation.SetOrAppend(row.O, "functions_reviewed", fr.min(frCap).value())

	if opts.Complete {
		row.O = validation.SetOrAppend(row.O, "status", validation.VStr("swept"))
	} else {
		status, err := reqKey(row, "status")
		if err != nil {
			return validation.VNull(), err
		}
		if status.S == "unknown" {
			row.O = validation.SetOrAppend(row.O, "status", validation.VStr("in-progress"))
		}
	}
	row.O = validation.SetOrAppend(row.O, "thoroughness", thoroughness(validation.ObjAt(row, "entry_points_reviewed"),
		validation.ObjAt(row, "entry_points_total")))
	return row, nil
}

// thoroughness is the row's density: round(reviewed/total, 3), or null when
// the total is falsy.
func thoroughness(reviewed, total validation.Value) validation.Value {
	if !validation.PyTruthy(total) {
		return validation.VNull()
	}
	return validation.VFloat(validation.PythonRound(numOrZero(reviewed).div(total), 3))
}

// RecordSurface is record_surface: set one cross-cutting surface's reviewed
// count, clamped to its total.
func RecordSurface(c *state.Campaign, surface string, reviewed int64) error {
	cov, err := Load(c)
	if err != nil {
		return err
	}
	surfaces, err := reqKey(cov, "surfaces")
	if err != nil {
		return err
	}
	row, ok := lookup(surfaces, surface)
	if !ok {
		return fmt.Errorf("%s", validation.PyReprStr(
			fmt.Sprintf("unknown surface %s", validation.PyReprStr(surface))))
	}
	total, err := reqKey(row, "total")
	if err != nil {
		return err
	}
	row.O = validation.SetOrAppend(row.O, "reviewed", numInt(reviewed).min(numOf(total)).value())
	surfaces.O = validation.SetOrAppend(surfaces.O, surface, row)
	cov.O = validation.SetOrAppend(cov.O, "surfaces", surfaces)
	_, err = Save(c, &cov)
	return err
}

// Seams for modules that are not ported yet (rule 5): injectable
// function hooks with safe defaults.

package bounty

import (
	"websec/internal/findings"
	"websec/internal/pricing"
	"websec/internal/state"
	"websec/internal/validation"
)

// --- seams for modules that are not ported yet (rule 5) --------------------
//
// maximization.load_ladder, fork_poc.fork_poc_status, completion.waivers and
// immunize.immunization_detail are P1+ modules. Each seam below has a safe
// default equal to the Python behavior on data those modules have not
// produced yet (no ladder, no proven fork PoC, no waivers, no patch
// verification). pricing.price_row and findings.GATE_REMEDIATION are ported,
// so those two defaults call the real modules.

var (
	loadLadderFunc = func(c *state.Campaign, findingID string) (validation.Value, error) {
		return validation.VNull(), nil
	}
	priceRowFunc = func(c *state.Campaign, priceID string) (validation.Value, error) {
		row, err := pricing.PriceRow(c, priceID)
		if err != nil {
			return validation.VNull(), err
		}
		if row == nil {
			return validation.VNull(), nil
		}
		return *row, nil
	}
	forkPocStatusFunc = func(c *state.Campaign, findingID string) (bool, string, error) {
		return false, "no fork PoC proven", nil
	}
	waiversFunc = func(c *state.Campaign, stage string) ([]validation.Value, error) {
		return nil, nil
	}
	immunizationDetailFunc = func(f validation.Value) (string, string) {
		return "missing", "no patch verification recorded (webv2 immunize " +
			"... against the FORK PoC)"
	}
	// B4: contract-name → source-path resolver for the scope check. The
	// default is a no-op (empty) — the real resolver (structidx) is wired by
	// the CLI's ensureSeams, which is the top module free of the
	// structidx→orchestrator→bounty import cycle. When it returns empty the
	// scope check falls back to name-only matching (the pre-B4 behaviour).
	contractPathFunc     = func(*state.Campaign, string) string { return "" }
	confirmedRemediation = findings.GATE_REMEDIATION
)

// SetLoadLadder installs maximization.load_ladder; nil restores the default.
func SetLoadLadder(f func(*state.Campaign, string) (validation.Value, error)) {
	if f == nil {
		f = func(c *state.Campaign, findingID string) (validation.Value, error) {
			return validation.VNull(), nil
		}
	}
	loadLadderFunc = f
}

// SetPriceRow overrides pricing.price_row; nil restores the default (the
// ported pricing module).
func SetPriceRow(f func(*state.Campaign, string) (validation.Value, error)) {
	if f == nil {
		f = func(c *state.Campaign, priceID string) (validation.Value, error) {
			row, err := pricing.PriceRow(c, priceID)
			if err != nil {
				return validation.VNull(), err
			}
			if row == nil {
				return validation.VNull(), nil
			}
			return *row, nil
		}
	}
	priceRowFunc = f
}

// SetForkPocStatus installs fork_poc.fork_poc_status; nil restores the
// default (not proven, "no fork PoC proven" — the module's literal fallback;
// its real reason text is one of three ledger-dependent messages).
func SetForkPocStatus(f func(*state.Campaign, string) (bool, string, error)) {
	if f == nil {
		f = func(c *state.Campaign, findingID string) (bool, string, error) {
			return false, "no fork PoC proven", nil
		}
	}
	forkPocStatusFunc = f
}

// SetWaivers installs completion.waivers; nil restores the default (none).
func SetWaivers(f func(*state.Campaign, string) ([]validation.Value, error)) {
	if f == nil {
		f = func(c *state.Campaign, stage string) ([]validation.Value, error) {
			return nil, nil
		}
	}
	waiversFunc = f
}

// SetImmunizationDetail installs immunize.immunization_detail; nil restores
// the default (the no-patch-verification verdict, byte-exact for that case).
func SetImmunizationDetail(f func(validation.Value) (string, string)) {
	if f == nil {
		f = func(v validation.Value) (string, string) {
			return "missing", "no patch verification recorded (webv2 immunize " +
				"... against the FORK PoC)"
		}
	}
	immunizationDetailFunc = f
}

// SetContractPathResolver installs the contract-name → source-path resolver
// the scope check uses (B4): a path-based scope entry can match a
// name-carrying finding only if the name resolves to its source path. nil
// restores the default (read the saved structural index; empty when absent).
func SetContractPathResolver(f func(*state.Campaign, string) string) {
	if f == nil {
		f = func(*state.Campaign, string) string { return "" }
	}
	contractPathFunc = f
}

// SetConfirmedGateRemediation overrides the CONFIRMED-gate half of the
// gate-explain catalog (findings.GATE_REMEDIATION by default); nil restores
// that default.
func SetConfirmedGateRemediation(m map[string]string) {
	if m == nil {
		m = findings.GATE_REMEDIATION
	}
	confirmedRemediation = m
}

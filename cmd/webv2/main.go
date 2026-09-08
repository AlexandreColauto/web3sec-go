// Command webv2 is the P1 trust-core CLI: init/status/snap/log/audit/
// verify over filesystem-backed campaigns. All output flows through the
// cli Runner's writers; main only maps the exit code and wires the
// cross-module seams (Python's import-time connections, in one place).
package main

import (
	"os"

	"websec/internal/cli"
	"websec/internal/dedup"
	"websec/internal/findings"
	"websec/internal/invariants"
	"websec/internal/taxonomy"
	// init() side effects: taxonomy wires findings.SetClassAdvisory,
	// floors wires findings.SetEffectiveFloor (Python import-time seams),
	// completion wires pipeline.SetCompletion + bounty.SetWaivers — without
	// this import the scheduler would silently auto-complete nothing and the
	// bounty gate would never see a stage waiver.
	_ "websec/internal/completion"
	_ "websec/internal/floors"
)

func init() {
	// dedup -> findings duplicate helpers (Python: dedup imports findings).
	dedup.SetMarkDuplicate(findings.MarkDuplicate)
	dedup.SetFlagPossibleDuplicate(findings.FlagPossibleDuplicate)
	dedup.SetFoldIntoLineage(findings.FoldIntoLineage)
	// taxonomy -> dedup compat-class tables (Python: _compat_classes()
	// reads dedup._ECONOMIC_COMPAT_GROUPS and dedup._ASSET_CLASS_HINTS).
	taxonomy.SetCompatClasses(func() []string {
		out := []string{}
		for _, g := range dedup.EconomicCompatGroups {
			out = append(out, g...)
		}
		for _, names := range dedup.AssetClassHints {
			out = append(out, names...)
		}
		return out
	})
	// invariants 2.1 guardrail (Python: _assert_invariants_verified).
	findings.SetInvariantGuard(invariants.AssertInvariantsVerified)
}

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}

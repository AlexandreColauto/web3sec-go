package cli

// cmd_model: `webv2 model <campaign> [file] [--json] [--facts PATH]
// [--facts-observed-at DATE]` — load a protocol model from a JSON file
// (seeds the invariant registry, reconciles against documented INV ids), or
// show the loaded one (cli.py cmd_model verbatim). --facts (I4) merges
// operator-supplied DNS/dependency facts into components[] BEFORE the model
// is stored; without it the verb moves zero bytes.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"websec/internal/orchestrator"
	"websec/internal/protocolgraph"
	"websec/internal/state"
	"websec/internal/validation"
)

const t14ModelUsage = `usage: webv2 model [-h] [--json] [--facts FACTS] ` +
	`[--facts-observed-at DATE] campaign [file]
`

const t14ModelHelp = `usage: webv2 model [-h] [--json] [--facts FACTS] ` +
	`[--facts-observed-at DATE] campaign [file]

positional arguments:
  campaign
  file

options:
  -h, --help            show this help message and exit
  --json
  --facts FACTS         operator facts JSON document, or a directory of
                        offline manifests (remappings.txt + lockfiles)
  --facts-observed-at DATE
                        the operator's YYYY-MM-DD observation date (required
                        for a directory, ignored for a JSON document)
`

// factsDateRe is the date shape the CLI accepts for --facts-observed-at: the
// fact's date is an operator assertion, so it is never defaulted to today.
var factsDateRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

func runModel(root string, args []string, r *Runner) error {
	var pos []string
	asJSON := false
	factsPath, factsDate := "", ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-h" || a == "--help":
			fmt.Fprint(r.Out, t14ModelHelp)
			return nil
		case a == "--json":
			asJSON = true
		case a == "--facts" && i+1 < len(args) && !looksLikeOption(args[i+1]):
			factsPath = args[i+1]
			i++
		case strings.HasPrefix(a, "--facts="):
			factsPath = strings.TrimPrefix(a, "--facts=")
		case a == "--facts-observed-at" && i+1 < len(args) &&
			!looksLikeOption(args[i+1]):
			factsDate = args[i+1]
			i++
		case strings.HasPrefix(a, "--facts-observed-at="):
			factsDate = strings.TrimPrefix(a, "--facts-observed-at=")
		case a == "--facts" || a == "--facts-observed-at":
			return t14ArgparseErr(t14ModelUsage, "model",
				"argument %s: expected one argument", a)
		case strings.HasPrefix(a, "-"):
			return t14Unrecognized(a)
		default:
			pos = append(pos, a)
		}
	}
	if len(pos) < 1 {
		return t14ArgparseErr(t14ModelUsage, "model",
			"the following arguments are required: campaign")
	}
	if len(pos) > 2 {
		return t14Unrecognized(strings.Join(pos[2:], " "))
	}
	c, err := t14Open(root, pos[0])
	if err != nil {
		return err
	}
	if len(pos) == 1 {
		if factsPath != "" {
			return t14ArgparseErr(t14ModelUsage, "model",
				"argument --facts: requires a model file to merge into")
		}
		return showLoadedModel(c, r.Out, asJSON)
	}
	return loadModelFile(c, pos[1], r.Out, r.Err, asJSON, factsPath, factsDate)
}

// showLoadedModel is the no-file branch: print the artifact already loaded.
// PG.load_model re-registers and re-logs the load (cli.py does the same).
func showLoadedModel(c *state.Campaign, stdout io.Writer, asJSON bool) error {
	pm := filepath.Join(c.ArtifactsDir, "protocol_model.json")
	if !t14Exists(pm) {
		fmt.Fprintln(stdout, "no protocol model loaded yet "+
			"(webv2 model "+c.CampaignID+" model.json)")
		return nil
	}
	m, err := protocolgraph.LoadModel(c, pm)
	if err != nil {
		return err
	}
	if asJSON {
		t14PrintJSON(stdout, m)
		return nil
	}
	fmt.Fprintf(stdout, "model: %d actors, %d assets, %d invariants, "+
		"%d relations\n", t14PyLen(validation.ObjAt(m, "actors")),
		t14PyLen(validation.ObjAt(m, "assets")), t14PyLen(validation.ObjAt(m, "invariants")),
		t14PyLen(validation.ObjAt(m, "relations")))
	return nil
}

// loadModelFile is the file branch: read, optionally merge operator facts,
// load into the orchestrator, report. The merge happens BEFORE the store, so
// the artifact on disk and the row the report renders are the merged model.
func loadModelFile(c *state.Campaign, path string, stdout, stderr io.Writer,
	asJSON bool, factsPath, factsDate string) error {
	text, err := t14ReadText(path)
	if err != nil {
		return err
	}
	model, err := t14ParseJSON(text)
	if err != nil {
		return err
	}
	var counts protocolgraph.FactCounts
	merged := false
	if factsPath != "" {
		model, counts, err = mergeFacts(model, factsPath, factsDate)
		if err != nil {
			return err
		}
		merged = true
	}
	res, err := orchestrator.New(c).LoadProtocolModel(model)
	if err != nil {
		return t14ExitErr(2, "model load failed: %s\n", err)
	}
	if asJSON {
		t14PrintJSON(stdout, res)
		return nil
	}
	m := validation.ObjAt(res, "model")
	fmt.Fprintf(stdout, "model loaded: %d actors, %d assets, %d invariants\n",
		t14PyLen(validation.ObjAt(m, "actors")), t14PyLen(validation.ObjAt(m, "assets")),
		t14PyLen(validation.ObjAt(m, "invariants")))
	seeded := objInt(res, "invariants_seeded")
	registered := objInt(res, "invariants_registered")
	if seeded == 0 {
		fmt.Fprintln(stderr, "  WARNING: the model declares no invariants — "+
			"the invariant registry was seeded with NOTHING "+
			"(invariants.seed_empty logged). Every evidence level rise will "+
			"be guardrail-blocked until the model is refined.")
	} else {
		fmt.Fprintf(stdout, "  invariant registry: %d invariant(s) "+
			"(%d from this load)\n", registered, seeded)
	}
	recon := validation.ObjAt(res, "invariant_reconciliation")
	missing := validation.ObjAt(recon, "missing_from_model")
	if t14PyLen(missing) > 0 {
		names := make([]string, 0, len(missing.A))
		for _, v := range missing.A {
			names = append(names, scalarStr(v))
		}
		fmt.Fprintf(stdout, "  RECONCILIATION: documented invariants missing "+
			"from the model: %s\n", strings.Join(names, ", "))
		fmt.Fprintf(stdout, "      %s\n", validation.ObjStr(recon, "note"))
	} else {
		fmt.Fprintf(stdout, "  reconciliation: %s\n", validation.ObjStr(recon, "note"))
	}
	if merged {
		// I4: the merge summary is additive output — every line above is
		// byte-identical to the run without --facts.
		fmt.Fprintf(stdout, "facts: %d applied (%d dns, %d dependency) "+
			"onto %d components\n", counts.Applied, counts.DNS,
			counts.Dependency, counts.Components)
	}
	return nil
}

// mergeFacts is the I4 entry point: read the operator facts from a JSON
// document or extract them from a directory of offline manifests, then join
// them onto the model. A directory has no date inside it, so
// --facts-observed-at is required there (a usage error, exit 2) and is
// ignored for a document, where every fact carries its own date.
func mergeFacts(model validation.Value, factsPath, factsDate string) (
	validation.Value, protocolgraph.FactCounts, error) {
	var counts protocolgraph.FactCounts
	info, err := os.Stat(factsPath)
	if err != nil {
		return validation.VNull(), counts, t14OSError(factsPath, err)
	}
	var facts validation.Value
	if info.IsDir() {
		if factsDate == "" {
			return validation.VNull(), counts, t14ArgparseErr(t14ModelUsage,
				"model", "argument --facts-observed-at: required when "+
					"--facts is a directory")
		}
		if !factsDateRe.MatchString(factsDate) {
			return validation.VNull(), counts, t14ArgparseErr(t14ModelUsage,
				"model", "argument --facts-observed-at: invalid date %q "+
					"(want YYYY-MM-DD)", factsDate)
		}
		facts, err = protocolgraph.FactsFromDir(factsPath, factsDate)
		if err != nil {
			return validation.VNull(), counts,
				t14ExitErr(2, "facts extraction failed: %s\n", err)
		}
	} else {
		facts, err = protocolgraph.LoadFacts(factsPath)
		if err != nil {
			return validation.VNull(), counts,
				t14ExitErr(2, "facts load failed: %s\n", err)
		}
	}
	mergedModel, counts, err := protocolgraph.ApplyFactsCounted(model, facts)
	if err != nil {
		return validation.VNull(), counts, t14ExitErr(2, "%s\n", err)
	}
	return mergedModel, counts, nil
}

func init() {
	register(command{ord: 33, name: "model",
		line: `model <campaign> [file] [--json]   load/show the protocol model`,
		run: func(root string, args []string, r *Runner) int {
			return t14Dispatch(root, r, func() error {
				return runModel(root, args, r)
			})
		}})
}

package cli

// cmd_schema: `webv2 schema [--list] [<name>]` — serve the embedded
// validation schemas themselves (B1, feedback-triage-morph-r2 §B1).
//
// Every refusal in this CLI names a schema ("... validation failed at
// artifacts/1/kind"), and `--example` payloads are only a SHAPE hint: an
// operator (or an agent) that needs the closed enums, the required fields or
// the nested object shape had no way to read the document the framework
// actually validates against. This verb is that read path, with no framework
// checkout and no `assets/schema/` path: the schemas ride the binary
// (assets.FS) and `validation.ReadSchemaFile` (schema_enum.go:45) is the same
// reader `Validate` uses, so the bytes served here are the bytes enforced.
//
// stdout discipline: `schema <name>` writes the RAW document bytes with
// nothing appended (byte-identical to the embedded file — a trailing newline
// is the FILE's, not ours), so `webv2 schema finding | jq .` works. The name
// listing and the unknown-name refusal are the only other output.

import (
	"fmt"
	"slices"
	"strings"

	"websec/internal/validation"
)

const schemaUsage = `usage: webv2 schema [-h] [--list] [name]
`

const schemaHelp = schemaUsage + `
print an embedded validation schema (the exact document the CLI validates
against), or list the known schema names

positional arguments:
  name              schema name, e.g. finding, protocol_model, bounty_policy
                    (omit it, or pass --list, to list the known names)

options:
  -h, --help        show this help message and exit
  --list            list the known schema names, one per line

bug classes are taxonomy DATA, not a schema: the class table and its
weights live at assets/taxonomy/class_weights.json (per-class evidence
floors read from there; see also 'webv2 floors'). No schema name
resolves them — this is by design, not a gap.
`

func runSchema(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error {
		return schemaCmd(args, r)
	})
}

func schemaCmd(args []string, r *Runner) error {
	list, name := false, ""
	for _, a := range args {
		switch {
		case a == "-h" || a == "--help":
			// argparse answers help before it validates anything (the
			// helpRequested convention, cli.go:209); this verb's block is
			// its own constant, so it prints it inline like cmd_prompts.go:50.
			fmt.Fprint(r.Out, schemaHelp)
			return nil
		case a == "--list":
			list = true
		case strings.HasPrefix(a, "-"):
			return t14Unrecognized(a)
		case name == "":
			name = a
		default:
			return t14Unrecognized(a)
		}
	}
	if list && name != "" {
		// argparse's mutually-exclusive-group text; silently ignoring one of
		// the two would make `--list finding` look like it listed something.
		return t14ArgparseErr(schemaUsage, "schema",
			"argument --list: not allowed with argument name")
	}
	if name == "" {
		for _, n := range validation.KnownSchemas() {
			fmt.Fprintln(r.Out, n)
		}
		return nil
	}
	if !slices.Contains(validation.KnownSchemas(), name) {
		// The canonical unknown-schema text (loadSchema, internal/validation) names every known
		// schema in contractual order; Validate reaches it in loadSchema
		// before it looks at the instance, so the CLI reuses that renderer
		// instead of re-spelling the list (which could drift from the one the
		// rest of the framework prints).
		return t14ExitErr(2, "%s\n", validation.Validate(
			validation.VNull(), name, 1))
	}
	raw, err := validation.ReadSchemaFile(name)
	if err != nil {
		// unreachable for a known name: the embedded FS is built from the
		// same schema set (loadSchema's file-missing branch); reachable only for a SCHEMA_DIR
		// override whose file disappeared between the two reads.
		return fmt.Errorf("schema: reading %s: %w", name, err)
	}
	// Verbatim: Write, not Fprint(string(raw)) — no byte is added or
	// reinterpreted on the way to stdout.
	if _, err := r.Out.Write(raw); err != nil {
		return err
	}
	return nil
}

// schemaPointerLine is the additive stderr pointer every `--example` branch
// ends with (B1(c)): the template shows the shape, the schema document shows
// every field and closed enum. Existing example bytes above it are untouched.
func schemaPointerLine(name string) string {
	return "schema: webv2 schema " + name + " — the raw schema document " +
		"(every field and enum)\n"
}

func init() {
	// ord 90: after every verb registered before this wave (the highest is
	// 83, artifact-prune) and before the trailing `help` line usageText
	// appends — the new verb must not renumber the existing catalog.
	register(command{ord: 90, name: "schema",
		line: `schema [--list] [name]          print an embedded validation ` +
			`schema (or list the known names)`,
		run: runSchema})
}

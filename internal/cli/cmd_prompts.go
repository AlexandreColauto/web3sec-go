package cli

// cmd_prompts: `webv2 prompts {list|show [name]}` — materialize the embedded
// stage prompts (D1).
//
// `run` halts naming a prompt file under assets/prompts/, but an
// operator workspace holding only the BINARY (or a bounty target, not the
// framework checkout) has no such path. The prompts ride the binary
// embedded (assets.PromptsFS); this verb serves them: list names, show
// prints bytes to stdout. Name resolution accepts the full filename, the
// stem with or without its NN_ stage prefix, and the bare stage number.

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"websec/assets"
)

const promptsUsage = "usage: webv2 prompts [-h] {list,show} [name]\n"

const promptsHelp = promptsUsage + `
materialize the embedded stage prompts (no framework checkout needed)

positional arguments:
  {list,show}       list prompt filenames, or show one prompt's text
  name              prompt name for show: full filename, stem with or
                    without its NN_ stage prefix, or bare stage number
                    (e.g. 37_protocol_knowledge_graph.md,
                    37_protocol_knowledge_graph, protocol_knowledge_graph, 37)

options:
  -h, --help        show this help message and exit
`

var promptsStemRe = regexp.MustCompile(`^[0-9]+_(.+)$`)

func runPrompts(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error {
		return promptsCmd(args, r)
	})
}

func promptsCmd(args []string, r *Runner) error {
	sub, name := "", ""
	for _, a := range args {
		if a == "-h" || a == "--help" {
			fmt.Fprint(r.Out, promptsHelp)
			return nil
		}
		if strings.HasPrefix(a, "-") {
			return t14Unrecognized(a)
		}
		if sub == "" {
			sub = a
		} else if name == "" {
			name = a
		} else {
			return t14Unrecognized(a)
		}
	}
	files, err := promptsFiles()
	if err != nil {
		return err
	}
	switch sub {
	case "list":
		if name != "" {
			return t14Unrecognized(name)
		}
		for _, f := range files {
			fmt.Fprintln(r.Out, f)
		}
		return nil
	case "show":
		if name == "" {
			return t14ArgparseErr(promptsUsage, "prompts",
				"show requires a prompt name (`webv2 prompts list` names them)")
		}
		match, ambiguous := promptsResolve(files, name)
		if match == "" {
			return t14ExitErr(2, "prompts: no prompt matching %q "+
				"(`webv2 prompts list` names them)\n", name)
		}
		if ambiguous != "" {
			return t14ExitErr(2, "prompts: %q is ambiguous: %s — "+
				"name one exactly\n", name, ambiguous)
		}
		raw, err := fs.ReadFile(assets.PromptsFS, "prompts/"+match)
		if err != nil {
			return fmt.Errorf("prompts: reading embedded %s: %w", match, err)
		}
		fmt.Fprint(r.Out, string(raw))
		return nil
	default:
		if sub == "" {
			return t14ArgparseErr(promptsUsage, "prompts",
				"a subcommand is required: {list,show}")
		}
		return t14ArgparseErr(promptsUsage, "prompts",
			"invalid choice: %s (choose from 'list', 'show')", sub)
	}
}

// promptsFiles lists the embedded prompt filenames, sorted.
func promptsFiles() ([]string, error) {
	entries, err := fs.ReadDir(assets.PromptsFS, "prompts")
	if err != nil {
		return nil, fmt.Errorf("prompts: reading embedded pack: %w", err)
	}
	files := []string{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	return files, nil
}

// promptsResolve maps an operator name onto one embedded filename: exact,
// with .md, stem with or without the NN_ prefix, or bare stage number.
// The second return names the ambiguity, "" when unambiguous.
func promptsResolve(files []string, name string) (string, string) {
	for _, f := range files {
		if f == name || f == name+".md" {
			return f, ""
		}
	}
	stem := strings.TrimSuffix(name, ".md")
	cands := []string{}
	for _, f := range files {
		base := strings.TrimSuffix(f, ".md")
		plain := base
		if m := promptsStemRe.FindStringSubmatch(base); m != nil {
			plain = m[1]
		}
		if base == stem || plain == stem {
			cands = append(cands, f)
		}
	}
	// bare stage number: the NN_ prefix itself
	if len(cands) == 0 {
		for _, f := range files {
			if strings.HasPrefix(f, stem+"_") {
				cands = append(cands, f)
			}
		}
	}
	if len(cands) == 1 {
		return cands[0], ""
	}
	if len(cands) > 1 {
		return "", strings.Join(cands, ", ")
	}
	return "", ""
}

func init() {
	register(command{ord: 79, name: "prompts",
		line: "prompts {list,show}               print embedded stage prompts",
		run:  runPrompts})
}

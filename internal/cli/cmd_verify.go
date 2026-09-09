package cli

// cmd_verify: `webv2 verify <campaign> [--queue]
// [--exec EXEC --finding F --verifier NAME --description D]` — event-log
// integrity check, the E6 independent-verification queue, or recording an
// independent reproduction (cli.py cmd_verify verbatim). The CLI is a thin
// wrapper (I3): the E6 machinery is orchestrator.VerifyIndependently /
// IndependentVerificationQueue.

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"websec/internal/findings"
	"websec/internal/orchestrator"
	"websec/internal/reproduction"
	"websec/internal/state"
	"websec/internal/validation"
)

// t36VerifyUsage is argparse's `verify` usage block (COLUMNS=80), pinned
// byte-for-byte from the live Python CLI.
const t36VerifyUsage = `usage: webv2 verify [-h] [--queue] [--exec EXEC_ID] [--finding FINDING]
                    [--verifier VERIFIER] [--description DESCRIPTION]
                    campaign
`

// t36VerifyHelp is `webv2 verify --help`.
const t36VerifyHelp = t36VerifyUsage + `
positional arguments:
  campaign

options:
  -h, --help            show this help message and exit
  --queue
  --exec EXEC_ID        EXEC id of the independent reproduction
  --finding FINDING     finding to independently verify (with --exec)
  --verifier VERIFIER   named identity performing the independent run
  --description DESCRIPTION
                        what the independent run demonstrates
`

// verifyArgs is the parsed verify command line.
type verifyArgs struct {
	campaign    string
	execID      string
	finding     string
	verifier    string
	description string
	queue       bool
}

// t36VerifyValue consumes `--name VALUE` / `--name=VALUE`. matched=false means
// the token is a different option; a missing value is argparse's error.
func t36VerifyValue(args []string, i int, name string) (string, int, bool,
	error) {
	if strings.HasPrefix(args[i], name+"=") {
		return strings.TrimPrefix(args[i], name+"="), i, true, nil
	}
	if args[i] != name {
		return "", i, false, nil
	}
	v, err := t23ValueArg(args, i, t36VerifyUsage, "verify", name)
	if err != nil {
		return "", i, false, err
	}
	return v, i + 1, true, nil
}

// parseVerifyArgs is the verify subparser: flags first, then argparse's
// required-campaign check, then the root parser's unrecognized arguments.
func parseVerifyArgs(args []string, r *Runner) (*verifyArgs, bool, error) {
	a := &verifyArgs{}
	var pos, extras []string
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok == "-h" || tok == "--help" {
			fmt.Fprint(r.Out, t36VerifyHelp)
			return nil, true, nil
		}
		if tok == "--queue" {
			a.queue = true
			continue
		}
		if strings.HasPrefix(tok, "--queue=") {
			return nil, false, t14ArgparseErr(t36VerifyUsage, "verify",
				"argument --queue: ignored explicit argument %s",
				validation.PyReprStr(strings.TrimPrefix(tok, "--queue=")))
		}
		matched := false
		for _, f := range []struct {
			name string
			dst  *string
		}{{"--exec", &a.execID}, {"--finding", &a.finding},
			{"--verifier", &a.verifier}, {"--description", &a.description}} {
			v, next, ok, err := t36VerifyValue(args, i, f.name)
			if err != nil {
				return nil, false, err
			}
			if ok {
				*f.dst, i, matched = v, next, true
				break
			}
		}
		if matched {
			continue
		}
		if t23IsOption(tok) {
			extras = append(extras, tok)
			continue
		}
		if len(pos) == 0 {
			pos = append(pos, tok)
			continue
		}
		extras = append(extras, tok)
	}
	if len(pos) == 0 {
		return nil, false, t14ArgparseErr(t36VerifyUsage, "verify",
			"the following arguments are required: campaign")
	}
	if len(extras) > 0 {
		return nil, false, t14Unrecognized(strings.Join(extras, " "))
	}
	a.campaign = pos[0]
	return a, false, nil
}

// verifyExec is cmd_verify's --exec branch: record the independent
// reproduction and print the E6 line.
func verifyExec(c *state.Campaign, a *verifyArgs, r *Runner) error {
	if a.verifier == "" || a.description == "" {
		return t14ExitErr(2,
			"verify --exec needs --verifier NAME and --description\n")
	}
	o := orchestrator.New(c)
	f, err := o.VerifyIndependently(a.finding, a.execID, a.description,
		a.verifier)
	if err != nil {
		var me *reproduction.MintError
		if errors.As(err, &me) {
			return t14ExitErr(2, "verify failed: %s\n", me.Error())
		}
		// An absent --finding is Python's None: load_finding(None) reports
		// `no finding None in <campaign>` (repr(None), not repr("")).
		if a.finding == "" &&
			err.Error() == "no finding '' in "+c.CampaignID {
			return errors.New("no finding None in " + c.CampaignID)
		}
		return err
	}
	level, err := findings.FindingLevel(f)
	if err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "%s: independently verified by %s — level %s\n",
		a.finding, a.verifier, level)
	return nil
}

// verifyQueue is cmd_verify's --queue branch: the E6 queue, mandatory first.
func verifyQueue(c *state.Campaign, r *Runner) error {
	q, err := orchestrator.New(c).IndependentVerificationQueue()
	if err != nil {
		return err
	}
	for _, item := range q.A {
		flag := "advisory"
		if objBool(item, "mandatory") {
			flag = "MANDATORY"
		}
		title := []rune(objStr(item, "title"))
		if len(title) > 60 {
			title = title[:60]
		}
		fmt.Fprintf(r.Out, "[%s] %s  at %s  %s  — %s\n", flag,
			objStr(item, "finding_id"), objStr(item, "evidence_level"),
			objStr(item, "bug_class"), string(title))
	}
	return nil
}

// verifyLog is cmd_verify's default branch: verify_log as indent-2 JSON,
// exit 1 when not ok.
func verifyLog(c *state.Campaign, stdout io.Writer) error {
	v, err := c.VerifyLog()
	if err != nil {
		return err
	}
	problems := make([]validation.Value, 0, len(v.Problems))
	for _, p := range v.Problems {
		problems = append(problems, validation.VStr(p))
	}
	// Key order is verify_log's dict order (contractual).
	res := validation.VObj(
		validation.KV{K: "events", V: validation.VInt(int64(v.Events))},
		validation.KV{K: "ok", V: validation.VBool(v.OK)},
		validation.KV{K: "problems", V: validation.VArr(problems...)},
		validation.KV{K: "chained", V: validation.VInt(int64(v.Chained))},
		validation.KV{K: "legacy_unchained", V: validation.VInt(
			int64(v.LegacyUnchained))},
		validation.KV{K: "malformed_lines", V: validation.VInt(
			int64(v.MalformedLines))},
	)
	fmt.Fprintln(stdout, prettyASCII(res))
	if !v.OK {
		return failSilent{}
	}
	return nil
}

func runVerify(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error { return verifyCmd(root, args, r) })
}

func verifyCmd(root string, args []string, r *Runner) error {
	ensureSeams()
	a, done, err := parseVerifyArgs(args, r)
	if err != nil || done {
		return err
	}
	c, err := t14Open(root, a.campaign)
	if err != nil {
		return err
	}
	if a.execID != "" {
		return verifyExec(c, a, r)
	}
	if a.queue {
		return verifyQueue(c, r)
	}
	return verifyLog(c, r.Out)
}

func init() {
	register(command{ord: 51, name: "verify",
		line: "verify <campaign>                    event-log integrity check",
		run:  runVerify})
}

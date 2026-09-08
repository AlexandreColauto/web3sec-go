package cli

// cmd_verify: `webv2 verify <campaign>` — event-log integrity check
// (cli.py cmd_verify's plain path verbatim: the verify_log dict as
// indent-2 JSON, exit 1 when not ok). The --queue/--exec E6 paths need
// the P1+ orchestrator/findings modules and are NOT wired (usage error).

import (
	"fmt"
	"io"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

func runVerify(root string, args []string, stdout io.Writer) error {
	var pos []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			return usageErrf("unrecognized arguments: %s", a)
		}
		pos = append(pos, a)
	}
	if len(pos) != 1 {
		return usageErrf("verify requires exactly one <campaign> argument")
	}
	c, err := state.Open(root, pos[0])
	if err != nil {
		return err
	}
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
		validation.KV{K: "legacy_unchained", V: validation.VInt(int64(v.LegacyUnchained))},
		validation.KV{K: "malformed_lines", V: validation.VInt(int64(v.MalformedLines))},
	)
	fmt.Fprintln(stdout, prettyASCII(res))
	if !v.OK {
		return failSilent{}
	}
	return nil
}

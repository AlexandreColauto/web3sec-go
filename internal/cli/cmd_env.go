// cmd_env: `webv2 env doctor [<campaign>] [--json]` — the environment doctor
// (read-only): what execution infrastructure exists, is the fork reachable,
// is the image digest-pinned, and (with a campaign) whether the environment
// can produce the evidence the campaign's floor requires. cli.py
// cmd_env_doctor verbatim.
//
// KNOWN DIVERGENCE (documented, see KNOWN_DIVERGENCES.md D23): bare
// `webv2 env` in the reference prints the help of whatever parser happened to
// be constructed LAST in build_parser() (a closure late-binding bug — today
// the `sft` parser). Reproducing that byte-for-byte would couple this file to
// another task's parser, so the Go twin prints the `env` usage block instead.
package cli

import (
	"fmt"
	"strings"

	"io"
	"os/exec"
	"websec/internal/envgo"
	"websec/internal/state"
	"websec/internal/validation"
)

const t26EnvUsage = `usage: webv2 env [-h] {doctor} ...
`

const t26EnvHelp = t26EnvUsage + `
positional arguments:
  {doctor}
    doctor    what can this box actually execute?

options:
  -h, --help  show this help message and exit
`

const t26EnvDoctorUsage = `usage: webv2 env doctor [-h] [--json] [campaign]
`

const t26EnvDoctorHelp = t26EnvDoctorUsage + `
positional arguments:
  campaign    optional: cross-check against the campaign's floor

options:
  -h, --help  show this help message and exit
  --json
`

func runEnv(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		if len(args) == 0 {
			fmt.Fprint(r.Out, t26EnvHelp)
			return nil
		}
		switch args[0] {
		case "-h", "--help":
			fmt.Fprint(r.Out, t26EnvHelp)
			return nil
		case "doctor":
			return runEnvDoctor(root, args[1:], r)
		}
		if strings.HasPrefix(args[0], "-") {
			return t14Unrecognized(args[0])
		}
		return t14ArgparseErr(t26EnvUsage, "env",
			"argument env_action: invalid choice: %s (choose from 'doctor')",
			validation.PyReprStr(args[0]))
	})
}

func runEnvDoctor(root string, args []string, r *Runner) error {
	var pos []string
	asJSON := false
	for _, a := range args {
		switch a {
		case "-h", "--help":
			fmt.Fprint(r.Out, t26EnvDoctorHelp)
			return nil
		case "--json":
			asJSON = true
			continue
		}
		if strings.HasPrefix(a, "-") {
			return t14Unrecognized(a)
		}
		pos = append(pos, a)
	}
	if len(pos) > 1 {
		return t14Unrecognized(strings.Join(pos[1:], " "))
	}
	var c *state.Campaign
	if len(pos) == 1 {
		opened, err := t14Open(root, pos[0])
		if err != nil {
			return err
		}
		c = opened
	}
	report, err := envgo.Doctor(c)
	if err != nil {
		return err
	}
	// r18 (MiniProver integration A1): the HOST prover CLIs are presence
	// rows the twin-era docker view never had — until now their absence
	// surfaced only as an exec `command not found` mid-pipeline. Printed
	// on STDERR: the stdout surface is twin-pinned, and the JSON report
	// carries a "host_provers" key for machines (--json included).
	host := hostProverRows()
	if objAt(report, "host_provers").Kind == validation.Null {
		report.O = append(report.O, validation.KV{K: "host_provers", V: host})
	}
	if asJSON {
		// cli.py's --json branch prints and `return`s: exit 0 even when the
		// report has issues (the CI exit code is the text surface).
		t14PrintJSON(r.Out, report)
		return nil
	}
	printHostProvers(r.Err, host)
	printEnvDoctor(r, report)
	if t26Truthy(report, "ok") {
		return nil
	}
	return t14ExitOut(1, "")
}

// printEnvDoctor is cli.py's human view, line for line.
func printEnvDoctor(r *Runner, report validation.Value) {
	docker := objAt(report, "docker")
	img := objAt(docker, "image")
	fmt.Fprintf(r.Out, "docker:        cli=%s  daemon=%s\n",
		yesNo(t26Truthy(docker, "cli")), yesNo(t26Truthy(docker, "daemon")))
	present, pinned := "ABSENT", " (tag reference!)"
	if t26Truthy(img, "present") {
		present = "present"
	}
	if t26Truthy(img, "pinned") {
		pinned = " (digest-pinned)"
	}
	fmt.Fprintf(r.Out, "image:         %s — %s%s\n", objStr(img, "image"),
		present, pinned)
	if d := objStr(img, "digest"); d != "" {
		fmt.Fprintf(r.Out, "  local digest: %s\n", d)
	}
	rpc := objAt(report, "fork_rpc")
	url := objStr(rpc, "url")
	if url == "" {
		url = "(unset)"
	}
	status := "UNREACHABLE (" + objStr(rpc, "error") + ")"
	if t26Truthy(rpc, "reachable") {
		status = "chain " + scalarStr(objAt(rpc, "chain_id"))
	}
	fmt.Fprintf(r.Out, "fork RPC:      %s — %s\n", url, status)
	// feedback-triage A7: when the doctor cross-checked the profiles
	// against the campaign floor (profile_fit), an available profile whose
	// evidence ceiling is below the floor is marked as such instead of a
	// bare "ok" — "present, floor will refuse".
	fit := objAt(report, "profile_fit")
	profs := []string{}
	for _, kv := range objAt(report, "profiles").O {
		verdict := "NO"
		if t26Truthy(kv.V, "") {
			verdict = "ok"
			if fit.Kind == validation.Obj {
				if fv := objStr(fit, kv.K); fv != "" && fv != "ok" {
					verdict = fv
				}
			}
		}
		profs = append(profs, kv.K+"="+verdict)
	}
	fmt.Fprintf(r.Out, "profiles:      %s\n", strings.Join(profs, " "))
	if cr := objAt(report, "campaign"); cr.Kind == validation.Obj {
		fmt.Fprintf(r.Out, "campaign:      max CONFIRMED floor %s, chain "+
			"pin %s\n", scalarStr(objAt(cr, "max_confirm_floor")),
			yesNo(t26Truthy(cr, "chain_pin")))
	}
	if solc := objAt(report, "solc"); solc.Kind == validation.Obj &&
		len(solc.O) > 0 {
		state := "not checked (no daemon)"
		if t26Truthy(solc, "present") {
			state = "present in image"
		} else if t26Truthy(solc, "checked") {
			state = "ABSENT from image"
		}
		fmt.Fprintf(r.Out, "solc:          %s — %s\n",
			scalarStr(objAt(solc, "required")), state)
	}
	issues := objAt(report, "issues").A
	if len(issues) > 0 {
		fmt.Fprint(r.Out, "\nISSUES:\n")
		for _, i := range issues {
			fmt.Fprintf(r.Out, "  - %s\n", scalarStr(i))
		}
	} else {
		fmt.Fprint(r.Out, "\nno issues — the environment can back the "+
			"evidence this campaign requires\n")
	}
}

// t26Truthy is Python truthiness for one object key.
func t26Truthy(v validation.Value, key string) bool {
	if key == "" {
		return pyTruthyCLI(v)
	}
	return pyTruthyCLI(objAt(v, key))
}

// yesNo is Python's `'yes' if x else 'NO'`.
func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "NO"
}

func init() {
	register(command{ord: 59, name: "env",
		line: "env doctor [<campaign>] [--json] environment doctor (read-only)",
		run:  runEnv})
}

// hostProverRows probes the two host prover CLIs the pipeline can drive.
// "probed" carries the --version first line (the same contract
// toolVersions writes into every EXEC record); missing says what to
// install, in the shape webv2 exec will hit later.
func hostProverRows() validation.Value {
	rows := validation.VObj()
	for _, tool := range []string{"minicertora", "miniprover"} {
		path, err := exec.LookPath(tool)
		if err != nil {
			rows.O = validation.SetOrAppend(rows.O, tool, validation.VObj(
				validation.KV{K: "present", V: validation.VBool(false)},
				validation.KV{K: "hint", V: validation.VStr(
					"absent from PATH — `uv tool install --editable " +
						"<repo>` or shim the venv bin/ (docs/MINICERTORA_" +
						"INTEGRATION.md §1, docs/MINIPROVER_INTEGRATION.md §1)"),
				}))
			continue
		}
		ver := "present (version probe failed)"
		res, verr := exec.Command(tool, "--version").Output()
		if verr == nil {
			line := strings.SplitN(strings.TrimSpace(string(res)), "\n", 2)[0]
			if line != "" {
				ver = line
			}
		}
		rows.O = validation.SetOrAppend(rows.O, tool, validation.VObj(
			validation.KV{K: "present", V: validation.VBool(true)},
			validation.KV{K: "path", V: validation.VStr(path)},
			validation.KV{K: "version", V: validation.VStr(ver)},
		))
	}
	return rows
}

func printHostProvers(w io.Writer, host validation.Value) {
	for _, kv := range host.O {
		row := kv.V
		if t26Truthy(row, "present") {
			fmt.Fprintf(w, "prover %s:   %s\n", kv.K, objStr(row, "version"))
		} else {
			fmt.Fprintf(w, "prover %s:   ABSENT — %s\n", kv.K, objStr(row, "hint"))
		}
	}
}

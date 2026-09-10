// cmd_doctor: `webv2 doctor <campaign> [--state-only] [--snapshot-only]
// [--json]` — health check + repair. Repairs oversized stage notes in the
// state file (the 1.7 GB self-DoS) and reports what the active pin actually
// covers (scope drift). The event log is never touched. cli.py cmd_doctor
// verbatim.
package cli

import (
	"fmt"
	"strconv"
	"strings"

	"websec/internal/doctor"
	"websec/internal/validation"
)

const t26DoctorUsage = `usage: webv2 doctor [-h] [--state-only] [--snapshot-only] [--json] campaign
`

const t26DoctorHelp = t26DoctorUsage + `
positional arguments:
  campaign

options:
  -h, --help       show this help message and exit
  --state-only     repair state only
  --snapshot-only  report pin scope only (no repair)
  --json
`

func runDoctor(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		var pos []string
		stateOnly, snapshotOnly, asJSON := false, false, false
		for _, a := range args {
			switch a {
			case "-h", "--help":
				fmt.Fprint(r.Out, t26DoctorHelp)
				return nil
			case "--state-only":
				stateOnly = true
				continue
			case "--snapshot-only":
				snapshotOnly = true
				continue
			case "--json":
				asJSON = true
				continue
			}
			if strings.HasPrefix(a, "-") && !isNegNumberCLI(a) {
				return t14Unrecognized(a)
			}
			pos = append(pos, a)
		}
		if len(pos) < 1 {
			return t14ArgparseErr(t26DoctorUsage, "doctor",
				"the following arguments are required: campaign")
		}
		if len(pos) > 1 {
			return t14Unrecognized(strings.Join(pos[1:], " "))
		}
		// Both modes at once used to resolve silently (snapshotOnly won, so
		// the requested repair never ran). They are alternatives.
		if stateOnly && snapshotOnly {
			return t14ArgparseErr(t26DoctorUsage, "doctor",
				"argument --snapshot-only: not allowed with argument "+
					"--state-only")
		}
		c, err := t14Open(root, pos[0])
		if err != nil {
			return err
		}
		var rep validation.Value
		switch {
		case snapshotOnly:
			snap, err := doctor.SnapshotScope(c)
			if err != nil {
				return err
			}
			rep = validation.VObj(validation.KV{K: "snapshot", V: snap})
		case stateOnly:
			st, err := doctor.StateHealth(c)
			if err != nil {
				return err
			}
			rep = validation.VObj(validation.KV{K: "state", V: st})
		default:
			rep, err = doctor.Doctor(c)
			if err != nil {
				return err
			}
		}
		if asJSON {
			t14PrintJSON(r.Out, rep)
			return nil
		}
		printDoctor(r, rep)
		return nil
	})
}

// printDoctor is the human view (cli.py's f-strings, verbatim).
func printDoctor(r *Runner, rep validation.Value) {
	if st := objAt(rep, "state"); st.Kind == validation.Obj {
		fmt.Fprintf(r.Out, "state: %s -> %s (freed %s)\n",
			mb(objFlt(st, "size_before")), mb(objFlt(st, "size_after")),
			mb(objFlt(st, "bytes_freed")))
		notes := objAt(st, "notes_truncated").A
		for _, t := range notes {
			fmt.Fprintf(r.Out, "  truncated note on stage %s: %s -> %s "+
				"chars\n", validation.PyReprStr(objStr(t, "stage")),
				pyThousands(objInt(t, "before")),
				pyThousands(objInt(t, "after")))
		}
		if len(notes) == 0 {
			fmt.Fprintln(r.Out, "  all stage notes within the cap")
		}
	}
	if snap := objAt(rep, "snapshot"); snap.Kind == validation.Obj {
		if objAt(snap, "active_snapshot").Kind == validation.Null {
			fmt.Fprintln(r.Out, "snapshot: "+objStr(snap, "note"))
		} else {
			fmt.Fprintf(r.Out, "snapshot %s: %s files, %s\n",
				objStr(snap, "active_snapshot"),
				scalarStr(objAt(snap, "files")),
				mb(objFlt(snap, "bytes")))
			if w := objStr(snap, "file_count_warning"); w != "" {
				fmt.Fprintf(r.Out, "  WARNING: %s\n", w)
			}
			for _, d := range firstN(objAt(snap, "top_directories").A, 5) {
				// Each entry is [name, count] (Python's list of pairs).
				if len(d.A) != 2 {
					continue
				}
				fmt.Fprintf(r.Out, "    %s files  %s/\n",
					pyRight(scalarStr(d.A[1]), 7), scalarStr(d.A[0]))
			}
		}
	}
	if pre := objAt(rep, "preflight"); pre.Kind == validation.Obj {
		fmt.Fprintln(r.Out, "preflight (sandbox readiness):")
		tags := map[string]string{"ok": "ok  ", "warn": "WARN", "fail": "FAIL",
			"na": "n/a "}
		for _, name := range []string{"docker", "image", "solc", "workdir"} {
			chk := objAt(objAt(pre, "checks"), name)
			fmt.Fprintf(r.Out, "  %s %s — %s\n", pyLeft(name, 7),
				tags[objStr(chk, "status")], objStr(chk, "detail"))
			if fix := objStr(chk, "fix"); fix != "" &&
				(objStr(chk, "status") == "fail" ||
					objStr(chk, "status") == "warn") {
				fmt.Fprintf(r.Out, "            fix: %s\n", fix)
			}
		}
	}
}

// mb is cli.py's `lambda b: f"{b / 1048576:.1f} MB"`.
func mb(b float64) string {
	return t26Fixed1(b/1048576) + " MB"
}

// pyThousands is Python's f"{n:,d}".
func pyThousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	out := b.String()
	if neg {
		out = "-" + out
	}
	return out
}

func firstN(vals []validation.Value, n int) []validation.Value {
	if len(vals) > n {
		return vals[:n]
	}
	return vals
}

func init() {
	register(command{ord: 3, name: "doctor",
		line: "doctor <campaign> [--state-only] [--snapshot-only] [--json]  health check + repair",
		run:  runDoctor})
}

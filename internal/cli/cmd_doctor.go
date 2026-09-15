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
			// r37b (F6): StateHealth parses the RAW state bytes and never
			// schema-validates, so a schema-dead state (budget:
			// "not-an-object") got the same clean bill a healthy campaign
			// gets — rc 0, "state: ... -> ...", nothing flagged — while
			// every other verb (the default doctor included, through
			// SnapshotScope's Campaign.State) refused rc 1. Refusing here
			// outright is NOT on the table: doctor is the one repair path
			// for a drifted state (the r14/r15 law — a state that fails
			// the schema must stay repairable — and the r36b note-cap
			// convergence pins both stand on --state-only reaching a
			// schema-dead file). So the run proceeds, but the bill stops
			// being clean: the JSON carries state_validation{ok,error}
			// and the human line says plainly that the state is
			// unreadable and what was NOT checked.
			if _, verr := c.State(); verr != nil {
				st.O = validation.SetOrAppend(st.O, "state_validation",
					validation.VObj(
						validation.KV{K: "ok", V: validation.VBool(false)},
						validation.KV{K: "error",
							V: validation.VStr(verr.Error())},
					))
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
		if sv := objAt(st, "state_validation"); sv.Kind == validation.Obj &&
			!objAt(sv, "ok").B {
			// r37b (F6): a schema-dead state may not bill as green. This
			// line precedes the size bill so the run never reads clean.
			fmt.Fprintf(r.Out, "  WARNING: campaign_state.json cannot be "+
				"parsed/validated (%s) — this bill is NOT clean: the "+
				"note-cap repair ran against raw bytes and every "+
				"schema-gated check was NOT performed; no other verb "+
				"can load this state\n", objStr(sv, "error"))
		}
		fmt.Fprintf(r.Out, "state: %s -> %s (freed %s)\n",
			mb(objFlt(st, "size_before")), mb(objFlt(st, "size_after")),
			mb(objFlt(st, "bytes_freed")))
		if objAt(st, "events_mirror_rebuilt").B {
			msg := "  rebuilt the events mirror from events.jsonl (the " +
				"ledger is the truth; the projection was stale)"
			if d := objAt(st, "events_mirror_delta"); d.Kind == validation.Obj {
				ch := objInt(d, "changed")
				dp := objInt(d, "dropped_from_projection")
				ad := objInt(d, "added_from_log")
				kept := objInt(d, "kept")
				switch {
				case ch > 0:
					// r37b (F3) + r39b (F1): the delta is POSITIONAL
					// (mirrorDelta compares same-index rows), so a
					// mid-ledger hole shifts every later row and counts
					// as "changed" although nobody edited a byte. The
					// old wording went on to call this delta "all the
					// evidence here" — false exactly when it matters: the
					// comparison cannot distinguish an edited payload
					// from a hole from a shifted alignment, and it says
					// nothing about scale. Name what is known — N
					// positional disagreements, three indistinguishable
					// causes — and keep the safe instruction: the
					// genuine tamper case must not read as benign.
					msg += fmt.Sprintf(": %d mirrored events DISAGREE "+
						"with the log at the same positions — the mirror "+
						"and the log disagree positionally at %d places, "+
						"and an edit, a hole and a shift are "+
						"indistinguishable from this comparison alone; "+
						"if you did not run the rewrite, treat the "+
						"campaign dir as tampered until a diff against "+
						"a known-good copy settles which", ch, ch)
				case dp > 0:
					// r17: tail truncation is the CHEAPEST forgery (seq
					// and chain stay valid when you delete the end) —
					// the rebuild must say what it erased, not just
					// count what it kept.
					msg += fmt.Sprintf(": %d events the projection remembered "+
						"are GONE from the log — a truncated tail keeps the "+
						"chain valid, so if you did not cut it, treat the "+
						"campaign dir as tampered (%d kept, %d adopted)",
						dp, kept, ad)
				default:
					msg += fmt.Sprintf(" (%d kept, %d adopted from log)",
						kept, ad)
				}
				// r39b (F1): the loss and the adoption are named IN
				// ADDITION to the positional delta, never instead of it.
				// The old if/else-if made the dropped branch dead whenever
				// any positional change existed — and on a capped mirror a
				// head-cut log is the NORMAL truncation shape, so 995
				// remembered events were erased with no line naming them.
				// The human surface may not omit what the JSON discloses.
				if ch > 0 && dp > 0 {
					// r40c P3: this sentence was INVERTED — it said
					// "the projection lost N events that the journal
					// records", but the journal is exactly the store
					// that no longer holds them: dp rows exist only in
					// the OLD projection, and the rebuilt mirror is
					// derived from the log (which is why doctor.json
					// calls the count dropped_from_projection). Say what
					// is known, in the sibling branch's own words: the
					// projection REMEMBERED them, the log no longer
					// holds them, and the rebuild erased them from the
					// mirror. The parenthetical stays the delta's own
					// numbers.
					msg += fmt.Sprintf("; %d event(s) the projection "+
						"remembered are GONE from the log — the rebuild "+
						"adopted the log's shorter history and erased "+
						"them from the mirror (%d kept, %d adopted "+
						"from the log)", dp, kept, ad)
				}
				if ch > 0 && ad > 0 {
					msg += fmt.Sprintf("; the rebuild adopted %d event(s) "+
						"from the log that the projection did not hold", ad)
				}
			}
			fmt.Fprintln(r.Out, msg)
		}
		if ref := objAt(st, "events_mirror_refused"); ref.Kind == validation.Str {
			fmt.Fprintf(r.Out, "  events mirror NOT rebuilt: %s\n"+
				"  fix the ledger damage through sanctioned verbs; "+
				"verify will keep naming it — do not hand-edit "+
				"events.jsonl\n", ref.S)
		}
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
		} else if ex := objAt(snap, "exists"); ex.Kind == validation.Bool && !ex.B {
			// r37b (F2): a MISSING ground-truth pin used to render as
			// "snapshot <id>: None files, 0.0 MB" — an empty-but-present
			// snapshot — because this branch had no exists/note case and
			// the missing shape carries no files/bytes keys at all. The
			// JSON honestly says exists:false + note; the human line
			// carries the same fact now.
			fmt.Fprintf(r.Out, "snapshot %s: MISSING — %s\n",
				objStr(snap, "active_snapshot"), objStr(snap, "note"))
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

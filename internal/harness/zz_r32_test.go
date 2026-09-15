package harness

// zz_r32_test.go — hostile round 32, the parse half.
//
// Three of the four findings trace to ONE line: cli.invocationBound took the
// harness KIND and threw it away (`_ = kind`), so a single Python-flavoured
// parse was applied to three tools with three different command-line
// languages. Every expectation below is OBSERVED on this box, not inferred:
//
//	forge 1.8.1 (Rust/clap + foundry config)
//	  forge test --fuzz-runs 4_000  -> error: invalid value '4_000' for
//	      '--fuzz-runs <RUNS>': invalid digit found in string      (exit 2)
//	  forge test --fuzz-runs ٤٢     -> same "invalid digit found in string"
//	  forge test --fuzz-runs $'500\r' -> same "invalid digit found in string"
//	  forge test --fuzz-runs ' 5'   -> same "invalid digit found in string"
//	  forge test --fuzz-runs ''     -> "cannot parse integer from empty string"
//	  forge test --fuzz-runs +5     -> accepted ("Nothing to compile")
//	  forge test --fuzz-runs 0005   -> accepted (5)
//	  forge test --fuzz-runs 4294967295 -> accepted (u32::MAX)
//	  forge test --fuzz-runs 4294967296 -> Error: failed to extract foundry
//	      config: foundry config error: invalid value unsigned int
//	      `4294967296`, expected u32 for setting `fuzz.runs`         (exit 1)
//	  forge test --fuzz-runs 0      -> foundry config error: `fuzz.runs`
//	      must be greater than 0
//	  forge test --fuzz-runs 0 --fuzz-runs 7 -> error: the argument
//	      '--fuzz-runs <RUNS>' cannot be used multiple times         (exit 2)
//	  forge test --loop 3           -> error: unexpected argument '--loop'
//	  forge test --loop-bound 3     -> error: unexpected argument
//	      '--loop-bound'
//
//	halmos 0.3.3 (argparse, type=int -> Python int)
//	  halmos --loop 4_000 / ٤٢ / +5 / 0 / -1 / 4294967296 -> all accepted
//	  halmos --loop 0x10 / 1e3 / ''  -> usage error               (exit 2)
//	  halmos --loop 4 --loop 7       -> accepted, last wins
//	  halmos --fuzz-runs 500 -> halmos: error: unrecognized arguments:
//	      --fuzz-runs 500
//
//	minicertora 0.1.0 (click, type=int -> Python int)
//	  minicertora --loop-bound 4_000 a.sol a.mspec -> accepted
//	  minicertora --loop-bound 0x10 a.sol a.mspec  -> Error: Invalid value
//	      for '--loop-bound': '0x10' is not a valid integer.
//	  minicertora --loop-bound 0 a.sol a.mspec -> {"verdict": "UNKNOWN",
//	      "reason": "malformed-input", "details": "--loop-bound must be
//	      >= 1, got 0"}
//	  minicertora --loop-bound 4 --loop-bound 0 a.sol a.mspec -> the 0 wins
//	  minicertora --loop 4 a.sol a.mspec -> Error: No such option '--loop'.
//	      (Did you mean one of: '--help', '--loop-bound'?)
//	  minicertora --fuzz-runs 200 a.sol a.mspec -> Error: No such option
//	      '--fuzz-runs'.
//
// No forge process ever ran under a value forge rejects, so a ledger that
// reads one as a number is a lie about an invocation that cannot exist.

import (
	"regexp"
	"strings"
	"testing"

	"websec/internal/validation"
)

// r32Duration matches the shape the old wording put the BOUND in ("4s",
// "8s", "-1s"): digits immediately followed by a seconds suffix.
var r32Duration = regexp.MustCompile(`[0-9]+\s*s\b`)

// ---------------------------------------------------------------------
// F1: forge's bound is parsed by FORGE's rule, not Python's
// ---------------------------------------------------------------------

// TestR32ForgeValuesFollowForge is F1's parse-level pin: the auditor's six
// repro values, each with the real tool's refusal, plus the controls that
// prove the floor is a property of the VALUE and not a blanket refusal.
//
// MUTATION (restore the r31 body of boundFromArgv's value arm — always
// `parseClickInt(last.value)` — or make invocationBound ignore the kind):
// every rejected row reads as a number (4_000 -> 4000, ٤٢ -> 42,
// "500\r" -> 500, 4294967296 -> 4294967296, the duplicate -> 7) and this
// test fails on the first one with
// `InvocationBoundKind(forge-fuzz, "forge test --fuzz-runs 4_000") = 4000,
// want the degenerate floor (-1)`.
func TestR32ForgeValuesFollowForge(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		// quoted marks a value a shell would only pass as ONE word when
		// the recorded command quotes it (the leading-space row): the
		// command string is the tool's argv spelled the way the shell
		// that ran it had to spell it.
		quoted bool
	}{
		// forge: "invalid value '4_000' for '--fuzz-runs <RUNS>': invalid
		// digit found in string" — Rust's u32 parser has no underscores.
		{"underscore grouping", "4_000", false},
		// forge: "invalid value '٤٢' …: invalid digit found in string" —
		// Rust is ASCII-only where Python's int() takes any Nd digit.
		{"arabic-indic 42", "\u0664\u0662", false},
		// The CR stays INSIDE the word (r30 P2-1: CR is not IFS
		// whitespace), and forge: "invalid value '500\r' …: invalid digit
		// found in string". Python's int() strips it ("500\r" -> 500).
		{"trailing CR", "500\r", false},
		{"leading space", " 5", true},
		// foundry config: "invalid value unsigned int `4294967296`,
		// expected u32 for setting `fuzz.runs`" — this used to record
		// k=4294967296, a bound no forge could have configured.
		{"one past u32", "4294967296", false},
		{"zero", "0", false},
		{"negative (equals form is a value)", "-1", false},
		{"hex", "0x10", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := tc.value
			if tc.quoted {
				value = "'" + value + "'"
			}
			for _, form := range []string{
				"forge test --fuzz-runs ",
				"forge test --fuzz-runs=",
			} {
				got := InvocationBoundKind(ForgeFuzz, form+value)
				if !BoundFloors(got) {
					t.Fatalf("InvocationBoundKind(forge-fuzz, %q) = %d, "+
						"want the floor (%d): forge refuses this "+
						"value and no run exists under it",
						form+value, got, BoundDegenerate)
				}
			}
			// The kind-free reader agrees, because the command names
			// forge itself: section 11 re-derives through this one.
			if got := InvocationBound("forge test --fuzz-runs " +
				value); !BoundFloors(got) {
				t.Fatalf("InvocationBound(%q) = %d, want the floor",
					"forge test --fuzz-runs "+value, got)
			}
		})
	}
	// Controls: the values forge ACCEPTS must still read as numbers —
	// otherwise "floor everything" would pass the rows above.
	for _, tc := range []struct {
		name  string
		value string
		want  int
	}{
		{"plain", "500", 500},
		{"u32::MAX is legal", "4294967295", 4294967295},
		// OBSERVED: forge test --fuzz-runs +5 -> "Nothing to compile"
		// (exit 0). Rust's u32::from_str accepts one leading '+'.
		{"A plus sign is a value for Rust", "+5", 5},
		{"zero-padded", "0005", 5},
		{"one", "1", 1},
	} {
		t.Run("control/"+tc.name, func(t *testing.T) {
			if got := InvocationBoundKind(ForgeFuzz,
				"forge test --fuzz-runs "+tc.value); got != tc.want {
				t.Fatalf("forge accepts %q as %d, got %d", tc.value,
					tc.want, got)
			}
		})
	}
	// A repeated --fuzz-runs is refused by clap, not last-wins. OBSERVED:
	// "error: the argument '--fuzz-runs <RUNS>' cannot be used multiple
	// times". The old reading bound 7 here.
	dup := "forge test --fuzz-runs 0 --fuzz-runs 7"
	if got := InvocationBoundKind(ForgeFuzz, dup); !BoundFloors(got) {
		t.Fatalf("InvocationBoundKind(forge-fuzz, %q) = %d, want the "+
			"floor: clap refuses a repeated --fuzz-runs", dup, got)
	}
	// The two PYTHON tools keep Python's int, which is what their parsers
	// really do: 4_000 is 4000 there, and forge's rule must not leak.
	for _, tc := range []struct {
		kind Kind
		cmd  string
	}{
		{MiniCertora, "miniprover run --loop-bound 4_000"},
		{MiniCertora, "minicertora V.sol INV.mspec --loop-bound 4_000"},
		{Halmos, "halmos check --loop 4_000"},
		{MiniCertora, "miniprover run --loop-bound \u0664\u0662"},
		{Halmos, "halmos check --loop \u0664\u0662"},
	} {
		if got := InvocationBoundKind(tc.kind, tc.cmd); got != 4000 &&
			got != 42 {
			t.Fatalf("InvocationBoundKind(%q, %q) = %d: the Python "+
				"tools accept underscores and Nd digits", tc.kind,
				tc.cmd, got)
		}
	}
}

// ---------------------------------------------------------------------
// F2: a LONE foreign bound flag is a flag the tool does not have
// ---------------------------------------------------------------------

// TestR32ForeignBoundFlagFloorsTheWrongTool is F2's parse-level pin: the
// three cross-kind pairs, each with the real tool's own refusal quoted, on
// BOTH the kind-aware entry point (the bind) and the kind-free one (the
// audit's re-derivation, which derives the tool from argv[0]).
//
// MUTATION (delete the foreign-flag loop in boundFromArgv, keeping only
// the old two-flag mixed check): `InvocationBoundKind(ForgeFuzz,
// "forge test --loop 3")` = 3 and this test fails with
// `InvocationBoundKind(forge-fuzz, "forge test --loop 3") = 3, want the
// degenerate floor (-1): forge has no --loop`.
func TestR32ForeignBoundFlagFloorsTheWrongTool(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kind   Kind
		cmd    string
		flag   string
		tool   string
		refuse string
	}{
		{"forge does not have --loop", ForgeFuzz, "forge test --loop 3",
			"--loop", "forge", "unexpected argument"},
		{"forge does not have --loop-bound", ForgeFuzz,
			"forge test --loop-bound 3", "--loop-bound", "forge",
			"unexpected argument"},
		{"halmos does not have --fuzz-runs", Halmos,
			"halmos check --fuzz-runs 500", "--fuzz-runs", "halmos",
			"unrecognized arguments"},
		{"minicertora does not have --fuzz-runs", MiniCertora,
			"minicertora V.sol INV.mspec --fuzz-runs 500", "--fuzz-runs",
			"minicertora", "No such option"},
		{"the twin does not have --fuzz-runs either", MiniCertora,
			"miniprover run --loop-bound 4 --fuzz-runs 500",
			"--fuzz-runs", "minicertora", "No such option"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, why := InvocationBoundKindReason(tc.kind, tc.cmd)
			if !BoundFloors(k) {
				t.Fatalf("InvocationBoundKindReason(%q, %q) = (%d, %q), "+
					"want the degenerate floor: %s", tc.kind, tc.cmd, k,
					why, tc.refuse)
			}
			if !strings.Contains(why, tc.flag) || !strings.Contains(why,
				tc.tool) {
				t.Fatalf("the floor must name the flag and the tool "+
					"(%q, %q): %q", tc.flag, tc.tool, why)
			}
			if !strings.Contains(why, tc.refuse) {
				t.Fatalf("the floor must name the observed refusal "+
					"%q: %q", tc.refuse, why)
			}
			// The kind-free reader: argv[0] names the tool, so section
			// 11's re-derivation reaches the same floor.
			fk, fwhy := InvocationBoundReason(tc.cmd)
			if !BoundFloors(fk) || fwhy == "" {
				t.Fatalf("InvocationBoundReason(%q) = (%d, %q), want the "+
					"same floor", tc.cmd, fk, fwhy)
			}
			// End to end: no rung may ride it, whatever the bytes say.
			rung, summary := MapRun(tc.kind, []byte(forgePass), false, k,
				why)
			if rung != RungInconclusive ||
				!strings.Contains(summary, "degenerate-bound") ||
				!strings.Contains(summary, "invocation-refused") {
				t.Fatalf("a foreign bound flag must floor as a refusal: "+
					"%q %q", rung, summary)
			}
			if cls, advice, ok := Disposition(summary); !ok ||
				cls != EscalateBound || advice == "" {
				t.Fatalf("Disposition(%q) = %q %q %v, want "+
					"escalate-bound", summary, cls, advice, ok)
			}
		})
	}
	// The boundary r32 F2 must NOT widen into "any unknown option floors":
	// a flag the tool HAS plus an unrelated unknown option still binds, and
	// the unknown word is not mistaken for a bound flag.
	for _, tc := range []struct {
		name string
		kind Kind
		cmd  string
		want int
	}{
		{"an unrelated long option", ForgeFuzz,
			"forge test --match-test test_* --fuzz-runs 500", 500},
		{"an unrelated unknown option before the bound", ForgeFuzz,
			"forge test --loopx 5 --fuzz-runs 500", 500},
		{"a lookalike suffix is not a foreign bound flag", MiniCertora,
			"miniprover run --loop-boundx 5 --loop-bound 4", 4},
		{"halmos's own flag with an unrelated option", Halmos,
			"halmos check --match-contract Inv1 --loop 100", 100},
	} {
		t.Run("control/"+tc.name, func(t *testing.T) {
			if got := InvocationBoundKind(tc.kind, tc.cmd); got != tc.want {
				t.Fatalf("InvocationBoundKind(%q, %q) = %d, want %d",
					tc.kind, tc.cmd, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------
// F8: a command that is PRESENT but not a string is not an absent command
// ---------------------------------------------------------------------

// TestR32NonStringCommandIsUnreadable pins F8 at the record reader: the
// blessed shape was a record whose `command` was an ARRAY
// (["forge","test","--fuzz-runs","0"]) or a NUMBER (500). The string
// reader returned "" for both, "" parses as "no bound flag", and the run
// was blessed "proved bounded (bound UNSTATED)" although the command was
// stated AND degenerate.
//
// MUTATION (make RecordCommandField return ("", false, "") for a non-string
// — that is, go back to recordStr): the array row fails with
// `RecordInvocationBoundReason(forge-fuzz, array command) = (0, ""), want
// (BoundUnreadable, …)` and DecideBound blesses proved-bounded with the
// unbound suffix, which is the auditor's exact signature.
func TestR32NonStringCommandIsUnreadable(t *testing.T) {
	for _, tc := range []struct {
		name  string
		shape string
		val   validation.Value
	}{
		{"array", "array", validation.VArr(
			validation.VStr("forge"), validation.VStr("test"),
			validation.VStr("--fuzz-runs"), validation.VStr("0"))},
		{"number", "number", validation.VInt(500)},
		{"float", "number", validation.VFloat(4.5)},
		{"boolean", "boolean", validation.VBool(true)},
		{"object", "object", validation.VObj(
			validation.KV{K: "argv", V: validation.VArr()})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := rdRecord(
				validation.KV{K: "exec_id", V: validation.VStr("EXEC-1")},
				validation.KV{K: "command", V: tc.val},
				validation.KV{K: "exit_status", V: validation.VInt(0)})
			cmd, present, why := RecordCommandField(rec)
			if cmd != "" || !present {
				t.Fatalf("RecordCommandField = (%q, %v, %q): a present "+
					"non-string is not an absent command", cmd, present,
					why)
			}
			if !strings.Contains(why, "not a string") ||
				!strings.Contains(why, tc.shape) {
				t.Fatalf("the reason must name the shape %q: %q",
					tc.shape, why)
			}
			k, kw := RecordInvocationBoundReason(ForgeFuzz, rec)
			if k != BoundUnreadable || !BoundFloors(k) || kw == "" {
				t.Fatalf("RecordInvocationBoundReason = (%d, %q), want "+
					"BoundUnreadable with the shape reason", k, kw)
			}
			// End to end through the bind's own decision: the bytes that
			// would prove under a good invocation must not.
			rung, summary, proof, bk := DecideBound(ForgeFuzz,
				validation.VNull(), []byte(forgePass), rec, nil, false,
				0, 0, "INV-1")
			if rung != RungInconclusive || bk != nil ||
				proof.Kind != validation.Null {
				t.Fatalf("a non-string command blessed: %q %q %v %s",
					rung, summary, bk,
					validation.CanonCompact(proof))
			}
			if !strings.Contains(summary, "degenerate-bound") ||
				!strings.Contains(summary, "invocation-unreadable: the "+
					"record's command field is not a string (JSON "+
					tc.shape+")") {
				t.Fatalf("the floor must name the shape: %q", summary)
			}
			if cls, _, ok := Disposition(summary); !ok ||
				cls != EscalateBound {
				t.Fatalf("Disposition(%q) = %q ok=%v, want "+
					"escalate-bound", summary, cls, ok)
			}
		})
	}
	// The documented choice, pinned so it cannot drift silently: an ABSENT
	// or NULL command is genuinely "no invocation on record" — no flag, no
	// value, no tool — so it keeps its old reading (0, "no bound"), and
	// the summary can only say UNSTATED rather than asserting a number no
	// tool ran under. The exit status is what gates a clean run there
	// (RecordExitStatus / r28b F2).
	for _, tc := range []struct {
		name string
		rec  validation.Value
	}{
		{"absent", rdRecord(validation.KV{K: "exec_id",
			V: validation.VStr("EXEC-1")})},
		{"null", rdRecord(validation.KV{K: "exec_id",
			V: validation.VStr("EXEC-1")},
			validation.KV{K: "command", V: validation.VNull()})},
	} {
		t.Run("missing/"+tc.name, func(t *testing.T) {
			k, why := RecordInvocationBoundReason(ForgeFuzz, tc.rec)
			if k != 0 || why != "" || BoundFloors(k) {
				t.Fatalf("RecordInvocationBoundReason = (%d, %q), want "+
					"the unstated reading", k, why)
			}
			if _, present, _ := RecordCommandField(tc.rec); present {
				t.Fatal("an absent/null command is not present")
			}
		})
	}
}

// ---------------------------------------------------------------------
// F3: the timeout arm floors too, and never prints a bound as seconds
// ---------------------------------------------------------------------

// TestR32TimeoutFloorsAndPrintsNoBoundAsSeconds pins F3: MapRun's timeout
// arm ran BEFORE the floor test and printed the BOUND in the seconds slot
// ("timeout after -1s" for --fuzz-runs 0, "timeout after 4s" for a run
// whose wall clock was 2.76s, "timeout after 7s" for a duplicate).
//
// MUTATION (restore the old first arm —
// `return RungInconclusive, fmt.Sprintf("timeout after %ss", boundText(k))`
// before the BoundFloors check): the -1 row fails with
// `MapRun(forge-fuzz, timedOut, k=-1) = "inconclusive (timeout after -1s)",
// want the degenerate-bound floor`, and the accepted-bound row prints the
// bound as a duration.
func TestR32TimeoutFloorsAndPrintsNoBoundAsSeconds(t *testing.T) {
	// A flooring bound floors on the timeout path exactly like the
	// untimed arm — same predicate, same class, same wording home.
	for _, k := range []int{BoundDegenerate, BoundUnreadable} {
		rung, summary := MapRun(ForgeFuzz, []byte(forgePass), true, k,
			"the record's command field is not a string (JSON array)")
		if rung != RungInconclusive ||
			!strings.Contains(summary, "degenerate-bound") {
			t.Fatalf("a flooring bound (k=%d) must floor a killed run: "+
				"%q %q", k, rung, summary)
		}
		if cls, _, ok := Disposition(summary); !ok ||
			cls != EscalateBound {
			t.Fatalf("a timeout floor keeps the escalate-bound class: "+
				"%q", summary)
		}
	}
	// A killed run under a STATED bound carries no number at all: MapRun
	// holds no record and therefore no wall clock, and the bound is not a
	// duration.
	for _, k := range []int{0, 4, 256, BoundCapped} {
		rung, summary := MapRun(Halmos, []byte(halmosProvedFlag), true, k)
		if rung != RungInconclusive || summary != "inconclusive (timeout)" {
			t.Fatalf("MapRun(timedOut, k=%d) = %q %q, want the "+
				"numberless timeout", k, rung, summary)
		}
	}
	// The three shapes the finding named, at the level the bind decides
	// them: forge killed under --fuzz-runs 0 (floor), under --fuzz-runs 4
	// (no number), and under a duplicate (floor, because clap refuses it).
	cases := []struct {
		name    string
		cmd     string
		floor   bool
		summary string
	}{
		{"--fuzz-runs 0", "forge test --fuzz-runs 0", true,
			"degenerate-bound"},
		{"--fuzz-runs 4", "forge test --fuzz-runs 4", false,
			"inconclusive (timeout)"},
		{"duplicate --fuzz-runs", "forge test --fuzz-runs 0 --fuzz-runs 7",
			true, "degenerate-bound"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := r31ExecRecord(tc.cmd)
			k, why := RecordInvocationBoundReason(ForgeFuzz, rec)
			rung, summary, _, bk := DecideBound(ForgeFuzz,
				validation.VNull(), []byte(forgePass), rec, nil, true,
				k, 137, "INV-1")
			if rung != RungInconclusive || bk != nil {
				t.Fatalf("a killed run never binds: %q %q %v", rung,
					summary, bk)
			}
			if !strings.Contains(summary, tc.summary) {
				t.Fatalf("summary = %q, want it to contain %q (bound "+
					"reason %q)", summary, tc.summary, why)
			}
			if strings.Contains(summary, "timeout after") ||
				r32Duration.MatchString(summary) {
				t.Fatalf("the timeout summary printed a bound as a "+
					"duration: %q", summary)
			}
		})
	}
	// The minicertora half: "no clean completion" is the RUNTIME class, so
	// a killed run under a bound the twin would refuse lost the
	// escalate-bound advice it was owed. Same predicate, same class as the
	// untimed arm — and the runtime wording still stands for an honest
	// bound, byte for byte.
	rec := rdRecord(
		validation.KV{K: "exec_id", V: validation.VStr("EXEC-1")},
		validation.KV{K: "command",
			V: validation.VStr("miniprover run --loop-bound 0")},
		validation.KV{K: "exit_status", V: validation.VInt(-1)})
	k, _ := RecordInvocationBoundReason(MiniCertora, rec)
	rung, summary, _, bk := DecideBound(MiniCertora, rdInv("x"),
		[]byte(mcProven), rec, nil, true, k, -1, MspecRuleName("INV-1"))
	if rung != RungInconclusive || bk != nil {
		t.Fatalf("a killed minicertora run never binds: %q %q %v", rung,
			summary, bk)
	}
	if !strings.Contains(summary, "degenerate-bound") {
		// The twin's <1 value keeps the r26/r27 class wording (no reason:
		// it is pinned byte-for-byte for the minicertora arm), but it is
		// the DEGENERATE class, not the runtime one.
		t.Fatalf("the minicertora timeout floor must keep the "+
			"degenerate-bound class: %q", summary)
	}
	if cls, advice, ok := Disposition(summary); !ok ||
		cls != EscalateBound || advice == "" {
		t.Fatalf("Disposition(%q) = %q %q %v, want escalate-bound "+
			"(the advice the runtime class silently replaced)", summary,
			cls, advice, ok)
	}
	honest := rdRecord(
		validation.KV{K: "exec_id", V: validation.VStr("EXEC-2")},
		validation.KV{K: "command",
			V: validation.VStr("miniprover run --loop-bound 8")},
		validation.KV{K: "exit_status", V: validation.VInt(137)})
	hk, _ := RecordInvocationBoundReason(MiniCertora, honest)
	hRung, hSummary, _, _ := DecideBound(MiniCertora, rdInv("x"),
		[]byte(mcProven), honest, nil, true, hk, 137, MspecRuleName("INV-1"))
	if hRung != RungInconclusive || !strings.HasPrefix(hSummary,
		"inconclusive (no clean completion; loop bound was 8)") {
		t.Fatalf("an honest bound's timeout keeps the runtime wording: "+
			"%q %q", hRung, hSummary)
	}
	if cls, _, ok := Disposition(hSummary); !ok || cls != EscalateRuntime {
		t.Fatalf("Disposition(%q) = %q ok=%v, want escalate-runtime",
			hSummary, cls, ok)
	}
}

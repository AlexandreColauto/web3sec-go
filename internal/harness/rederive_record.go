package harness

import (
	"websec/internal/validation"
)

// recordField is dict.get(key) over an exec record (absent vs null kept
// distinct by the ok flag).
func recordField(rec validation.Value, key string) validation.Value {
	if rec.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range rec.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

// recordStr is rec[key] as a string; an absent or non-string field reads "".
func recordStr(rec validation.Value, key string) string {
	if v := recordField(rec, key); v.Kind == validation.Str {
		return v.S
	}
	return ""
}

// RecordExitStatus is THE reading of an exec record's exit_status, one home
// for the bind and for the audit (r28b F2). An int exit_status is the run's
// own report; anything else — absent, null, or an integer too wide for
// int64 — is "unknown" (-2), which MapMinicertora's negative floor refuses
// ("inconclusive (exit output unmapped)").
//
// The absent/null default is load-bearing and was the F2 lie: section 11's
// blessing arm read this field with `es := 0` and no guard, so a chain-valid
// forged pair (slot + event + prose all claiming proved-bounded) over a
// record whose exit_status was ABSENT or null re-derived proved-bounded from
// a PROVEN line and audited green — absence read as "the tool exited 0".
// Absence is inconclusive, never a blessing.
func RecordExitStatus(rec validation.Value) int {
	if v := recordField(rec, "exit_status"); v.Kind == validation.Int &&
		v.Big == "" {
		return int(v.I)
	}
	return -2
}

// RecordTimedOut is the MapRun timedOut bit of a record: TimedOutBit over
// RecordExitStatus, so a record with no usable exit status reads as NOT
// timed out while its exit status still floors the mapper at -2. (The two
// are deliberately different questions: -2 is "never reported a clean
// exit", the timeout bit is "the sandbox killed it".)
func RecordTimedOut(rec validation.Value) bool {
	return TimedOutBit(RecordExitStatus(rec))
}

// RecordCommand is the exec record's command string ("" when absent). It is
// the TEXT, not the reading: the invocation bound both halves use is
// RecordInvocationBound(KIND, rec), which shapes the parse by the tool the
// rung's kind names (r33 F1).
//
// r32 F8: a command field that is PRESENT but not a string is NOT an
// absent command, and this reader must not launder one into the other —
// RecordCommandField is the shape-aware reader both halves now use, and
// RecordInvocationBoundReason is the bound it feeds. This one keeps its
// signature (and its "" for a non-string) because callers that only want
// "the command text, if any" — cli.harnessCompilerPin's --solc-path scan —
// have no floor to raise.
//
// The pre-r33 sentence here ("The invocation bound is
// InvocationBound(RecordCommand(rec)) for both the bind and the audit") was
// TRUE when it was written and became the F1 lie: the bind had already moved
// to the kind-aware reader while all three section-11 sites still passed the
// kind-free one, so one record could be read two ways. Both halves read
// RecordInvocationBound now; nothing in either package calls the kind-free
// reader for a rung's bound.
func RecordCommand(rec validation.Value) string {
	cmd, _, _ := RecordCommandField(rec)
	return cmd
}

// RecordCommandField reads the exec record's `command` field with its
// SHAPE: the command string, whether the record STATES an invocation at
// all, and — for a field that is present but not a string — the reason the
// invocation cannot be read.
//
// r32 F8: this is the asymmetry r28b closed for exit_status. The record
// read path does no schema check, so a forged record could carry `command`
// as an ARRAY (["forge","test","--fuzz-runs","0"]) or a NUMBER (500).
// RecordCommand's string reader returned "" for both, "" parses as "no
// bound flag", and the run was blessed "proved bounded (bound UNSTATED)"
// although the command was stated AND degenerate — a blessing over an
// invocation nothing can even read.
//
//	absent key  -> ("", false, ""): genuinely "no invocation on record".
//	null value  -> ("", false, ""): the same statement in its explicit
//	               spelling, which is why the two share an arm.
//	string      -> (s, true, "")
//	anything else -> ("", true, "the record's command field is not a
//	               string (JSON <shape>)"), and the caller floors it as
//	               UNREADABLE.
//
// Why absent/null may keep its old behaviour: with no command on record
// there is no invocation to be degenerate ABOUT — no flag, no value, no
// tool — so the rung rests on the run's own output and the summary can only
// say "bound UNSTATED". It asserts no number, and no tool could have been
// refused a flag the record does not contain. (Absence is still not
// evidence of a clean run: the exit status gates that separately, and
// r28b F2 floors an absent exit_status.) A present non-string, by
// contrast, IS a statement about how the tool was invoked — one written in
// a shape no command line can have — so it floors.
func RecordCommandField(rec validation.Value) (command string, present bool,
	why string) {
	v := recordField(rec, "command")
	switch v.Kind {
	case validation.Str:
		return v.S, true, ""
	case validation.Null:
		return "", false, ""
	}
	return "", true, "the record's command field is not a string (JSON " +
		commandShapeName(v) + ")"
}

// commandShapeName names the JSON shape of a command field the record read
// path accepted without a schema check, for the floor summary ("JSON
// array", "JSON number"). It names the SHAPE, never a guess at the value.
func commandShapeName(v validation.Value) string {
	switch v.Kind {
	case validation.Arr:
		return "array"
	case validation.Int:
		return "number"
	case validation.Flt:
		return "number"
	case validation.Bool:
		return "boolean"
	case validation.Obj:
		return "object"
	}
	return "value"
}

// RecordInvocationBoundReason is THE reading of an exec record's invocation
// bound: the shape check (RecordCommandField, r32 F8) and then the
// tool-shaped parse (InvocationBoundKindReason, r32 F1/F2) with the
// harness KIND the caller holds.
//
// Both halves of the law read it: the bind (cli.verifyHarnessResult) and
// harness.DecideBound's own authoritative re-read, so section 11's
// re-derivation — which passes whatever bound it computed — cannot hold a
// second opinion about a record whose command is a foreign flag's, a
// value the tool refuses, or a shape that is not a string at all.
func RecordInvocationBoundReason(kind Kind, rec validation.Value) (int,
	string) {
	cmd, present, why := RecordCommandField(rec)
	if why != "" {
		return BoundUnreadable, why
	}
	if !present {
		return 0, ""
	}
	return InvocationBoundKindReason(kind, cmd)
}

// RecordInvocationBound is RecordInvocationBoundReason without the reason.
func RecordInvocationBound(kind Kind, rec validation.Value) int {
	k, _ := RecordInvocationBoundReason(kind, rec)
	return k
}

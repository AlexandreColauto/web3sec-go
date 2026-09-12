// minicertora.go: MapMinicertora — the G8 third kind's outcome mapper.
// Where halmos/forge-fuzz print prose (outcome.go), MiniCertora prints a
// JSON-lines verdict stream: one object per line, exactly one of which is
// attributed to this invariant by the scaffold-pinned rule name
// (mspec.go). The scan is structural — a rule key, a verdict key, an exit
// status — and never reads prose.
//
// Fail-open-to-inconclusive law: inherited from outcome.go verbatim. A
// prover that disagrees with itself gets zero trust, so a malformed line,
// an abort line (no rule key), zero or two attributed lines, an
// exit-status/verdict disagreement and an unrecognised verdict all land
// inconclusive. The proof sidecar is captured for the three verdict rungs
// only (UNKNOWN included); every refusal returns a null sidecar rather
// than a partial one.
//
// Timeout law: it lives in the CALLER. `verify --harness-result` checks
// harnessTimedOut and maps a killed run to inconclusive before this
// function is ever invoked, so the timeout-wins rule is unchanged. A
// negative exitStatus means no process exit was recorded at all, so this
// mapper skips ONLY the contradiction check — with no exit there is
// nothing to contradict — and still maps the attributed line's verdict.
// That boundary is the caller contract's, not a second timeout rail.
package harness

import (
	"fmt"
	"strings"

	"websec/internal/validation"
)

// MapMinicertora maps one MiniCertora run (the raw stdout bytes, the exec
// record's exit_status, and the scaffold-pinned rule name) onto the rung
// vocabulary of outcome.go, plus the proof sidecar captured verbatim.
// proof is VNull() when no verdict line was attributed or when the run is
// refused. boundedK is non-nil only for proved-bounded.
//
// The law is applied in stream order: blank lines are skipped, and the
// first line that is not a JSON object, that carries no rule key, or that
// duplicates an already attributed line decides the outcome.
func MapMinicertora(raw []byte, exitStatus int, ruleName string) (rung,
	summary string, proof validation.Value, boundedK *int) {
	verdict, obj, refusal, ok := mcAttributed(raw, ruleName)
	if !ok {
		return RungInconclusive, refusal, validation.VNull(), nil
	}
	if want, known := mcExpectedExit(verdict); known && exitStatus >= 0 &&
		exitStatus != want {
		return RungInconclusive, fmt.Sprintf("inconclusive "+
			"(report-contradiction: exit %d with verdict %s)",
			exitStatus, verdict), validation.VNull(), nil
	}
	switch verdict {
	case "PROVEN":
		k, ok := mcIntAt(obj, "bounds", "loop_bound")
		if !ok {
			return RungProvedBounded, "proved bounded",
				mcProof(obj), nil
		}
		return RungProvedBounded,
			fmt.Sprintf("proved bounded (k=%d)", k), mcProof(obj), &k
	case "VIOLATED":
		return RungCounterexample, mcCounterexampleSummary(obj),
			mcProof(obj), nil
	case "UNKNOWN":
		return RungInconclusive, mcUnknownSummary(obj), mcProof(obj), nil
	default:
		return RungInconclusive, "inconclusive (exit output unmapped)",
			validation.VNull(), nil
	}
}

// mcAttributed scans the JSONL stream for the single verdict line whose
// rule field matches ruleName. ok=false carries the byte-exact refusal
// summary; verdict is the attributed line's own verdict string.
func mcAttributed(raw []byte, ruleName string) (verdict string,
	obj validation.Value, refusal string, ok bool) {
	var found validation.Value
	seen := false
	for _, line := range strings.Split(string(raw), "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		v, err := validation.ParseOrdered([]byte(t))
		if err != nil || v.Kind != validation.Obj {
			return "", validation.VNull(),
				"inconclusive (output is not JSONL)", false
		}
		rv, hasRule := mcField(v, "rule")
		if !hasRule {
			return "", validation.VNull(), mcAbortSummary(v), false
		}
		if rv.Kind != validation.Str || rv.S != ruleName {
			continue
		}
		if seen {
			return "", validation.VNull(),
				"inconclusive (duplicate verdict lines for rule)",
				false
		}
		found, seen = v, true
	}
	if !seen {
		return "", validation.VNull(), fmt.Sprintf(
			"inconclusive (no verdict line for rule %s)", ruleName), false
	}
	return mcStr(found, "verdict"), found, "", true
}

// mcAbortSummary is the abort line's refusal text: the tool's own reason
// and details, with the details capped like every other excerpt. A line
// that cannot even name a reason reads "unknown" rather than empty.
func mcAbortSummary(obj validation.Value) string {
	reason := mcStr(obj, "reason")
	if reason == "" {
		reason = "unknown"
	}
	return "aborted: " + reason + ": " +
		truncateRunes(mcStr(obj, "details"), maxExcerpt)
}

// mcExpectedExit is the exit status a verdict claims for itself — the
// report-contradiction rail's table (PROVEN 0, VIOLATED 1, UNKNOWN 2).
// known=false for a verdict the vocabulary does not name.
func mcExpectedExit(verdict string) (int, bool) {
	switch verdict {
	case "PROVEN":
		return 0, true
	case "VIOLATED":
		return 1, true
	case "UNKNOWN":
		return 2, true
	default:
		return 0, false
	}
}

// mcCounterexampleSummary reads the witness excerpt: the failed
// assertion's expression, falling back to the tool's reason and then to
// the fixed "assertion-violated" label. The confidence flag is appended
// only for the two classes the architecture names, so a confirmed
// counterexample carries no flag.
func mcCounterexampleSummary(obj validation.Value) string {
	expr := mcStrAt(obj, "failed_assertion", "expression")
	if expr == "" {
		expr = mcStr(obj, "reason")
	}
	if expr == "" {
		expr = "assertion-violated"
	}
	summary := "counterexample: " + truncateRunes(expr, maxExcerpt)
	switch mcStr(obj, "confidence") {
	case "unconfirmed":
		summary += " [unconfirmed: crosses a havoc'd call]"
	case "modeled":
		summary += " [modeled]"
	}
	return summary
}

// mcUnknownSummary is the honest-UNKNOWN text: the tool's reason paired
// with its details, the details capped at maxExcerpt.
func mcUnknownSummary(obj validation.Value) string {
	reason := mcStr(obj, "reason")
	if reason == "" {
		reason = "unknown"
	}
	return fmt.Sprintf("inconclusive (%s: %s)", reason,
		truncateRunes(mcStr(obj, "details"), maxExcerpt))
}

// mcProof captures the verdict line's sidecar in the fixed key order
// tool_version, solc_version, spec_version, evm_version, confidence,
// reason, bounds, assumptions, warnings, ghosts. Scalars and arrays are
// copied out of the parsed line as parsed — the tool's own caveat list is
// the honesty layer, and webv2 neither invents nor drops caveats. The
// counterexample witness (params, calls, final_storage) deliberately does
// NOT ride along: it stays in the EXEC stdout artifact, which is where
// the L4 repro plane reads it from.
func mcProof(obj validation.Value) validation.Value {
	return validation.VObj(
		validation.KV{K: "tool_version", V: mcOr(obj, "tool_version")},
		validation.KV{K: "solc_version", V: mcOr(obj, "solc_version")},
		validation.KV{K: "spec_version", V: mcOr(obj, "spec_version")},
		validation.KV{K: "evm_version", V: mcOr(obj, "evm_version")},
		validation.KV{K: "confidence", V: mcOr(obj, "confidence")},
		validation.KV{K: "reason", V: mcOr(obj, "reason")},
		validation.KV{K: "bounds", V: mcBounds(obj)},
		validation.KV{K: "assumptions", V: mcArr(obj, "assumptions")},
		validation.KV{K: "warnings", V: mcArr(obj, "warnings")},
		validation.KV{K: "ghosts", V: mcArr(obj, "ghosts")},
	)
}

// mcBounds renders bounds as the fixed three-key object the audit reads
// (loop_bound, path_cap, solver_timeout_ms), each value taken verbatim.
// An absent bounds object, or one of another shape, renders those same
// three keys as null rather than dropping the key: the sidecar's shape is
// pinned by the schema, its values belong to the tool.
func mcBounds(obj validation.Value) validation.Value {
	b, ok := mcField(obj, "bounds")
	if !ok || b.Kind != validation.Obj {
		b = validation.VNull()
	}
	return validation.VObj(
		validation.KV{K: "loop_bound", V: mcOr(b, "loop_bound")},
		validation.KV{K: "path_cap", V: mcOr(b, "path_cap")},
		validation.KV{K: "solver_timeout_ms",
			V: mcOr(b, "solver_timeout_ms")},
	)
}

// mcOr is obj[key] verbatim, or null when the key (or the object itself)
// is absent.
func mcOr(obj validation.Value, key string) validation.Value {
	if v, ok := mcField(obj, key); ok {
		return v
	}
	return validation.VNull()
}

// mcArr is obj[key] verbatim when it is an array, the empty array when
// the field is absent (the schema's nullable-by-design shape), and null
// when the tool put some other shape there — a scalar in an array slot is
// a tool bug, and the sidecar admits no schema-busting value.
func mcArr(obj validation.Value, key string) validation.Value {
	v, ok := mcField(obj, key)
	switch {
	case !ok:
		return validation.VArr()
	case v.Kind == validation.Arr:
		return v
	default:
		return validation.VNull()
	}
}

// mcField is dict.get(key) over a parsed JSONL line (absent vs null kept
// distinct by the ok flag).
func mcField(obj validation.Value, key string) (validation.Value, bool) {
	if obj.Kind != validation.Obj {
		return validation.VNull(), false
	}
	for _, kv := range obj.O {
		if kv.K == key {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}

// mcStr is obj[key] as a string; an absent or non-string field reads "".
func mcStr(obj validation.Value, key string) string {
	if v, ok := mcField(obj, key); ok && v.Kind == validation.Str {
		return v.S
	}
	return ""
}

// mcStrAt is obj[outer][inner] as a string; "" when either hop is absent
// or of another shape.
func mcStrAt(obj validation.Value, outer, inner string) string {
	if v, ok := mcField(obj, outer); ok && v.Kind == validation.Obj {
		return mcStr(v, inner)
	}
	return ""
}

// mcIntAt is obj[outer][inner] as an int. ok=false when the field is
// absent, null, of another shape, or an integer that does not fit int64
// (a big int is real data but never a loop bound we can name).
func mcIntAt(obj validation.Value, outer, inner string) (int, bool) {
	v, ok := mcField(obj, outer)
	if !ok || v.Kind != validation.Obj {
		return 0, false
	}
	n, ok := mcField(v, inner)
	if !ok || n.Kind != validation.Int || n.Big != "" {
		return 0, false
	}
	return int(n.I), true
}

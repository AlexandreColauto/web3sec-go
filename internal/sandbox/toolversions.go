// toolversions.go: the host toolchain probe (tool_versions) and the solc
// version-line extractor shared with the verify-side pin probe.
package sandbox

import (
	"os/exec"
	"strings"
	"time"
	"websec/internal/state"
	"websec/internal/validation"
)

// toolVersions is _tool_versions: the host toolchain, probed once per exec.
// halmos and minicertora ride the same host LookPath + `--version`
// first-line probe as slither/aderyn (fail-open: a missing binary is
// omitted, a failed probe records "present (version probe failed)").
func toolVersions() validation.Value {
	out := []validation.KV{}
	for _, tool := range []string{"forge", "cast", "slither", "aderyn",
		"halmos", "minicertora", "miniprover", "solc", "python3", "docker"} {
		if _, err := exec.LookPath(tool); err != nil {
			continue
		}
		res, err := runProc([]string{tool, "--version"}, "", nil, 15*time.Second)
		if err != nil && err != errTimeout {
			out = append(out, validation.KV{K: tool, V: validation.VStr(
				"present (version probe failed)")})
			continue
		}
		text := res.Stdout
		if text == "" {
			text = res.Stderr
		}
		line := pyFirstLine80(text)
		if tool == "solc" {
			// solc's FIRST line is a banner; its version rides the
			// "Version: X" line (r18: the harness toolchain check
			// consumes this row, so it stores the VERSION, not the
			// banner).
			line = solcVersionLine(res.Stdout + res.Stderr)
		}
		out = append(out, validation.KV{K: tool, V: validation.VStr(line)})
	}
	return validation.VObj(out...)
}

// pyFirstLine80 is `(stdout or stderr).strip().splitlines()[0][:80]`.
func pyFirstLine80(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	line := strings.SplitN(text, "\n", 2)[0]
	rs := []rune(line)
	if len(rs) > 80 {
		line = string(rs[:80])
	}
	return line
}

// shortID is Python's `new_id("x", n).split("-")[1]`: n hex chars.
func shortID(n int) string {
	parts := strings.SplitN(state.NewID("x", n), "-", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return ""
}

// SolcVersionFromText exports the extractor for the verify-side pin
// probe (same parsing, one law).
func SolcVersionFromText(text string) string { return solcVersionLine(text) }

// solcVersionLine extracts "0.8.36" from solc --version output
// ("Version: 0.8.36+commit..."). "" when no version line exists.
func solcVersionLine(text string) string {
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "Version:") {
			continue
		}
		v := strings.TrimSpace(strings.TrimPrefix(ln, "Version:"))
		if i := strings.IndexAny(v, "+ "); i >= 0 {
			v = v[:i]
		}
		return v
	}
	return ""
}

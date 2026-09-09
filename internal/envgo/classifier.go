// classifier.go: env.classify_failure — the exec failure classifier. It is
// what stops an environment failure from burning the finding's
// fresh-context retry budget: a fresh context does not fix a missing image.
package envgo

import (
	"regexp"
	"strconv"
	"strings"

	"websec/internal/sandbox"
	"websec/internal/validation"
)

// Python's four IGNORECASE signal patterns, transcribed verbatim. RE2 has no
// lookahead, so _SETUP_ERR's `Error: (?!.*assert)` clause is applied by
// errorNotAssert. pySpace is Python's \s.
const pySpace = `[\t\n\f\r\v\p{Z}]`

var (
	dockerErrRe = regexp.MustCompile(`(?i)Cannot connect to the Docker daemon|` +
		`docker[^\n]*is not running|no such image|pull access denied|` +
		`Get https?://|runsc|OCI runtime|exec format error|connection refused`)
	setupErrRe = regexp.MustCompile(`(?i)error` + pySpace + `*\[|compiler error|` +
		`compilation failed|forge-std|src/forge-std|module not found|` +
		`cannot find (use of )?(package|library)|unresolved reference|` +
		`failed to compile`)
	setupErrorColonRe = regexp.MustCompile(`(?i)error: `)
	logicErrRe        = regexp.MustCompile(`(?i)assertion (failed|violation)|` +
		`panic:|test failed|VM Exception while|revert|Expected|but got|` +
		`balance mismatch`)
	solcErrRe = regexp.MustCompile(`(?i)binaries\.soliditylang\.org|` +
		`failed to download solc|error sending request for url ` +
		`\(?https?://[^\s\p{Z})]*solc|\.svm/0\.`)
)

// ClassifyFailure is classify_failure: classify a FAILED exec record
// (exit != 0) by cause. Classification signals are listed so the operator
// can disagree with the classifier — the class is a routing hint, not a
// verdict.
func ClassifyFailure(rec validation.Value) validation.Value {
	exitCode := exitCodeOf(rec)
	if exitCode != nil && *exitCode == 0 {
		return classifyResult("none", nil, "exec succeeded; nothing to classify")
	}
	text := sandbox.ExecOutput(rec)
	var signals []string

	if exitCode != nil && (*exitCode == 125 || *exitCode == 126 || *exitCode == 127) {
		return classifyResult("environment", []string{
			"docker-level exit code " + strconv.FormatInt(*exitCode, 10)},
			"docker itself failed before the command ran")
	}
	solcFailed := solcErrRe.MatchString(text)
	if solcFailed {
		signals = append(signals, "solc download failure pattern (offline container)")
	}
	dockerHit := dockerErrRe.MatchString(text)
	if dockerHit {
		signals = append(signals, "docker/daemon/network error pattern in output")
	}
	setupHit := setupErrRe.MatchString(text) || errorNotAssert(text)
	if setupHit {
		signals = append(signals, "compilation/setup error pattern")
	}
	logicHit := logicErrRe.MatchString(text)
	if logicHit {
		signals = append(signals, "assertion/logic failure pattern in output")
	}

	var cls string
	switch {
	case solcFailed:
		cls = "environment"
	case dockerHit:
		cls = "environment"
	case setupHit:
		cls = "setup"
	case logicHit:
		cls = "logic"
	default:
		cls = "unknown"
	}
	if cls == "environment" && solcFailed {
		return classifyResult(cls, signals,
			"the container tried to DOWNLOAD solc and the network is cut — "+
				"preinstall the solc binary into the image's svm cache "+
				"(~/.svm/<version>/solc-<version>) or set WEBV2_SOLC_DIR "+
				"(host dir bind-mounted to /home/foundry/.svm); do NOT "+
				"spend a fresh-context retry")
	}
	notes := map[string]string{
		"environment": "fix the environment; do NOT spend a fresh-context " +
			"retry on this",
		"setup": "retry in a fresh context with this failure record",
		"logic": "the harness ran and the hypothesis lost a round — this " +
			"is the only class that argues the finding",
		"unknown": "unclassified; routed as setup (the cheap error)",
	}
	return classifyResult(cls, signals, notes[cls])
}

// errorNotAssert applies `Error: (?!.*assert)`: an "Error: " whose line does
// not later contain "assert" (Python's `.` never crosses a newline).
func errorNotAssert(text string) bool {
	for _, m := range setupErrorColonRe.FindAllStringIndex(text, -1) {
		rest := text[m[1]:]
		if i := strings.IndexByte(rest, '\n'); i >= 0 {
			rest = rest[:i]
		}
		if !strings.Contains(strings.ToLower(rest), "assert") {
			return true
		}
	}
	return false
}

// exitCodeOf is `exec_record.get("exit_status", exec_record.get("exit_code"))`
// — a PRESENT exit_status wins even when it is null.
func exitCodeOf(rec validation.Value) *int64 {
	v, ok := lookupKey(rec, "exit_status")
	if !ok {
		v, _ = lookupKey(rec, "exit_code")
	}
	switch v.Kind {
	case validation.Int:
		n := v.I
		return &n
	case validation.Flt:
		n := int64(v.F)
		return &n
	}
	return nil
}

func lookupKey(rec validation.Value, key string) (validation.Value, bool) {
	for _, kv := range rec.O {
		if kv.K == key {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}

func classifyResult(class string, signals []string, note string) validation.Value {
	sig := make([]validation.Value, 0, len(signals))
	for _, s := range signals {
		sig = append(sig, validation.VStr(s))
	}
	return validation.VObj(
		validation.KV{K: "class", V: validation.VStr(class)},
		validation.KV{K: "signals", V: validation.VArr(sig...)},
		validation.KV{K: "note", V: validation.VStr(note)},
	)
}

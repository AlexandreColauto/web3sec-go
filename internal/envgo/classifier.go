// classifier.go: env.classify_failure — the exec failure classifier. It is
// what stops an environment failure from burning the finding's
// fresh-context retry budget: a fresh context does not fix a missing image,
// and (RUNBOOK §0/§6a, Task 9) it does not fix a missing toolchain binary
// either — an absent solc/forge/docker is ENVIRONMENT, not SETUP.
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

	// Task 9 (production-readiness plan §Task 9): the TOOLCHAIN BINARY itself
	// is absent — solc, the foundry tools, or the docker client. RUNBOOK §0:
	// "with the network cut …, a missing solc binary is an environment
	// failure, not a harness bug"; §6a names ENVIRONMENT (daemon down, image
	// missing, solc download cut) as the class that must NOT spend the
	// finding's fresh-context retry. Only absence EVIDENCE for those binaries
	// matches: a missing Solidity LIBRARY (forge-std, "module not found") is
	// repository setup, and a compile error is the hypothesis losing a round —
	// both keep their class.
	solcAbsentRe   = toolAbsentRe(`solc`, true)
	forgeAbsentRe  = toolAbsentRe(`forge|cast|anvil`, true)
	dockerAbsentRe = toolAbsentRe(`docker`, false)
	// shellAbsentRe is the shell/exec layer's "I could not find the command"
	// with no binary named: POSIX sh/dash (`sh: 1: jq: not found`), bash
	// (`bash: jq: command not found`), Go's exec (`executable file not
	// found in $PATH`). The box lacks a binary the run needs, so it is the
	// environment — never the hypothesis.
	shellAbsentRe = regexp.MustCompile(`(?im)` +
		`command not found|executable file not found|` +
		`^[^\n]{0,80}: not found$`)
)

// toolAbsentRe builds the absence pattern for ONE binary (an alternation for
// the foundry tools). BOTH boundaries are load-bearing: the trailing
// delimiter keeps `forge-std`, `forge-std/Test.sol` and `lib/forge/` out (a
// missing Solidity LIBRARY is repository setup, already a setup signal), and
// the LEADING `\b` keeps `cast` inside `broadcast`/`forecast`/`recast` out (a
// missing broadcast artifact is repository setup too, task-9 review F1).
// `missing` is admitted only for the compiler/foundry binaries: a missing
// docker IMAGE is not a missing docker CLI, and only the latter is a
// toolchain absence.
func toolAbsentRe(tool string, allowMissing bool) *regexp.Regexp {
	tok := `\b(?:` + tool + `)[\s:,;)"'\]}]`
	missing := ""
	if allowMissing {
		missing = tok + `[^\n]{0,60}?\bmissing\b|`
	}
	return regexp.MustCompile(`(?i)` +
		tok + `[^\n]{0,60}?\bnot (?:be )?found\b|` +
		tok + `[^\n]{0,60}?\bnot installed\b|` +
		tok + `[^\n]{0,60}?\bcannot (?:be )?found\b|` +
		missing +
		`\bnot (?:be )?found\b[^\n]{0,60}?` + tok + `|` +
		`\bnot installed\b[^\n]{0,60}?` + tok + `|` +
		`\bcannot find\b[^\n]{0,20}?` + tok + `|` +
		`\bno ` + tok + `[^\n]{0,40}?\b(?:installed|found)\b`)
}

// toolAbsentSignal is the evidence line `classify` prints for an absent
// toolchain binary, so the class never travels without what produced it.
const toolAbsentSignal = "toolchain binary absent (not found / not installed)"

// The fix-naming notes, one per absent binary. Every one of them names the
// fix AND the retry discipline (§6a: do NOT spend a fresh-context retry).
const (
	noteSolcAbsent = "the solc binary is MISSING on this box — nothing can " +
		"compile: preinstall it into the image's svm cache " +
		"(~/.svm/<version>/solc-<version>) or set WEBV2_SOLC_DIR (host dir " +
		"bind-mounted to /home/foundry/.svm), then confirm with " +
		"`webv2 env doctor`; do NOT spend a fresh-context retry"
	noteFoundryAbsent = "the foundry toolchain (forge/cast/anvil) is not on " +
		"this box's PATH — install it with `foundryup` (or preinstall it in " +
		"the image), then confirm with `webv2 env doctor`; do NOT spend a " +
		"fresh-context retry"
	noteDockerAbsent = "the docker side of this run is missing — either the " +
		"docker CLI is not on this box's PATH or the image it needs is not " +
		"there: install the docker CLI (or use the host-readonly profile, " +
		"which needs no docker) and pull the pinned image; `webv2 env " +
		"doctor` shows the CLI, the daemon and the image; do NOT spend a " +
		"fresh-context retry"
	noteToolAbsent = "a toolchain binary this run needs is not on this box — " +
		"install it (solc into the image's svm cache or WEBV2_SOLC_DIR; " +
		"foundry via `foundryup`; the docker CLI for container profiles), " +
		"then confirm with `webv2 env doctor`; do NOT spend a " +
		"fresh-context retry"
)

// toolAbsentNote returns the fix-naming note for the absent toolchain binary
// the text evidences, or "" when there is no absence evidence.
func toolAbsentNote(text string) string {
	switch {
	case solcAbsentRe.MatchString(text):
		return noteSolcAbsent
	case forgeAbsentRe.MatchString(text):
		return noteFoundryAbsent
	case dockerAbsentRe.MatchString(text):
		return noteDockerAbsent
	case shellAbsentRe.MatchString(text):
		return noteToolAbsent
	}
	return ""
}

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
		return classifyDockerLevelExit(rec, *exitCode, text)
	}
	solcFailed := solcErrRe.MatchString(text)
	if solcFailed {
		signals = append(signals, "solc download failure pattern (offline container)")
	}
	dockerHit := dockerErrRe.MatchString(text)
	if dockerHit {
		signals = append(signals, "docker/daemon/network error pattern in output")
	}
	// Task 9: absence EVIDENCE outranks the setup heuristic below — "Error:
	// solc 0.8.24 is not installed" is a missing binary, not a broken build.
	// It does NOT outrank a logic signal (task-9 review F2): a capture that
	// merely ECHOES a subprocess not-found while an assertion fails is
	// hypothesis space, and LOGIC is the only class that argues it.
	toolAbsent := toolAbsentNote(text)
	if toolAbsent != "" {
		signals = append(signals, toolAbsentSignal)
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
	case logicHit:
		cls = "logic"
	case toolAbsent != "":
		cls = "environment"
	case setupHit:
		cls = "setup"
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
	// A docker/daemon or solc-download failure that ALSO shows absence text
	// keeps its own, more specific note (the two only co-occur in
	// contradictory captures); the absence note owns the pure cases.
	if cls == "environment" && toolAbsent != "" && !dockerHit {
		return classifyResult(cls, signals, toolAbsent)
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

// classifyDockerLevelExit names the REAL state behind exit 125/126/127
// (r36 F3). It is a faithful transcription of
// sandbox.defaultClassifyFailure's classifyDockerLevelExit, and it must
// stay one: this package is installed OVER the sandbox seam (cmd_dedup's
// ensureSeams and cmd/webv2/main.go both call
// sandbox.SetClassifyFailure(envgo.ClassifyFailure)), so calling
// sandbox.ClassifyFailure from here would recurse into itself, and the
// honest default it must mirror (sandbox.defaultClassifyFailure) is
// unexported. internal/sandbox owns the reference; the wired-path tests in
// internal/cli/zz_r38a_test.go and the differential test in this package
// pin this copy to it so the transcription cannot silently drift.
//
//   - 125 is docker's own contract for `docker run` failing itself — only
//     meaningful on a container profile;
//   - 126/127 come from the shell that executed the command: on a host
//     profile they are a missing binary / not-executable; in a container
//     the captured output distinguishes "the command ran and was not
//     found" (its output is in the logs) from a docker client/runtime
//     failure (docker's own error text), and absence of output is
//     reported as INCONCLUSIVE, never resolved by invention.
func classifyDockerLevelExit(rec validation.Value, ec int64,
	text string) validation.Value {
	profile := strAt(rec, "profile")
	code := strconv.FormatInt(ec, 10)
	if profile != "" && sandbox.HostProfile(profile) {
		switch ec {
		case 127:
			return classifyResult("environment", []string{
				"exit 127 on host profile " + profile +
					" (no docker involved)"},
				"exit 127: the host shell could not find the command — "+
					"check PATH and the binary name (docker is not involved "+
					"on this profile)")
		case 126:
			return classifyResult("environment", []string{
				"exit 126 on host profile " + profile +
					" (no docker involved)"},
				"exit 126: the command was found but is not executable — "+
					"check permissions (docker is not involved on this profile)")
		default:
			return classifyResult("environment", []string{
				"exit 125 on host profile " + profile +
					" (no docker involved)"},
				"exit 125 on a host profile: no docker is involved — the "+
					"command itself exited 125 (permission/exec failure)")
		}
	}
	// Container profile (or a record without a profile key, where docker's
	// own exit-code contract applies).
	if ec == 125 {
		return classifyResult("environment", []string{
			"docker-level exit code " + code},
			"docker itself failed before the command ran (exit 125 is "+
				"docker's own code for a `docker run` failure)")
	}
	if dockerErrRe.MatchString(text) {
		return classifyResult("environment", []string{
			"docker-level exit code " + code,
			"docker/daemon error text in the captured output"},
			"the docker client/runtime failed before or around the command "+
				"(docker's error text is in the captured output)")
	}
	if strings.TrimSpace(text) != "" {
		return classifyResult("environment", []string{
			"exit " + code + " with captured output present",
			"the command ran"},
			"the command RAN inside the container and was not found or "+
				"not executable (exit "+code+"; its output is in "+
				"stdout.log/stderr.log)")
	}
	return classifyResult("environment", []string{
		"exit " + code + " with no captured output — inconclusive"},
		"exit "+code+" with NO captured output: inconclusive between "+
			"'the docker client failed before the command ran' and 'the "+
			"command was not found and its shell error was lost' — inspect "+
			"the daemon; this classification does not guess which")
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

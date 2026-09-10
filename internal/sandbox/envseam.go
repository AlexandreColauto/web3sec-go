// envseam.go: the seam to webv2.env's failure classifier and sandbox
// preflight (env.py).
//
// env.py is not ported in this wave and is not owned by T20; the P2 CLI
// verbs `exec` and `classify` cannot be byte-exact without it, so this file
// carries a FAITHFUL transcription as the seam DEFAULT. When internal/env
// lands, it installs the real implementation through SetClassifyFailure /
// SetSandboxPreflight (nil restores this default). The default is never the
// absent-module behavior of inventing a verdict: it is the reference
// algorithm, line for line.
package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// --- failure classifier -----------------------------------------------------

// Python's four IGNORECASE signal patterns. RE2 has no lookahead, so
// _SETUP_ERR's `Error: (?!.*assert)` clause is applied by errorNotAssert.
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
	solcErrRe = regexp.MustCompile(`(?i)binaries` + `\.soliditylang\.org|` +
		`failed to download solc|error sending request for url ` +
		`\(?https?://[^\s\p{Z})]*solc|\.svm/0\.`)
)

// classifyFn is the installed classifier (the env seam).
var classifyFn = defaultClassifyFailure

// SetDockerDaemonOK installs the docker_daemon_ok probe (the Python twin
// monkeypatches SB.docker_daemon_ok); nil restores the real probe.
func SetDockerDaemonOK(f func() bool) {
	if f == nil {
		f = probeDockerDaemon
	}
	dockerDaemonOK = f
}

// SetClassifyFailure installs the webv2.env.classify_failure implementation;
// nil restores the transcribed default.
func SetClassifyFailure(f func(validation.Value) validation.Value) {
	if f == nil {
		f = defaultClassifyFailure
	}
	classifyFn = f
}

// ClassifyFailure is classify_failure: classify a FAILED exec record (exit
// != 0) by cause. Classification signals are listed so the operator can
// disagree with the classifier — the class is a routing hint, not a verdict.
func ClassifyFailure(rec validation.Value) validation.Value {
	return classifyFn(rec)
}

// defaultClassifyFailure is env.classify_failure verbatim.
func defaultClassifyFailure(rec validation.Value) validation.Value {
	exitCode := exitCodeOf(rec)
	if exitCode != nil && *exitCode == 0 {
		return classifyResult("none", nil, "exec succeeded; nothing to classify")
	}
	text := ExecOutput(rec)
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

// exitCodeOf is `rec.get("exit_status", rec.get("exit_code"))`.
func exitCodeOf(rec validation.Value) *int64 {
	if v, ok := fieldOf(rec, "exit_status"); ok {
		if v.Kind == validation.Int {
			n := v.I
			return &n
		}
		return nil
	}
	if v, ok := fieldOf(rec, "exit_code"); ok && v.Kind == validation.Int {
		n := v.I
		return &n
	}
	return nil
}

func fieldOf(rec validation.Value, key string) (validation.Value, bool) {
	if rec.Kind != validation.Obj {
		return validation.VNull(), false
	}
	for _, kv := range rec.O {
		if kv.K == key {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}

func classifyResult(class string, signals []string,
	note string) validation.Value {
	items := make([]validation.Value, 0, len(signals))
	for _, s := range signals {
		items = append(items, validation.VStr(s))
	}
	return validation.VObj(
		validation.KV{K: "class", V: validation.VStr(class)},
		validation.KV{K: "signals", V: validation.VArr(items...)},
		validation.KV{K: "note", V: validation.VStr(note)},
	)
}

// --- sandbox preflight ------------------------------------------------------

// preflightFn is the installed preflight (the env seam).
var preflightFn = defaultSandboxPreflight

// SetSandboxPreflight installs the webv2.env.sandbox_preflight
// implementation; nil restores the transcribed default.
func SetSandboxPreflight(f func(*state.Campaign, *string,
	*string) (validation.Value, error)) {
	if f == nil {
		f = defaultSandboxPreflight
	}
	preflightFn = f
}

// SandboxPreflight is sandbox_preflight: the sandbox's readiness as a
// CHECKABLE PRECONDITION. Severity: FAILs block (issues — every one names
// the exact fix); WARNs are advisory. profile nil means "container
// readiness" — what `webv2 doctor` reports.
func SandboxPreflight(c *state.Campaign, workdir, profile *string) (
	validation.Value, error) {
	return preflightFn(c, workdir, profile)
}

// defaultSandboxPreflight is env.sandbox_preflight verbatim.
func defaultSandboxPreflight(c *state.Campaign, workdir, profile *string) (
	validation.Value, error) {
	var checks []validation.KV
	var issues, warnings []validation.Value

	check := func(name, status, detail string, fix *string) {
		var fixV validation.Value = validation.VNull()
		if fix != nil {
			fixV = validation.VStr(*fix)
		}
		checks = append(checks, validation.KV{K: name, V: validation.VObj(
			validation.KV{K: "status", V: validation.VStr(status)},
			validation.KV{K: "detail", V: validation.VStr(detail)},
			validation.KV{K: "fix", V: fixV})})
		if status == "fail" || status == "warn" {
			line := name + ": " + detail
			if fix != nil {
				line += " — fix: " + *fix
			}
			if status == "fail" {
				issues = append(issues, validation.VStr(line))
			} else {
				warnings = append(warnings, validation.VStr(line))
			}
		}
	}

	container := profile != nil && *profile != "host-readonly"
	if !container {
		check("docker", "na",
			"host-readonly executes on the host — no container involved", nil)
		check("image", "na", "no container image involved", nil)
		check("solc", "na", "no container to compile in", nil)
	} else {
		daemon := dockerDaemonOK()
		if daemon {
			check("docker", "ok", "daemon answering", nil)
		} else {
			check("docker", "fail", "docker daemon not answering", strPtr(
				"start the docker daemon (container profiles are the only "+
					"honest execution path — evidence produced un-sandboxed "+
					"cannot be minted at E4+)"))
		}
		if daemon {
			img := DockerImageProbe(nil)
			if boolAt(img, "present") {
				detail := strAt(img, "image") + " present locally" +
					map[bool]string{true: " (digest-pinned)",
						false: " (tag reference — may float)"}[boolAt(img, "pinned")]
				check("image", "ok", detail, nil)
			} else {
				fix := "docker pull " + strAt(img, "image")
				if !boolAt(img, "pinned") {
					fix += " and pin by digest"
				}
				check("image", "warn", strAt(img, "image")+
					" not present locally — the first run will pull it "+
					"(a floating tag may pull a different build than the PoC "+
					"assumes)", &fix)
			}
		} else {
			check("image", "na", "daemon down — image check skipped", nil)
		}
	}

	version := pinnedCompiler(c)
	if version == nil {
		check("solc", "na", "no compiler pinned by the active snapshot — "+
			"nothing to check against", nil)
	} else if !SolcVersionPin(*version) {
		// The pin is target-repo input: it may not be joined into a host path.
		fix := "set foundry.toml's solc to a release (for example 0.8.24) — " +
			"webv2 only uses a version as the svm cache path component"
		check("solc", "fail", "the active snapshot pins compiler "+
			SolcPinText(*version)+", which is not a solc version — "+
			"refusing to treat it as an svm cache path", &fix)
	} else {
		svm := SolcDir()
		if svm == nil {
			fix := "set WEBV2_SOLC_DIR to a host dir with the svm layout (" +
				*version + "/solc-" + *version + ") or preinstall the image"
			check("solc", "warn", "solc "+*version+" pinned by foundry.toml "+
				"but WEBV2_SOLC_DIR is unset — an offline container cannot "+
				"download it; the image must ship it (`webv2 env doctor` "+
				"probes that)", &fix)
		} else {
			binary := filepath.Join(*svm, *version, "solc-"+*version)
			if fileExists(binary) {
				check("solc", "ok", "solc "+*version+
					" present in the svm cache "+*svm, nil)
			} else {
				fix := "place the solc binary at " + binary + " (svm layout: " +
					*version + "/solc-" + *version + ") or preinstall it in " +
					"the image (`webv2 env doctor` probes the image)"
				if profile != nil && *profile == "fork-runner" {
					check("solc", "warn", "solc "+*version+
						" missing from the svm cache "+*svm+" — the "+
						"fork-runner bridge may still reach the registry, "+
						"but that is not guaranteed", &fix)
				} else {
					check("solc", "fail", "solc "+*version+" pinned by "+
						"foundry.toml but missing from the svm cache "+
						*svm+" — this profile's container has no network "+
						"and cannot download it", &fix)
				}
			}
		}
	}

	if workdir == nil {
		detail := "no workdir given — "
		if container {
			detail += "container uses a tmpfs"
		} else {
			detail += "the host shell uses the current directory"
		}
		check("workdir", "na", detail, nil)
	} else {
		p := *workdir
		if !pathExists(p) {
			check("workdir", "fail", "workdir "+p+" does not exist — a "+
				"missing bind source fails the whole run", strPtr(
				"create "+p+" or point --workdir at an existing directory"))
		} else if !isDirPath(p) {
			check("workdir", "fail", "workdir "+p+" is not a directory",
				strPtr("point --workdir at a directory ("+p+" is a file)"))
		} else {
			check("workdir", "ok", "binds "+resolvedPath(p), nil)
		}
	}

	var profileV validation.Value = validation.VNull()
	if profile != nil {
		profileV = validation.VStr(*profile)
	}
	return validation.VObj(
		validation.KV{K: "profile", V: profileV},
		validation.KV{K: "checks", V: validation.VObj(checks...)},
		validation.KV{K: "issues", V: validation.VArr(issues...)},
		validation.KV{K: "warnings", V: validation.VArr(warnings...)},
		validation.KV{K: "ok", V: validation.VBool(len(issues) == 0)},
	), nil
}

// pinnedCompiler is the compiler version the active snapshot's toolchain
// detection pinned (str(compiler).split(",")[0].strip()), or nil.
func pinnedCompiler(c *state.Campaign) *string {
	if c == nil {
		return nil
	}
	sid, err := c.ActiveSnapshotIDOrNone()
	if err != nil || sid == nil {
		return nil
	}
	pinPath := filepath.Join(c.Dir, "snapshots", *sid, "snapshot.json")
	if !pathExists(pinPath) {
		return nil
	}
	pin, err := validation.ReadJson(pinPath)
	if err != nil {
		return nil
	}
	compiler := objAt(objAt(pin, "config"), "compiler")
	if compiler.Kind == validation.Null {
		return nil
	}
	text := scalarText(compiler)
	if text == "" {
		return nil
	}
	first := strings.SplitN(text, ",", 2)[0]
	first = strings.TrimSpace(first)
	return &first
}

// scalarText is Python's str() for the JSON scalars a compiler pin can hold.
func scalarText(v validation.Value) string {
	switch v.Kind {
	case validation.Str:
		return v.S
	case validation.Int:
		return validation.IntText(v)
	case validation.Bool:
		return pyReprBool(v.B)
	default:
		return ""
	}
}

// dockerImageProbeFn is the installed image probe (the env seam, D17).
var dockerImageProbeFn = defaultDockerImageProbe

// SetDockerImageProbe installs the webv2.env.docker_image_probe
// implementation; nil restores the transcribed default.
func SetDockerImageProbe(f func(*string) validation.Value) {
	if f == nil {
		f = defaultDockerImageProbe
	}
	dockerImageProbeFn = f
}

// DockerImageProbe is env.docker_image_probe: the exact image the container
// profiles would run, plus whether the reference is digest-pinned.
func DockerImageProbe(image *string) validation.Value {
	return dockerImageProbeFn(image)
}

// defaultDockerImageProbe is the transcription env.py's docker_image_probe
// (the seam default until internal/envgo is wired over it).
func defaultDockerImageProbe(image *string) validation.Value {
	name := DockerImage()
	if image != nil {
		name = *image
	}
	base := name
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	pinned := strings.Contains(base, "@")
	daemon, present := false, false
	digest := ""
	detail := ""
	if _, err := exec.LookPath("docker"); err != nil {
		detail = "docker CLI not found"
	} else if !dockerDaemonOK() {
		detail = "docker daemon not answering"
	} else {
		daemon = true
		res, err := runProc([]string{"docker", "image", "inspect", "--format",
			"{{.Id}}", name}, "", nil, 20*timeSecond)
		if err != nil && err != errTimeout {
			detail = "docker image inspect failed: " + err.Error()
		} else if res.ReturnCode != 0 {
			stderr := strings.TrimSpace(res.Stderr)
			if len([]rune(stderr)) > 120 {
				stderr = string([]rune(stderr)[:120])
			}
			detail = "image not present locally (" + stderr + ") — the " +
				"first E4+ run will pull it, and a floating tag may pull a " +
				"different build than your PoC assumes"
		} else {
			present = true
			digest = strings.TrimSpace(res.Stdout)
			head := digest
			if len([]rune(head)) > 19 {
				head = string([]rune(head)[:19])
			}
			if !pinned {
				detail = "tag reference — local digest " + head + "...; " +
					"pin by digest (name@sha256:...) for drift-proof runs"
			} else {
				detail = "digest-pinned — " + head + "..."
			}
		}
	}
	var digestV validation.Value = validation.VNull()
	if digest != "" {
		digestV = validation.VStr(digest)
	}
	return validation.VObj(
		validation.KV{K: "image", V: validation.VStr(name)},
		validation.KV{K: "daemon", V: validation.VBool(daemon)},
		validation.KV{K: "present", V: validation.VBool(present)},
		validation.KV{K: "digest", V: digestV},
		validation.KV{K: "pinned", V: validation.VBool(pinned)},
		validation.KV{K: "detail", V: validation.VStr(detail)},
	)
}

func strPtr(s string) *string { return &s }

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func isDirPath(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

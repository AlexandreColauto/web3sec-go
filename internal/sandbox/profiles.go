// profiles.go: the sandbox policy layer — PROFILES, policy_check, the
// docker/runtime probes and build_container_argv (webv2.sandbox).
//
// Every LLM-produced artifact is hostile until proven otherwise. This is the
// policy half: DENY-by-default for network and writes outside the sandbox,
// plus the argv builder the container profiles run through.
package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"websec/internal/validation"
)

// Profiles is PROFILES: every named execution profile. halmos, forge-fuzz
// and minicertora are G8 harness profiles: they execute on the HOST (no
// container), running the host toolchain the way the slither/aderyn
// toolVersions probes do — network none, read-only workspace. They can
// never back E4+ evidence (see HostProfile).
//
// minicertora is the G8 THIRD KIND (host-readonly + halmos + forge-fuzz +
// minicertora), so its argv expects a host-installed SHIM named
// 'minicertora' (package-root + venv + absolute --solc-path folded into
// argv[0]); the framework probes and executes it like halmos, E3-capped
// likewise. The shim binary is OPERATOR infrastructure, not shipped here:
// this profile only pins that the host probes for it and omits it honestly
// when absent.
var Profiles = []string{"host-readonly", "halmos", "forge-fuzz", "minicertora",
	"docker-networkless", "docker-gvisor", "vm-snapshot", "fork-runner"}

// profileNetwork is _PROFILE_NETWORK: the CONTAINER network label per
// profile — the isolation the profile's argv actually asks docker for.
// It is NOT the record label for a host profile: a host run has the host's
// full network, so callers must go through networkLabel, which discloses
// that instead of reading this map directly (Task 2, r36 F5's twin).
// "bridge-host-gateway" is fork-runner's: the container sits on docker's
// bridge and reaches the host only via the host-gateway alias — egress
// restriction is the operator's RPC endpoint's job, not docker's.
var profileNetwork = map[string]string{
	"host-readonly":      "none",
	"halmos":             "none",
	"forge-fuzz":         "none",
	"minicertora":        "none",
	"docker-networkless": "none",
	"docker-gvisor":      "none",
	"vm-snapshot":        "none",
	"fork-runner":        "bridge-host-gateway",
}

// profileFilesystem is _PROFILE_FILESYSTEM.
var profileFilesystem = map[string]string{
	"host-readonly":      "readonly",
	"halmos":             "readonly",
	"forge-fuzz":         "readonly",
	"minicertora":        "readonly",
	"docker-networkless": "sandbox-tmp",
	"docker-gvisor":      "sandbox-tmp",
	"vm-snapshot":        "sandbox-tmp",
	"fork-runner":        "sandbox-tmp",
}

// networkLabel is the HONEST network label for a profile — the network twin
// of profileFilesystemLabel (r36 F5): a host profile executes with the
// HOST's full network (nothing here enforces network-off; the deny rules
// are static tripwires, not a boundary), so the record must not assert
// "none" while the process can reach everything the host can. Container
// profiles keep their label verbatim: the container's --network IS the
// enforcement mechanism.
func networkLabel(profile string) string {
	if HostProfile(profile) {
		return "host (unconfined — nothing enforces network-off)"
	}
	return profileNetwork[profile]
}

// pyWord is Python's \w (str.isalnum plus "_"); pyNonWord is [^\w].
const (
	pyWord    = `\p{L}\p{N}_`
	pyNonWord = `^\p{L}\p{N}_`
	// pySpace is Python's \s: ASCII whitespace including \v, plus the
	// Unicode separator categories (RE2's \s is ASCII-only and lacks \v).
	pySpace = `[\t\n\f\r\v\p{Z}]`
)

// denyRule is one _DENY_PATTERNS entry. Python's \b is Unicode-aware and
// RE2's is ASCII-only, so every boundary is spelled out as an explicit
// non-word class (the same translation LooksLikeForgeTest uses).
type denyRule struct {
	name string
	re   *regexp.Regexp
}

func bounded(words ...string) *regexp.Regexp {
	alt := strings.Join(words, "|")
	return regexp.MustCompile(`(?:^|[^` + pyWord + `])(?:` + alt +
		`)(?:[^` + pyWord + `]|$)`)
}

var denyRules = []denyRule{
	{"network-egress-tool", bounded("curl", "wget", "nc", "ssh", "scp")},
	{"privilege-escalation", regexp.MustCompile(
		`(?:^|[^` + pyWord + `])(?:eval|sudo|su|chmod` + pySpace +
			`+777)(?:[^` + pyWord + `]|$)`)},
	{"destructive-path", regexp.MustCompile(`rm` + pySpace + `+-rf` +
		pySpace + `+/`)},
	{"secret-access", regexp.MustCompile(
		`\.ssh|\.aws|\.env(?:[^` + pyWord + `]|$)|id_rsa|credentials`)},
	{"external-publish", regexp.MustCompile(
		`git` + pySpace + `+push|docker` + pySpace + `+push`)},
	{"system-write", regexp.MustCompile(`>` + pySpace + `*/etc/|>>` +
		pySpace + `*/etc/`)},
}

// PolicyCheck is policy_check: the static verdict on what a command may do
// per profile. Tripwires, not a security boundary — the real boundary is the
// container.
func PolicyCheck(command, profile string) (validation.Value, error) {
	if !inProfiles(profile) {
		return validation.VNull(), fmt.Errorf("unknown profile %s",
			validation.PyReprStr(profile))
	}
	violations := []validation.Value{}
	checked := make([]validation.Value, 0, len(denyRules))
	for _, rule := range denyRules {
		checked = append(checked, validation.VStr(rule.name))
		if ruleViolated(rule, command) {
			violations = append(violations, validation.VStr(rule.name))
		}
	}
	return validation.VObj(
		validation.KV{K: "allowed", V: validation.VBool(len(violations) == 0)},
		validation.KV{K: "violations", V: validation.VArr(violations...)},
		validation.KV{K: "checked_rules", V: validation.VArr(checked...)},
	), nil
}

// ruleViolated applies one deny rule, honouring the negative lookahead in
// destructive-path (Python's `rm\s+-rf\s+/(?!tmp)`).
func ruleViolated(rule denyRule, command string) bool {
	matches := rule.re.FindAllStringIndex(command, -1)
	for _, m := range matches {
		if rule.name != "destructive-path" {
			return true
		}
		if !strings.HasPrefix(command[m[1]:], "tmp") {
			return true
		}
	}
	return false
}

func inProfiles(profile string) bool {
	for _, p := range Profiles {
		if p == profile {
			return true
		}
	}
	return false
}

// DockerImage is docker_image: the image for container profiles. Operators
// point WEBV2_DOCKER_IMAGE at a local image — pulling is docker's job.
func DockerImage() string {
	if v := os.Getenv("WEBV2_DOCKER_IMAGE"); v != "" {
		return v
	}
	return "ghcr.io/foundry-rs/foundry:latest"
}

// SolcDir is solc_dir: the host svm cache mounted into the container as
// /home/foundry/.svm, or nil. A missing directory is treated as unset — a
// dangling bind mount would fail the whole run.
func SolcDir() *string {
	raw := os.Getenv("WEBV2_SOLC_DIR")
	if raw == "" {
		return nil
	}
	abs, err := filepath.Abs(expandUser(raw))
	if err != nil {
		return nil
	}
	fi, err := os.Stat(abs)
	if err != nil || !fi.IsDir() {
		return nil
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		resolved = abs
	}
	return &resolved
}

// expandUser is Python's Path.expanduser for the "~" forms that matter here.
func expandUser(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~/"))
		}
	}
	return p
}

// solcVersionRe is the version grammar a foundry.toml `solc` pin is written
// in: 0.8.24, v0.8.24, 0.8, 0.8.24-nightly.2024.1.1, 0.8.24+commit.e11b9ed9.
var solcVersionRe = regexp.MustCompile(
	`^v?[0-9]+\.[0-9]+(\.[0-9]+)?([-+][0-9A-Za-z.+-]*[0-9A-Za-z])?$`)

// SolcVersionPin reports whether a snapshot's compiler pin may be used as the
// svm cache path component (<dir>/<version>/solc-<version>) and passed to a
// shell. The pin comes from the TARGET repository's foundry.toml, so it is
// untrusted input: before 2026-09-10 the string was interpolated verbatim into
// `docker run … /bin/sh -c "ls /home/foundry/.svm/<pin>"`, so a pin of
// `0.8.20; curl … | sh` ran inside the probe container (which has network) and
// its exit 0 also forged "solc present" in the environment report. A path, a
// URL, a flag or a shell fragment is refused by the callers with a stated
// reason instead of being executed or joined.
func SolcVersionPin(pin string) bool {
	return solcVersionRe.MatchString(strings.TrimSpace(pin))
}

// SolcPinText is the human-facing form of a rejected pin: one line, bounded,
// so an absurd pin cannot flood a report.
func SolcPinText(pin string) string {
	p := strings.TrimSpace(pin)
	if r := []rune(p); len(r) > 60 {
		p = string(r[:60]) + "…"
	}
	return validation.PyReprStr(p)
}

// dockerDaemonOK is docker_daemon_ok's probe. A package var so tests can
// stub the daemon (Python monkeypatches sandbox.docker_daemon_ok).
var dockerDaemonOK = probeDockerDaemon

// probeDockerDaemon is docker_daemon_ok: true only when a docker daemon
// actually answers. The CLI binary existing is NOT availability: a
// "container" profile that would run on the host is the exact lie this
// module exists to refuse.
func probeDockerDaemon() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	res, err := runProc([]string{"docker", "info"}, "", nil, 20*timeSecond)
	if err != nil {
		return false
	}
	return res.ReturnCode == 0
}

// DockerDaemonOK is the exported probe (env.py's doctor reads it).
func DockerDaemonOK() bool { return dockerDaemonOK() }

// HostProfile reports whether a profile executes on the host (no
// container): host-readonly plus the G8 harness profiles, which run the
// host halmos/forge/minicertora binaries like the slither/aderyn probes
// do. Host profiles can never back E4+ evidence — the doctor's e4_capable
// filter and the exec dispatch both key off this (Task 17; Task 18's
// MapRun will route harness runs through exec, still host-side).
func HostProfile(profile string) bool {
	switch profile {
	case "host-readonly", "halmos", "forge-fuzz", "minicertora":
		return true
	default:
		return false
	}
}

// ProfileAvailable is _profile_available.
func ProfileAvailable(profile string) bool {
	switch profile {
	case "host-readonly", "halmos", "forge-fuzz", "minicertora":
		return true
	case "docker-networkless", "docker-gvisor", "fork-runner":
		return dockerDaemonOK()
	default:
		return false // vm-snapshot requires external VM infrastructure
	}
}

// EnvVar is one ordered environment entry: Python's dict insertion order is
// the argv order, so the env mapping is a slice, never a map.
type EnvVar struct{ Key, Value string }

// ContainerMeta is build_container_argv's recorded isolation metadata.
type ContainerMeta struct {
	Image     string
	Runtime   *string
	Network   string
	Workdir   string
	EnvKeys   []string
	SvmMount  *string
	Container validation.Value
}

// BuildContainerArgv is build_container_argv: the real `docker run` argv for
// container profiles plus the `container` metadata recorded on the exec
// record. The command runs INSIDE the container under /bin/sh; the host
// environment is never passed in — only the operator's explicit env mapping
// (plus FORK_RPC_URL for fork-runner).
func BuildContainerArgv(profile, command string, workdir *string,
	env []EnvVar) ([]string, ContainerMeta, error) {
	if !inProfiles(profile) {
		return nil, ContainerMeta{}, fmt.Errorf("unknown profile %s",
			validation.PyReprStr(profile))
	}
	image := DockerImage()
	argv := []string{"docker", "run", "--rm", "--init"}
	var runtime *string
	if profile == "docker-gvisor" {
		argv = append(argv, "--runtime=runsc")
		r := "runsc"
		runtime = &r
	}
	var network string
	if profile == "docker-networkless" || profile == "docker-gvisor" {
		argv = append(argv, "--network", "none")
		network = "none"
	} else { // fork-runner: bridge + host-gateway for the operator's RPC
		argv = append(argv, "--add-host", "host.docker.internal:host-gateway")
		network = "bridge-host-gateway"
	}
	workdirMode := "tmpfs"
	if workdir != nil {
		argv = append(argv, "-v", resolvedPath(*workdir)+":/wd", "-w", "/wd")
		workdirMode = "bind"
	} else {
		argv = append(argv, "--tmpfs", "/wd:rw,size=1g", "-w", "/wd")
	}
	svm := SolcDir()
	if svm != nil {
		argv = append(argv, "-v", *svm+":/home/foundry/.svm")
	}
	containerEnv := append([]EnvVar(nil), env...)
	if profile == "fork-runner" && !hasEnvKey(containerEnv, "FORK_RPC_URL") {
		url := os.Getenv("FORK_RPC_URL")
		if url == "" {
			url = "http://host.docker.internal:8545"
		}
		containerEnv = append(containerEnv, EnvVar{Key: "FORK_RPC_URL", Value: url})
	}
	// The foundry image lints on every `forge build` and PANICS on the
	// first lint hit in a fresh pin — the operator had to hand-set
	// FOUNDRY_LINT_ON_BUILD=false before any Solidity target could build
	// (feedback-triage A3, recommendation #10). Default it off for every
	// container profile (all run the foundry image); an explicit operator
	// env entry still wins.
	if !hasEnvKey(containerEnv, "FOUNDRY_LINT_ON_BUILD") {
		containerEnv = append(containerEnv,
			EnvVar{Key: "FOUNDRY_LINT_ON_BUILD", Value: "false"})
	}
	for _, e := range containerEnv {
		argv = append(argv, "-e", e.Key+"="+e.Value)
	}
	// Pin the entrypoint: the foundry image ships ENTRYPOINT
	// ["/bin/sh","-c"], which would swallow this payload and leave a bare
	// /bin/sh on empty stdin — exit 0, zero output, command never ran.
	argv = append(argv, "--entrypoint", "/bin/sh", image, "-c", command)
	keys := make([]string, 0, len(containerEnv))
	for _, e := range containerEnv {
		keys = append(keys, e.Key)
	}
	sort.Strings(keys)
	meta := ContainerMeta{Image: image, Runtime: runtime, Network: network,
		Workdir: workdirMode, EnvKeys: keys, SvmMount: svm}
	meta.Container = containerValue(meta)
	return argv, meta, nil
}

// resolvedPath is Python's Path(workdir).resolve().
func resolvedPath(p string) string {
	abs, err := filepath.Abs(expandUser(p))
	if err != nil {
		return p
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}

func hasEnvKey(env []EnvVar, key string) bool {
	for _, e := range env {
		if e.Key == key {
			return true
		}
	}
	return false
}

// containerValue renders the `container` metadata dict in Python's key order.
func containerValue(meta ContainerMeta) validation.Value {
	var rt validation.Value
	if meta.Runtime == nil {
		rt = validation.VNull()
	} else {
		rt = validation.VStr(*meta.Runtime)
	}
	var svm validation.Value
	if meta.SvmMount == nil {
		svm = validation.VNull()
	} else {
		svm = validation.VStr(*meta.SvmMount)
	}
	keys := make([]validation.Value, 0, len(meta.EnvKeys))
	for _, k := range meta.EnvKeys {
		keys = append(keys, validation.VStr(k))
	}
	return validation.VObj(
		validation.KV{K: "image", V: validation.VStr(meta.Image)},
		validation.KV{K: "runtime", V: rt},
		validation.KV{K: "network", V: validation.VStr(meta.Network)},
		validation.KV{K: "workdir", V: validation.VStr(meta.Workdir)},
		validation.KV{K: "env_keys", V: validation.VArr(keys...)},
		validation.KV{K: "svm_mount", V: svm},
	)
}

// boolAt is the boolean field reader (a missing/non-bool key reads false).
func boolAt(v validation.Value, key string) bool {
	f := validation.ObjAt(v, key)
	return f.Kind == validation.Bool && f.B
}

// strAt is objStr spelled for the seam code.
func strAt(v validation.Value, key string) string { return validation.ObjStr(v, key) }

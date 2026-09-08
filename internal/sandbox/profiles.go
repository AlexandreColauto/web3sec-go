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

// Profiles is PROFILES: every named execution profile.
var Profiles = []string{"host-readonly", "docker-networkless", "docker-gvisor",
	"vm-snapshot", "fork-runner"}

// profileNetwork is _PROFILE_NETWORK: the honest network label per profile.
// "bridge-host-gateway" is fork-runner's: the container sits on docker's
// bridge and reaches the host only via the host-gateway alias — egress
// restriction is the operator's RPC endpoint's job, not docker's.
var profileNetwork = map[string]string{
	"host-readonly":      "none",
	"docker-networkless": "none",
	"docker-gvisor":      "none",
	"vm-snapshot":        "none",
	"fork-runner":        "bridge-host-gateway",
}

// profileFilesystem is _PROFILE_FILESYSTEM.
var profileFilesystem = map[string]string{
	"host-readonly":      "readonly",
	"docker-networkless": "sandbox-tmp",
	"docker-gvisor":      "sandbox-tmp",
	"vm-snapshot":        "sandbox-tmp",
	"fork-runner":        "sandbox-tmp",
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

// ProfileAvailable is _profile_available.
func ProfileAvailable(profile string) bool {
	switch profile {
	case "host-readonly":
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
	f := objAt(v, key)
	return f.Kind == validation.Bool && f.B
}

// strAt is objStr spelled for the seam code.
func strAt(v validation.Value, key string) string { return objStr(v, key) }

// objAt is the sandbox-local dict lookup (a missing key reads as null).
func objAt(v validation.Value, key string) validation.Value {
	if v.Kind != validation.Obj {
		return validation.VNull()
	}
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

// Package envgo is webv2/env.py: the read-only environment doctor and the
// EXEC FAILURE CLASSIFIER.
//
// The doctor answers, deterministically: what execution infrastructure is
// present, is the fork reachable (and on which chain), and is the image
// digest-pinned. Plus a failure classifier that routes a failed exec to
// environment / setup / logic so an environment failure never burns the
// finding's fresh-context retry budget.
//
// The doctor is READ-ONLY: it probes, it reports, it never mutates the
// campaign (and never logs — a diagnostic that appends events would itself
// stale the report's state-head stamp). It is the REAL implementation behind
// internal/sandbox's seams (D17): cmd/webv2/main.go installs ClassifyFailure
// and SandboxPreflight over the transcription the P2 wave shipped.
package envgo

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"websec/internal/findings"
	"websec/internal/floors"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// Seams. Python's env.py reads these through module globals, and its tests
// monkeypatch ENV.docker_image_probe / ENV.docker_daemon_ok / ENV.solc_dir /
// ENV.subprocess.run. The Go port keeps the same indirection so the ported
// tests can do the same.
var (
	dockerDaemonOK = sandbox.DockerDaemonOK
	dockerImage    = sandbox.DockerImage
	solcDir        = sandbox.SolcDir
	dockerProbe    = DockerImageProbe
	runProc        = realRunProc
	httpDo         = realHTTPDo
)

// procResult is subprocess.CompletedProcess for the probes here.
type procResult struct {
	ReturnCode int
	Stdout     string
	Stderr     string
}

// --- seam setters -----------------------------------------------------------
//
// The Python tests monkeypatch ENV.docker_image_probe / ENV.docker_daemon_ok /
// ENV.solc_dir / ENV.subprocess.run. These setters expose the same four
// indirections to other packages (the CLI-level tests live in package cli).
// A nil argument restores the real implementation.

// SetDockerImageProbe installs docker_image_probe.
func SetDockerImageProbe(f func(*string) validation.Value) {
	if f == nil {
		f = DockerImageProbe
	}
	dockerProbe = f
}

// SetDockerDaemonOK installs the docker_daemon_ok probe.
func SetDockerDaemonOK(f func() bool) {
	if f == nil {
		f = sandbox.DockerDaemonOK
	}
	dockerDaemonOK = f
}

// SetSolcDir installs the solc_dir lookup.
func SetSolcDir(f func() *string) {
	if f == nil {
		f = sandbox.SolcDir
	}
	solcDir = f
}

// SetRunProc installs the subprocess.run stand-in.
func SetRunProc(f func([]string, time.Duration) (procResult, error)) {
	if f == nil {
		f = realRunProc
	}
	runProc = f
}

// ProcResult is the exported view of subprocess.CompletedProcess.
type ProcResult = procResult

// realRunProc is subprocess.run(argv, capture_output=True, text=True,
// timeout=t). A timeout is reported as an error (Python's TimeoutExpired,
// a SubprocessError subclass the probes catch).
func realRunProc(argv []string, timeout time.Duration) (procResult, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	var out, errB strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errB
	if err := cmd.Start(); err != nil {
		return procResult{Stdout: out.String(), Stderr: errB.String()}, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		res := procResult{ReturnCode: cmd.ProcessState.ExitCode(),
			Stdout: out.String(), Stderr: errB.String()}
		if err != nil {
			// A non-zero exit is data, not an error, in Python.
			if _, ok := err.(*exec.ExitError); !ok {
				return res, err
			}
		}
		return res, nil
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		return procResult{Stdout: out.String(), Stderr: errB.String()},
			fmt.Errorf("Command %s timed out after %d seconds",
				pyArgvRepr(argv), int(timeout.Seconds()))
	}
}

// pyArgvRepr is Python's repr of the argv list inside TimeoutExpired.
func pyArgvRepr(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, a := range argv {
		parts = append(parts, validation.PyReprStr(a))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// --- image digest probe -----------------------------------------------------

// DockerImageProbe is docker_image_probe: probe the daemon for the exact
// image the container profiles would run. `digest` is the sha256 image id;
// `pinned` is true only when the reference itself is a digest
// (name@sha256:...) — a tag (even a version tag) can float, a digest cannot.
func DockerImageProbe(image *string) validation.Value {
	name := dockerImage()
	if image != nil {
		name = *image
	}
	daemon, present, pinned := false, false, false
	var digest *string
	detail := ""
	base := name
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	pinned = strings.Contains(base, "@")
	if _, err := exec.LookPath("docker"); err != nil {
		detail = "docker CLI not found"
		return imageProbeValue(name, daemon, present, digest, pinned, detail)
	}
	if !dockerDaemonOK() {
		detail = "docker daemon not answering"
		return imageProbeValue(name, daemon, present, digest, pinned, detail)
	}
	daemon = true
	r, err := runProc([]string{"docker", "image", "inspect", "--format",
		"{{.Id}}", name}, 20*time.Second)
	if err != nil {
		detail = "docker image inspect failed: " + err.Error()
		return imageProbeValue(name, daemon, present, digest, pinned, detail)
	}
	if r.ReturnCode != 0 {
		stderr := strings.TrimSpace(r.Stderr)
		if len([]rune(stderr)) > 120 {
			stderr = string([]rune(stderr)[:120])
		}
		detail = "image not present locally (" + stderr + ") — the first " +
			"E4+ run will pull it, and a floating tag may pull a different " +
			"build than your PoC assumes"
		return imageProbeValue(name, daemon, present, digest, pinned, detail)
	}
	present = true
	d := strings.TrimSpace(r.Stdout)
	digest = &d
	head := d
	if len([]rune(head)) > 19 {
		head = string([]rune(head)[:19])
	}
	if !pinned {
		detail = "tag reference — local digest " + head + "...; pin by " +
			"digest (name@sha256:...) for drift-proof runs"
	} else {
		detail = "digest-pinned — " + head + "..."
	}
	return imageProbeValue(name, daemon, present, digest, pinned, detail)
}

func imageProbeValue(name string, daemon, present bool, digest *string,
	pinned bool, detail string) validation.Value {
	var digestV validation.Value = validation.VNull()
	if digest != nil {
		digestV = validation.VStr(*digest)
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

// --- fork RPC probe ---------------------------------------------------------

// httpReply is the minimal response shape fork_rpc_probe reads.
type httpReply struct {
	Body []byte
}

// realHTTPDo is urllib.request.urlopen(req, timeout=t) for the one JSON-RPC
// POST this module makes.
func realHTTPDo(url string, payload []byte, timeout time.Duration) (httpReply, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(string(payload)))
	if err != nil {
		return httpReply{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return httpReply{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return httpReply{}, err
	}
	return httpReply{Body: body}, nil
}

// ForkRPCProbe is fork_rpc_probe: a minimal JSON-RPC eth_chainId —
// reachability AND the chain id, so a campaign can compare it against its
// chain pin.
func ForkRPCProbe(url *string, timeout float64) validation.Value {
	var u *string
	if url != nil {
		u = url
	} else if v := os.Getenv("FORK_RPC_URL"); v != "" {
		u = &v
	}
	var urlV validation.Value = validation.VNull()
	if u != nil {
		urlV = validation.VStr(*u)
	}
	reachable, chainID, errText := false, (*int64)(nil), ""
	if u == nil {
		errText = "FORK_RPC_URL is not set"
		return rpcValue(urlV, reachable, chainID, errText)
	}
	payload := []byte(`{"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", ` +
		`"params": []}`)
	reply, err := httpDo(*u, payload, time.Duration(timeout*float64(time.Second)))
	if err != nil {
		errText = pyURLOpenError(err)
		return rpcValue(urlV, reachable, chainID, errText)
	}
	var body map[string]any
	if err := json.Unmarshal(reply.Body, &body); err != nil {
		errText = pyErrText("JSONDecodeError", err.Error())
		return rpcValue(urlV, reachable, chainID, errText)
	}
	result, ok := body["result"].(string)
	if ok && strings.HasPrefix(result, "0x") {
		var n int64
		if _, err := fmt.Sscanf(result, "0x%x", &n); err == nil {
			reachable = true
			chainID = &n
			return rpcValue(urlV, reachable, chainID, "")
		}
	}
	raw, _ := json.Marshal(body["result"])
	errText = pyErrText("", "unexpected result: "+pyHead(string(raw), 120))
	return rpcValue(urlV, reachable, chainID, errText)
}

func rpcValue(url validation.Value, reachable bool, chainID *int64,
	errText string) validation.Value {
	var chainV validation.Value = validation.VNull()
	if chainID != nil {
		chainV = validation.VInt(*chainID)
	}
	var errV validation.Value = validation.VNull()
	if errText != "" {
		errV = validation.VStr(errText)
	}
	return validation.VObj(
		validation.KV{K: "url", V: url},
		validation.KV{K: "reachable", V: validation.VBool(reachable)},
		validation.KV{K: "chain_id", V: chainV},
		validation.KV{K: "error", V: errV},
	)
}

// pyErrText renders `{type(exc).__name__}: {str(exc)[:120]}`.
func pyErrText(name, msg string) string {
	msg = pyHead(msg, 120)
	if name == "" {
		return msg
	}
	return name + ": " + msg
}

// pyURLOpenError maps a Go transport error onto Python's urllib text for
// the failures an operator actually hits (connection refused, DNS, timeout).
// Deviation (reported): Go's transport strings differ from Python's, so the
// Errno phrasing is reproduced for the common cases and the raw Go text is
// used otherwise.
func pyURLOpenError(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "connection refused"):
		return "URLError: <urlopen error [Errno 111] Connection refused>"
	case strings.Contains(msg, "no such host"):
		return "URLError: <urlopen error [Errno -2] Name or service not known>"
	case strings.Contains(msg, "Client.Timeout") ||
		strings.Contains(msg, "context deadline exceeded"):
		return "URLError: <urlopen error [Errno 110] Connection timed out>"
	}
	return pyErrText("URLError", msg)
}

func pyHead(s string, n int) string {
	rs := []rune(s)
	if len(rs) <= n {
		return s
	}
	return string(rs[:n])
}

// --- the doctor -------------------------------------------------------------

// Doctor is doctor(campaign=None): one read-only pass over the execution
// environment. With a campaign, the result is cross-checked against what the
// campaign's evidence floor actually REQUIRES.
func Doctor(campaign *state.Campaign) (validation.Value, error) {
	var issues []validation.Value
	image := dockerProbe(nil)
	rpc := ForkRPCProbe(nil, 5.0)
	profiles := validation.VObj()
	e4 := []validation.Value{}
	for _, p := range sandbox.Profiles {
		ok := sandbox.ProfileAvailable(p)
		profiles.O = append(profiles.O, validation.KV{K: p,
			V: validation.VBool(ok)})
		if ok && p != "host-readonly" {
			e4 = append(e4, validation.VStr(p))
		}
	}
	if len(e4) == 0 {
		issues = append(issues, validation.VStr("no E4-capable profile "+
			"available — reproduction evidence cannot be minted at all "+
			"(start the docker daemon: the container profiles are the only "+
			"honest execution path)"))
	}
	if !boolAt(image, "present") && boolAt(image, "daemon") {
		line := "image " + validation.PyReprStr(strAt(image, "image")) +
			" not pulled locally — the first container run will pull it"
		if !boolAt(image, "pinned") {
			line += "; a floating tag may pull a different build than the " +
				"PoC assumes"
		}
		issues = append(issues, validation.VStr(line))
	}
	if !boolAt(rpc, "reachable") {
		issues = append(issues, validation.VStr("fork RPC unreachable ("+
			strAt(rpc, "error")+") — E5+ fork evidence and the fork-runner "+
			"profile are dead until a fork is running and FORK_RPC_URL "+
			"points at it"))
	}

	result := validation.VObj(
		validation.KV{K: "docker", V: validation.VObj(
			validation.KV{K: "cli", V: validation.VBool(hasDockerCLI())},
			validation.KV{K: "daemon", V: validation.VBool(
				boolAt(image, "daemon"))},
			validation.KV{K: "image", V: image})},
		validation.KV{K: "fork_rpc", V: rpc},
		validation.KV{K: "profiles", V: profiles},
		validation.KV{K: "e4_capable", V: validation.VArr(e4...)},
		validation.KV{K: "issues", V: validation.VArr(issues...)},
		validation.KV{K: "ok", V: validation.VBool(len(issues) == 0)},
	)
	if campaign == nil {
		result.O = append(result.O, validation.KV{K: "solc",
			V: validation.VNull()})
		return result, nil
	}
	req, err := CampaignRequirements(campaign)
	if err != nil {
		return validation.VNull(), err
	}
	// feedback-triage A7: a profile that is merely AVAILABLE is not a
	// profile this campaign can USE — docker-networkless=ok next to
	// "max CONFIRMED floor E5" pointed the operator at an E4-only
	// container the floor loop was about to refuse. Pre-run the same
	// floor comparison and record the per-profile fit (appended after
	// solc: the Python-compatible key prefix is untouched).
	fit, err := profileFit(profiles, strAt(req, "max_confirm_floor"))
	if err != nil {
		return validation.VNull(), err
	}
	result.O = append(result.O, validation.KV{K: "campaign", V: req})
	all := append([]validation.Value{}, objAt(result, "issues").A...)
	all = append(all, objAt(req, "issues").A...)
	solc, err := SolcProbe(campaign, image)
	if err != nil {
		return validation.VNull(), err
	}
	if solc != nil {
		if p := objStr(*solc, "problem"); p != "" {
			all = append(all, validation.VStr(p))
		}
	}
	result = setKey(result, "issues", validation.VArr(all...))
	var solcV validation.Value = validation.VNull()
	if solc != nil {
		solcV = *solc
	}
	result.O = append(result.O, validation.KV{K: "solc", V: solcV})
	result.O = append(result.O, validation.KV{K: "profile_fit", V: fit})
	result = setKey(result, "ok", validation.VBool(len(all) == 0))
	return result, nil
}

// profileMaxLevel is the highest evidence level each E4-capable profile can
// honestly back: the isolated containers prove at most E4; fork-runner is
// the E5 shape (a T3/T4 fork test).
var profileMaxLevel = map[string]string{
	"docker-networkless": "E4",
	"docker-gvisor":      "E4",
	"vm-snapshot":        "E4",
	"fork-runner":        "E5",
}

// profileFit is the A7 cross-check: for every AVAILABLE container profile,
// whether its evidence ceiling meets the campaign's max CONFIRMED floor.
// Unavailable profiles are skipped — their "NO" verdict already says all
// there is; host-readonly has no evidence ceiling at all.
func profileFit(profiles validation.Value, maxFloor string) (validation.Value, error) {
	fit := validation.VObj()
	fIdx, err := findings.LevelIndex(maxFloor)
	if err != nil {
		return validation.VNull(), err
	}
	for _, kv := range profiles.O {
		cap, ok := profileMaxLevel[kv.K]
		if !ok || !truthy(kv.V) {
			continue
		}
		cIdx, err := findings.LevelIndex(cap)
		if err != nil {
			return validation.VNull(), err
		}
		if cIdx >= fIdx {
			fit.O = append(fit.O, validation.KV{K: kv.K,
				V: validation.VStr("ok")})
		} else {
			fit.O = append(fit.O, validation.KV{K: kv.K,
				V: validation.VStr(cap + "-only (campaign floor " +
					maxFloor + ")")})
		}
	}
	return fit, nil
}

func hasDockerCLI() bool {
	_, err := exec.LookPath("docker")
	return err == nil
}

// confirmFloorOrder is CLASS_CONFIRM_FLOOR in Python's declaration order
// (Go maps are unordered; campaign_requirements takes a strict maximum, so
// the order only keeps the tie-break identical to the reference).
var confirmFloorOrder = []string{
	"access-control", "signature-replay", "upgrade-initializer",
	"authorization", "reentrancy", "logic-error", "dos-griefing",
	"token-integration", "share-price-accounting", "oracle-manipulation",
	"flash-loan", "share-price-inflation", "economic-invariant",
	"liquidation-logic", "bridge-message", "cross-chain-replay",
}

// CampaignRequirements is campaign_requirements: what this campaign's
// evidence floor needs from the environment, and whether it has it.
func CampaignRequirements(campaign *state.Campaign) (validation.Value, error) {
	var issues []validation.Value
	maxFloor := "E4"
	maxIdx, err := findings.LevelIndex(maxFloor)
	if err != nil {
		return validation.VNull(), err
	}
	for _, cls := range confirmFloorOrder {
		fl := findings.CLASS_CONFIRM_FLOOR[cls]
		eff := fl
		override, err := floors.FloorOverride(campaign, cls)
		if err != nil {
			return validation.VNull(), err
		}
		if override != nil {
			eff = *override
		}
		idx, err := findings.LevelIndex(eff)
		if err != nil {
			return validation.VNull(), err
		}
		if idx > maxIdx {
			maxFloor, maxIdx = eff, idx
		}
	}
	chainPin := false
	st, err := campaign.State()
	if err != nil {
		return validation.VNull(), err
	}
	if sid := objStr(st, "active_snapshot_id"); sid != "" {
		meta := filepath.Join(campaign.Dir, "snapshots", sid, "snapshot.json")
		if pathExists(meta) {
			pin, err := validation.ReadJson(meta)
			if err != nil {
				return validation.VNull(), err
			}
			chainPin = truthy(objAt(pin, "chain"))
		}
	}
	e5Idx, err := findings.LevelIndex("E5")
	if err != nil {
		return validation.VNull(), err
	}
	if maxIdx >= e5Idx {
		if !chainPin {
			issues = append(issues, validation.VStr("campaign: no chain pin "+
				"on the active snapshot — fork evidence (E5+) has no fork "+
				"target (`webv2 snap` with a chain pin)"))
		}
	}
	if os.Getenv("FORK_RPC_URL") == "" && maxIdx >= e5Idx {
		issues = append(issues, validation.VStr("campaign: FORK_RPC_URL "+
			"unset while the effective CONFIRMED floor is E5+ — either "+
			"start a fork or record a floor override (`webv2 floors set`)"))
	}
	return validation.VObj(
		validation.KV{K: "max_confirm_floor", V: validation.VStr(maxFloor)},
		validation.KV{K: "chain_pin", V: validation.VBool(chainPin)},
		validation.KV{K: "issues", V: validation.VArr(issues...)},
	), nil
}

// SolcProbe is solc_probe: does the local image carry the solc the active
// snapshot pinned? None unless a compiler is pinned AND a daemon is up.
func SolcProbe(campaign *state.Campaign, imageProbe validation.Value) (
	*validation.Value, error) {
	sid, err := campaign.ActiveSnapshotIDOrNone()
	if err != nil || sid == nil {
		return nil, err
	}
	pinPath := filepath.Join(campaign.Dir, "snapshots", *sid, "snapshot.json")
	if !pathExists(pinPath) {
		return nil, nil
	}
	pin, err := validation.ReadJson(pinPath)
	if err != nil {
		return nil, nil
	}
	compiler := objStr(objAt(pin, "config"), "compiler")
	if compiler == "" {
		return nil, nil
	}
	version := strings.TrimSpace(strings.SplitN(compiler, ",", 2)[0])
	out := validation.VObj(
		validation.KV{K: "required", V: validation.VStr(version)},
		validation.KV{K: "checked", V: validation.VBool(false)},
		validation.KV{K: "present", V: validation.VNull()},
		validation.KV{K: "problem", V: validation.VNull()},
	)
	if !boolAt(imageProbe, "daemon") {
		return nil, nil
	}
	imageName := strAt(imageProbe, "image")
	if !boolAt(imageProbe, "present") {
		out = setKey(out, "problem", validation.VStr("solc "+version+
			" pinned by the snapshot but image "+
			validation.PyReprStr(imageName)+" is not local — an offline "+
			"first run cannot download it; pull the image or set "+
			"WEBV2_SOLC_DIR"))
		return &out, nil
	}
	r, err := runProc([]string{"docker", "run", "--rm", "--entrypoint",
		"/bin/sh", imageName, "-c", "ls /home/foundry/.svm/" + version},
		20*time.Second)
	if err != nil {
		out = setKey(out, "problem", validation.VStr("solc probe failed: "+
			err.Error()))
		return &out, nil
	}
	out = setKey(out, "checked", validation.VBool(true))
	out = setKey(out, "present", validation.VBool(r.ReturnCode == 0))
	if r.ReturnCode != 0 {
		out = setKey(out, "problem", validation.VStr("solc "+version+
			" missing from image "+validation.PyReprStr(imageName)+
			" — offline containers cannot download it; preinstall it into "+
			"the image's svm cache or set WEBV2_SOLC_DIR (host dir with "+
			"svm layout)"))
	}
	return &out, nil
}

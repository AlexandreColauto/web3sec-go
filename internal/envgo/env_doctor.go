// The environment doctor: one read-only pass over the execution
// infrastructure, cross-checked against the campaign's floor requirements.
package envgo

import (
	"os/exec"

	"websec/internal/findings"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

// doctorState carries the probe results shared by Doctor's sections.
type doctorState struct {
	campaign *state.Campaign
	image    validation.Value
	rpc      validation.Value
	profiles validation.Value
	e4       []validation.Value
	issues   []validation.Value
}

// doctorProbeProfiles probes each sandbox profile, records the per-profile
// availability map and appends the base issues: no E4-capable profile, the
// image not pulled locally, and the fork RPC unreachable.
func (dc *doctorState) doctorProbeProfiles() {
	dc.profiles = validation.VObj()
	dc.e4 = []validation.Value{}
	for _, p := range sandbox.Profiles {
		ok := sandbox.ProfileAvailable(p)
		dc.profiles.O = append(dc.profiles.O, validation.KV{K: p,
			V: validation.VBool(ok)})
		if ok && !sandbox.HostProfile(p) {
			dc.e4 = append(dc.e4, validation.VStr(p))
		}
	}
	if len(dc.e4) == 0 {
		dc.issues = append(dc.issues, validation.VStr("no E4-capable profile "+
			"available — reproduction evidence cannot be minted at all "+
			"(start the docker daemon: the container profiles are the only "+
			"honest execution path)"))
	}
	if !boolAt(dc.image, "present") && boolAt(dc.image, "daemon") {
		line := "image " + validation.PyReprStr(strAt(dc.image, "image")) +
			" not pulled locally — the first container run will pull it"
		if !boolAt(dc.image, "pinned") {
			line += "; a floating tag may pull a different build than the " +
				"PoC assumes"
		}
		dc.issues = append(dc.issues, validation.VStr(line))
	}
	if !boolAt(dc.rpc, "reachable") {
		dc.issues = append(dc.issues, validation.VStr("fork RPC unreachable ("+
			strAt(dc.rpc, "error")+") — E5+ fork evidence and the fork-runner "+
			"profile are dead until a fork is running and FORK_RPC_URL "+
			"points at it"))
	}
}

// doctorResult assembles the base doctor result object.
func (dc *doctorState) doctorResult() validation.Value {
	return validation.VObj(
		validation.KV{K: "docker", V: validation.VObj(
			validation.KV{K: "cli", V: validation.VBool(hasDockerCLI())},
			validation.KV{K: "daemon", V: validation.VBool(
				boolAt(dc.image, "daemon"))},
			validation.KV{K: "image", V: dc.image})},
		validation.KV{K: "fork_rpc", V: dc.forkSection()},
		validation.KV{K: "profiles", V: dc.profiles},
		validation.KV{K: "e4_capable", V: validation.VArr(dc.e4...)},
		validation.KV{K: "issues", V: validation.VArr(dc.issues...)},
		validation.KV{K: "ok", V: validation.VBool(len(dc.issues) == 0)},
	)
}

// forkSection is the fork_rpc probe result plus, when the pinned URL is a
// loopback one, the CONTAINER-facing URL the fork-runner profile actually
// receives (R3-1b, through sandbox.ContainerForkURL — the same function
// the launcher uses, so the report can never claim a rewrite the container
// did not get). The host-facing probe object is otherwise untouched.
func (dc *doctorState) forkSection() validation.Value {
	if dc.rpc.Kind != validation.Obj {
		return dc.rpc
	}
	if validation.ObjAt(dc.rpc, "container_url").Kind != validation.Null {
		return dc.rpc // already named (idempotence for a second caller)
	}
	u := strAt(dc.rpc, "url")
	if u == "" {
		return dc.rpc
	}
	cu := sandbox.ContainerForkURL(u)
	if cu == u {
		return dc.rpc
	}
	dc.rpc.O = append(dc.rpc.O, validation.KV{K: "container_url",
		V: validation.VStr(cu)})
	return dc.rpc
}

// doctorCampaign cross-checks the result against what the campaign's evidence
// floor actually REQUIRES.
func (dc *doctorState) doctorCampaign(result validation.Value) (
	validation.Value, error) {
	req, err := CampaignRequirements(dc.campaign)
	if err != nil {
		return validation.VNull(), err
	}
	// feedback-triage A7: a profile that is merely AVAILABLE is not a
	// profile this campaign can USE — docker-networkless=ok next to
	// "max CONFIRMED floor E5" pointed the operator at an E4-only
	// container the floor loop was about to refuse. Pre-run the same
	// floor comparison and record the per-profile fit (appended after
	// solc: the Python-compatible key prefix is untouched).
	fit, err := profileFit(dc.profiles, strAt(req, "max_confirm_floor"))
	if err != nil {
		return validation.VNull(), err
	}
	result.O = append(result.O, validation.KV{K: "campaign", V: req})
	all := append([]validation.Value{}, validation.ObjAt(result, "issues").A...)
	all = append(all, validation.ObjAt(req, "issues").A...)
	solc, err := SolcProbe(dc.campaign, dc.image)
	if err != nil {
		return validation.VNull(), err
	}
	if solc != nil {
		if p := validation.ObjStr(*solc, "problem"); p != "" {
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

// Doctor is doctor(campaign=None): one read-only pass over the execution
// environment. With a campaign, the result is cross-checked against what the
// campaign's evidence floor actually REQUIRES.
func Doctor(campaign *state.Campaign) (validation.Value, error) {
	dc := doctorState{campaign: campaign}
	dc.image = dockerProbe(nil)
	dc.rpc = ForkRPCProbe(nil, 5.0)
	dc.doctorProbeProfiles()
	result := dc.doctorResult()
	if dc.campaign == nil {
		result.O = append(result.O, validation.KV{K: "solc",
			V: validation.VNull()})
		return result, nil
	}
	return dc.doctorCampaign(result)
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

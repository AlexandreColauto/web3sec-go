// Campaign requirements and the solc probe: what the campaign's evidence
// floor needs from the environment, and whether the pinned compiler is in
// the image.
package envgo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"websec/internal/findings"
	"websec/internal/floors"
	"websec/internal/sandbox"
	"websec/internal/state"
	"websec/internal/validation"
)

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
	if sid := validation.ObjStr(st, "active_snapshot_id"); sid != "" {
		meta := filepath.Join(campaign.Dir, "snapshots", sid, "snapshot.json")
		// r45b: the pin manifest is read, not merely stat'ed. ENOENT is the
		// FACT "no chain pin on the active snapshot" (the advisory below
		// stands); every other stat/read failure is a REFUSAL naming the path
		// and the errno — an unreadable pin is not an absent pin.
		pst, perr := os.Stat(meta)
		switch {
		case perr != nil && os.IsNotExist(perr):
			// no pin manifest at all: nothing pinned, nothing to refuse
		case perr != nil:
			return validation.VNull(), fmt.Errorf("the active snapshot's pin "+
				"manifest %s cannot be read: %v", meta, perr)
		case pst.IsDir():
			return validation.VNull(), fmt.Errorf("the active snapshot's pin "+
				"manifest %s is a directory", meta)
		default:
			pin, rerr := validation.ReadJson(meta)
			if rerr != nil {
				return validation.VNull(), fmt.Errorf("the active snapshot's "+
					"pin manifest %s cannot be read: %v", meta, rerr)
			}
			chainPin = truthy(validation.ObjAt(pin, "chain"))
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
	// r45b: this reader used pathExists (any stat error -> false) and folded
	// a ReadJson error into (nil, nil) = "no solc required". ENOENT is the
	// FACT that nothing is pinned; any other failure is a REFUSAL naming the
	// path and the errno.
	if pst, perr := os.Stat(pinPath); perr != nil {
		if os.IsNotExist(perr) {
			return nil, nil
		}
		return nil, fmt.Errorf("the active snapshot's pin manifest %s cannot "+
			"be read: %v", pinPath, perr)
	} else if pst.IsDir() {
		return nil, fmt.Errorf("the active snapshot's pin manifest %s is a "+
			"directory", pinPath)
	}
	pin, err := validation.ReadJson(pinPath)
	if err != nil {
		return nil, fmt.Errorf("the active snapshot's pin manifest %s cannot "+
			"be read: %v", pinPath, err)
	}
	compiler := validation.ObjStr(validation.ObjAt(pin, "config"), "compiler")
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
	// The pin is read out of the TARGET repo's foundry.toml, so it is
	// untrusted input: only a plain version may be handed to the container
	// (as argv, never as a shell word) or joined into the svm cache path.
	if !sandbox.SolcVersionPin(version) {
		out = setKey(out, "problem", validation.VStr("the active snapshot "+
			"pins compiler "+sandbox.SolcPinText(version)+", which is not a "+
			"solc version — refusing to probe image "+
			validation.PyReprStr(strAt(imageProbe, "image"))+" with it "+
			"(foundry.toml 'solc' must name a release such as 0.8.24, not "+
			"a path or a command)"))
		return &out, nil
	}
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
	// $1 is the version: the pin never becomes part of the shell source.
	r, err := runProc([]string{"docker", "run", "--rm", "--entrypoint",
		"/bin/sh", imageName, "-c", `ls "/home/foundry/.svm/$1"`,
		"solc-probe", version},
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

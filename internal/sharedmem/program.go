// Program identity: the (program, platform, chains) key every store row
// and recall query is namespaced by.

package sharedmem

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// ---- program identity ------------------------------------------------------

// programKey is _program_key.
func programKey(policy validation.Value) (string, validation.Value, error) {
	program := strings.TrimSpace(validation.ObjStr(policy, "program"))
	platform := strings.TrimSpace(validation.ObjStr(policy, "platform"))
	var platformV validation.Value = validation.VNull()
	if platform != "" {
		platformV = validation.VStr(platform)
	}
	chains := strList(validation.ObjAt(policy, "chains"))
	sort.Strings(chains)
	if program == "" {
		return "", validation.VNull(), errors.New(
			"policy has no program name — cannot derive a program key")
	}
	platformPart := platform
	if platformPart == "" {
		platformPart = "-"
	}
	key := program + "|" + platformPart + "|" + strings.Join(chains, ",")
	return key, validation.VObj(
		kv("program", validation.VStr(program)),
		kv("platform", platformV),
		kv("chains", validation.StrArr(chains))), nil
}

// ProgramKeyOf is program_key_of: the campaign's program identity, from its
// loaded bounty policy.
func ProgramKeyOf(c *state.Campaign) (string, validation.Value, error) {
	st, err := c.State()
	if err != nil {
		return "", validation.VNull(), err
	}
	policyPath := validation.ObjStr(st, "policy_path")
	if policyPath == "" {
		return "", validation.VNull(), noPolicyErr(c)
	}
	if _, err := os.Stat(policyPath); err != nil {
		return "", validation.VNull(), noPolicyErr(c)
	}
	policy, err := validation.ReadJson(policyPath)
	if err != nil {
		return "", validation.VNull(), err
	}
	return programKey(policy)
}

func noPolicyErr(c *state.Campaign) error {
	return fmt.Errorf("%s: no policy loaded — run scope(policy_path=...) "+
		"before sharing or recalling", c.CampaignID)
}

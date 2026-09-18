// Routing concern: ROUTING_CONFIG overrides, effective stage config, and the
// routing surfaces (load_routing, route, routing_table).
package adapter

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

var stageRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// RoutingConfig is ROUTING_CONFIG (REPO_ROOT/config/stage_routing.json).
func RoutingConfig() string {
	return filepath.Join(RepoRoot, "config", "stage_routing.json")
}

// routingOverride is _routing_override(): deployment overrides. A missing
// file is normal (defaults apply); malformed JSON is a loud error.
func routingOverride() (validation.Value, error) {
	p := RoutingConfig()
	raw, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return validation.VObj(), nil
		}
		return validation.VNull(), err
	}
	data, err := validation.ParseOrdered(raw)
	if err != nil {
		return validation.VNull(), err
	}
	if data.Kind != validation.Obj {
		return validation.VNull(), fmt.Errorf("%s must contain a JSON object", p)
	}
	return data, nil
}

// StageConfig is stage_config(): effective (budget_class, prompt) after
// overrides.
func StageConfig(stage string) (budgetClass, prompt string, err error) {
	base := stagesByID[stage]
	if _, ok := stagesByID[stage]; !ok {
		base = Stage{ID: stage, BudgetClass: "standard"}
	}
	budgetClass, prompt = base.BudgetClass, base.Prompt
	ov, err := routingOverride()
	if err != nil {
		return "", "", err
	}
	entry := validation.ObjAt(ov, stage)
	if entry.Kind != validation.Obj {
		return budgetClass, prompt, nil
	}
	if v := validation.ObjAt(entry, "budget_class"); v.Kind == validation.Str {
		budgetClass = v.S
	}
	if v := validation.ObjAt(entry, "prompt"); v.Kind == validation.Str {
		prompt = v.S
	} else if v := validation.ObjAt(entry, "prompt"); v.Kind == validation.Null {
		prompt = ""
	}
	return budgetClass, prompt, nil
}

// LoadRouting is load_routing(): stage -> budget class, campaign-local
// routing.json winning over the global config, which wins over defaults.
// The returned object preserves Python's dict order.
func LoadRouting(c *state.Campaign) (validation.Value, error) {
	out := validation.VObj()
	seen := map[string]bool{}
	for _, s := range Stages {
		cls, _, err := StageConfig(s.ID)
		if err != nil {
			return validation.VNull(), err
		}
		out.O = append(out.O, validation.KV{K: s.ID, V: validation.VStr(cls)})
		seen[s.ID] = true
	}
	if c == nil {
		return out, nil
	}
	override := filepath.Join(c.Dir, "routing.json")
	raw, err := os.ReadFile(override)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return validation.VNull(), err
	}
	data, err := validation.ParseOrdered(raw)
	if err != nil {
		return validation.VNull(), err
	}
	if data.Kind != validation.Obj {
		return validation.VNull(), fmt.Errorf("%s must contain a JSON object", override)
	}
	for _, kv := range data.O {
		val := kv.V
		if val.Kind == validation.Obj {
			val = validation.ObjAt(val, "budget_class")
		}
		if val.Kind != validation.Null && val.Kind != validation.Str {
			return validation.VNull(), fmt.Errorf(
				"%s: budget class for %s must be a string", override,
				validation.PyReprStr(kv.K))
		}
		if seen[kv.K] {
			setObj(out, kv.K, val)
		} else {
			out.O = append(out.O, validation.KV{K: kv.K, V: val})
			seen[kv.K] = true
		}
	}
	return out, nil
}

// Route is route(): the budget class a stage routes to.
func Route(c *state.Campaign, stage string) (string, error) {
	if !stageRe.MatchString(stage) {
		return "", fmt.Errorf("bad stage id %s", validation.PyReprStr(stage))
	}
	if !KnownStage(stage) {
		return "", fmt.Errorf("unknown stage %s; known stages: %s",
			validation.PyReprStr(stage), strings.Join(StageIDs(), ", "))
	}
	routing, err := LoadRouting(c)
	if err != nil {
		return "", err
	}
	cls := validation.ObjAt(routing, stage)
	if cls.Kind != validation.Str {
		return "", fmt.Errorf("stage %s routed to unknown budget class %s; "+
			"known: %s", validation.PyReprStr(stage), validation.PyRepr(cls),
			strings.Join(BudgetClassNames(), ", "))
	}
	if _, ok := BudgetHintOf(cls.S); !ok {
		return "", fmt.Errorf("stage %s routed to unknown budget class %s; "+
			"known: %s", validation.PyReprStr(stage), validation.PyRepr(cls),
			strings.Join(BudgetClassNames(), ", "))
	}
	return cls.S, nil
}

// RoutingTable is routing_table(): stage -> {budget_class, hint, prompt}.
func RoutingTable(c *state.Campaign) (validation.Value, error) {
	routing, err := LoadRouting(c)
	if err != nil {
		return validation.VNull(), err
	}
	out := validation.VObj()
	for _, kv := range routing.O {
		cls := kv.V.S
		_, prompt, err := StageConfig(kv.K)
		if err != nil {
			return validation.VNull(), err
		}
		hint, _ := BudgetHintOf(cls)
		out.O = append(out.O, validation.KV{K: kv.K, V: validation.VObj(
			validation.KV{K: "budget_class", V: validation.VStr(cls)},
			validation.KV{K: "hint", V: validation.VStr(hint)},
			validation.KV{K: "prompt", V: nullableStr(prompt)},
		)})
	}
	return out, nil
}

func nullableStr(s string) validation.Value {
	if s == "" {
		return validation.VNull()
	}
	return validation.VStr(s)
}

func setObj(v validation.Value, key string, val validation.Value) {
	for i := range v.O {
		if v.O[i].K == key {
			v.O[i].V = val
			return
		}
	}
}

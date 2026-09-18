// plan_lifecycle.go: Task 2 — the model's own adversarial-lifecycle
// state machines mint into the plan queue through the same scoring path.
package planner

import (
	"sort"
	"strings"
	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- Task 2: adversarial-lifecycle surfaces mint into the queue ------------

// lifecycleVocabulary is the adversarial-lifecycle verb vocabulary: the verbs
// a commit→challenge→finalize (or propose→vote→execute) game is spelled with.
// Asset-flow verbs (deposit/transfer/relay/swap/mint/burn) are deliberately
// absent — they are happy-path surface, not the game an adversary wins.
var lifecycleVocabulary = []string{"commit", "challenge", "finalize", "settle",
	"claim", "withdraw", "dispute", "prove", "refund", "liquidate", "redeem"}

// lifecycleSurface is one qualifying state machine: its name (the STABLE
// handle — see the id scheme below) and its verb chain, in vocabulary order.
type lifecycleSurface struct {
	name  string
	chain string
}

// adversarialLifecycleSurfaces is the model's own state machines that carry an
// adversarial game, sorted by machine name. The CARDINALITY RULE is binding: a
// machine qualifies only when >= 2 DISTINCT vocabulary tokens occur across its
// name and its transition action names combined. A lone `withdraw` (every
// vault), lone `claim` (airdrops), lone `redeem` (receipt tokens) or lone
// `settle` (oracle fulfillment) is benign happy-path surface, and minting rows
// for those would recreate the very noise this task exists to remove.
//
// Only transition OBJECTS count, through their schema `trigger` (the action
// name): a machine whose transitions are not schema-shaped is degenerate and
// contributes nothing.
func adversarialLifecycleSurfaces(model validation.Value) []lifecycleSurface {
	out := []lifecycleSurface{}
	for _, sm := range listOf(model, "state_machines") {
		name := validation.ObjStr(sm, "name")
		if name == "" {
			continue
		}
		toks := lifecycleMachineTokens(sm)
		if len(toks) < 2 {
			continue
		}
		out = append(out, lifecycleSurface{name: name,
			chain: strings.Join(toks, " → ")})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].name < out[j].name
	})
	return out
}

// AdversarialLifecycleMachines is the exported handle for the selection above:
// the sorted names of the model's adversarial lifecycle machines (Task 2).
// Downstream consumers match on the NAME, never on a minted row id — the
// LC-%03d ids are positional, so a later model that adds an alphabetically
// earlier machine shifts every id after it.
func AdversarialLifecycleMachines(model validation.Value) []string {
	out := []string{}
	for _, s := range adversarialLifecycleSurfaces(model) {
		out = append(out, s.name)
	}
	return out
}

// lifecycleMachineTokens is the distinct vocabulary tokens the machine's NAME
// and its transition action names carry, left-boundary and case-insensitive,
// in vocabulary order (deterministic, independent of transition order).
func lifecycleMachineTokens(sm validation.Value) []string {
	hit := map[string]bool{}
	scan := func(text string) {
		for _, tok := range lifecycleVocabulary {
			if tokenOccursLeftBound(text, tok) {
				hit[tok] = true
			}
		}
	}
	scan(validation.ObjStr(sm, "name"))
	for _, tr := range listOf(sm, "transitions") {
		if tr.Kind != validation.Obj {
			continue
		}
		scan(validation.ObjStr(tr, "trigger"))
	}
	out := []string{}
	for _, tok := range lifecycleVocabulary {
		if hit[tok] {
			out = append(out, tok)
		}
	}
	return out
}

// tokenOccursLeftBound reports whether text contains token starting at a left
// boundary: the match begins the string, or the character before it is outside
// [0-9a-z_]. Matching is case-insensitive and there is deliberately NO trailing
// boundary — `commitBatch` and `challengeState` are action names, so a trailing
// \b would reject exactly the machines this task must rank.
//
// This is the same spec as invariants' tokenOccursLeftBound (Task 1), spelled
// out here on purpose: the invariants helper is unexported, the two packages'
// pinned tables are independent, and neither should have to move for the
// other. Keep the two in sync.
func tokenOccursLeftBound(text, token string) bool {
	if token == "" {
		return false
	}
	body := strings.ToLower(text)
	tok := strings.ToLower(token)
	for from := 0; from < len(body); {
		i := strings.Index(body[from:], tok)
		if i < 0 {
			return false
		}
		at := from + i
		if at == 0 || !isLowerWordByte(body[at-1]) {
			return true
		}
		from = at + 1
	}
	return false
}

// isLowerWordByte is the left-boundary alphabet on the lowered text: [0-9a-z_].
func isLowerWordByte(b byte) bool {
	return b == '_' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z')
}

// bootstrapLifecycleSurfaces mints one `now`-slotted row per adversarial
// lifecycle machine, LAST in the plan build so no pre-existing question's
// Q-number moves. The rows carry the machine name as their named component, so
// the EXISTING planner scoring (untouched * 1.0 + severity * 2.0 + openQ *
// 1.5, slot class primary) ranks them — no new scoring path.
//
// Skips are deliberate and run against the ENTIRE work queue minted so far
// (every earlier minter's rows, not just one family's output), the campaign's
// live findings, and the coverage ledger's own swept test — the same predicate
// the queue scoring calls "untouched". A machine whose surface is already
// covered would make the row's "no covering finding" claim false.
func bootstrapLifecycleSurfaces(b *planBuilder, campaign *state.Campaign,
	model validation.Value) error {
	surfaces := adversarialLifecycleSurfaces(model)
	if len(surfaces) == 0 {
		return nil
	}
	signals, err := buildQueueSignals(campaign, model)
	if err != nil {
		return err
	}
	live, err := findings.LoadLiveFindings(campaign)
	if err != nil {
		return err
	}
	for i, s := range surfaces {
		if lifecycleSurfaceCovered(s.name, b.priorities, signals, live) {
			continue
		}
		// risk 0.9 / cheap: the adversarial game is answerable by a look at
		// the code, and it is the highest-risk unmodeled surface — it belongs
		// in the `now` slot (DecisionRule(0.9, "cheap")), ahead of generic
		// index work. Positional id over the SORTED machines: a skipped
		// machine keeps its position, and the machine NAME stays the handle.
		b.addWithID(lifecycleID(i+1), validation.VNull(),
			"review adversarial lifecycle "+s.name+" ("+s.chain+
				") — no covering finding", 0.9, []string{s.name},
			[]string{"lifecycle"}, addOpts{budget: "cheap"})
	}
	return nil
}

// lifecycleSurfaceCovered is the skip predicate: a queue row already names the
// machine as one of its components, a live finding already implicates it, or
// the coverage ledger already marks its surface swept. The component test is
// exact (not a text search): the queue's own scoring reads `components` as the
// row's surface identity, and a substring match would let a machine named
// `rollup` suppress `rollup_finalization`.
func lifecycleSurfaceCovered(name string, queue []validation.Value,
	signals *queueSignals, live []validation.Value) bool {
	for _, row := range queue {
		for _, c := range listOf(row, "components") {
			if validation.PyStr(c) == name {
				return true
			}
		}
	}
	for _, f := range live {
		for _, a := range listOf(f, "affected") {
			if validation.ObjStr(a, "contract") == name || validation.ObjStr(a, "path") == name {
				return true
			}
		}
	}
	path, ok := signals.inScope[name]
	return ok && signals.touched[path]
}

// lifecycleID is f"LC-{n:03d}" — the display-only positional id of a minted
// lifecycle row. Never a handle: match on the machine name.
func lifecycleID(n int) string {
	return "LC-" + pad3(n)
}

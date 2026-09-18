package chainengine

import (
	"fmt"

	"websec/internal/state"
	"websec/internal/validation"
)

// maxDeriveDepth is the B3 terminal-search depth (the terminal report's
// working depth).
const maxDeriveDepth = 5

// derivedTerminal is the B3 terminal derivation: the hypothesis-mode
// terminal search is asked for reachable terminal paths, and a path whose
// member set is exactly this chain's members becomes the terminal
// annotation. No match (or a search error) means no annotation — the chain
// still materializes, just unpriced. The search's own proposal cap applies,
// so a campaign with hundreds of competing paths may miss a match; that
// degrades to "unpriced", never to a wrong price.
func derivedTerminal(c *state.Campaign, memberIDs []string) *validation.Value {
	paths, err := FindTerminalChainsMode(c, nil, maxDeriveDepth,
		len(memberIDs), true)
	if err != nil {
		return nil
	}
	want := setOf(memberIDs)
	for _, p := range paths {
		path := strList(validation.ObjAt(p, "path"))
		if len(path) != len(want) {
			continue
		}
		got := setOf(path)
		if len(got) != len(want) {
			continue
		}
		if !subsetOf(got, want) {
			continue
		}
		term := validation.ObjStr(p, "terminal_finding")
		if term == "" {
			continue
		}
		doc := validation.VObj(
			kvOf("capability", validation.VStr(validation.ObjStr(p, "terminal_capability"))),
			kvOf("via_finding", validation.VStr(term)),
			kvOf("total_capital_required_usd",
				validation.ObjAt(p, "total_capital_required_usd")),
		)
		return &doc
	}
	return nil
}

// chainDuplicate is the idempotence guard: a chain over this exact member set
// may exist only once.
func chainDuplicate(c *state.Campaign, signature string) error {
	existing, err := chainDocs(c, false)
	if err != nil {
		return err
	}
	for _, ch := range existing {
		if validation.ObjStr(ch, "chain_signature") == signature {
			return fmt.Errorf(
				"a chain over this member set already exists: %s",
				validation.ObjStr(ch, "chain_id"))
		}
	}
	return nil
}

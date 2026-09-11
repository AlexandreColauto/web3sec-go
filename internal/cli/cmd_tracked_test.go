package cli

// Task 6 (G9) CLI tests — the tracked-but-opaque component surfaces in the
// plan view and the brief cockpit. TDD: written BEFORE the renderers; must
// FAIL (no tracked block) until the views render it.

import (
	"strings"
	"testing"
)

// t14ComponentsModelJSON is t14TestModelJSON plus one paid, in-scope
// frontend component (Task 1 shape, verbatim field names).
const t14ComponentsModelJSON = `{"protocol_id":"sharevault","name":"ShareVault",` +
	`"snapshot_id":"unpinned","chains":["ethereum"],"subsystems":["defi-vault"],` +
	`"contracts":[{"name":"ShareVault","path":"src/ShareVault.sol",` +
	`"role":"core","in_scope":true,"entry_points":["deposit","withdraw"],` +
	`"state_variables":[{"name":"totalAssets","kind":"balance",` +
	`"accounting":true}]}],"actors":[{"id":"user","kind":"EOA",` +
	`"trust":"externally-owned"}],"assets":[{"id":"share","kind":"share",` +
	`"erc":"4626","decimals":18},{"id":"ETH","kind":"token","decimals":18}],` +
	`"liabilities":[],"privileges":[],"trust_boundaries":[],"relations":[],` +
	`"state_machines":[],"economic_relations":[],"invariants":[{"id":"INV-5",` +
	`"statement":"the exchange rate must not move in favor of existing shares ` +
	`from out-of-band asset transfers","applies_to":["ShareVault"],` +
	`"kind":"economic","severity_if_broken":"critical"}],"oracles":[],` +
	`"components":[{"kind":"frontend","path":"app/","trust":"untrusted",` +
	`"in_scope":true,"paid_for":true}]}`

func TestPlanTrackedSurfacesGated(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	t14TestSeed(t, root, cid)
	// Baseline: no components key, no tracked block — byte-stability.
	code, out, errS := run(t, "--root", root, "plan", cid)
	if code != 0 {
		t.Fatalf("plan exit %d: %q", code, errS)
	}
	if strings.Contains(out, "tracked-but-opaque") {
		t.Fatalf("plan without components must not render tracked surfaces:\n%s",
			out)
	}
	// Rebuild over a component model: the block lists the surface.
	model := t14TestWrite(t, root, "components-model.json",
		t14ComponentsModelJSON)
	if code, _, errS := run(t, "--root", root, "model", cid,
		model); code != 0 {
		t.Fatalf("model exit %d: %q", code, errS)
	}
	code, out, errS = run(t, "--root", root, "plan", cid, "--rebuild")
	if code != 0 {
		t.Fatalf("plan exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "- frontend app/: in_scope, paid") {
		t.Fatalf("plan missing the tracked component line:\n%s", out)
	}
}

func TestBriefTrackedSurfacesGated(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("brief exit %d: %q", code, errS)
	}
	if strings.Contains(out, "tracked-but-opaque") {
		t.Fatalf("brief without components must not render tracked surfaces:\n%s",
			out)
	}
	model := t14TestWrite(t, root, "components-model.json",
		t14ComponentsModelJSON)
	if code, _, errS := run(t, "--root", root, "model", cid,
		model); code != 0 {
		t.Fatalf("model exit %d: %q", code, errS)
	}
	code, out, errS = run(t, "--root", root, "brief", cid)
	if code != 0 {
		t.Fatalf("brief exit %d: %q", code, errS)
	}
	if !strings.Contains(out, "- frontend app/: in_scope, paid") {
		t.Fatalf("brief missing the tracked component line:\n%s", out)
	}
}

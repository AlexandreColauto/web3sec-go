package cli

// T14 cmd_scope tests — plus the shared T14 fixture helpers (the T14 command
// files own no other test file that could hold them). Every expected string
// was captured from the live Python CLI; see py3.json [untracked].

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// t14TestModelJSON is the T14 twin protocol model (a valid protocol_model).
const t14TestModelJSON = `{"protocol_id":"sharevault","name":"ShareVault",` +
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
	`"kind":"economic","severity_if_broken":"critical"}],"oracles":[]}`

// t14TestPolicyJSON is the T14 twin bounty policy (a valid bounty_policy).
const t14TestPolicyJSON = `{"program":"Acme Immunefi","program_url":"https://x",` +
	`"platform":"immunefi","chains":["ethereum"],` +
	`"scope":[{"target":"Vault","kind":"contract"}],"exclusions":[],` +
	`"severity_rules":[{"severity":"critical","match":{"bug_classes":` +
	`["access-control"],"require_invariant_violation":true}}],` +
	`"poc_requirements":{"min_evidence_level":"E4","require_fork_repro":false},` +
	`"reporting":{"contact":"immunefi","required_fields":["PoC","impact"]}}`

// t14TestHypothesisJSON is a schema-valid hypothesis payload (variant 1).
const t14TestHypothesisJSON = `{"title":"ShareVault deposit inflates share ` +
	`price (variant 1)","root_cause":{"class":"share-price-inflation",` +
	`"description":"The first depositor sets the share price with a single ` +
	`wei, so all later depositors buy shares at a price the attacker chose, ` +
	`diluting their position.","mechanism":"deposit() mints shares at ` +
	`total_assets/total_shares before any real assets are in the vault"},` +
	`"affected":[{"path":"src/ShareVault.sol","contract":"ShareVault",` +
	`"function":"deposit","lines":[42,60],"entry_point":true}],` +
	`"attacker":{"profile":"arbitrary EOA","capabilities":["deposit"]},` +
	`"evidence":[],"invariant":{"id":"INV-1","statement":"a depositor's share ` +
	`of total assets may not decrease as a result of their own deposit"},` +
	`"assumptions":[{"id":"A1","type":"state","claim":"the vault can be empty ` +
	`when the first deposit arrives","status":"UNKNOWN","model_belief":0.9,` +
	`"blocking":true}],"preconditions":[{"kind":"state","description":"vault ` +
	`is empty (total_shares == 0)","satisfied_by":"be the first depositor"}],` +
	`"exploit_sequence":[{"step":1,"actor":"attacker","action":"deposit(1 ` +
	`wei) to set the share price"},{"step":2,"actor":"victim","action":` +
	`"deposit(1 ETH) at the attacker-set price"}]}`

// t14TestWrite writes a fixture file and returns its path.
func t14TestWrite(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// t14TestSeed loads the protocol model and bootstraps the default plan, the
// state every plan-dependent T14 command needs. Returns the model path.
func t14TestSeed(t *testing.T, root, cid string) string {
	t.Helper()
	model := t14TestWrite(t, root, "model.json", t14TestModelJSON)
	code, out, errS := run(t, "--root", root, "model", cid, model)
	if code != 0 {
		t.Fatalf("model exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "model loaded: 1 actors, 2 assets, 1 invariants") {
		t.Fatalf("model output = %q", out)
	}
	code, out, errS = run(t, "--root", root, "plan", cid)
	if code != 0 {
		t.Fatalf("plan exit %d: %q", code, errS)
	}
	if !strings.HasPrefix(out, "plan: 8 queued priorities\n") {
		t.Fatalf("plan output = %q", out)
	}
	return model
}

func TestScopeNoPolicy(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	code, out, errS := run(t, "--root", root, "scope", cid)
	if code != 0 {
		t.Fatalf("scope exit %d: %q", code, errS)
	}
	want := "no policy provided (load one before BOUNTY_GATE with " +
		"`webv2 scope C-xxx --policy p.json`)\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

func TestScopeLoadPolicy(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	policy := t14TestWrite(t, root, "policy.json", t14TestPolicyJSON)
	code, out, errS := run(t, "--root", root, "scope", cid,
		"--policy", policy)
	if code != 0 {
		t.Fatalf("scope --policy exit %d: %q", code, errS)
	}
	want := "policy loaded from " + policy + " — 1 scope entries, " +
		"0 exclusions\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	// a bare `scope` reprints the no-policy line even after a load (Python
	// prints unconditionally when --policy is absent) — parity, not a bug
	code, out2, _ := run(t, "--root", root, "scope", cid)
	if code != 0 {
		t.Fatalf("scope read-back exit %d", code)
	}
	if out2 == out {
		t.Fatalf("read-back repeated the load line: %q", out2)
	}
	if !strings.Contains(out2, "no policy provided") {
		t.Fatalf("read-back = %q", out2)
	}
}

func TestScopeMissingFile(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	missing := filepath.Join(root, "nope.json")
	code, out, errS := run(t, "--root", root, "scope", cid,
		"--policy", missing)
	if code != 1 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	want := "error: [Errno 2] No such file or directory: '" + missing + "'\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestScopeMissingCampaignBeatsMissingPolicy(t *testing.T) {
	root := mkroot(t)
	// cli.py opens the campaign first (_campaign), so with both the campaign
	// and the policy file missing the campaign error is the whole output.
	code, out, errS := run(t, "--root", root, "scope", "C-0000000000",
		"--policy", filepath.Join(root, "nope.json"))
	if code != 1 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != "" {
		t.Fatalf("stdout = %q", out)
	}
	if !strings.HasPrefix(errS, "error: no such campaign: ") {
		t.Fatalf("stderr = %q", errS)
	}
	if strings.Contains(errS, "Errno 2") {
		t.Fatalf("policy error leaked: %q", errS)
	}
}

func TestScopeBadPolicy(t *testing.T) {
	root := mkroot(t)
	cid := initOne(t, root)
	bad := t14TestWrite(t, root, "badpolicy.json", `{"program":"x"}`)
	code, _, errS := run(t, "--root", root, "scope", cid, "--policy", bad)
	if code != 1 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	want := "error: bounty_policy validation failed at <root>: " +
		"'program_url' is a required property (+5 more errors)\n"
	if errS != want {
		t.Fatalf("stderr = %q, want %q", errS, want)
	}
}

func TestScopeHelp(t *testing.T) {
	code, out, errS := run(t, "scope", "--help")
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	if out != t14ScopeHelp {
		t.Fatalf("help = %q, want %q", out, t14ScopeHelp)
	}
	if errS != "" {
		t.Fatalf("stderr = %q", errS)
	}
}

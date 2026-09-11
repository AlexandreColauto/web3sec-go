// autotune_test.go (G17 tactic batting average): the policy gate is
// conservative — absent or false behaves byte-for-byte as before,
// true/false validate, and a non-boolean is refused by the schema (with
// AutoTuneEnabled as the last line of defense). Campaign resolution
// degrades to off when the policy file is absent or unreadable.
package bounty

import (
	"os"
	"path/filepath"
	"testing"

	"websec/internal/state"
	"websec/internal/validation"
)

func TestAutoTuneEnabled(t *testing.T) {
	if AutoTuneEnabled(validation.VNull()) {
		t.Error("null policy must not enable auto-tune")
	}
	if AutoTuneEnabled(testPolicy()) {
		t.Error("the default policy (no flag) must not enable auto-tune")
	}
	off := testPolicy()
	off.O = validation.SetOrAppend(off.O, "auto_tune",
		validation.VBool(false))
	if AutoTuneEnabled(off) {
		t.Error("explicit false must not enable auto-tune")
	}
	on := testPolicy()
	on.O = validation.SetOrAppend(on.O, "auto_tune",
		validation.VBool(true))
	if !AutoTuneEnabled(on) {
		t.Error("explicit true must enable auto-tune")
	}
	// A hand-built non-boolean never enables (the schema refuses it at
	// load time; this is the defense in depth).
	junk := testPolicy()
	junk.O = validation.SetOrAppend(junk.O, "auto_tune",
		validation.VStr("yes"))
	if AutoTuneEnabled(junk) {
		t.Error("a string flag must not enable auto-tune")
	}
}

func TestAutoTuneSchemaGate(t *testing.T) {
	if err := validation.Validate(testPolicy(), "bounty_policy", 1); err != nil {
		t.Fatalf("default policy must validate: %v", err)
	}
	for _, b := range []bool{true, false} {
		p := testPolicy()
		p.O = validation.SetOrAppend(p.O, "auto_tune",
			validation.VBool(b))
		if err := validation.Validate(p, "bounty_policy", 1); err != nil {
			t.Fatalf("auto_tune=%v must validate: %v", b, err)
		}
	}
	p := testPolicy()
	p.O = validation.SetOrAppend(p.O, "auto_tune",
		validation.VStr("yes"))
	if err := validation.Validate(p, "bounty_policy", 1); err == nil {
		t.Fatal("a string auto_tune must be rejected by the schema")
	}
}

// TestAutoTuneForCampaign pins the campaign resolution: absent policy
// file, garbage file, explicit false all degrade to off; only a parsing
// policy with auto_tune:true enables.
func TestAutoTuneForCampaign(t *testing.T) {
	if AutoTuneForCampaign(nil) {
		t.Error("nil campaign must not enable auto-tune")
	}
	dir := t.TempDir()
	c, err := state.Init(dir, "auto-tune probe", state.InitOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if AutoTuneForCampaign(c) {
		t.Error("a campaign with no policy file must not enable auto-tune")
	}
	if err := os.WriteFile(filepath.Join(c.Dir, "bounty_policy.json"),
		[]byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if AutoTuneForCampaign(c) {
		t.Error("an unparseable policy file must not enable auto-tune")
	}
	off := testPolicy()
	if err := validation.WriteJson(
		filepath.Join(c.Dir, "bounty_policy.json"), off, ""); err != nil {
		t.Fatal(err)
	}
	if AutoTuneForCampaign(c) {
		t.Error("absent flag (T11-style defaulting) must not enable auto-tune")
	}
	on := testPolicy()
	on.O = validation.SetOrAppend(on.O, "auto_tune", validation.VBool(true))
	if err := validation.WriteJson(
		filepath.Join(c.Dir, "bounty_policy.json"), on, ""); err != nil {
		t.Fatal(err)
	}
	if !AutoTuneForCampaign(c) {
		t.Error("auto_tune:true must enable auto-tune for the campaign")
	}
}

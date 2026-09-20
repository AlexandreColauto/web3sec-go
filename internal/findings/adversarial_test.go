package findings

// IMPROVEMENTS B2 — the adversarial-game clause: a liveness finding must
// answer "who profits from the freeze, how does the profit work, and why
// does the challenge path not undo it?" The setter stores the answer as
// DATA and logs finding.adversarial_game_set; the gate (check15)
// re-validates the stored value.

import (
	"strconv"
	"strings"
	"testing"

	"websec/internal/validation"
)

// The four clause arguments, each well past the 20-rune floor.
const (
	agWho = "the sequencer operator — every frozen hour pays their " +
		"uptime fees while rival bridges lose the deposits in transit"
	agMech = "freezing withdrawals lets the operator's own staked " +
		"position absorb the fee flow while the halted bridge bleeds " +
		"TVL to competitors"
	agInter = "the timelock challenge path expires into a no-op once " +
		"the upgrade queue is blocked, so the freeze cannot be voted " +
		"away before the challenge window closes"
	// agAttack (morph §7.2): the strongest attacker variant defeats the
	// interplay answer — the claim must say which one, or why none does.
	agAttack = "the strongest variant is a proof-valid bad batch: the " +
		"operator posts a fake prev root and proves a valid transition " +
		"FROM it, so the challenge verifies and the freeze survives"
)

// livenessPayload is hypoPayload re-classed as a chain-freeze finding.
func livenessPayload() validation.Value {
	return hypoPayload(
		kv("root_cause", validation.VObj(
			kv("class", validation.VStr("chain-freeze")),
			kv("description", validation.VStr(
				"the owner can block the upgrade queue and freeze "+
					"withdrawals indefinitely")))))
}

// TestIsLivenessFinding is the check15 trigger matrix: the liveness
// bug-class set, the B1 non-economic impact kind, and a granted
// liveness terminal — and the negatives.
func TestIsLivenessFinding(t *testing.T) {
	cases := []struct {
		name    string
		finding validation.Value
		want    bool
	}{
		{"empty", validation.VObj(), false},
		{"class chain-freeze", validation.VObj(
			kv("root_cause", validation.VObj(
				kv("class", validation.VStr("chain-freeze"))))), true},
		{"class sequencer-halt", validation.VObj(
			kv("root_cause", validation.VObj(
				kv("class", validation.VStr("sequencer-halt"))))), true},
		{"class liveness", validation.VObj(
			kv("root_cause", validation.VObj(
				kv("class", validation.VStr("liveness"))))), true},
		{"class oracle-manipulation", validation.VObj(
			kv("root_cause", validation.VObj(
				kv("class", validation.VStr("oracle-manipulation"))))),
			false},
		{"impact kind liveness", validation.VObj(
			kv("economic_impact", validation.VObj(
				kv("kind", validation.VStr("liveness"))))), true},
		{"impact kind extractable", validation.VObj(
			kv("economic_impact", validation.VObj(
				kv("kind", validation.VStr("extractable"))))), false},
		{"granted liveness terminal", validation.VObj(
			kv("capabilities", validation.VObj(
				kv("granted", validation.VArr(
					validation.VStr("liveness_loss")))))), true},
		{"granted economic terminal", validation.VObj(
			kv("capabilities", validation.VObj(
				kv("granted", validation.VArr(
					validation.VStr("extract protocol liquidity")))))),
			false},
		{"class + kind both", validation.VObj(
			kv("root_cause", validation.VObj(
				kv("class", validation.VStr("oracle-manipulation")))),
			kv("economic_impact", validation.VObj(
				kv("kind", validation.VStr("liveness"))))), true},
		{"root_cause without class", validation.VObj(
			kv("root_cause", validation.VObj(
				kv("description", validation.VStr("no class set"))))),
			false},
	}
	for _, tc := range cases {
		if got := IsLivenessFinding(tc.finding); got != tc.want {
			t.Errorf("%s: IsLivenessFinding = %v, want %v", tc.name, got,
				tc.want)
		}
	}
}

// TestAdversarialGameDeficits: "missing" for no clause, one entry per
// absent/short field, empty for the complete clause.
func TestAdversarialGameDeficits(t *testing.T) {
	if got := AdversarialGameDeficits(validation.VObj()); len(got) != 1 ||
		got[0] != "missing" {
		t.Errorf("no clause: deficits = %v, want [missing]", got)
	}
	partial := validation.VObj(
		kv("adversarial_game", validation.VObj(
			kv("who_profits", validation.VStr(agWho)),
			kv("profit_mechanism", validation.VStr("short")))))
	if got := AdversarialGameDeficits(partial); len(got) != 3 ||
		got[0] != "profit_mechanism" || got[1] != "challenge_interplay" ||
		got[2] != "strongest_attacker" {
		t.Errorf("partial: deficits = %v, want [profit_mechanism "+
			"challenge_interplay strongest_attacker]", got)
	}
	complete := validation.VObj(
		kv("adversarial_game", validation.VObj(
			kv("who_profits", validation.VStr(agWho)),
			kv("profit_mechanism", validation.VStr(agMech)),
			kv("challenge_interplay", validation.VStr(agInter)),
			kv("strongest_attacker", validation.VStr(agAttack)))))
	if got := AdversarialGameDeficits(complete); len(got) != 0 {
		t.Errorf("complete: deficits = %v, want []", got)
	}
}

// The morph pass-1 lesson (review §7.2): a three-field clause whose interplay
// claim is "the challenge path undoes it" passed the gate unexamined. The
// fourth field — the claim under the STRONGEST attacker variant (a
// proof-VALID bad batch wins the challenge) — is what forces the half-step.
func TestAdversarialGameStrongestAttackerRequired(t *testing.T) {
	partial := validation.VObj(
		kv("adversarial_game", validation.VObj(
			kv("who_profits", validation.VStr(agWho)),
			kv("profit_mechanism", validation.VStr(agMech)),
			kv("challenge_interplay", validation.VStr(agInter)))))
	if got := AdversarialGameDeficits(partial); len(got) != 1 ||
		got[0] != "strongest_attacker" {
		t.Fatalf("deficits = %v, want [strongest_attacker]", got)
	}
}

// TestSetAdversarialGame: the setter stores the clause in field order,
// persists it, and logs one finding.adversarial_game_set event with the
// per-field character counts.
func TestSetAdversarialGame(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, livenessPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	got, err := SetAdversarialGame(c, fid, agWho, agMech, agInter, agAttack)
	if err != nil {
		t.Fatal(err)
	}
	ag := validation.ObjAt(got, "adversarial_game")
	if validation.ObjStr(ag, "who_profits") != agWho ||
		validation.ObjStr(ag, "profit_mechanism") != agMech ||
		validation.ObjStr(ag, "challenge_interplay") != agInter ||
		validation.ObjStr(ag, "strongest_attacker") != agAttack {
		t.Errorf("clause = %s", validation.CanonSpaced(ag))
	}
	keys := make([]string, 0, len(ag.O))
	for _, kvv := range ag.O {
		keys = append(keys, kvv.K)
	}
	if s := strings.Join(keys, ","); s !=
		"who_profits,profit_mechanism,challenge_interplay,strongest_attacker" {
		t.Errorf("clause key order = %q", s)
	}
	stored, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if validation.ObjStr(validation.ObjAt(stored, "adversarial_game"), "who_profits") != agWho {
		t.Error("persisted clause missing")
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	n, ev := 0, validation.VNull()
	for _, e := range events {
		if validation.ObjStr(e, "type") == "finding.adversarial_game_set" {
			n, ev = n+1, e
		}
	}
	if n != 1 {
		t.Fatalf("adversarial_game_set events = %d, want 1", n)
	}
	data := validation.ObjAt(ev, "data")
	if validation.ObjAt(data, "who_profits_chars").I !=
		int64(len([]rune(agWho))) ||
		validation.ObjAt(data, "profit_mechanism_chars").I !=
			int64(len([]rune(agMech))) ||
		validation.ObjAt(data, "challenge_interplay_chars").I !=
			int64(len([]rune(agInter))) ||
		validation.ObjAt(data, "strongest_attacker_chars").I !=
			int64(len([]rune(agAttack))) {
		t.Errorf("event data = %s", validation.CanonSpaced(data))
	}
}

// TestSetAdversarialGameShortField: a stub below the 20-rune floor is an
// InputError naming the field; nothing persists, no event fires.
func TestSetAdversarialGameShortField(t *testing.T) {
	shorts := []struct {
		who, mech, inter, attack, field string
	}{
		{"short", agMech, agInter, agAttack, "who_profits"},
		{agWho, "short", agInter, agAttack, "profit_mechanism"},
		{agWho, agMech, "short", agAttack, "challenge_interplay"},
		{agWho, agMech, agInter, "short", "strongest_attacker"},
	}
	for _, s := range shorts {
		c := ingestCamp(t)
		f, err := IngestHypothesis(c, livenessPayload(), "code", "", "")
		if err != nil {
			t.Fatal(err)
		}
		fid := validation.ObjStr(f, "finding_id")
		_, err = SetAdversarialGame(c, fid, s.who, s.mech, s.inter, s.attack)
		if err == nil {
			t.Fatalf("%s: expected an error for a short field", s.field)
		}
		if !strings.Contains(err.Error(),
			"adversarial_game."+s.field+" must be >= "+
				strconv.Itoa(AdversarialGameFieldMin)) {
			t.Errorf("%s: error = %q", s.field, err.Error())
		}
		if _, ok := err.(*InputError); !ok {
			t.Errorf("%s: error type = %T, want *InputError", s.field, err)
		}
		stored, err := LoadFinding(c, fid)
		if err != nil {
			t.Fatal(err)
		}
		if validation.ObjAt(stored, "adversarial_game").Kind != validation.Null {
			t.Errorf("%s: a rejected clause must not persist", s.field)
		}
		events, err := c.Events()
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if validation.ObjStr(e, "type") == "finding.adversarial_game_set" {
				t.Errorf("%s: a rejected clause must not log", s.field)
			}
		}
	}
}

// TestSetAdversarialGameUnknownFinding: a missing finding is a load
// error, not an InputError.
func TestSetAdversarialGameUnknownFinding(t *testing.T) {
	c := ingestCamp(t)
	_, err := SetAdversarialGame(c, "F-doesnotexist", agWho, agMech,
		agInter, agAttack)
	if err == nil {
		t.Fatal("expected an error for an unknown finding")
	}
	if _, ok := err.(*InputError); ok {
		t.Error("an unknown finding must not be an InputError")
	}
}

// TestSetAdversarialGameOverwrites: re-setting replaces the clause (a
// changed argument, not an append) and logs a second event.
func TestSetAdversarialGameOverwrites(t *testing.T) {
	c := ingestCamp(t)
	f, err := IngestHypothesis(c, livenessPayload(), "code", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fid := validation.ObjStr(f, "finding_id")
	if _, err := SetAdversarialGame(c, fid, agWho, agMech, agInter,
		agAttack); err != nil {
		t.Fatal(err)
	}
	who2 := "the bridge operator — the halt strands the relay fees they " +
		"were paid to earn, and the insurance fund pays the stuck users"
	if _, err := SetAdversarialGame(c, fid, who2, agMech, agInter,
		agAttack); err != nil {
		t.Fatal(err)
	}
	stored, err := LoadFinding(c, fid)
	if err != nil {
		t.Fatal(err)
	}
	if got := validation.ObjStr(validation.ObjAt(stored, "adversarial_game"), "who_profits"); got != who2 {
		t.Error("the second answer must replace the first")
	}
	events, err := c.Events()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if validation.ObjStr(e, "type") == "finding.adversarial_game_set" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("adversarial_game_set events = %d, want 2", n)
	}
}

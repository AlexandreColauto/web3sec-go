package playbooks

import (
	"strings"
	"testing"

	"websec/internal/validation"
)

// amps is tests/test_risk_amplifiers.py::AMPS.
var amps = []string{"flash-loan", "oracle", "bridge", "delegatecall",
	"arbitrary-call", "cross-chain", "rebasing-fee-accounting"}

// Port of tests/test_risk_amplifiers.py::test_playbook_schema_accepts_amplifiers.
func TestPlaybookSchemaAcceptsAmplifiers(t *testing.T) {
	pb, found, err := PlaybookForClass("oracle-manipulation")
	if err != nil || !found {
		t.Fatalf("playbook_for_class = %v, %v", found, err)
	}
	if err := validation.Validate(pb, "playbook", 1); err != nil {
		t.Fatalf("shipped playbook fails its own schema: %v", err)
	}
	for _, tag := range playbookStrings(pb, "amplifiers") {
		if !containsString(amps, tag) {
			t.Errorf("amplifier %q outside AMPS", tag)
		}
	}
}

// Port of tests/test_risk_amplifiers.py::test_shipped_playbook_tags.
func TestShippedPlaybookTags(t *testing.T) {
	for _, tc := range []struct {
		class string
		tags  []string
	}{
		{"access-control", []string{"arbitrary-call"}},
		{"bridge-message", []string{"bridge", "cross-chain"}},
		{"oracle-manipulation", []string{"oracle", "flash-loan"}},
		{"precision-rounding", []string{"rebasing-fee-accounting"}},
		{"reentrancy", nil},
		{"upgrade-initializer", []string{"delegatecall"}},
	} {
		t.Run(tc.class, func(t *testing.T) {
			pb, found, err := PlaybookForClass(tc.class)
			if err != nil || !found {
				t.Fatalf("playbook_for_class(%q) = %v, %v", tc.class, found,
					err)
			}
			got := playbookStrings(pb, "amplifiers")
			if strings.Join(got, ",") != strings.Join(tc.tags, ",") {
				t.Fatalf("amplifiers = %v, want %v", got, tc.tags)
			}
		})
	}
}

// Port of tests/test_outcome_events.py::test_all_playbooks_are_listed.
func TestAllPlaybooksAreListed(t *testing.T) {
	listed, err := AvailablePlaybooks()
	if err != nil {
		t.Fatal(err)
	}
	for _, cls := range append([]string{"reentrancy", "upgrade-initializer",
		"bridge-message"}, "access-control", "oracle-manipulation",
		"precision-rounding") {
		if !containsString(listed, cls) {
			t.Errorf("available_playbooks() omits %q: %v", cls, listed)
		}
	}
}

// Port of tests/test_outcome_events.py::test_new_playbooks_load_and_validate.
func TestNewPlaybooksLoadAndValidate(t *testing.T) {
	floors := map[string]string{"reentrancy": "E4",
		"upgrade-initializer": "E3", "bridge-message": "E4"}
	for cls, floor := range floors {
		t.Run(cls, func(t *testing.T) {
			pb, found, err := PlaybookForClass(cls)
			if err != nil || !found {
				t.Fatalf("playbook_for_class(%q) = %v, %v", cls, found, err)
			}
			if got := objAt(pb, "bug_class"); got.S != cls {
				t.Errorf("bug_class = %q, want %q", got.S, cls)
			}
			if got := objAt(pb, "evidence_floor"); got.S != floor {
				t.Errorf("evidence_floor = %q, want %q", got.S, floor)
			}
		})
	}
}

// playbookStrings reads a top-level array of strings.
func playbookStrings(pb validation.Value, key string) []string {
	out := []string{}
	for _, kv := range pb.O {
		if kv.K == key && kv.V.Kind == validation.Arr {
			for _, v := range kv.V.A {
				out = append(out, v.S)
			}
		}
	}
	return out
}

// containsString is a slice membership check.
func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

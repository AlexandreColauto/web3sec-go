package validation

// Task 3 (Wave L advice-dispositions) profile registry parity: both
// execution_profile enums carry the EIGHT names in the declaration order of
// sandbox.Profiles (internal/sandbox/profiles.go — the source of truth,
// mirrored here literally because validation cannot import sandbox), so the
// model-facing contracts accept the three G8 host kinds.
//
// The two definitions are the schema homes of the field:
// model_response.reproducer_request (the model's own output contract) and
// trajectory.model_reproducer_request (the logged event payload).

import (
	"strings"
	"testing"
)

// profilesEight is the enum value both schemas must carry, in
// sandbox.Profiles declaration order.
var profilesEight = []string{
	"host-readonly", "halmos", "forge-fuzz", "minicertora",
	"docker-networkless", "docker-gvisor", "vm-snapshot", "fork-runner",
}

// profileReproducerRequest renders a minimal valid
// model_response.reproducer_request with the given execution_profile.
func profileReproducerRequest(profile string) string {
	return `{"finding_id":"F-0123456789ab","snapshot_id":"SNAP-0001",` +
		`"execution_profile":"` + profile + `",` +
		`"success_criteria":{"exit_status":0,"min_evidence_level":"E3",` +
		`"requires_captured_output":true},` +
		`"program":"forge test --match-test poc"}`
}

// profileTrajectoryEvent renders a minimal valid
// trajectory.model_reproducer_request with the given execution_profile.
func profileTrajectoryEvent(profile string) string {
	return `{"snapshot_id":"SNAP-0001","execution_profile":"` + profile + `",` +
		`"min_evidence_level":"E3",` +
		`"request_sha256":"` + strings.Repeat("a", 64) + `"}`
}

// TestExecutionProfileEnumEightNames pins that every sandbox.Profiles name is
// admitted by both execution_profile enums and that an unknown profile is
// still refused.
func TestExecutionProfileEnumEightNames(t *testing.T) {
	for _, tc := range []struct {
		schema string
		def    string
		doc    func(string) string
	}{
		{"model_response", "reproducer_request", profileReproducerRequest},
		{"trajectory", "model_reproducer_request", profileTrajectoryEvent},
	} {
		t.Run(tc.schema, func(t *testing.T) {
			for _, p := range profilesEight {
				v, err := ParseOrdered([]byte(tc.doc(p)))
				if err != nil {
					t.Fatalf("parse %s: %v", p, err)
				}
				bad, err := ValidateDefinition(v, tc.schema, tc.def)
				if err != nil {
					t.Fatalf("validate %s: %v", p, err)
				}
				if bad != nil {
					t.Errorf("profile %q must pass %s.%s: %v", p,
						tc.schema, tc.def, bad)
				}
			}
			// The pre-existing names keep working too (vm-snapshot is
			// already inside profilesEight) and a bogus one still fails.
			v, _ := ParseOrdered([]byte(tc.doc("bogus-profile")))
			bad, err := ValidateDefinition(v, tc.schema, tc.def)
			if err != nil {
				t.Fatalf("validate bogus: %v", err)
			}
			if bad == nil {
				t.Errorf("%s.%s must refuse bogus-profile", tc.schema,
					tc.def)
			}
		})
	}
}

// TestExecutionProfileEnumOrder pins the ENUM ORDER itself against the
// sandbox.Profiles declaration order — parity is not just membership.
func TestExecutionProfileEnumOrder(t *testing.T) {
	for _, tc := range []struct {
		schema string
		def    string
	}{
		{"model_response", "reproducer_request"},
		{"trajectory", "model_reproducer_request"},
	} {
		entry, err := loadSchema(tc.schema)
		if err != nil {
			t.Fatal(err)
		}
		enum := objKey(objKey(objKey(objKey(objKey(entry.doc,
			"definitions"), tc.def), "properties"),
			"execution_profile"), "enum")
		if enum.Kind != Arr {
			t.Fatalf("%s.%s execution_profile enum kind = %v",
				tc.schema, tc.def, enum.Kind)
		}
		var got []string
		for _, item := range enum.A {
			got = append(got, item.S)
		}
		if strings.Join(got, ",") != strings.Join(profilesEight, ",") {
			t.Errorf("%s enum = %v, want %v", tc.schema, got,
				profilesEight)
		}
	}
}

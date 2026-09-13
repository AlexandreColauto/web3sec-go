package sequencepoc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/validation"
)

// TestExplicitWorkdirMustExist pins r5 issue 7: the operator's own
// --workdir is a promise about an existing place; a typo is refused, not
// invented. The campaign-derived default keeps creating itself.
func TestExplicitWorkdirMustExist(t *testing.T) {
	c := testCampaign(t)
	spec := validation.VObj(
		validation.KV{K: "spec_id", V: validation.VStr("SEQ-r5test01")},
	)
	ghost := filepath.Join(t.TempDir(), "mispelled-wokdir")
	opts := RunSequenceOpts{}
	wd := ghost
	opts.Workdir = &wd
	if _, err := sequenceWorkdir(c, spec, opts); err == nil ||
		!strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("invented workdir must be refused, got %v", err)
	}
	if _, serr := os.Stat(ghost); !os.IsNotExist(serr) {
		t.Fatal("the refusal must not create the directory")
	}
	// An existing explicit workdir resolves (and gets its spec.json).
	real := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	opts.Workdir = &real
	if got, err := sequenceWorkdir(c, spec, opts); err != nil || got != real {
		t.Fatalf("real workdir must resolve: %q %v", got, err)
	}
	if _, serr := os.Stat(filepath.Join(real, "spec.json")); serr != nil {
		t.Fatalf("spec provenance missing: %v", serr)
	}
	// Default (no --workdir): derived under execs/, created on demand.
	opts.Workdir = nil
	got, err := sequenceWorkdir(c, spec, opts)
	if err != nil {
		t.Fatalf("default workdir must self-create: %v", err)
	}
	if !strings.HasSuffix(got, "seqwork-SEQ-r5test01") {
		t.Fatalf("default path shape: %q", got)
	}
}

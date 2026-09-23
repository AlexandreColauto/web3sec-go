package regression

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"websec/internal/validation"
)

// WriteRepoRecord writes one repo-level regression artefact plus its sha256
// sidecar, in the eval store's own discipline (internal/evalstore: cases.json
// + cases.sha256): the sidecar always describes the file just written, so a
// hand edit is detectable drift rather than silent truth. Used by the derived
// labels (Task 3) and the suite composition (Task 10).
func WriteRepoRecord(path string, doc validation.Value, schema string) error {
	if err := validation.Validate(doc, schema, 1); err != nil {
		return err
	}
	if err := validation.WriteJson(path, doc, ""); err != nil {
		return err
	}
	digest, err := validation.Sha256File(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path+".sha256", []byte(digest+"\n"), 0o644)
}

// ReadRepoRecord reads a repo-level artefact and verifies its sidecar. A
// missing sidecar is a refusal, not a warning: an unverifiable answer key or
// suite composition is exactly the drift the sidecar exists to catch.
func ReadRepoRecord(path string) (validation.Value, error) {
	raw, err := os.ReadFile(path + ".sha256")
	if err != nil {
		return validation.VNull(), fmt.Errorf(
			"%s has no sha256 sidecar (%v) — an unverifiable record is refused",
			path, err)
	}
	want := strings.TrimSpace(string(raw))
	got, err := validation.Sha256File(path)
	if err != nil {
		return validation.VNull(), err
	}
	if want != got {
		return validation.VNull(), fmt.Errorf(
			"%s has been edited since it was written (sidecar %s, file %s)",
			filepath.Base(path), want, got)
	}
	return validation.ReadJson(path)
}

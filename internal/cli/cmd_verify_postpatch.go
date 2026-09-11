package cli

// cmd_verify_postpatch: `webv2 verify <campaign> --post-patch FINDING
// --exec EXEC [--snapshot SID]` (Task 8, G11) — land one post-patch run's
// verdict on its finding as verification.patch_regression.
//
// Attribution is explicit (both ids on the command line, same rail as the
// harness-result branch): the verdict compares the NEW exec's exit-vector
// against the ORIGINAL repro exec the finding's minted evidence cites.
// --snapshot is accepted but only recorded (stored on the record as
// snapshot, an advisory pin) — the tree comparison is scope review's job,
// not this command's.
//
// Fail-open: the verdict never changes finding status and never blocks
// anything — it is metadata plus stdout. Promotion rides triage reading
// the record, same law as the harness rungs. No audit event is logged.

import (
	"errors"
	"fmt"

	"websec/internal/findings"
	"websec/internal/reproduction"
	"websec/internal/state"
	"websec/internal/validation"
)

// verifyPostPatch is cmd_verify's --post-patch branch.
func verifyPostPatch(c *state.Campaign, a *verifyArgs, r *Runner) error {
	if a.execID == "" {
		return t14ExitErr(2,
			"verify --post-patch needs --exec EXEC\n")
	}
	verdict, detail, err := reproduction.PostPatchVerdict(c, a.postPatch,
		a.execID)
	if err != nil {
		var uid *reproduction.UnknownIDError
		if errors.As(err, &uid) {
			return t14ExitErr(2, "verify: unknown %s %s\n", uid.Kind,
				validation.PyReprStr(uid.ID))
		}
		return err
	}
	f, err := findings.LoadFinding(c, a.postPatch)
	if err != nil {
		// Unreachable: the verdict just loaded this finding.
		return err
	}
	base, _ := reproduction.BaselineReproExec(f)
	ver := objAt(f, "verification")
	if ver.Kind != validation.Obj {
		ver = validation.VObj()
	}
	ver.O = validation.SetOrAppend(ver.O, "patch_regression",
		reproduction.PatchRegressionRecord(verdict, a.execID, base,
			detail, a.snapshot))
	f.O = validation.SetOrAppend(f.O, "verification", ver)
	// The same finding-save path immunize uses (SaveFinding stamps
	// updated_at and validates — status itself is never touched).
	if err := findings.SaveFinding(c, &f); err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "%s: patch regression %s (%s → %s)\n", a.postPatch,
		verdict, base, a.execID)
	if a.snapshot != "" {
		fmt.Fprintf(r.Out, "note: snapshot %s recorded (advisory — "+
			"tree comparison deferred to scope review)\n", a.snapshot)
	}
	return nil
}

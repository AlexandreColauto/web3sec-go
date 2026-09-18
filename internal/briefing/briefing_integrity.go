// Integrity internals: build_brief's integrity block (deep audit or the
// fast event-log chain check), split out of the build phase helpers.
package briefing

import (
	"websec/internal/audit"
	"websec/internal/sharedmem"
	"websec/internal/validation"
)

// setIntegrity attaches the integrity block: the deep audit when asked,
// otherwise the fast event-log chain check.
func (b *briefCtx) setIntegrity(brief *validation.Value) error {
	if b.deepAudit {
		// Python's `from . import audit` registers every section at import
		// time; the port registers them through audit.Setup().
		audit.Setup()
		report, err := audit.AuditCampaign(b.campaign)
		if err != nil {
			return err
		}
		shared, err := sharedmem.VerifySharedStore(b.campaign.Root)
		if err != nil {
			return err
		}
		integProblems := []validation.KV{}
		for _, sec := range validation.AsObj(validation.ObjAt(report, "sections")).O {
			if pyTruthyInt64Only(validation.ObjAt(sec.V, "problems")) {
				integProblems = append(integProblems, validation.KV{K: sec.K,
					V: validation.ObjAt(sec.V, "problems")})
			}
		}
		if pyTruthyInt64Only(validation.ObjAt(shared, "problems")) {
			integProblems = append(integProblems, validation.KV{
				K: "shared_store", V: validation.ObjAt(shared, "problems")})
		}
		setKey(brief, "integrity", validation.VObj(
			kv("ok", validation.VBool(pyTruthyInt64Only(validation.ObjAt(report, "ok")) &&
				pyTruthyInt64Only(validation.ObjAt(shared, "ok")))),
			kv("summary", validation.VStr(audit.AuditSummaryLine(report))),
			kv("problems", validation.VObj(integProblems...)),
			kv("shared_store", shared)))
	} else {
		chain, err := b.campaign.VerifyLog()
		if err != nil {
			return err
		}
		chainProblems := []validation.Value{}
		if !chain.OK {
			for _, p := range chain.Problems {
				chainProblems = append(chainProblems, validation.VStr(p))
			}
		}
		setKey(brief, "integrity", validation.VObj(
			kv("ok", validation.VBool(chain.OK)),
			kv("events_checked", validation.VInt(int64(chain.Events))),
			kv("note", validation.VStr("event-log chain checked (fast); run "+
				"`webv2 brief --deep` (or `webv2 audit`) for the full "+
				"integrity check — artifact re-hashes, exec hashes, "+
				"snapshot trees")),
			kv("problems", validation.VArr(chainProblems...))))
	}
	return nil
}

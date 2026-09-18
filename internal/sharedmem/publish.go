// publish: explicit, logged, actor-attributed publishing of derived
// signatures and approved memory rows into a store tier.
package sharedmem

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"websec/internal/findings"
	"websec/internal/learning"
	"websec/internal/state"
	"websec/internal/validation"
)

// PublishOpts carries the publish-time additions that do NOT change any
// pre-existing record unless they are set. The zero value is the pre-I6
// publish, byte for byte.
type PublishOpts struct {
	// DisclosureSHA256 is the hex digest of the campaign-local disclosure
	// bundle attached to this publish. "" means no bundle was attached: the
	// record then carries neither disclosure field. It is a THIRD, separate
	// hash — never folded into signatures_sha256 or memory_sha256.
	DisclosureSHA256 string
	// DisclosureEmbargoUntil is the bundle's embargo_until recorded verbatim;
	// "" is recorded as null (the key is required, the value may be null).
	// RECORDED, never enforced: an open embargo does not refuse, delay, or
	// suppress the publish.
	DisclosureEmbargoUntil string
}

// PublishCampaign is publish_campaign: explicit, logged, actor-attributed,
// idempotent. It is PublishCampaignWith with the zero-value options, so every
// existing caller and every existing record is unchanged.
func PublishCampaign(c *state.Campaign, actor string,
	toGlobal bool) (validation.Value, error) {
	return PublishCampaignWith(c, actor, toGlobal, PublishOpts{})
}

// publishRun carries one PublishCampaignWith run's derived state across its
// extracted phases.
type publishRun struct {
	c                   *state.Campaign
	actor               string
	opts                PublishOpts
	key                 string
	program             validation.Value
	store               string
	tier                string
	sigs                []validation.Value
	mems                []validation.Value
	cs                  map[string]struct{}
	sigsAdded           int
	memAdded            int
	publishableFindings int
	approvedRows        int
	memDeduped          int
}

// newPublishRun resolves the program identity, the target tier, the tier's
// current rows and the campaign's code-sourced capability labels.
func newPublishRun(c *state.Campaign, actor string, toGlobal bool,
	opts PublishOpts) (*publishRun, error) {
	key, program, err := ProgramKeyOf(c)
	if err != nil {
		return nil, err
	}
	store := StoreDir(c.Root)
	tier := "root"
	if toGlobal {
		store = GlobalStoreDir()
		tier = "global"
	}
	sigs, err := tierSignatures(store)
	if err != nil {
		return nil, err
	}
	mems, err := tierMemory(store)
	if err != nil {
		return nil, err
	}
	cs, err := CodeSourced(c)
	if err != nil {
		return nil, err
	}
	return &publishRun{
		c: c, actor: actor, opts: opts, key: key, program: program,
		store: store, tier: tier, sigs: sigs, mems: mems, cs: cs,
	}, nil
}

// publishSignatures derives a capability signature for every publishable
// finding and appends the ones the tier does not hold yet.
func (pr *publishRun) publishSignatures() error {
	sigKeys := map[string]struct{}{}
	for _, s := range pr.sigs {
		sigKeys[sigKey(s)] = struct{}{}
	}
	all, err := findings.LoadAllFindings(pr.c)
	if err != nil {
		return err
	}
	for _, f := range all {
		if !slices.Contains(PublishableStatuses, validation.ObjStr(f, "status")) {
			continue
		}
		pr.publishableFindings++
		sig := DeriveSignature(f, pr.key, pr.program, pr.c.CampaignID, pr.cs)
		if _, ok := sigKeys[sigKey(sig)]; ok {
			continue
		}
		full := validation.VObj()
		full.O = append(full.O, kv("signature_id",
			validation.VStr("SIG-"+idTail(8))))
		full.O = append(full.O, sig.O...)
		full.O = append(full.O, kv("created_at", validation.VStr(state.NowIso())))
		if err := validation.Validate(full, "shared_signature", 1); err != nil {
			return err
		}
		pr.sigs = append(pr.sigs, full)
		sigKeys[sigKey(full)] = struct{}{}
		pr.sigsAdded++
	}
	return nil
}

// publishMemoryRows appends the campaign's human-approved memory rows that
// the tier does not hold yet, collapsing pattern duplicates (r8) and
// refusing non-dev partitions (leakage constraint 4).
func (pr *publishRun) publishMemoryRows() error {
	memIDs := map[string]struct{}{}
	for _, m := range pr.mems {
		memIDs[validation.ObjStr(validation.ObjAt(m, "row"), "memory_id")] = struct{}{}
	}
	rows, err := learning.AllMemory(pr.c)
	if err != nil {
		return err
	}
	for _, m := range rows {
		if !slices.Contains(ApprovedMemory, validation.ObjStr(m, "promotion_status")) {
			continue
		}
		pr.approvedRows++
		mid := validation.ObjStr(m, "memory_id")
		if _, ok := memIDs[mid]; ok {
			continue
		}
		// r8: two campaigns that learned the SAME lesson must not
		// double-promote it into every later campaign's recall. The
		// collapse is per (program_key, kind, normalized pattern) —
		// provenance stays visible (the store keeps the first publisher's
		// row untouched), but the shared surface stays a SET. The skipped
		// count is reported, never silent.
		if patternInStore(pr.mems, pr.key, m) {
			pr.memDeduped++
			continue
		}
		// Leakage-partition guard (dataset-ingestion sprint, constraint 4).
		partition := validation.ObjStr(m, "partition")
		if partition == "" {
			partition = "dev"
		}
		if partition != "dev" {
			return fmt.Errorf("%s has partition %s: "+
				"'held-out'/'training' rows never enter the shared store "+
				"(leakage-partition constraint 4)", mid, validation.PyReprStr(partition))
		}
		wrapper := validation.VObj(
			kv("program_key", validation.VStr(pr.key)),
			kv("published_at", validation.VStr(state.NowIso())),
			kv("row", m))
		if err := validation.Validate(wrapper, "shared_memory_row", 1); err != nil {
			return err
		}
		if err := validation.Validate(m, "memory", 1); err != nil {
			return err
		}
		pr.mems = append(pr.mems, wrapper)
		memIDs[mid] = struct{}{}
		pr.memAdded++
	}
	return nil
}

// persistAndLog writes the updated store files, appends the manifest record
// (with the I6 disclosure fields only when a bundle was attached) and logs
// shared.published — rolling all three files back when the log refuses.
func (pr *publishRun) persistAndLog() (string, error) {
	// r18 P2 (memory sites): the shared store is the ONE place where a
	// refused event used to be UNDOABLE by any retry — the sigs/mem rows
	// and the manifest record land globally, deduped silently by the next
	// publish while `shared.published` never exists. Capture all three
	// files' bytes before writeStore; restore together on refusal.
	sigPrev, sigHad := prevOrEmpty(sigsPath(pr.store))
	memPrev, memHad := prevOrEmpty(memPath(pr.store))
	manPath := manifestPath(pr.store)
	manPrev, manHad := prevOrEmpty(manPath)
	if err := writeStore(pr.store, pr.sigs, pr.mems); err != nil {
		return "", err
	}
	record := validation.VObj(
		kv("record_id", validation.VStr("PUB-"+idTail(8))),
		kv("campaign_id", validation.VStr(pr.c.CampaignID)),
		kv("program_key", validation.VStr(pr.key)),
		kv("actor", validation.VStr(pr.actor)),
		kv("at", validation.VStr(state.NowIso())),
		kv("tier", validation.VStr(pr.tier)),
		kv("signatures_added", validation.VInt(int64(pr.sigsAdded))),
		kv("memory_added", validation.VInt(int64(pr.memAdded))),
		kv("signatures_sha256", validation.VStr(fileSha256(sigsPath(pr.store)))),
		kv("memory_sha256", validation.VStr(fileSha256(memPath(pr.store)))))
	// I6: the disclosure hash and embargo date ride the record — present ONLY
	// when a bundle was attached, so a publish without one stays byte-
	// identical to the pre-I6 record. The embargo is recorded, not enforced.
	if pr.opts.DisclosureSHA256 != "" {
		record.O = append(record.O,
			kv(DisclosureSHA256Field, validation.VStr(pr.opts.DisclosureSHA256)),
			kv(DisclosureEmbargoField,
				disclosureEmbargoValue(pr.opts.DisclosureEmbargoUntil)))
	}
	record, err := manifestAppend(pr.store, record)
	if err != nil {
		return "", err
	}
	rid := validation.ObjStr(record, "record_id")
	data := validation.VObj(
		kv("program_key", validation.VStr(pr.key)),
		kv("signatures_added", validation.VInt(int64(pr.sigsAdded))),
		kv("memory_added", validation.VInt(int64(pr.memAdded))),
		kv("tier", validation.VStr(pr.tier)),
		kv("actor", validation.VStr(pr.actor)))
	if _, err := pr.c.Log("shared.published", &rid, &data); err != nil {
		publishRollback(pr.store, sigPrev, sigHad, memPrev, memHad, manPath,
			manPrev, manHad)
		return "", err
	}
	return rid, nil
}

// noopReasons builds the noop report for a publish that added nothing: the
// reasons nothing was added and the operator's next steps.
func (pr *publishRun) noopReasons() validation.Value {
	var noop validation.Value = validation.VNull()
	if pr.sigsAdded == 0 && pr.memAdded == 0 {
		reasons := []string{}
		if pr.publishableFindings == 0 {
			reasons = append(reasons, "no CONFIRMED finding or CHAIN to "+
				"publish (only confirmed knowledge crosses)")
		} else {
			reasons = append(reasons, fmt.Sprintf("all %d publishable "+
				"finding(s) already have a signature in the %s store",
				pr.publishableFindings, pr.tier))
		}
		if pr.approvedRows == 0 {
			reasons = append(reasons, "no human-approved memory row for this program")
		} else {
			msg := fmt.Sprintf("all %d approved memory row(s) are already "+
				"published to the %s store", pr.approvedRows, pr.tier)
			if pr.memDeduped > 0 {
				msg = fmt.Sprintf("all %d approved memory row(s) are "+
					"already published to the %s store (%d collapsed as "+
					"pattern duplicates of rows from other campaigns)",
					pr.approvedRows, pr.tier, pr.memDeduped)
			}
			reasons = append(reasons, msg)
		}
		next := []string{}
		if pr.publishableFindings == 0 {
			next = append(next, "webv2 move "+pr.c.CampaignID+" <F-...> "+
				"CONFIRMED --reason '...'")
		}
		if pr.approvedRows == 0 {
			next = append(next, "webv2 memory "+pr.c.CampaignID+
				" --approve MEM-... --by NAME")
		}
		noop = validation.VObj(
			kv("reasons", validation.StrArr(reasons)),
			kv("next", validation.StrArr(next)))
	}
	return noop
}

// PublishCampaignWith is publish_campaign with the I6 disclosure options.
// Only opts.DisclosureSHA256 changes anything: when it is set, the publish
// record gains disclosure_sha256 and disclosure_embargo_until (the bundle's
// prose never leaves the campaign).
func PublishCampaignWith(c *state.Campaign, actor string,
	toGlobal bool, opts PublishOpts) (validation.Value, error) {
	if actor == "" {
		return validation.VNull(), errors.New("publish requires a recorded " +
			"actor — cross-campaign sharing is a boundary-crossing act")
	}
	pr, err := newPublishRun(c, actor, toGlobal, opts)
	if err != nil {
		return validation.VNull(), err
	}
	if err := pr.publishSignatures(); err != nil {
		return validation.VNull(), err
	}
	if err := pr.publishMemoryRows(); err != nil {
		return validation.VNull(), err
	}
	rid, err := pr.persistAndLog()
	if err != nil {
		return validation.VNull(), err
	}
	noop := pr.noopReasons()
	return validation.VObj(
		kv("record_id", validation.VStr(rid)),
		kv("program_key", validation.VStr(pr.key)),
		kv("signatures_added", validation.VInt(int64(pr.sigsAdded))),
		// r8: the ledger record's key set is byte-frozen (twin), but the
		// operator-facing report says everything: pattern collapses are
		// counted here too, never silent.
		kv("memory_added", validation.VInt(int64(pr.memAdded))),
		kv("memory_pattern_deduped", validation.VInt(int64(pr.memDeduped))),
		kv("tier", validation.VStr(pr.tier)),
		kv("store", validation.VStr(pr.store)),
		kv("noop", noop)), nil
}

// writeStore is _write_store.
func writeStore(store string, sigs, mems []validation.Value) error {
	if err := os.MkdirAll(store, 0o755); err != nil {
		return err
	}
	if err := validation.WriteJson(sigsPath(store), validation.VArr(sigs...), ""); err != nil {
		return err
	}
	return validation.WriteJson(memPath(store), validation.VArr(mems...), "")
}

// patternInStore reports whether an equal lesson (same kind, same pattern
// modulo case/whitespace collapse) already rides the store for this
// program_key. The campaign-LOCAL row always keeps its own copy; only the
// shared tier collapses.
func patternInStore(mems []validation.Value, programKey string,
	m validation.Value) bool {
	kind, pat := validation.ObjStr(m, "kind"), normPattern(validation.ObjStr(m, "pattern"))
	if pat == "" {
		return false
	}
	for _, w := range mems {
		if validation.ObjStr(w, "program_key") != programKey {
			continue
		}
		row := validation.ObjAt(w, "row")
		if validation.ObjStr(row, "kind") == kind &&
			normPattern(validation.ObjStr(row, "pattern")) == pat {
			return true
		}
	}
	return false
}

// normPattern is the collapse key: case-folded runs of whitespace.
func normPattern(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

// prevOrEmpty / restoreOrKeep / publishRollback: the publish-site
// unwind trio (absent file = remove on restore, never create empty).
func prevOrEmpty(path string) ([]byte, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return raw, true
}

func restoreOrKeep(path string, raw []byte, had bool) {
	if !had {
		os.Remove(path)
		return
	}
	_ = os.WriteFile(path, raw, 0o644)
}

func publishRollback(store string, sigPrev []byte, sigHad bool,
	memPrev []byte, memHad bool, manPath string, manPrev []byte,
	manHad bool) {
	restoreOrKeep(sigsPath(store), sigPrev, sigHad)
	restoreOrKeep(memPath(store), memPrev, memHad)
	restoreOrKeep(manPath, manPrev, manHad)
}

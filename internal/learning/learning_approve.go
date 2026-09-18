package learning

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// Human-gate concerns for memory rows: the approval record, the rejection
// record and the leakage-partition guard. Split from learning.go (same package).

// memoryIDRe is the only shape a memory id may have (newId("MEM", n) emits
// MEM-<hex>). The id arrives from the command line and is joined into a path,
// so an id carrying a separator or ".." must not reach the filesystem; it gets
// the same not-found error a missing row gets, so the CLI's wording does not
// change for the garbage case.
var memoryIDRe = regexp.MustCompile(`^MEM-[0-9a-f]+$`)

// AssertApprovable is assert_approvable: the leakage-partition guard
// (constraint 4). Rows partitioned 'held-out'/'training' are evaluation data
// and can never be approved or promoted. Absent partition == 'dev'.
func AssertApprovable(memoryID string, mem validation.Value) error {
	partition := validation.ObjStr(mem, "partition")
	if partition == "" {
		partition = "dev"
	}
	if partition != "dev" {
		return fmt.Errorf("%s has partition %s: 'held-out'/'training' rows "+
			"are evaluation data and can never be approved or promoted "+
			"(leakage-partition constraint 4)", memoryID, pyReprStr(partition))
	}
	return nil
}

// ApproveMemory is approve_memory: record human approval. It refuses to
// self-authorize: approver must be a non-empty identity string recorded in
// the file and the event log.
func ApproveMemory(c *state.Campaign, memoryID, approver string) (validation.Value, error) {
	if approver == "" {
		return validation.VNull(), errors.New(
			"memory promotion requires a recorded human approver")
	}
	path := filepath.Join(c.MemoryDir, memoryID+".json")
	// r7 (critic): a bare id as an error message names nothing — the
	// operator cannot tell a typo from a missing row from a shape bug.
	if !memoryIDRe.MatchString(memoryID) {
		return validation.VNull(), fmt.Errorf(
			"%s is not a memory id (expected MEM-<12 hex>)", memoryID)
	}
	if _, err := os.Stat(path); err != nil {
		return validation.VNull(), fmt.Errorf(
			"memory %s not found in %s's queue — `webv2 memory %s` lists "+
				"what is there", memoryID, c.CampaignID, c.CampaignID)
	}
	mem, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), err
	}
	if err := AssertApprovable(memoryID, mem); err != nil {
		return validation.VNull(), err
	}
	mem.O = validation.SetOrAppend(mem.O, "promotion_status",
		validation.VStr("human-approved"))
	mem.O = validation.SetOrAppend(mem.O, "approved_by", validation.VStr(approver))
	mem.O = validation.SetOrAppend(mem.O, "approved_at", validation.VStr(state.NowIso()))
	if err := validation.Validate(mem, "memory", 1); err != nil {
		return validation.VNull(), err
	}
	data := validation.VObj(kv("approver", validation.VStr(approver)))
	// r40: the approval flip is the HUMAN GATE's state — PromotionCommands
	// refuses to promote anything not human-approved, so a flip without
	// its event is a gate decision the ledger never recorded. Unwind.
	if err := writeThenLog(c, []string{path}, func() error {
		return validation.WriteJson(path, mem, "")
	}, func() error {
		_, lerr := c.Log("memory.approved", &memoryID, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return mem, nil
}

// RejectMemory is the missing other half of ApproveMemory (D5, 2026-09-10): a
// queued candidate could only ever be approved, so a wrong or unreachable row
// stayed in the inbox forever and a reviewer had no way to record "no". The
// REASON is required and goes into the event log (`memory.rejected`), not into
// the row: the memory schema has additionalProperties:false and no reason
// field, and the audit trail is the log. rejection_class carries the schema's
// three-way classification (invalid-hypothesis / not-exploitable /
// below-threshold) when the reviewer can give one; empty means null.
//
// Refuses to reject a row that is already human-approved or promoted — that is
// a revocation, not a rejection, and silently overwriting an approval would
// erase the record of who approved what.
func RejectMemory(c *state.Campaign, memoryID, reason, rejectionClass string) (validation.Value, error) {
	if strings.TrimSpace(reason) == "" {
		return validation.VNull(), errors.New(
			"memory rejection requires a written reason")
	}
	path := filepath.Join(c.MemoryDir, memoryID+".json")
	// r7 (critic): a bare id as an error message names nothing — the
	// operator cannot tell a typo from a missing row from a shape bug.
	if !memoryIDRe.MatchString(memoryID) {
		return validation.VNull(), fmt.Errorf(
			"%s is not a memory id (expected MEM-<12 hex>)", memoryID)
	}
	if _, err := os.Stat(path); err != nil {
		return validation.VNull(), fmt.Errorf(
			"memory %s not found in %s's queue — `webv2 memory %s` lists "+
				"what is there", memoryID, c.CampaignID, c.CampaignID)
	}
	mem, err := validation.ReadJson(path)
	if err != nil {
		return validation.VNull(), err
	}
	status := validation.ObjStr(mem, "promotion_status")
	if status == "human-approved" || status == "promoted" {
		return validation.VNull(), fmt.Errorf(
			"%s is already %s: revoke the approval instead of rejecting it",
			memoryID, status)
	}
	mem.O = validation.SetOrAppend(mem.O, "promotion_status", validation.VStr("rejected"))
	if rejectionClass != "" {
		mem.O = validation.SetOrAppend(mem.O, "rejection_class",
			validation.VStr(rejectionClass))
	}
	if err := validation.Validate(mem, "memory", 1); err != nil {
		return validation.VNull(), err
	}
	rc := validation.VNull()
	if rejectionClass != "" {
		rc = validation.VStr(rejectionClass)
	}
	data := validation.VObj(
		kv("reason", validation.VStr(reason)),
		kv("rejection_class", rc))
	// r40: a row flipped to "rejected" without its event is a reviewer's
	// "no" nobody recorded — and the schema keeps no reason field, so the
	// event IS the record. Unwind on refusal.
	if err := writeThenLog(c, []string{path}, func() error {
		return validation.WriteJson(path, mem, "")
	}, func() error {
		_, lerr := c.Log("memory.rejected", &memoryID, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return mem, nil
}

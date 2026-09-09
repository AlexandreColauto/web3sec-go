package cli

// cmd_t28_wire: the T28 cross-module seams (Python's import-time
// connections for learning / relations / shared_memory, in one place).
//
// D18: maximization.queueMemory is learning.queue_memory. Before this
// port it was a documented no-op, so `ladder disprove` wrote the rung and
// the ladder.rung_disproved event but neither the negative-memory row nor
// the memory.queued event.
//
// D15: findings.visible_memory_rows reads learning.all_memory (campaign
// tier) and shared_memory.load_shared_memory (root + user-global tiers);
// both defaults were empty, so recall saw no rows.

import (
	"websec/internal/audit/sections"
	"websec/internal/corpus"
	"websec/internal/findings"
	"websec/internal/learning"
	"websec/internal/maximization"
	"websec/internal/relations"
	"websec/internal/sharedmem"
	"websec/internal/state"
	"websec/internal/validation"
)

// wireT28Seams installs the T28 seam targets. Idempotent.
func wireT28Seams() {
	maximization.SetQueueMemory(queueMemoryT28)
	findings.SetLearningAllMemory(learning.AllMemory)
	findings.SetSharedMemoryRows(sharedmem.LoadSharedMemory)
	corpus.SetLoadSharedMemory(sharedmem.LoadSharedMemory)
	sections.SetRelations(relations.API{})
}

// WireT28Seams is wireT28Seams for cmd/webv2's init (Python's import-time
// connections are wired in both the CLI dispatch path and the binary's
// init, exactly like the T26 seams).
func WireT28Seams() { wireT28Seams() }

// queueMemoryT28 adapts learning.queue_memory to maximization's request
// struct (maximization.disprove_rung's keyword arguments).
func queueMemoryT28(c *state.Campaign,
	req maximization.MemoryRequest) (validation.Value, error) {
	return learning.QueueMemory(c, learning.QueueOpts{
		Kind:            req.Kind,
		Status:          req.Status,
		Pattern:         req.Pattern,
		FindingID:       req.FindingID,
		BugClass:        req.BugClass,
		EvidenceSummary: req.EvidenceSummary,
		Negative:        req.Negative,
	})
}

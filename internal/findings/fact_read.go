package findings

// Deployment-fact reads (framework-plan-v1.6 Part 8, non-negotiable 5): a
// value not read from the deployment is an assumption. The snapshot proves
// which CODE runs, never what the INSTANCE holds — so a config value the
// exploit depends on (a cap, an oracle address, a role grant) is recorded
// with the command that read it and the block it was read at, or it stays an
// assumption on the ladder.

import (
	"fmt"
	"regexp"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// mutatingPattern matches the verbs and flags that make a command a WRITE.
var mutatingPattern = regexp.MustCompile(`(?i)(^|\s)(cast\s+send|cast\s+mktx|` +
	`cast\s+publish|cast\s+wallet|forge\s+create|forge\s+script)(\s|$)` +
	`|--private-key|--ledger|--unlocked`)

// knownReadPattern is the recognized read shape: no attestation needed.
var knownReadPattern = regexp.MustCompile(
	`(?i)^(cast\s+(call|storage|code|balance|block|logs)|[a-z0-9_.-]+\s+query)\s`)

// pyTruncStr is a local three-line truncation for error text.
func pyTruncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// RecordFactRead appends one read to the finding's deployment_facts and logs
// finding.fact_read. Refused: a read with no pinned block (a mutable view of a
// mutable chain proves nothing), and any command carrying a mutating verb or a
// signing flag. The check is a DENYLIST, not an allowlist of `cast call` /
// `cast storage`: an unrecognized-but-harmless read on another chain must be
// recordable, or the operator skips it (or fakes it) and the fact never lands.
// An unrecognized command needs --read-only, an explicit attestation by the
// actor whose name goes on the row.
func RecordFactRead(c *state.Campaign, findingID, command, value, chain,
	actor string, block int64, readOnlyAttested bool) (validation.Value, error) {
	trimmed, err := factReadChecked(command, block, readOnlyAttested)
	if err != nil {
		return validation.VNull(), err
	}
	finding, err := LoadFinding(c, findingID)
	if err != nil {
		return validation.VNull(), err
	}
	appendFactRead(&finding, factReadRow(trimmed, value, chain, actor, block,
		readOnlyAttested))
	fid := validation.ObjStr(finding, "finding_id")
	if err := SaveThenLog(c, &finding, func() error {
		data := validation.VObj(
			validation.KV{K: "command", V: validation.VStr(trimmed)},
			validation.KV{K: "block", V: validation.VInt(block)},
		)
		_, lerr := c.Log("finding.fact_read", &fid, &data)
		return lerr
	}); err != nil {
		return validation.VNull(), err
	}
	return finding, nil
}

// factReadChecked is the refusal half of a fact read: the command must be
// non-empty, must carry no mutating verb or signing flag, must be a recognized
// read shape unless the actor attested --read-only, and must name a pinned
// block. It returns the trimmed command the row records.
func factReadChecked(command string, block int64, attested bool) (string, error) {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return "", fmt.Errorf("--command is required")
	}
	if m := mutatingPattern.FindString(trimmed); m != "" {
		return "", fmt.Errorf("fact reads are read-only: %q is a write",
			strings.TrimSpace(m))
	}
	if !knownReadPattern.MatchString(trimmed) && !attested {
		return "", fmt.Errorf(
			"unrecognized read command %q: pass --read-only to attest it writes nothing",
			pyTruncStr(trimmed, 80))
	}
	if block <= 0 {
		return "", fmt.Errorf(
			"a fact read needs a pinned block (--block N): an unpinned read is an assumption")
	}
	return trimmed, nil
}

// factReadRow is one deployment_facts row: the exact command, the raw value,
// the chain and the pinned block, the clock, the actor, and the attestation.
func factReadRow(command, value, chain, actor string, block int64,
	attested bool) validation.Value {
	return validation.VObj(
		validation.KV{K: "command", V: validation.VStr(command)},
		validation.KV{K: "value", V: validation.VStr(value)},
		validation.KV{K: "chain", V: validation.VStr(orDefault(chain, "ethereum"))},
		validation.KV{K: "block", V: validation.VInt(block)},
		validation.KV{K: "read_at", V: validation.VStr(state.NowIso())},
		validation.KV{K: "actor", V: validation.VStr(orDefault(actor, "operator"))},
		validation.KV{K: "read_only_attested", V: validation.VBool(attested)},
	)
}

// appendFactRead appends one row to the finding's deployment_facts. The key is
// OPTIONAL (old findings still validate), so the first read on a finding has no
// array to append to: ObjAt answers VNull, whose Kind stays Null through the
// append and serializes as `null` — which the schema then refuses. The
// amend.go idiom is the fix.
func appendFactRead(finding *validation.Value, row validation.Value) {
	facts := validation.ObjAt(*finding, "deployment_facts")
	if facts.Kind != validation.Arr {
		facts = validation.VArr()
	}
	facts.A = append(facts.A, row)
	finding.O = validation.SetOrAppend(finding.O, "deployment_facts", facts)
}

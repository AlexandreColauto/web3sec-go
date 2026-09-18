package cli

// P1b CLI tests — shared fixtures + `dedup`.
//
// Ports: tests/test_cli.py::test_unknown_campaign_is_a_clean_error (the
// unknown-campaign shape every command shares), tests/test_dedup_*.py via
// the command's report shape, and the argparse surface captured from the
// Python reference by usage_blocks.py [untracked].
//
// The unported shared-memory/learning readers are seam-injected here exactly
// as the parity probe does (goprobe.go [untracked]): the tests consult the
// same files the Python twin consults, never a fake store.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// t15Campaign is a fresh campaign on a fresh root, opened through the CLI's
// own init so the fixture path is the production one.
func t15Campaign(t *testing.T, program string) (*state.Campaign, string) {
	t.Helper()
	root := t.TempDir()
	cid := initOne(t, root)
	c, err := state.Open(root, cid)
	if err != nil {
		t.Fatalf("open campaign: %v", err)
	}
	return c, root
}

// t15Finding ingests a minimal hypothesis (the Python tests' MINIMAL dict).
func t15Finding(t *testing.T, c *state.Campaign, title, class string) validation.Value {
	t.Helper()
	payload := validation.VObj(
		kvT("title", validation.VStr(title)),
		kvT("root_cause", validation.VObj(
			kvT("class", validation.VStr(class)),
			kvT("description", validation.VStr("the mechanism described in detail")),
		)),
		kvT("affected", validation.VArr(validation.VObj(
			kvT("path", validation.VStr("src/V.sol")),
			kvT("function", validation.VStr("f")),
		))),
		kvT("attacker", validation.VObj(
			kvT("profile", validation.VStr("arbitrary EOA")),
			kvT("capabilities", validation.VArr()),
		)),
	)
	f, err := findings.IngestHypothesis(c, payload, "code", "", "")
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	return f
}

// t15GlobalRow seeds one approved shared-memory row (tests/test_cli_recall.py
// _seed_global_row) and wires the unported loader seam to that file.
func t15GlobalRow(t *testing.T, memoryID, bugClass string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "global-shared-memory")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	row := validation.VObj(
		kvT("memory_id", validation.VStr(memoryID)),
		kvT("campaign_id", validation.VStr("ingest:test:case")),
		kvT("finding_id", validation.VNull()),
		kvT("snapshot_id", validation.VNull()),
		kvT("created_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kvT("kind", validation.VStr("confirmed")),
		kvT("status", validation.VStr("CONFIRMED")),
		kvT("pattern", validation.VStr("Donation attack on share price")),
		kvT("bug_class", validation.VStr(bugClass)),
		kvT("cwe", validation.VNull()),
		kvT("evidence_summary", validation.VStr("Test incident.")),
		kvT("partition", validation.VStr("dev")),
		kvT("schema_version", validation.VInt(2)),
		kvT("rejection_class", validation.VNull()),
		kvT("deciding_propositions", validation.VArr()),
		kvT("promotion_status", validation.VStr("promoted")),
		kvT("approved_by", validation.VStr("operator")),
		kvT("approved_at", validation.VStr("2026-09-06T00:00:00+00:00")),
	)
	wrapper := validation.VArr(validation.VObj(
		kvT("program_key", validation.VStr("test|other|-")),
		kvT("published_at", validation.VStr("2026-09-06T00:00:00+00:00")),
		kvT("row", row),
		kvT("scope", validation.VStr("global")),
	))
	if err := validation.WriteJson(filepath.Join(dir, "memory.json"),
		wrapper, ""); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WEBV2_GLOBAL_MEMORY_DIR", dir)
	wireTestSharedMemory(t, dir)
}

// wireTestSharedMemory installs shared_memory.load_shared_memory's contract
// over one directory (the probe's seam, see goprobe.go [untracked]).
func wireTestSharedMemory(t *testing.T, dir string) {
	t.Helper()
	findings.SetSharedMemoryRows(func(string) ([]validation.Value, error) {
		rows, err := validation.ReadJson(filepath.Join(dir, "memory.json"))
		if err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			return nil, err
		}
		return rows.A, nil
	})
	t.Cleanup(func() {
		findings.SetSharedMemoryRows(func(string) ([]validation.Value, error) {
			return nil, nil
		})
	})
}

func kvT(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

// ---- dedup ---------------------------------------------------------------

func TestDedupReportsSweep(t *testing.T) {
	c, root := t15Campaign(t, "dedup")
	t15Finding(t, c, "the first hypothesis", "logic-error")
	t15Finding(t, c, "the second hypothesis", "oracle-manipulation")
	code, out, errS := run(t, "--root", root, "dedup", c.CampaignID)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, errS)
	}
	var report map[string]any
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	want := []string{"tier1_merges", "tier2_clusters", "tier3_flags",
		"cross_snapshot_flags", "untouched"}
	got := keyOrder(t, out)
	if len(got) != len(want) {
		t.Fatalf("key order %v, want %v", got, want)
	}
	for i, k := range want {
		if got[i] != k {
			t.Fatalf("key order %v, want %v", got, want)
		}
	}
	if report["untouched"] != float64(2) {
		t.Fatalf("untouched = %v, want 2", report["untouched"])
	}
}

func TestDedupUnknownCampaign(t *testing.T) {
	root := t.TempDir()
	code, _, errS := run(t, "--root", root, "dedup", "C-0000000000")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(errS, "no such campaign") {
		t.Fatalf("stderr %q", errS)
	}
}

func TestDedupMissingCampaignArgIsArgparse(t *testing.T) {
	code, _, errS := run(t, "dedup")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	want := "usage: webv2 dedup [-h] campaign\n" +
		"webv2 dedup: error: the following arguments are required: campaign\n"
	if errS != want {
		t.Fatalf("stderr\n%q\nwant\n%q", errS, want)
	}
}

func TestDedupExtraPositionalIsRootUsage(t *testing.T) {
	code, _, errS := run(t, "dedup", "C-0000000000", "extra")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(errS, "error: unrecognized arguments: extra") {
		t.Fatalf("stderr %q", errS)
	}
}

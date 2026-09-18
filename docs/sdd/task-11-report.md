# Task 11 — cold probe surface warning during discovery

- **BASE** `eb44603a` (worktree `.worktrees/production-readiness`, branch
  `production-readiness`)
- **COMMIT** `c15a1291 feat(briefing): cold probe surface warning during discovery`
- **STATUS** complete, green

## Law implemented

While a campaign is in phase `DISCOVERY` and the ledger records no
`probes run --emit` execution, `brief` prints a standing warning that names the
exact command. It is advisory, never a gate.

## What changed

- `internal/probes/campaign.go` (+19): `Emitted(c *state.Campaign) (bool, error)`
  scans the campaign's ledger events for `type == "probes.emit"` (the event
  `probes.EmitRows` writes), returning false when the ledger exists and is
  readable but carries no emit. An unreadable ledger returns the error; the
  caller decides.
- `internal/briefing/briefing.go` (+15): in `NextActions`, right after
  `cid := lensActionCampaign(...)`, and only when the campaign is non-nil and
  the brief's own campaign phase is `DISCOVERY`, a line is appended:

  `webv2 probes <cid> run --emit  # cold probe surface — DISCOVERY is running with no probe emit on record, so the mechanical surface is unprobed`

  The command comes first (Task 7/fix1 law: copyable `webv2 …` commands, no
  parentheses in minted prose). The signal is the ledger event, not the
  `probe_surface.json` artifact, so a stale artifact cannot silence or fake it.

## Red → green (evidence)

Red (`internal/briefing/briefing.go` restored to its pre-commit content;
`.scratch/sdd/task-11-red.txt`):

```
--- FAIL: TestColdProbeWarningDuringDiscovery (0.00s)
    task11_cold_probe_test.go:56: no cold probe surface warning in [webv2 run C-7efa6d7622 webv2 plan C-7efa6d7622 webv2 ingest C-7efa6d7622 --json-file <payload.json> webv2 prioritize C-7efa6d7622 webv2 prove C-7efa6d7622 --stage discovery  # 1 missing]
FAIL	websec/internal/briefing	0.019s
```

Green (same command, implementation in place):

```
ok  	websec/internal/briefing	0.851s
```

Tests: `internal/briefing/task11_cold_probe_test.go`

- `TestColdProbeWarningDuringDiscovery` — a `DISCOVERY` campaign with an empty
  emit surface carries the exact line (command asserted verbatim); after an
  emitted probe row lands, the warning is gone.
- `TestColdProbeWarningOnlyDuringDiscovery` — the same campaign in a later
  phase does not warn.

Independent probe evidence (`.scratch/sdd/task-10-brief-probe.txt`, a scratch
probe written/run/deleted, not committed): a real brief of a fresh
`DISCOVERY` campaign renders
`webv2 probes C-7be7648b04 run --emit  # cold probe surface — DISCOVERY is running with no probe emit on record, so the mechanical surface is unprobed`.

Not a gate: the line is appended to `next_actions` only. No completion proof,
floor, or phase transition reads it; `prove --stage discovery` and campaign
completion behave exactly as before (existing cli/orchestrator suites green).

## Gates

- `go test ./internal/orchestrator ./internal/briefing ./internal/cli ./internal/planner -count=1` — green
- full `go test ./... -count=1` — green (`TEST EXIT 0`)
- `go vet ./...` — green (`VET EXIT 0`)
- `scripts/golden.sh` — green, no pin changes (`GOLDEN EXIT 0`)
- `scripts/runbook-walkthrough.sh` — 150 passed / 0 failed (`RUNBOOK EXIT 0`)

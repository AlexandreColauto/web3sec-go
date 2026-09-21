# scripts/legacy — the reader-compatibility fixture

`campaigns/C-45488bdaf5` is a complete campaign built **end to end by the
retired Python reference** (`web3sec-final`, frozen at the 2026-09-09
retirement; the tree was produced by the last live cross-audit run of
`scripts/verify-full.sh` on 2026-09-09, under the standard pinned clock
`WEBV2_NOW=2026-09-09T12:00:01+00:00` + per-step `WEBV2_UUID` seed).

It exercises the full P1+P2+P3 op sequence: init, model, plan, two findings
(tier-3 twin pair + critic verdict), dedup + resolve-candidate, answered,
gate dry-run, artifact-register, invariant verify/contradict, exec ledger
(pass + fail), an out-of-band E4 mint, the complete ladder lifecycle with a
disproved rung queuing the negative memory row (the D18 happy path),
chains/terminals/privileged, priced impact, sequence verify, report, and the
structural leg (snap/index/sinks/prescreen/probes run+emit/relations over
the accumulator-blind fixture).

## What it proves

`scripts/verify-full.sh` step 9 copies this tree into a scratch root and
asserts that the **Go** binary:

1. `audit` PASSes it with all 14 rendered sections (`ok: true`) — the
   registry carries 15; the `eval` section is presence-gated and this
   fixture matches no gold-eval suite program, so it renders 14,
2. `verify` accepts the hash-chained event log written by Python's encoder,
3. every P2/P3 reader works on Python-written state (`execs --json`, ladder
   report, memory view, probe axes).

That is the survivor of the old cross-twin steps: Python-era campaign
directories must stay readable forever, with no Python required to prove it.

## Invariants of this fixture

* It is **read-only history**: never regenerate it from Go, never edit it to
  make a check pass. If Go's readers start rejecting it, Go has a bug.
* It was verified portable (audits clean after `cp -r` to a fresh root) —
  recorded absolute paths (`/home/xand/...` in some event payloads) are
  inert data; the auditors follow campaign-relative files.
* A regeneration path would need the twin checkout; it is deliberately
  undocumented, because regeneration is not what this fixture is for.

## Repair log

* **2026-09-21 — `REP-adc3248d` was not self-contained.** Step 9's audit
  failed with `[artifacts] REP-adc3248d: missing file
  <ROOT>/.scratch/verify-p1/fixtures/note.md`: the reference had registered
  `note.md` from the harness scratch dir, so the row recorded the capturing
  machine's ABSOLUTE path (and no file the fixture shipped). Six of the seven
  rows record a campaign-relative path; this one did not, and step 10 creates
  a *different* `note.md` later. `internal/audit/sections/artifacts.go` was
  right. The file now ships at `artifacts/note.md` and the row records
  `campaigns/C-45488bdaf5/artifacts/note.md`, like its siblings.
  Consequences, all inside the fixture: the `artifact.registered` event
  (seq 17) was re-pointed at the same path and the log re-sealed from seq 17
  on — in Go, with `validation.CanonSpaced`/`Sha256Hex` over
  `state.eventHash`'s own six-field body; `artifact-reconcile` re-hashed the
  row against the shipped bytes (`artifact.refreshed`, seq 54), which is what
  recorded the new sha256; and `doctor --state-only` rebuilt the `events`
  mirror from the re-sealed log. The `at`-stamps of the repair events are the
  repair date, not the fixture's pinned 2026-09-09 clock — the repair is not
  pretending the reference did it. The remaining `/home/xand/...` strings in
  event payloads are inert data, exactly as the invariant above says.
  `.superpowers/sdd/2026-09-21-v16-p1-p2-record-and-evidence/step9-fixture.md`
  carries the full proof.

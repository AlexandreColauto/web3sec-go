# v1.6 — the exec-record anchor: scope, decision and plan

**Verdict: the `sandbox.exec` event must carry a digest of the FINAL
`exec_record.json` as written, labelled with its canonical encoding. One
mechanism closes both the new expectation keys and `exit_status`. No code has
been written; this is analysis only.**

Written at HEAD `1684e640` (tree clean). Predecessors: `a8fc132f` (an
absent-guard reproduction can be minted) and `1684e640` (the signature must name
a real per-test failure).

**Postscript (added at HEAD `7e0eac87`, after the anchor and the archived
verdict landed):** every table and code block below describes the PRE-anchor
shape as it stood when this scope was written — `sandbox.exec` now carries SIX
data keys (`profile`, `exit`, `finding`, `failure_class`,
`exec_record_sha256`, `exec_record_sha256_alg`) and `sandbox.exec.registered`
SEVEN (the same six plus `reported_by`), so the "only three data keys" and the
per-writer key lists in §1.1 are historical, not current.

**Ordering decision, recorded and not revisited:** the anchor lands BEFORE the
finding `F-cfff3ebc0250` is driven to CONFIRMED. Nothing in this document drives
any finding anywhere; the ordering is stated only so the plan below is executed
in the right order.

---

## 0. The problem

`a8fc132f` + `1684e640` made an ABSENT-GUARD defect mintable. Under
`expected_outcome: "fail"` a record is admitted only when `exit_status` is
non-zero, `expected_failure` appears on a per-test failure line, and the run
classifies as class `logic` (`internal/findings/exec_evidence.go:164-181` and
`checkExpectedFailure` at `:314`). The design's whole integrity argument is that the
operator commits to the expectation BEFORE the run:

- the keys are stamped into the record at exec time, before the payload runs —
  `runWriteInitialRecord` calls `applyExecExpectation` and then
  `validation.WriteJson(f.path, f.record, "sandbox_execution")`
  (`internal/sandbox/exec.go:164-174`, `internal/sandbox/expect.go:55-63`);
- the CLI refuses to accept the pair in any other shape (`--expect-failure`
  requires `--expect fail`, and `--expect fail` requires a signature:
  `internal/cli/cmd_exec.go:228-244`).

**That commitment is not enforced anywhere.** The record is plain mutable JSON on
disk, read straight from disk with no integrity anchor:

```
internal/findings/ingest_evidence_gate.go:96   recPath := filepath.Join(campaign.ExecsDir, artifact, "exec_record.json")
internal/findings/ingest_evidence_gate.go:101  rec, err := validation.ReadJson(recPath)
```

while the hash-chained `sandbox.exec` event carries only three data keys:

```
internal/sandbox/exec.go:252-256   data := validation.VObj(
                                     {profile}, {exit}, {finding})
internal/sandbox/exec.go:257       if _, err := f.s.Campaign.Log("sandbox.exec", &ref, &data); err != nil {
```

So: run a failing suite, then edit `expected_outcome: "fail"` and
`expected_failure` into the record, and mint. The result is indistinguishable
from an exec-time declaration.

**This is a channel that did not exist before the change.** Pre-change, exit 1
was refused outright — `checkExecExit`'s message is *"a run that did not succeed
is not a reproduction"* (`internal/findings/exec_evidence.go:247-250`) — so
there was no path to mint on a non-zero exit. Post-change, exit 1 plus a mutable
unanchored expectation is admitted.

**It is not a two-key patch.** `exit_status` is exactly as unanchored as
`expected_outcome`: the same hand-edit that adds the expectation can also flip
`exit_status` from 7 to 0, or the reverse. Anchoring the two expectation keys
alone would leave the exit-status half of `checkExecExit` — the older and more
load-bearing half — still hand-editable. **The scope anchors the whole record or
it anchors nothing**, and §6 shows `exit_status` being closed by the same
mechanism.

---

## 1. Facts this scope rests on (each verified against the tree)

### 1.1 Write/event ordering — the structural fact that makes this cheap

`runExecuteAndLog` sets `finished_at`, `exit_status`, `artifact_hashes` and
`output_capture` on the record, **writes `exec_record.json`**, and only then
appends the event:

```
internal/sandbox/exec.go:244-247   setKey(finished_at), setKey(exit_status),
                                   setKey(artifact_hashes), setKey(output_capture)
internal/sandbox/exec.go:248       validation.WriteJson(f.path, f.record, "sandbox_execution")
internal/sandbox/exec.go:252-257   build data; Campaign.Log("sandbox.exec", ...)
```

The final record exists immediately before the event append, in the same
function. A digest computed over the final record can be added to that same
event's `data` with **no ordering problem and no second write**.

Two other writers exist and both matter:

| writer | record write | event | event data today |
|---|---|---|---|
| `Run` (pre-execution fields) | `exec.go:170` | — | — |
| `Run` (final fields) | `exec.go:248` | `sandbox.exec` (`exec.go:257`) | profile, exit, finding |
| `Run` refusal path | `exec.go:192` | `sandbox.refused` (`exec.go:198`) | violations |
| `RegisterExec` | `register_exec.go:149` | `sandbox.exec.registered` (`register_exec.go:166`) | profile, exit, reported_by, finding |

The digest must be over the record as written at `exec.go:248`, and the same
mechanism must be applied at `register_exec.go:149` — see §2.4. The refusal path
and `--dry-run` need nothing: a refused command never ran and no evidence can
cite it (`ValidateExecRecord` refuses a record with no `exit_status`), and
`--dry-run` writes no record and no event (`cmd_exec.go:270-272`).

### 1.2 The canonical encoder already exists and is already oracle-pinned

`internal/jval` implements CPython-compatible canonical JSON:

```
internal/jval/value.go:139   func Canon(v Value, compact bool) string
internal/jval/value.go:146   func CanonSpaced(v Value) string { return Canon(v, false) }
internal/jval/value.go:149   func CanonCompact(v Value) string { return Canon(v, true) }
```

with the documented split — *"CanonSpaced is the spaced flavor (event/context/row
hashes)"*, *"CanonCompact is the compact flavor (snapshot manifests, spec_hash,
fingerprint)"* (`internal/jval/value.go:145-149`). Both are re-exported by
`internal/validation` (`internal/validation/jval_alias.go:44-45`), as is
`Sha256Hex` (`internal/validation/atomicio.go:177-181`).

The encoding is **already differentially pinned against CPython**:
`scripts/canon-oracle.py` (a CPython `json.dumps(sort_keys=True,
ensure_ascii=True)` oracle) is byte-diffed against the Go encoder by
`internal/validation/fuzz/canon_oracle_test.go`. Choosing the existing encoder
means the anchor adds **no new encoding to prove**.

### 1.3 The chain already covers anything inside `data` — no chain change

```
internal/state/chain.go:16-19  func eventHash(event validation.Value) string {
                                 body := pickEventBody(event)
                                 return validation.Sha256Hex([]byte(validation.CanonSpaced(body)))
                               }
internal/state/chain.go:37     for _, k := range []string{"seq", "at", "type", "ref", "data", "prev_hash"}
```

`data` is one of the six hashed fields and is hashed as a whole, so a new key
added INSIDE `data` is automatically covered by the existing chain hash. **No
change to `chain.go`, no rehash of history**, and the committed fixture's
existing `event_hash` values stay valid.

### 1.4 There is no event schema, and the record schema forbids extra keys

- No schema is applied to ledger event data: `WriteJson` validates only when a
  schema name is passed (`internal/validation/atomicio.go:34-39`), and the exec
  **record** is the thing that passes `"sandbox_execution"`
  (`exec.go:170`, `exec.go:248`, `register_exec.go:149`). Adding a key to an
  event's `data` needs **no schema edit and no `assets/` change**.
- The record schema is closed:
  `assets/schema/sandbox_execution.schema.json` has
  `"additionalProperties": false` at the top level. **A digest cannot live on
  the record** — the write path would reject it, and the golden records
  (`scripts/golden-run.py:308-358`, `scripts/verify-full.sh:204-246`) are
  byte-pinned fixtures.

The two facts together settle the design: **the anchor lives only in the event,
never on the record.** If it were on the record, it would be self-referential
(a digest of a document containing its own digest) and a hand-edit would update
both halves at once, which is precisely the failure mode being closed.

### 1.5 `WriteJson` writes indented bytes, so the digest must be canonical

```
internal/validation/atomicio.go:53   fh.WriteString(DumpIndented(data) + "\n")
```

Raw file bytes are indented; a digest over raw bytes would be defeated by
re-indentation alone. Both harnesses already re-emit records with Python's
`json.dumps(rec, indent=1)` (`scripts/verify-full.sh:245`,
`scripts/golden-run.py:358`). The digest is therefore defined over the **decoded
record value in canonical form**, which is also what makes it survive a campaign
copy to another root (step 9 copies the fixture: `verify-full.sh:355-357`).

### 1.6 Audit registry, pins and the idiom to imitate

- `internal/audit/sections/register.go:25-53` registers 18 sections; the newest
  four are appended LAST so the ported 14 keep their relative order.
- The presence-gated idiom is `return validation.Value{}, ErrSkip`
  (`internal/audit/sections/regressionsuite.go:55`), and `AuditCampaign` omits a
  skipped section (`internal/audit/audit.go:86-90`).
- `internal/audit/sections/floorpolicy.go` is the *"the projection must agree
  with the log"* idiom to imitate: it replays the log and reconciles it against
  the on-disk projection, reporting drift as a problem.
- The section list is pinned in **eight** places: the **five registry pins**
  enumerated in §8.3, plus **three report pins that count rendered sections**
  and are easy to miss — `internal/cli/cli_test.go:161` (`len(secs) != 15`),
  `internal/audit/eval_gate_test.go:76` (`len(got) != 15`), and
  `internal/audit/audit_test.go:104-110` (an exact 15-name report list). **Those
  three are load-bearing on the fact that their campaigns contain no exec
  events**: `TestAuditClean`'s campaign is a bare `init` (`cli_test.go:39-53`),
  `gateCampaign` only ingests hypotheses (`eval_gate_test.go:41-54`), and
  `initCampaign` is a bare `state.Init` (`audit_test.go:51-59`). The new section
  is presence-gated, so all three stay green as written — but **a future fixture
  that execs will break one of them**, and whoever writes that fixture must move
  the count in the same commit. §8.3 lists them with the registry pins.

---

## 2. §4.1 — WHAT GETS ANCHORED

**Recommendation: (a) a digest anchor, as two keys inside the `sandbox.exec`
event's `data`.**

| key | value | size |
|---|---|---|
| `exec_record_sha256` | 64 lowercase hex | fixed |
| `exec_record_sha256_alg` | the pinned literal `sha256-canon-spaced` | fixed |

Produced by one helper so the writer and the auditor cannot drift:
`ExecRecordDigest(rec) = validation.Sha256Hex([]byte(validation.CanonSpaced(rec)))`,
emitted as `data[exec_record_sha256]` alongside
`data[exec_record_sha256_alg]`.

### 2.1 Why a digest of the whole record

1. **It covers `exit_status`, both expectation keys, and every field added
   later, with no maintained list.** The task's requirement — *"covering
   exit_status and both expectation keys and any field added later"* — is
   satisfied by construction, not by discipline. The record's key set has grown
   three times in recent history alone (`workdir_resolved` r36 F4,
   `output_capture` r36 F6, `expected_outcome`/`expected_failure` v16 §5.3); a
   hand-maintained subset would have silently missed each one.
2. **The domain is already schema-pinned.** `additionalProperties: false`
   (`assets/schema/sandbox_execution.schema.json`) means "the whole record" is
   not an open set: the schema is the authority on which keys exist, so the
   digest has a stable, reviewable domain.
3. **It closes `exit_status` — the reason this task exists** (§6).
4. **It is one mechanism for two writers.** `Run` and `RegisterExec` both call
   the same helper with their own final record.
5. **It is tamper-*evident*, not tamper-proof, in the right direction:** the
   digest cannot prevent an edit; it makes the edit *detectable*, which is what
   the audit and the mint gate need.

### 2.2 Why field carry (b) is rejected

| | (a) digest | (b) field carry |
|---|---|---|
| event size | fixed 2 keys | grows with every future record field |
| maintenance | none | the carried set must be kept in step with the schema, by hand |
| future fields | covered automatically | silently uncovered until someone remembers |
| second source of truth | none | the event and the record can disagree about `exit_status`, and the reader must know which wins |
| readability | no gain | **no gain either** — `webv2 log` prints only `seq / at / type / ref` (`internal/cli/cmd_log.go:63-67`), so carried fields are not more readable to the operator |

Field carry's only real advantage — legibility — does not exist at any current
CLI surface, and its costs are exactly the drift the anchor exists to remove.

### 2.3 Why the encoding must be named in the event

`exec_record_sha256` alone is an unlabelled hex string. The project has already
paid for that mistake once:

> *"Every sha256 in this record carries its encoding, because an unlabelled
> canonical encoding is not evidence."* — `docs/gates/v16-P0-control-target.md:336-337`

The recorded defect class: sha256 of a `0x`-prefixed hex **string**
(`a6b12297…`) versus sha256 of the bytecode **bytes** (`c71f1646…`) — *"both
encodings are valid fingerprints and they differ, so anyone reproducing by
hashing bytes gets different values and will think the record is wrong"*
(`docs/gates/v16-P0-control-target.md:330-338`). A bare digest of "the record"
has the same shape of ambiguity: canonical spaced form vs compact form, decoded
value vs raw file bytes, all legitimate. Hence the second key, and hence a
pinned literal rather than a free-form string (§3).

The label is not itself the migration marker. **The presence of EITHER anchor
key is the data-based marker of a new-style event** (§4), which is how the
migration position is expressed without a timestamp cutoff. The label's own job
is the one above — it names the encoding — and a digest that carries no label is
refused (§3.3, §5.1), because it is exactly the unlabelled-encoding defect class
this section exists to close.

### 2.4 Both writers, or the hole just moves

`RegisterOpts` has no expectation field (`internal/sandbox/register_exec.go:14-24`),
so a registered record cannot be *asked* for `expected_outcome: "fail"` through
the API. It does not need to be: the record is plain JSON and the ingest gate
reads the record, not the event. An operator can register a run with
`exit_status: 7`, hand-edit the two expectation keys in, and cite it — the same
channel, a different writer. `sandbox.exec.registered` is anchored by the same
helper in the same place (`register_exec.go:149` → `register_exec.go:166`), with
no ordering problem. **Anchoring only the `Run` path would leave the register
path open**, so the plan covers both.

---

## 3. §4.2 — THE CANONICAL ENCODING, PINNED

No implementation judgement call may remain. The specification is:

| dimension | pinned value | authority |
|---|---|---|
| **encoder** | `validation.CanonSpaced` | `internal/validation/jval_alias.go:44` → `internal/jval/value.go:146` |
| **why this one** | it is the flavour the ledger already uses for every event hash, so the anchor adds no second canonicalizer and no second oracle | `internal/jval/value.go:145-146`, `internal/state/chain.go:18` |
| **digest domain** | the **whole decoded record value** — every key present in `exec_record.json`, at any depth | §3.1 |
| **key order** | sorted by the encoder (`sort.Slice` on the key) | `internal/jval/value.go:187-190` |
| **separators** | `", "` and `": "` (the spaced form) | `internal/jval/value.go:191-194` |
| **numbers** | Python-compatible rendering: ints via `IntText`, floats via `PythonFloat` | `internal/jval/value.go:161-164` |
| **unicode** | `ensure_ascii` — non-ASCII is escaped, so the digest is independent of U+2028/U+2029 and friends | `internal/jval/value.go` `writeEscaped`; rationale at `internal/state/chain.go:11-15` |
| **absent vs null** | absent key ⇒ absent from the canonical text; explicit `null` ⇒ `"k": null`. **They produce different digests.** | §3.2 |
| **algorithm** | sha256 | `internal/validation/atomicio.go:178-181` |
| **output encoding** | lowercase hex, 64 characters, via `validation.Sha256Hex` | `internal/validation/atomicio.go:177-181` |
| **name carried in the event** | `exec_record_sha256_alg = "sha256-canon-spaced"` | §2.3 |

### 3.1 The domain is the value, not the file bytes — and why that is decidable

`WriteJson` writes `DumpIndented(data) + "\n"`
(`internal/validation/atomicio.go:53`), so the file bytes are *not* canonical and
are not stable across writers (both harnesses re-emit with
`json.dumps(rec, indent=1)`: `scripts/verify-full.sh:245`,
`scripts/golden-run.py:358`). A raw-bytes digest would report drift on a
re-indentation that changed nothing.

Therefore:

```
write path:  digest = validation.Sha256Hex([]byte(validation.CanonSpaced(f.record)))   // f.record, post-WriteJson
audit path:  rec, _ = validation.ReadJson(recPath)                                     // atomicio.go:15
             digest = validation.Sha256Hex([]byte(validation.CanonSpaced(rec)))
```

**Same helper, both sides.** The recomputation depends on `parse → canonical`
stability, which the project already relies on for its own chain: `VerifyLog`
recomputes `eventHash(e)` from each parsed line and reports *"event_hash does not
recompute (content edited?)"* (`internal/state/verifylog.go:263-275`). The anchor
inherits a property that is already load-bearing, and the plan's test list
includes an explicit round-trip test rather than assuming it (§8.2).

Two useful consequences:

- **Root independence.** The digest covers the record's content, not its path,
  so a campaign copied to another root keeps its anchors — which is exactly what
  step 9 requires of the fixture (`scripts/verify-full.sh:355-357`).
- **No new oracle.** The encoding is already byte-diffed against CPython
  (`scripts/canon-oracle.py`, `internal/validation/fuzz/canon_oracle_test.go`),
  so choosing `CanonSpaced` adds zero new encoding surface to prove.

### 3.2 Absent vs null, precisely

The chain's "missing field renders as JSON null" rule is a property of
`pickEventBody`'s six top-level fields only — it substitutes `VNull()` for a
field it cannot find (`internal/state/chain.go:45-47`). **It does not apply
inside `data`.** Inside `data`, and therefore inside the digest domain, the
record's own key set governs: a key absent from the record is absent from the
canonical object, while `"k": null` is present-and-null. The two canonical
strings differ, so the two digests differ.

That distinction is not pedantry — it is load-bearing in both directions:

- `output_capture.stdout_total_bytes` is deliberately **present-and-null** when
  output was withheld — *"absence, never a fabricated count"*
  (`internal/sandbox/capture.go:110-125`). A digest that flattened null into
  absent would erase a meaningful distinction.
- `expected_outcome` **absent** means `"pass"` (`internal/sandbox/expect.go:37-42`),
  and a present-and-null value reads the same way to the gate because `ObjStr`
  returns `""` for a non-string. **The gate is indifferent to absent-vs-null for
  this key; the digest is not.** So an edit that adds `"expected_outcome": null`
  (or removes the key) is caught by the anchor even though no admission rule
  would have noticed — a small, concrete illustration of why the whole record is
  the right domain.

### 3.3 Why the label is mandatory (restated as an implementation rule)

`exec_record_sha256` without `exec_record_sha256_alg` is **not** a valid anchor:
it is an unlabelled canonical encoding, i.e. not evidence
(`docs/gates/v16-P0-control-target.md:336-338`; the `a6b12297` vs `c71f1646`
collision). The audit section therefore treats these as problems (§5): a digest
with no label, a label with no digest, a label that is not the pinned literal,
and a digest whose **value** is malformed — not 64 lowercase hex, or not a
string at all. The malformed-value case is not decoration: such a digest can
never equal a recomputed one, so it is a mismatch, and the reader must say so
rather than treating it as an unverifiable curiosity. A reader that guesses the
encoding — or that shrugs at a garbled digest — is exactly the reader the B2
record warns about.

---

## 4. §4.3 — BACKWARD COMPATIBILITY / MIGRATION

**Recommendation: fail-open on an absent anchor, fail-closed on a present one.**

- **Neither** anchor key on the event (`exec_record_sha256` and
  `exec_record_sha256_alg` both absent) ⇒ the event is **UNANCHORED**: reported
  in the section's `unanchored` list, **not** a problem, `ok` stays true, and the
  mint gate admits the record exactly as today.
- **Either** anchor key present ⇒ the event is **new-style**, and every rule is
  enforced: a digest that does not match the on-disk record, a label without a
  digest, a digest without a label, a label that is not the pinned literal, a
  digest that is not 64 lowercase hex, or a record that is not on disk ⇒
  **refused** at mint and reported as a problem by the audit.

**The presence of EITHER anchor key is the migration marker.** The rule has one
reading and it is the strict one: `{digest present, label absent}` is new-style
and **refused**, never fail-open. An unlabelled digest is precisely the defect
class §3.3 exists to close (the project's own `a6b12297…` / `c71f1646…` B2
collision), so it cannot also be the escape hatch from the rule. §2.3, §4.1,
§5.1, §8.1 and §8.2 all state this same predicate. It is a property of the data,
not of a date, so it cannot drift with a clock and it cannot be forged without
also forging the digest (which is checked).

### 4.1 The three populations

| population | state | audit section | mint gate |
|---|---|---|---|
| **(i) pre-existing events in live campaigns** | no anchor keys | renders them in `unanchored`; `ok` stays true | admits (behaviour unchanged) |
| **(ii) the committed Python-era fixture** (`scripts/legacy/campaigns/C-45488bdaf5`, 2 `sandbox.exec` events, 3 exec records) | no anchor keys | same as (i): `unanchored: 2`, `ok: true` | not exercised by step 9, and admits if it were |
| **(iii) new events** | both keys stamped by the writer | digest recomputed and compared | refused on any anchor violation |

### 4.2 The measured cost of fail-closed — it is not a preference

Fail-closed (absent ⇒ invalid) is the codebase's general lean: an unverified
invariant refuses a level rise (`invariants.AssertInvariantsVerified`), and a
torn tail is refused rather than repaired (`SECURITY.md`). Here it is wrong, and
the cost is measurable, not hypothetical:

1. **Step 9 goes red.** `scripts/verify-full.sh:358-365` asserts both
   `audit PASS:` and `audit --json` → `ok is True` on the fixture. Every fixture
   event predates the anchor, so fail-closed makes the fixture's audit DIRTY by
   construction. That is a *measured* consequence of the fixture's contents
   (its two `sandbox.exec` events carry only `{exit, finding, profile}`).
2. **The fixture can never be re-anchored.** Its entire value is that it was
   built end to end by the Python reference and committed as a
   reader-compatibility fixture — *"everything the Go auditors and readers must
   accept from Python-era state"* (`scripts/verify-full.sh:345-349`,
   `scripts/legacy/README.md`). Stamping a Go-computed anchor into it would
   rewrite `event_hash` on the edited events and destroy the provenance it
   exists to carry. So fail-closed-on-absent is **permanently unadoptable while
   step 9 exists** — not "adopt it later".
3. **Mint would go red in two harnesses.** Both the golden recipe and the P2
   smoke seed an E4 record out-of-band and mint against it:
   `seed_p2_exec` (`scripts/verify-full.sh:204-246`, used by step 11 at
   `:589` and step 12 at `:710`) and `seed_exec` (`scripts/golden-run.py:283-358`).
   Neither writes a `sandbox.exec` event at all, so a mint gate that demanded an
   anchor would refuse them and break step 7 (golden), step 11 and step 12's mint.
4. **It would retroactively invalidate every prior record.** The anchor can only
   ever prove *"this record was not edited after the event"*. It can prove
   nothing about a record whose event predates it, so treating absence as
   invalidity converts an integrity gain into a wholesale rejection of history
   without adding one bit of evidence.

### 4.3 What fail-open leaves, honestly

The anchor closes **"edit the record after the event"**. It does not close
**"remove the event"** — but the removal is *not* as cheap as "truncate the last
line", and the log's chain check is not what catches it. Both halves of that
sentence are stated below; the first version of this section got each of them
wrong in the opposite direction.

**Truncation IS caught today — by the mirror, not by the chain.** A
truncated-at-a-line-boundary log passes the chain check: the chain has no
external head pin, it is anchored only at 64 zeros (`internal/state/chain.go:7-8`,
`SECURITY.md`), and its tamper checks are `prev_hash` linkage plus per-event
recomputation (`internal/state/verifylog.go:262-275`). What catches it is
`campaign_state.json`, which mirrors the event tail: `verify` reconciles the
mirror against the log's suffix and reports *"state event tail is LONGER than the
log (%d projected vs %d logged) — events are GONE from the tail; a truncated log
still verifies its chain, and doctor rebuilds TO it, adopting the loss"*
(`internal/state/verifylog.go:335-352`). The comparison is `arraysEq` over whole
event values — `valueEq` is `CanonSpaced(a) == CanonSpaced(b)`
(`internal/state/verifylog.go:546-562`) — so it compares the event's `data`,
the anchor keys included, not just its length. Deleting the anchoring line from
the log therefore leaves the mirror longer than the log and is reported as a
problem. (The first version of this section claimed such a log "is therefore
invisible to `verify`" and that the exec would merely read as *unanchored*; both
were wrong, and the mirror check is why.)

**The attack that actually slips through must edit two files, and recompute
hashes.** To remove an anchoring event undetected an attacker must (i) delete the
line from `events.jsonl` — and if it is not the last line, recompute `prev_hash`
and `event_hash` for every surviving event after it — and (ii) delete the
mirrored copy from `campaign_state.json`, because otherwise the mirror check
above fires. That is strictly harder than editing one JSON file, and it is
detectable by anyone holding an external copy of the head hash.

**What this design leaves open, stated exactly.** The section's reader is
event-driven *by design* (§5): it iterates `c.Events()` and deliberately does
**not** enumerate `execs/` (`state.AllExecs`), because the anchor is a claim an
event makes about a record. The consequence is sharper than "the exec reads as
unanchored": an exec whose carrier event has been deleted **produces no row at
all** — not a problem, not anchored, not unanchored. It is simply absent from the
section's verdict. Therefore:

- the section's `unanchored` count bounds **key-stripping only** — an event that
  is still present and still readable but carries no anchor keys (populations
  (i)/(ii) of §4.1, and any attacker who strips the keys without deleting the
  event);
- **event-deletion-plus-projection-edit is an unclosed residual of this design**,
  not a mitigation. No in-tree mechanism catches it: the section never sees the
  record, `Execs` only reports a deleted *record*, and `verify` sees a log and a
  mirror that agree. **Only an external copy of the head hash — or of the mirror
  — would catch it**, because the in-tree ledger has no such pin.
- the residual is recorded here, and §9 asks whether adding that external pin is
  in scope. It is a pre-existing boundary of the ledger rather than something the
  anchor introduces, but this section must not pretend to close it.

A stronger rule — *"a campaign that contains any anchored event must have an
anchored event for every cited exec"* — is rejected for the same measured reason
as fail-closed: it breaks the two seeding harnesses, which have no event at all
for the record they mint against. It would not close the residual either: it is
still evaluated over the events that exist.

**RESIDUAL — carrier-event deletion (named, accepted, NOT closed).** The threat
is that an adversary deletes the carrier `sandbox.exec` event that anchors a
record's digest — and, because `verify` compares the `campaign_state.json` mirror
against the log's suffix, the mirrored copy of that event too — after which the
exec's `exec_record.json` can be edited freely and the campaign still audits
green: the section is event-driven by design (§5), so a deleted carrier produces
no `exec_record_anchor` row at all, and no other section ever recomputes the
digest. The capability this requires is **ledger-write** — rewriting the
hash-chained `events.jsonl`, recomputing `prev_hash`/`event_hash` for the
surviving events after the deleted one, and rewriting the projection — which is
strictly stronger than editing a JSON projection; the anchor closes *post-hoc
stamping of a live record* by whoever can write the record, not an adversary who
can rewrite the ledger file itself. The single mechanism that would close it is
an **external head-hash pin** (a committed head hash, or a copy of the mirror
outside the campaign directory), which is a separate mechanism carrying its own
trust question — where the head lives, who writes it, and what happens on
deliberate drift. It is out of scope here and is deliberately left open (§9,
question 2). The precise boundary of the residual: a DAMAGED ledger — an
`events.jsonl` that cannot be read — fails closed at mint, because
`VerifyExecRecordAnchor` propagates the `c.Events()` read error, while an
ABSENT ledger folds to an empty log inside `(*state.Campaign).Events`
(ENOENT → nil) and therefore fails OPEN at mint, exactly like the
pre-anchor state; the audit still goes red on both through the `event_log`
section, so the asymmetry is recorded here rather than closed.

### 4.4 The deferred strictness decision

Whether an *unanchored* event should ever gate an admission is an operator-policy
question, not a technical one, and it is listed in §9. My recommendation is
**no, and permanently** for pre-anchor state, for the reason in 4.2(2) and
4.2(4): the fixture is frozen and history cannot be anchored retroactively. If
the operator later wants a stricter posture, the only implementable form is
campaign-era based (**the presence of either anchor key**, §4 — never "the label
alone", which would make an unlabelled digest fail-open), which is what this
design already provides as a predicate.

---

## 5. §4.4 — THE AUDIT SECTION

**Recommendation: yes, and it is the half that makes the anchor load-bearing.**
A digest that nothing recomputes is a field with no consumer.

- **Section key:** `exec_record_anchor` (snake_case, matching
  `floor_policy` / `invariant_verification` / `regression_suite`).
- **Registration:** `internal/audit/sections/register.go`, **appended LAST**,
  after `register("regression_suite", RegressionSuite)` (`register.go:52`), with
  the same "registered LAST so the ported sections keep their relative order"
  comment idiom.
- **Presence-gated: yes, with the `ErrSkip` idiom** — `return
  validation.Value{}, ErrSkip` (`internal/audit/sections/regressionsuite.go:55`,
  omitted by `AuditCampaign` at `internal/audit/audit.go:86-90`) — **when the
  campaign has no `sandbox.exec` / `sandbox.exec.registered` events at all.**
  - Rejected: gating on *"no anchored event exists"*. That would make the
    section vanish exactly when coverage is zero — the least informative moment
    — and would hide the migration state of every live Python-era campaign.
  - Rejected: unconditional. The Python parity oracle compares
    `AuditSummaryLine` byte-exactly against the vectors' `summary_line`
    (`internal/audit/p1_sections_test.go:199-215`,
    `internal/audit/testdata/p1_audit_vectors.json`), and those fixtures contain
    no `sandbox.exec` events. An unconditional section would force a second
    `stripSummaryToken` (`p1_sections_test.go:219-229`) for zero informational
    gain — a campaign with no exec events has no anchors to report.
- **Reader:** `c.Events()` in log order (`internal/state/eventlog_read.go:35-40`)
  for the event side, and `filepath.Join(c.ExecsDir, execID, "exec_record.json")`
  — the same path construction as the ingest gate
  (`internal/findings/ingest_evidence_gate.go:96`) — for the record side. It
  does **not** enumerate `execs/` (`state.AllExecs`, `internal/state/execs.go:37`):
  the anchor is a claim an EVENT makes about a record, so the event is the
  driving collection. That also keeps the harness-seeded records (which have no
  event at all) out of the section's verdict. **This choice has a stated cost,
  and §4.3 records it as the design's unclosed residual:** an exec whose carrier
  event was deleted produces no row at all — not a problem, not anchored, not
  unanchored — because the section never looks at `execs/` on its own. That is
  deliberate (an enumeration would drag the harness seeds into the verdict) and
  it is why §4.3 says only an external head-hash copy would catch that attack.
- **Payload:** `{checked, anchored, unanchored, problems, ok}` — the
  `floorpolicy.go` shape (`{checked, problems, ok}`, `floor_policy` idiom at
  `internal/audit/sections/floorpolicy.go:17-44`), with `checked` counting the
  anchor-carrying events examined and `unanchored` a separate informational
  list. **Counting rule, stated so no judgement call remains: `anchored` counts
  only digest-VERIFIED matches.** A problem row (mismatch, malformed anchor,
  missing record, unparseable record, disagreeing carriers) increments
  `checked` only — **never** `anchored`. `unanchored` is disjoint from
  `problems` by construction, and it is *not* a subset of `checked`: `checked`
  counts anchor-carrying events, and an unanchored event carries no anchor. §8.2
  pins these counts as concrete literals.
- **Two reachable states, decided here rather than left to the implementer:**

  **(a) A record that exists but fails to parse is a PROBLEM ROW, not an
  abort.** `validation.ReadJson` (`internal/validation/atomicio.go:15-21`)
  returns an error both when the file is missing and when its bytes do not
  parse, so the reader must separate the two: `os.Stat` first (missing ⇒ the
  "not on disk" row below), then `ReadJson` (error ⇒ *"EXEC-x: the
  sandbox.exec event anchors a record that cannot be parsed — the anchor cannot
  be verified"*). That is the same order the ingest gate already uses
  (`internal/findings/ingest_evidence_gate.go:97-104`: `os.Stat`, then
  `ReadJson`). Returning the error instead is rejected: `AuditCampaign`
  treats any non-`ErrSkip` error as fatal and aborts the entire report
  (`internal/audit/audit.go:88-91`), so one unreadable record would suppress
  every other section's verdict — an availability liability in the exact place
  the design wants a verdict. It is also the same shape `Execs` already uses for
  a deleted record (`internal/audit/sections/execs.go:18-22`), and it is the
  fail-closed answer the design asks for: the anchor is present but
  unverifiable, so the section reports it and `ok` goes false. This is
  **decided**, not deferred to §9.

  **(b) No carrier event at all, and disagreeing carriers.** `VerifyExecRecordAnchor`
  returns **nil** when the campaign holds no carrier event for the execID — the
  two seeding harnesses mint records with no event of their own, and fail-open
  is §4's decision — and nil when the carriers it holds carry no anchor key.
  When a ref *does* have anchored carriers, **no digest wins by precedence**: the
  section requires unanimity among the anchored carriers for one ref, so any
  disagreement between two anchored carriers is itself a problem row
  (*"EXEC-x: the sandbox.exec and sandbox.exec.registered events for this exec
  carry different digests (<sha-a> vs <sha-b>) — the carriers disagree about the
  record"*), and any disagreement with the record on disk is the mismatch row.
  On the mint side the predicate walks the ref's carrier events in log order and
  refuses at the first anchored carrier whose digest does not match the record,
  so the refusal is deterministic and never depends on map iteration.

### 5.1 The states

| state | `problems` | `ok` |
|---|---|---|
| **digest matches** — the record on disk recomputes to the event's digest | nothing; counted in `anchored` (and in `checked`) | true |
| **digest mismatches** — the stored value is not the record's digest. Two causes, one row: (i) the record was edited after the event, or (ii) the stored digest is malformed — not 64 lowercase hex, or not a string — and so can never match | *"EXEC-x: exec_record.json does not recompute to the digest the sandbox.exec event anchored (event <sha>, record <sha>) — the record was edited after the run, or the stored digest is not 64 lowercase hex; either way its declared exit/expectation cannot be trusted"* | **false** |
| **digest absent on a new-style event** — label present, digest missing; or digest present, label absent; or label not the pinned literal | *"EXEC-x: the sandbox.exec event names the anchor encoding but carries no digest"* / *"…carries a digest with no encoding label — an unlabelled canonical encoding is not evidence"* / *"…names anchor encoding <x>, not sha256-canon-spaced"* | **false** |
| **record file missing** while the event carries an anchor | *"EXEC-x: the sandbox.exec event anchors a record that is not on disk — the anchor cannot be verified"* | **false** |
| **record present but unparseable** while the event carries an anchor | *"EXEC-x: the sandbox.exec event anchors a record that cannot be parsed — the anchor cannot be verified"* (the whole audit is **not** aborted; see §5, state (a)) | **false** |
| **carriers disagree** — two anchored carrier events for one exec ref carry different digests | *"EXEC-x: the sandbox.exec and sandbox.exec.registered events for this exec carry different digests (<sha-a> vs <sha-b>) — the carriers disagree about the record"* (see §5, state (b)) | **false** |
| *(migration)* **no anchor keys at all** | nothing; listed in `unanchored` with the reason | true |

Every problem row (rows 2-6) leaves the event in `checked` but **not** in
`anchored` — `anchored` is digest-verified matches only (§5). The migration row
is in neither `checked` nor `anchored`: it is listed in `unanchored`.

The mismatch wording deliberately echoes the chain's own verdict style —
*"event_hash does not recompute (content edited?)"*
(`internal/state/verifylog.go:272-274`) — so the operator meets one vocabulary
for "content edited after the fact".

**One deliberate overlap, stated:** a deleted record is already a problem for
`Execs` (*"exec events whose record was deleted are a problem"*,
`internal/audit/sections/execs.go:18-22`, `execCheckEvents`). The anchor section
reports it again because an anchor with no record is *this* section's own
unverifiable claim. The two sections compute it independently and agree by
construction; a test asserts both fire (§8.2). A reviewer who prefers strict
de-duplication could instead have this section skip record-missing events and
count them in `unanchored` — that is the one place in this design where a
defensible alternative exists, and it is flagged rather than hidden.

### 5.2 Determinism

Events are iterated in log order; `problems` and `unanchored` are appended in
that order; no map iteration reaches the rendered payload; no clock, no ids.
This matters for verify-full step 5, which byte-diffs `go test -count=1` run
twice (§7.1).

---

## 6. §4.6 — DOES `exit_status` MOVE INTO THE EVENT?

**No.** Under the digest anchor it need not, and it should not:

- The digest covers the record's `exit_status` field like every other field, so
  the tamper-evident value of `exit_status` is the digest. Moving the value into
  the event as well would create a second copy that can disagree with the record
  — the field-carry objection of §2.2, applied to the field this task exists to
  close.
- The event already carries `exit` as a readability copy of the exec-time value
  (`internal/sandbox/exec.go:254`), and the record's `exit_status` is set from
  the same local variable one statement earlier (`exec.go:245`). The two agree
  by construction at write time, and after the anchor they cannot be made to
  disagree silently: editing the record breaks the digest; editing the event
  breaks the chain (`internal/state/verifylog.go:272`).

So the attack is closed end to end. The exact sequence the task describes —
run a suite that exits 0, then edit `exit_status: 7`, `expected_outcome: "fail"`
and `expected_failure` into the record and mint — now fails at both gates:

1. the audit section recomputes the record's digest, gets a different value, and
   reports a problem with `ok: false` (§5.1);
2. the mint/ingest gate, which already reads the record at
   `internal/findings/ingest_evidence_gate.go:101`, refuses with the digest
   mismatch *before* `checkExecExpectationShape` / `ValidateExecRecord` ever get
   to bless the hand-written expectation.

**Scope boundary, stated plainly:** under the fail-open recommendation this
protects records whose anchoring event was written by anchor-era code. A
pre-existing record (population (i)/(ii)) keeps its present, already-mintable
status; the anchor cannot retroactively constrain it (§4.2(4)).

---

## 7. §4.5 — BLAST RADIUS, ENUMERATED

### 7.1 `scripts/verify-full.sh` (14 steps)

| step | effect | why |
|---|---|---|
| **5** determinism (`go test -count=1` twice, byte-identical, `verify-full.sh:105-119`) | must stay green | the new tests must be deterministic: `t.TempDir()`, frozen record values, no real clock, no map-order iteration in a rendered payload (§5.2) |
| **7** golden (`scripts/golden.sh`, `check-golden.py`) | **edit required** | the P2 recipe runs real `exec` calls (`golden-run.py:1102-1128`), so the golden campaigns DO carry anchored events and the section renders. `check-golden.py` must add `exec_record_anchor` to `EXPECTED_SECTIONS` (appended last, `:42-59`) and to `OPTIONAL_SECTIONS` (`:65`, because campaigns that never exec skip it) |
| **9** legacy cross-audit (`:350-462`; the assertions this row cites live at `:358-374`) | renders, `ok: true`, **edit required** | the fixture has 2 unanchored `sandbox.exec` events → `unanchored: 2`, no problems, so `ok is True` (`:364-365`) and `audit PASS:` (`:360`) both hold. `p2_sections_ok "Go audit of legacy campaign"` (`:371`) must accept the rendered name (see below). No fixture byte changes |
| **11** P2 CLI smoke (`:540-666`) | renders, **edit required** | two real execs (`exec pass`, `exec fail`, `:580-581`) carry anchors that match; the seeded `SEEDEX` record has no event at all, so it is invisible to the section and `mint` still succeeds under fail-open. `p2_sections_ok "P2 smoke audit"` (`:633`) must accept the rendered name |
| **12** P3 CLI smoke (`:668-882`) | **renders**, **edit required** | step 12 DOES run a real exec — `p3_ok "exec pass" 0 exec "$CID3" --command "echo p3-smoke" --finding "$F1"` (`:708`) — so its campaign carries a `sandbox.exec` event and the section renders. The report becomes **17** sections (14 ported + `v16_coverage` + `price_table` + `exec_record_anchor`), **not 16**. The seeded `SEEDEX` record (`seed_p2_exec …`, `:710`) still has no event of its own and stays invisible to the section. `p2_sections_ok "P3 smoke audit"` (`:880`) must accept the rendered name, and the step's comment block (`:665-667`, "16 sections (15 unconditional + the presence-gated price_table…)") is now false |
| **13** runbook walkthrough (`:885-901`) | unchanged | no new verb, no new flag, no usage-text change (§7.3) |
| **14** entropy ratchet (`:902-985`) | unchanged | `.entropy-baseline.json` ratchets only `python/ruff` (195) and `python/ruff-format` (8). This change adds Go files and one `.md` — no ratcheted metric moves. (The pre-commit hook runs the same machinery; the same reasoning applies to the doc commit.) |

`p2_sections_ok` (`verify-full.sh:268-298`) needs a real edit, not just a comment:
its `gated = ["eval", "price_table"]` + `always = ["v16_coverage"]` projection
(`:280-287`) does not include a section registered after `v16_coverage`, and its
`extra` assertion (`:287`) hard-fails an unexpected name. The helper has **three
call sites, and all three render the new section**: step 9's legacy fixture
(`:371`, 2 `sandbox.exec` events), step 11 (`:633`), and step 12 (`:880`) — the
earlier text named only the first two. The minimal change is a
third tail list — `gated_tail = ["exec_record_anchor"]` — with
`proj = [n for n in want + gated + always + gated_tail if n in secs]` and
`extra` excluding it. That preserves the existing property (base rows and
registration order are hard failures; only the gated tail is optional) while
keeping `regression_suite`'s absence-from-the-list behaviour untouched.

Comments that carry now-false counts: `verify-full.sh:21` and `:51` ("all 15
rendered sections (17 registered)"), `:54` ("steps 9-11 … render exactly 15"),
`:249-267`, `:537` ("all 15 unconditional sections (17 registered)"),
`:665-667` (step 12's own block: "16 sections (15 unconditional + the
presence-gated price_table, priced above)"); and `p2-docker-e2e.sh:321`.

### 7.2 Other gate scripts

- `scripts/p2-docker-e2e.sh:329-331` asserts `len(secs) != 15` with a literal
  `want 15`. Its campaign runs execs, so it becomes **16**. The `!=` form means
  this is a hard failure, not a tolerance.
- `scripts/check-golden.py:14` and `:216` docstrings ("all 15 rendered
  sections"), `:32-40` (the registry comment says 17; the registry already
  carries 18), and `scripts/golden.sh:9` ("14 audit sections") — comment updates.
- `internal/audit/testdata/p1_audit_vectors.json` — **no edit**, because the
  section is presence-gated on exec events and those fixtures have none (verified:
  no `sandbox.exec` occurrence in the file). This is the reason the gate is
  "no exec events" rather than "no anchored events" (§5).

### 7.3 Byte-pinned CLI surfaces

| surface | effect |
|---|---|
| `webv2 execs`, `execs --json`, `execs --id` | **unchanged** — they read records via `state.AllExecs` (`internal/state/execs.go:37`), and the anchor is not on the record (§2) |
| `webv2 log` | **unchanged** — it prints only `seq / at / type / ref` (`internal/cli/cmd_log.go:63-67`); the new keys live inside `data` and are never rendered |
| `webv2 audit --json` | **the only output change**: one new section object |
| `webv2 audit` (text) | the summary line grows one token — `AuditSummaryLine` prints every section (`internal/audit/audit.go:115-132`). Step 9's check is prefix-anchored (`grep -q '^audit PASS:'`, `verify-full.sh:360`) so it survives; the problem lines print only for `problems`, so an unanchored event is **not** visible in the text audit (see §9) |
| help / usage text | **unchanged** — no new flag and no new verb. `execHelp` (`internal/cli/cmd_exec.go:58-90`) is byte-exact pinned and untouched; the command list is untouched. This is deliberate: a `--expect`-style flag was the alternative, and a flag would have moved the decision into the CLI contract instead of the record |

### 7.4 `assets/` and `scripts/sync-asset-manifest.py`

**Not run, and nothing under `assets/` moves.** The digest is event-side: the
record schema (`assets/schema/sandbox_execution.schema.json`) is unchanged and
keeps `additionalProperties: false`, no new schema is added (there is no event
schema to extend, §1.4), and no runbook text changes. `TestAssetPackManifest`
therefore stays green with no manifest regeneration.

### 7.5 Determinism pins

- No new entropy source. The digest is a pure function of the record's content;
  the implementation adds no `time.Now()` and no raw UUID, and it adds **no new
  record field at all** — the anchor is derived, not stamped.
- The existing seams stay the only pins: `WEBV2_NOW`
  (`internal/state/id.go:17-26`), `WEBV2_UUID` (`internal/state/id.go:40-51`),
  `ResetIDStream` (`internal/state/id.go:66`).
- Consequence for tests: a test must never assert a literal digest for a record
  carrying a real-clock `finished_at`. The frozen-vector test uses a fixed record
  value; the end-to-end test computes the expectation with the same helper (§8).

### 7.6 The ledger law

- **One hash-chained event per mutation.** The anchor adds no event: it rides the
  `sandbox.exec` event that already exists (`exec.go:257`) and the
  `sandbox.exec.registered` event that already exists
  (`register_exec.go:166`). A new key inside `data` is covered by the existing
  chain hash automatically (`internal/state/chain.go:16-19,35-50`) — no chain
  change, no rehash, and the committed fixture's stored `event_hash` values stay
  valid.
- **Projection unwind on log-write failure is unchanged.** `exec.go:257-273`
  restores the pre-write state when the ledger refuses: the exec dir is removed
  and the error says the command EXECUTED but its record was NOT KEPT. The digest
  is computed from the in-memory record before the `Log` call, so it cannot
  survive a refused log, and it can never exist without its event. The same holds
  for `register_exec.go:166-180`. **No new unwind obligation, and no new
  projection**: the anchor is not written to `campaign_state.json` (the mirror
  carries the event as-is, and only the last 1000 events at that).
- The refusal path (`sandbox.refused`, `exec.go:198`) is deliberately out of
  scope: nothing ran, and the record it writes carries no `exit_status`, so no
  evidence can cite it.

---

## 8. IMPLEMENTATION PLAN (no code written yet)

### 8.1 Ordered steps

1. **`internal/sandbox/exec_record_anchor.go` — the single definition.**
   - `const ExecRecordAnchorAlg = "sha256-canon-spaced"`
   - `const KeyExecRecordSHA256 = "exec_record_sha256"`,
     `KeyExecRecordSHA256Alg = "exec_record_sha256_alg"`
   - `func ExecRecordDigest(rec validation.Value) string` —
     `validation.Sha256Hex([]byte(validation.CanonSpaced(rec)))`
   - `func ExecRecordAnchorKVs(rec validation.Value) []validation.KV` — the two
     pairs, so both writers stamp an identical shape
   - `func EventAnchor(ev validation.Value) (digest, alg string, present bool)` —
     reads the two keys out of `data`; `present` is true when *either* is there
     (so a half-written anchor is detectable, not silently unanchored)
   - `var AnchorCarrierEventTypes = []string{"sandbox.exec", "sandbox.exec.registered"}`
   - `func VerifyExecRecordAnchor(c *state.Campaign, execID string,
     rec validation.Value) error` — the mint-side predicate; **`nil` when the
     campaign holds no carrier event for `execID`, and `nil` when the carriers it
     holds carry no anchor key** (fail-open, §4), an error naming both digests
     otherwise. With several anchored carriers for one ref it walks them in log
     order and refuses at the first mismatch — no digest wins by precedence, and
     a disagreement between carriers is itself a problem in the audit (§5).
     `internal/sandbox`
     already imports `internal/state` (`register_exec.go:9`) and already owns
     `LoadExec(c, ref)`, so the writer and the verifier live together — one
     implementation of one law, which is the house rule the ported sections state
     explicitly (`internal/audit/sections/events.go:18-20`).
2. **`internal/sandbox/exec.go:252-256`** — append `ExecRecordAnchorKVs(f.record)`
   to `data`. The record has just been written at `:248`; nothing else moves.
3. **`internal/sandbox/register_exec.go:160-165`** — the same append for
   `sandbox.exec.registered`.
4. **`internal/findings`** — call `sandbox.VerifyExecRecordAnchor` at both
   admission sites: `verifyExecReference` right after `validation.ReadJson(recPath)`
   (`ingest_evidence_gate.go:101-104`, so it precedes
   `checkExecExpectationShape` at `:126` and both `ValidateExecRecord` branches at
   `:130`), and `IngestExecRefEvidence` after its `ValidateExecRecord` call
   (`exec_evidence.go:454`). It cannot live inside `ValidateExecRecord`: that
   function's signature is `(execID string, rec validation.Value)`
   (`exec_evidence.go:164`) and has no campaign to read the ledger from.
5. **`internal/audit/sections/exec_record_anchor.go`** + `register("exec_record_anchor", …)`
   appended last in `register.go:52`.
6. **Update the five registry pins** (§8.3) **and the three report pins** (§8.3),
   plus the gate scripts (§7.1, §7.2).
7. **Run the offline checks**: `gofmt -l internal cmd`, `go vet ./internal/...`,
   and the three targeted packages — `go test ./internal/sandbox ./internal/findings ./internal/audit/...`
   — then verify-full's **steps 6-14**. Explicitly **not** `go test ./...` (it
   OOMs this machine) and **not** the docker tiers (`p2-docker-e2e.sh` needs a
   daemon; its count assertion is updated but not run here).
   - **Steps 3-5 of `verify-full.sh` are excluded here for exactly the same
     reason, and the script cannot be run as a whole on this machine.**
     `verify-full.sh` runs `go test ./...` at `:96` (step 3), `go test -race
     ./...` at `:101` (step 4) and `go test -count=1 ./...` twice at `:112-113`
     (step 5), so invoking it end-to-end contradicts the "not `go test ./...`"
     rule one line above. The instruction is therefore one of two things, stated
     so no implementer guesses: run the **whole** script on a machine where
     `./...` fits, **or** run steps 6-14 by hand here and record in the commit
     message that steps 3-5 were skipped for the OOM reason. The targeted
     package list above covers the new code either way; steps 6-14 are the ones
     this change actually moves.
8. **Commit** under the entropy hook (no ratcheted metric moves, §7.1 step 14).

### 8.2 Test plan (plain Go, same package, `t.TempDir()`, no Docker / network / model)

`internal/sandbox/exec_record_anchor_test.go` (package `sandbox`):

| test | proves |
|---|---|
| `TestExecRecordDigestIsCanonicalSpacedOverTheWholeRecord` | the digest equals `Sha256Hex(CanonSpaced(rec))` for a frozen record, and is 64 lowercase hex |
| `TestExecRecordDigestChangesWhenExitStatusChanges` | mutation: `exit_status` 0 → 7 changes the digest |
| `TestExecRecordDigestChangesWhenTheExpectationIsAdded` | **mutation check for the mint key** — adding `expected_outcome` / `expected_failure` changes the digest |
| `TestExecRecordDigestDistinguishesAbsentFromNull` | §3.2, in both directions |
| `TestExecRecordDigestRoundTripsThroughWriteJsonAndReadJson` | `WriteJson` → `ReadJson` → digest equality for a schema-valid record with a non-ASCII `command` |
| `TestExecRecordDigestNumberAndUnicodeRendering` | int/float rendering and `ensure_ascii` escaping, pinned as literals |
| `TestExecRecordAnchorIsNotOnTheRecord` | the record carries neither key, and still validates against `sandbox_execution` |

`internal/sandbox/exec_anchor_event_test.go`:

| test | proves |
|---|---|
| `TestRunStampsTheRecordAnchorOnTheExecEvent` | host-profile `sb.Run("echo ANCHOR", RunOpts{Timeout: 5})` (offline precedent: `internal/sandbox/zz_r39_test.go:115`) — the event's digest equals `ExecRecordDigest` of the record on disk |
| `TestRegisterExecStampsTheRecordAnchorOnTheRegisteredEvent` | the second writer, same shape |
| `TestTheAnchorSurvivesACampaignCopy` | copy `execs/<id>/` + `events.jsonl` to a second root (`t.TempDir()`); the digest still recomputes (§3.1 root independence) |

`internal/findings/exec_record_anchor_gate_test.go`:

| test | proves |
|---|---|
| **`TestMintRefusesAnExecRecordEditedAfterTheEvent`** | **the bite test.** Write an honest exit-0 record, log the `sandbox.exec` event carrying its digest, then rewrite the record with `exit_status: 7` + `expected_outcome: "fail"` + `expected_failure` and a stdout.log carrying a `[FAIL]` line with that signature. Assert: (i) `ValidateExecRecord` alone *accepts* the edited record — i.e. the pre-anchor gate genuinely cannot tell, which is the whole point; (ii) the anchor check refuses, and the error names both digests; (iii) the admission path (`verifyExecReference` / `IngestExecRefEvidence`) refuses. **Mutation check:** the test must go green→red if the anchor call is removed from step 4 — verified by removing it once and watching (ii)/(iii) fail, so the test cannot pass for the wrong reason |
| `TestAnUnanchoredLegacyRecordStillMints` | the fail-open decision is pinned, not accidental: an unanchored event admits exactly as today |
| `TestAMalformedAnchorRefuses` | digest-without-label, label-without-digest, unknown label, and a **malformed digest value** (not 64 lowercase hex — e.g. uppercase, short, and a non-string) — all refused (§3.3) |
| `TestSeveralCarrierEventsMustAgree` | §5 state (b): one exec ref carrying a `sandbox.exec` and a `sandbox.exec.registered` event with **different** digests is refused at mint (at the first mismatch, in log order), and `nil` is returned when the ref has no carrier event at all |
| `TestAnUnparseableRecordRefuses` | §5 state (a): an anchored event whose record exists but is not parseable is refused at mint, and the audit reports it as a problem row rather than aborting the whole report |

`internal/audit/sections/exec_record_anchor_test.go` (package `sections`):

| test | proves |
|---|---|
| `TestExecRecordAnchorReportsAMatch` | the happy path, `ok: true`, `anchored: 1` |
| `TestExecRecordAnchorReportsDrift` | hand-edit the record after the event → `ok: false`, the drift problem, and the **concrete counts**: `checked: 1`, `anchored: 0`, `unanchored: []`, `problems: 1` — i.e. a problem row counts in `checked` only, never in `anchored` (§5) |
| `TestExecRecordAnchorReportsANewStyleEventWithoutADigest` | §5.1 row 3, `checked: 1`, `anchored: 0`, `problems: 1` |
| `TestExecRecordAnchorReportsAMissingRecord` | §5.1 row 4, and that `Execs` reports the deletion too (§5.1 overlap); `checked: 1`, `anchored: 0` |
| `TestExecRecordAnchorReportsAnUnparseableRecord` | §5 state (a): the report is still produced (no abort), `checked: 1`, `anchored: 0`, `problems: 1` |
| `TestExecRecordAnchorReportsDisagreeingCarriers` | §5 state (b): two anchored carriers for one ref with different digests → `problems: 1`, `anchored: 0` |
| `TestExecRecordAnchorCountsOnlyVerifiedMatches` | the counting rule of §5 directly: a campaign with one verified match and one drifted record reports `checked: 2`, `anchored: 1`, `problems: 1` |
| `TestExecRecordAnchorTreatsAnUnanchoredEventAsACoverageFact` | `ok: true`, `unanchored: 1` — the step-9 property, unit-tested |
| `TestExecRecordAnchorSkipsACampaignWithNoExecEvents` | the `ErrSkip` gate |
| `TestExecRecordAnchorIsDeterministic` | audit twice, byte-identical payload (§5.2, step 5) |

### 8.3 The five registry pins to update

1. `internal/audit/sections/register.go:52` — append the registration.
2. `internal/audit/audit_test.go:85-87` — `len(n) != 18` → `19`, plus the new
   `n[18]` assertion.
3. `internal/audit/audit_test.go:472-481` — append `"exec_record_anchor"` to the
   pinned `want` list.
4. `internal/audit/sections/eval_test.go:262-275` — the tail-order assertion
   (the `if` is at `:270-274`): `regression_suite` is no longer last;
   `exec_record_anchor` is.
5. `internal/audit/p1_sections_test.go:269-281` — append
   `"exec_record_anchor"` after `"regression_suite"` in `withAppended`
   (`:279-280`).

**The three report pins (§1.6) — not registry pins, and the easiest to miss.**
They count *rendered* sections, not registered ones, and they stay green only
because their campaigns contain no exec events:

6. `internal/cli/cli_test.go:161` — `len(secs) != 15` in `TestAuditClean`. Its
   campaign is a bare `init` (`:39-53`), so no `sandbox.exec` event exists and
   the section skips. **No edit needed today**; the comment above it (`:159-160`)
   is what must not silently rot.
7. `internal/audit/eval_gate_test.go:76` — `len(got) != 15` in
   `TestEvalAbsentWithoutMatch`. `gateCampaign` (`:41-54`) only ingests
   hypotheses. **No edit needed today.**
8. `internal/audit/audit_test.go:104-110` — the exact 15-name report list in
   `TestAuditCleanCampaignPasses`, over a bare `initCampaign`
   (`:51-59`). **No edit needed today.**

All three are **load-bearing on the no-exec-events fact**, so they are listed
here rather than left implicit: a fixture that starts executing will fail one of
them, and the fix is to move the count, never to relax the assertion.

Plus the gate scripts in §7.1/§7.2. Note that `check-golden.py`'s
`EXPECTED_SECTIONS` is explicitly *not* a copy of the registry
(`check-golden.py:40-41`) — it gains the new name only because the golden
campaigns render it.

---

## 9. QUESTIONS THE SCOPE CANNOT SETTLE WITHOUT THE HUMAN

Three questions remain. Everything else this document previously left ambiguous
is now resolved in the text, and the resolutions are listed after the questions
so they are visible rather than buried.

1. **Strictness policy for unanchored events.** This scope recommends
   fail-open, permanently, for pre-anchor state (§4.2, §4.4) — the alternative is
   technically implementable only as a campaign-era rule keyed on **the presence
   of either anchor key** (§4; the marker predicate has one reading, and an
   unlabelled digest is *refused*, not fail-open), and it would still have to
   exempt the frozen fixture and the two seeding harnesses. Confirm that
   "unanchored never gates" is the intended posture, or name the condition under
   which it should flip.
2. **Whether to close the event-deletion residual, and how.** §4.3 now states
   the residual exactly: truncating the anchoring line is **caught** today by the
   `campaign_state.json` mirror check (`internal/state/verifylog.go:335-352`), so
   the attack that slips through must edit **both** `events.jsonl` (recomputing
   the surviving events' hashes) **and** the mirror — and because this section's
   reader is event-driven by design (§5), an exec whose carrier event is deleted
   produces **no row at all**. The `unanchored` count bounds **key-stripping
   only**. **Only an external copy of the head hash (or of the mirror) catches
   the residual**, because the in-tree ledger has no such pin
   (`internal/state/chain.go:7-8`). The question for the human is whether adding
   that external pin — a committed head-hash file, or a mirror copy outside the
   campaign dir — is in scope for v1.6 or a later task. This scope does not
   assume either answer, and does not pretend the anchor closes it.
3. **Text-audit visibility of coverage.** `webv2 audit` prints only `problems`
   (`internal/cli/cmd_audit.go:62-67`) and a per-section problem count
   (`internal/audit/audit.go:115-132`), so the `unanchored` count is visible only
   in `audit --json`. Option (a) leave it JSON-only (recommended: no byte-pinned
   text surface moves); option (b) surface it in the text audit as a WARN, which
   would make the legacy fixture's text audit carry a WARN line while still
   exiting PASS. This is a reader-experience call, not an integrity one.

**Decided by the operator (2026-09-21), recorded so the questions above are not
re-opened:**

- **Q1 — fail-open stands, permanently.** "Unanchored never gates" is the
  intended posture, exactly as §4.2/§4.4 recommend.
- **Q2 — the residual is ACCEPTED and documented, not closed.** See the named
  residual at the end of §4.3. No external head pin is added in v1.6.
- **Q3 — option (b), as an ADVISORY, never a WARN.** The count is surfaced in
  the text audit (`webv2 audit`), on a channel that **cannot** count as a
  problem: the audit grew a non-problem advisory channel
  (`audit.AuditAdvisories` → `note:` lines on stderr, `internal/cli/cmd_audit.go`)
  rather than a WARN row, because the frozen fixture's two unanchored events
  would otherwise turn `scripts/verify-full.sh` step 9 red by construction.

**Resolved here, not open — recorded so a reader does not re-litigate them:**

- **The migration marker.** The marker is the presence of **either** anchor
  key, and `{digest present, label absent}` is **refused**. §2.3, §4, §4.1,
  §4.4, §5.1, §8.1 and §8.2 all state that one predicate. There is no
  fail-open reading of an unlabelled digest; the earlier text's two-reading
  contradiction is gone.
- **An unparseable record.** A **problem row**, not an abort — §5 state
  (a) gives the reason (`AuditCampaign` aborts the whole report on any
  non-`ErrSkip` error, `internal/audit/audit.go:88-91`).
- **No carrier event / disagreeing carriers.** `VerifyExecRecordAnchor`
  returns **nil** with no carrier event; several anchored carriers must agree, and
  disagreement is a problem row — §5 state (b).
- **`anchored` counts only digest-verified matches.** A problem row counts
  in `checked` only — §5, and §8.2 pins the counts as literals.

// artifacts_citation.go: the ONE cite predicate (ArtifactCitedByLiveBinds),
// its content/identity arms, and the per-event cite helpers.
package state

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"websec/internal/validation"
)

// --- the ONE cite predicate ------------------------------------------------
//
// r35 F1: a live bind's evidence names a registry ROW in two shapes, and the
// r34 ghost-prune saw only the first:
//
//   - by CONTENT: the row's sha256 is what a live harness_run event pins as
//     its report bytes, or what an exec record that event names hashes as the
//     bytes the run took in (input_hashes) or produced (artifact_hashes);
//   - by IDENTITY: the row's artifact_id is named outright, where byte
//     equality cannot look — a harness_scaffold event's `ref` (the scaffold a
//     live bind re-reads: audit/sections/invariantverification.go:544 and 582,
//     cli/cmd_verify_harness.go:627), an invariant.verified / linked_test /
//     contradicted event's payload, the invariants registry's `verified_by` /
//     `tests` / `contradiction` fields (invariants/guard.go:109 and 124,
//     invariants/invariants.go:503, 689, 721), and a finding's evidence /
//     repro-attempt `artifact_id` (risk/risk.go:786 — E7 must cite a
//     registered artifact — findings/assumptions.go:158).
//
// Byte equality cannot see the second shape at all, which is how retiring a
// same-path ghost turned section 11's rung UNBACKED FOREVER: the log is
// append-only and the ids are uuid-random, so an id the evidence still names
// can never be minted again (re-running `verify --scaffold` prints "unchanged"
// and writes no second event; re-binding refuses "the scaffold artifact … is
// not registered").
//
// Every arm is answered from the campaign's OWN sources: the event log
// (Campaign.Events), the invariants registry (artifacts/invariant_links.json),
// the findings store (findings/F-*.json) and the exec ledger (AllExecs). An
// arm whose source cannot be READ returns an error, never a silent false — a
// check that cannot read its sources is not a clearance to destroy, so the
// callers report the unreadable source instead of pruning on it.

// ArtifactCitedByLiveBinds is the ONE cite predicate: does any live evidence
// in this campaign still name the registry row id? `why` names the exact
// citation that holds it ("harness_scaffold event 12 refs this row as INV-1's
// minicertora scaffold"), because the caller prints it; it is "" when the row
// is uncited. An id no registry row carries is uncited by definition — the
// row is already gone, so there is nothing left for the evidence to name.
func ArtifactCitedByLiveBinds(c *Campaign, id string) (bool, string, error) {
	if c == nil || id == "" {
		return false, "", nil
	}
	st, err := c.State()
	if err != nil {
		return false, "", err
	}
	row := validation.VNull()
	for _, a := range validation.ObjAt(st, "artifacts").A {
		if validation.ObjStr(a, "artifact_id") == id {
			row = a
			break
		}
	}
	if row.Kind != validation.Obj {
		return false, "", nil
	}
	events, err := c.Events()
	if err != nil {
		return false, "", err
	}
	// Every arm is consulted and EVERY citation is reported: a row can be
	// named both by its bytes and by its id (a scaffold row is), and the
	// operator reading the warning is entitled to the whole reason — an
	// early return on the first hit hid the id-citation that makes the row
	// unretirable (r35 F1).
	var whys []string
	cited, why, err := artifactShaCitedRow(c, events, validation.ObjStr(row, "sha256"))
	if err != nil {
		return false, "", err
	}
	if cited {
		whys = append(whys, why)
	}
	cited, why, err = artifactIDCitedByEvents(events, id)
	if err != nil {
		return false, "", err
	}
	if cited {
		whys = append(whys, why)
	}
	cited, why, err = artifactIDCitedByRegistry(c, id)
	if err != nil {
		return false, "", err
	}
	if cited {
		whys = append(whys, why)
	}
	if len(whys) == 0 {
		return false, "", nil
	}
	return true, strings.Join(whys, "; "), nil
}

// artifactShaCitedRow is the CONTENT half of the predicate: the two arms the
// cli's cite-guard and prune warning used (r25/r28/N1), moved here so the
// decision has one home.
func artifactShaCitedRow(c *Campaign, events []validation.Value,
	dig string) (bool, string, error) {
	if dig == "" {
		return false, "", nil
	}
	pins, err := ArtifactCitedExecIDs(events, c, dig)
	if err != nil {
		return false, "", err
	}
	for _, ev := range events {
		if validation.ObjStr(ev, "type") != "harness_run" {
			continue
		}
		d := validation.ObjAt(ev, "data")
		if !ArtifactEventCitesDig(d, dig, pins) {
			continue
		}
		iid := validation.ObjStr(d, "invariant")
		if iid == "" {
			iid = "an invariant the event does not name"
		}
		if validation.ObjStr(d, "report_sha256") == dig {
			return true, fmt.Sprintf("harness_run event %s for %s pins this "+
				"row's sha256 as its report bytes", eventSeq(ev), iid), nil
		}
		return true, fmt.Sprintf("harness_run event %s for %s names exec %s, "+
			"whose record pins this row's sha256 as the bytes the run took in",
			eventSeq(ev), iid, validation.ObjStr(d, "exec")), nil
	}
	return false, "", nil
}

// artifactIDCitedByEvents is the IDENTITY half's log arm: the events that
// name a registry row id as evidence.
//
// artifact.registered / artifact.refreshed / artifact.pruned are deliberately
// NOT arms: their `ref` is the row's OWN id (a registration names the row it
// mints, a prune names the row it retires), so reading them as citations
// would make every row unprunable and the cite predicate vacuous.
func artifactIDCitedByEvents(events []validation.Value, id string) (bool,
	string, error) {
	for _, ev := range events {
		d := validation.ObjAt(ev, "data")
		switch validation.ObjStr(ev, "type") {
		case "harness_scaffold":
			if validation.ObjStr(ev, "ref") != id || !scaffoldRefIsLive(events, d) {
				continue
			}
			label, kind := validation.ObjStr(d, "artifact_id"), validation.ObjStr(d, "kind")
			if label == "" {
				label = "an unnamed scaffold"
			}
			if kind == "" {
				kind = "unstated-kind"
			}
			return true, fmt.Sprintf("harness_scaffold event %s refs this row "+
				"as %s's %s scaffold, which the live harness_run bind for %s "+
				"re-reads", eventSeq(ev), label, kind,
				validation.ObjStr(d, "invariant")), nil
		case "invariant.verified":
			if validation.ObjStr(d, "artifact") == id {
				return true, fmt.Sprintf("invariant.verified event %s binds "+
					"this row to %s as its CHECKED_AGAINST_CODE artifact",
					eventSeq(ev), validation.ObjStr(ev, "ref")), nil
			}
		case "invariant.linked_test":
			if validation.ObjStr(d, "artifact") == id {
				return true, fmt.Sprintf("invariant.linked_test event %s "+
					"registers this row as a test artifact of %s",
					eventSeq(ev), validation.ObjStr(ev, "ref")), nil
			}
		case "invariant.contradicted":
			if validation.ObjStr(d, "evidence") == id {
				return true, fmt.Sprintf("invariant.contradicted event %s "+
					"names this row as %s's contradiction anchor",
					eventSeq(ev), validation.ObjStr(ev, "ref")), nil
			}
		case "finding.impact_quantified":
			if validation.ObjStr(d, "artifact_id") == id {
				return true, fmt.Sprintf("finding.impact_quantified event %s "+
					"names this row as the artifact quantifying %s",
					eventSeq(ev), validation.ObjStr(ev, "ref")), nil
			}
		}
	}
	return false, "", nil
}

// scaffoldRefIsLive: a harness_scaffold event's `ref` is a LIVE citation only
// when a harness_run bind exists that re-reads that scaffold. The readers
// (audit/sections/invariantverification.go's harnessScaffoldArtifactBytes,
// cli.harnessScaffoldBytes) resolve HARNESS-<invariant>-<kind> off the latest
// harness_scaffold event, and the audit asks them ONLY while re-deriving an
// invariant's landed harness slot (InvariantVerification calls
// harnessEvidenceRecheck under harnessRunLine's `ok` arm), so a scaffold no
// bind re-reads is not evidence any reader consults. The gate is the bind's
// own identity: a harness_run event for the same invariant and — when the
// event states one — the same kind (a report-kind bind re-reads the report
// row, never a scaffold).
//
// Pinned by TestR35CiteScaffoldRefNeedsALiveBind (state) and, on the verb
// side, by cmd_artifact_prune_test.go's TestR28ExecCitationNeedsALiveEvent:
// a scaffold event alone must not make a row unretirable.
func scaffoldRefIsLive(events []validation.Value, scaffold validation.Value) bool {
	iid := validation.ObjStr(scaffold, "invariant")
	if iid == "" {
		return false
	}
	kind := validation.ObjStr(scaffold, "kind")
	for _, ev := range events {
		if validation.ObjStr(ev, "type") != "harness_run" {
			continue
		}
		d := validation.ObjAt(ev, "data")
		if validation.ObjStr(d, "invariant") != iid {
			continue
		}
		if evKind := validation.ObjStr(d, "kind"); evKind == "" || kind == "" ||
			evKind == kind {
			return true
		}
	}
	return false
}

// artifactIDCitedByRegistry is the IDENTITY half's store arm: the two
// id-keyed stores that are not the event log.
func artifactIDCitedByRegistry(c *Campaign, id string) (bool, string, error) {
	links, err := citationLinks(c)
	if err != nil {
		return false, "", err
	}
	for _, entry := range validation.ObjAt(links, "invariants").O {
		iid, e := entry.K, entry.V
		if e.Kind != validation.Obj {
			continue
		}
		if validation.ObjStr(e, "verified_by") == id {
			return true, fmt.Sprintf("%s links this row as its verified_by "+
				"artifact (CHECKED_AGAINST_CODE)", iid), nil
		}
		if validation.ObjStr(e, "contradiction") == id {
			return true, fmt.Sprintf("%s names this row as its "+
				"contradiction anchor", iid), nil
		}
		if arrHasStr(validation.ObjAt(e, "tests"), id) {
			return true, fmt.Sprintf("%s lists this row among its test "+
				"artifacts", iid), nil
		}
	}
	findings, err := citationFindings(c)
	if err != nil {
		return false, "", err
	}
	for _, f := range findings {
		fid := validation.ObjStr(f, "finding_id")
		for _, item := range validation.ObjAt(f, "evidence").A {
			if validation.ObjStr(item, "artifact_id") != id {
				continue
			}
			what := validation.ObjStr(item, "evidence_id")
			if what == "" {
				what = "an unnamed item"
			}
			return true, fmt.Sprintf("finding %s evidence %s names this row "+
				"as its artifact_id", fid, what), nil
		}
		attempts := validation.ObjAt(validation.ObjAt(validation.ObjAt(f, "verification"), "reproduction"),
			"attempts")
		for _, a := range attempts.A {
			if validation.ObjStr(a, "artifact_id") != id {
				continue
			}
			what := validation.ObjStr(a, "attempt_id")
			if what == "" {
				what = "an unnamed attempt"
			}
			return true, fmt.Sprintf("finding %s reproduction attempt %s "+
				"names this row as its artifact_id", fid, what), nil
		}
	}
	return false, "", nil
}

// citationLinks reads the invariants registry STRAIGHT OFF DISK. The citation
// fields are stored verbatim, and the package's own reader
// (invariants.LoadLinks) runs the legacy migration — which REWRITES the
// registry and logs invariant.migrated. A read-only predicate must not mutate
// the campaign it is asked about. A missing file is the empty registry; an
// unreadable one is an error the caller must not read as "uncited".
func citationLinks(c *Campaign) (validation.Value, error) {
	p := filepath.Join(c.ArtifactsDir, "invariant_links.json")
	raw, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return validation.VNull(), nil
	}
	if err != nil {
		return validation.VNull(), fmt.Errorf("the invariants registry %s "+
			"cannot be read: %v", p, err)
	}
	links, perr := validation.ParseOrdered(raw)
	if perr != nil {
		return validation.VNull(), fmt.Errorf("the invariants registry %s "+
			"does not parse (%v) — its citations cannot be checked", p, perr)
	}
	return links, nil
}

// citationFindings reads the findings store (findings/F-*.json, the layout
// findings.storage uses). A missing store is no findings; a store that cannot
// be listed or a file that cannot be read is an error, never "no citations".
//
// r43a: the same distinction is now expressed by the listing helper itself
// (ListPrefixedOptional folds ONLY IsNotExist into emptiness), so this reader
// no longer pre-stat's the directory — one read, one place the decision is
// made.
func citationFindings(c *Campaign) ([]validation.Value, error) {
	paths, err := validation.ListPrefixedOptional(c.FindingsDir, "F-", ".json")
	if err != nil {
		return nil, fmt.Errorf("the findings store %s cannot be listed: %v",
			c.FindingsDir, err)
	}
	var out []validation.Value
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("the finding %s cannot be read: %v", p, err)
		}
		f, perr := validation.ParseOrdered(raw)
		if perr != nil {
			return nil, fmt.Errorf("the finding %s does not parse (%v) — its "+
				"citations cannot be checked", p, perr)
		}
		out = append(out, f)
	}
	return out, nil
}

// arrHasStr is membership for a string array read off disk (a non-array or a
// non-string element contributes nothing).
func arrHasStr(v validation.Value, want string) bool {
	for _, e := range v.A {
		if e.Kind == validation.Str && e.S == want {
			return true
		}
	}
	return false
}

// eventSeq renders an event's seq for citation messages ("?" when a
// hand-written line carries none).
func eventSeq(ev validation.Value) string {
	if s := validation.ObjAt(ev, "seq"); s.Kind == validation.Int {
		return strconv.FormatInt(s.I, 10)
	}
	return "?"
}

// ArtifactEventCitesDig is THE per-event cite predicate, one home for every
// caller (the bind's cite-guard, the ghost-prune, the prune verb's warning). A
// live harness_run event cites dig when EITHER
//
//   - its own data.report_sha256 IS dig — the report-bound rungs (miniprover
//     autoprove, minicertora report binds), whose event names the exact bytes
//     it mapped; OR
//   - it names an exec (data.exec) whose recorded exec pins dig in
//     input_hashes / artifact_hashes — the EXEC rungs, whose evidence is the
//     scaffold file the sandbox hashed as the run's input (N1: the scaffold
//     artifact row was prunable with an EMPTY stderr, because the scan saw
//     only report_sha256, while the usage line and the RUNBOOK both promise
//     the warning whenever a live bind cites the row).
func ArtifactEventCitesDig(d validation.Value, dig string,
	citedExecs map[string]bool) bool {
	if dig == "" {
		return false
	}
	if validation.ObjStr(d, "report_sha256") == dig {
		return true
	}
	id := validation.ObjStr(d, "exec")
	return id != "" && citedExecs[id]
}

// ArtifactCitedExecIDs is the second CONTENT arm's resolution: the exec ids
// that a live harness_run event names AND whose exec record pins dig. It is a
// local re-read of the harness bind's hash reader (cli.harnessRecordedHashes,
// owned elsewhere): the same two maps, the same "non-empty string VALUE is a
// hash" rule — re-read here so the prune verb agrees with the bind instead of
// holding a second opinion about what the bind recorded.
//
// "Live" is the same notion the report arm already used: every harness_run
// event on the append-only ledger (nothing removes one; a superseded bind is
// still a bind the audit re-derives). Reading an extra event as cited burns
// nothing — it only makes the warning more conservative.
func ArtifactCitedExecIDs(events []validation.Value, c *Campaign,
	dig string) (map[string]bool, error) {
	if dig == "" {
		return nil, nil
	}
	named := map[string]bool{}
	for _, ev := range events {
		if validation.ObjStr(ev, "type") != "harness_run" {
			continue
		}
		if id := validation.ObjStr(validation.ObjAt(ev, "data"), "exec"); id != "" {
			named[id] = true
		}
	}
	if len(named) == 0 {
		return nil, nil
	}
	execs, err := AllExecs(c)
	if err != nil {
		return nil, err
	}
	pins := map[string]bool{}
	for _, rec := range execs {
		id := validation.ObjStr(rec, "exec_id")
		if named[id] && artifactExecPins(rec, dig) {
			pins[id] = true
		}
	}
	return pins, nil
}

// artifactExecPins: does one exec record pin dig among the bytes the run took
// in (input_hashes) or produced (artifact_hashes)? The record maps a file NAME
// to a sha256 STRING; only non-empty strings are hashes, so a
// null/absent/scalar map contributes nothing (same filter as the bind's
// reader).
func artifactExecPins(rec validation.Value, dig string) bool {
	if dig == "" {
		return false
	}
	for _, key := range []string{"input_hashes", "artifact_hashes"} {
		m := validation.ObjAt(rec, key)
		if m.Kind != validation.Obj {
			continue
		}
		for _, kv := range m.O {
			if kv.V.Kind == validation.Str && kv.V.S == dig {
				return true
			}
		}
	}
	return false
}

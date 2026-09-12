package cli

// cmd_verify_harness: `webv2 verify <campaign> --harness-result INV-id
// --exec EXEC-... [--kind halmos|forge-fuzz|minicertora]` (Task 18, G8) —
// land one harness run's rung on its invariant as verification.harness.
//
// There is deliberately NO auto-detect hook: a stray halmos run must never
// be attributed to an invariant by guesswork, so attribution is always an
// explicit operator act (both ids on the command line). The flow:
//
//  1. load the EXEC record (execs/EXEC-*/exec_record.json) and read its
//     stdout file (stdout_path, resolved relative to the exec dir when
//     relative; read capped at 1MB);
//  2. resolve the kind: --kind, else the scaffold artifact id
//     HARNESS-<INV>-<kind> from the harness_scaffold events (ambiguous
//     when both skeletons exist — then --kind is required);
//  3. load the scaffold ARTIFACT bytes T17 wrote (harness_scaffold event
//     ref -> registered artifact -> file) and bind the run to them
//     (Decision 2b): a recorded hash equal to the scaffold sha binds the
//     run; a harness-named hash entry with a different sha is a
//     scaffold-bound violation (rung inconclusive, the output is NOT
//     used); no hash info maps normally with an "(unbound: ...)" suffix;
//  4. map the stdout to a rung: an untimed minicertora run through
//     MapMinicertora(raw, exit_status, MspecRuleName(inv)) — which also
//     captures the proof sidecar for every attributed verdict line
//     (UNKNOWN included) — and every other run through
//     MapRun(kind, stdout, timedOut, k). Write verification.harness
//     {kind, rung, exec, bounded_k, summary[, proof]} onto the invariant
//     entry (the existing invariant_links.json store — no parallel store)
//     and log a harness_run {rung, exec, invariant, summary} audit event.
//
// What this path does NOT do (rails): it appends no evidence items to
// findings (mint's E4 gate does not accept host profiles — promotion
// rides triage reading the rung), and it queues no learning memory:
// invariant entries carry no intent-claim marker (their kind/source axes
// are security|...|liveness and documented|model; intent claims live in
// the separate IntentClaims view), so per the controller there is nothing
// to record — the rung field plus the harness_run event are the complete
// record.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"websec/internal/harness"
	"websec/internal/invariants"
	"websec/internal/state"
	"websec/internal/validation"
)

// harnessStdoutCap is the 1MB read cap on exec stdout files.
const harnessStdoutCap = 1 << 20

// verifyHarnessResult is cmd_verify's --harness-result branch.
func verifyHarnessResult(c *state.Campaign, a *verifyArgs, r *Runner) error {
	if a.execID == "" {
		return t14ExitErr(2,
			"verify --harness-result needs --exec EXEC-...\n")
	}
	links, err := invariants.LoadLinks(c)
	if err != nil {
		return err
	}
	entry, found := harnessInvEntry(links, a.harnessResult)
	if !found {
		return t14ExitErr(2, "verify: unknown invariant %s\n",
			validation.PyReprStr(a.harnessResult))
	}
	kind, err := harnessKindFor(c, a.harnessResult, a.kind)
	if err != nil {
		return err
	}
	rec, execDir, err := harnessExecRecord(c, a.execID)
	if err != nil {
		return err
	}
	raw, err := harnessExecStdout(execDir, rec)
	if err != nil {
		return err
	}
	scaffold, err := harnessScaffoldBytes(c, a.harnessResult, kind)
	if err != nil {
		return err
	}
	timedOut := harnessTimedOut(rec)
	// The minicertora mapper is exit-status aware: an int exit_status is
	// the run's own report, anything else (absent/null/big) is "unknown"
	// (-2), and MapMinicertora's negative floor refuses it — a run that
	// never reported a clean exit is never promoted. timedOut only covers
	// -1, so -2 is the fail-open remainder.
	exitStatus := -2
	if v := objAt(rec, "exit_status"); v.Kind == validation.Int &&
		v.Big == "" {
		exitStatus = int(v.I)
	}
	k := invocationBound(harnessCommand(rec), kind)
	ruleName := harness.MspecRuleName(a.harnessResult)
	rung, summary, proof, boundedK := harnessMapBound(kind, raw, rec,
		scaffold, timedOut, k, exitStatus, ruleName)
	entry.O = validation.SetOrAppend(entry.O, "verification",
		validation.VObj(harnessField(kind, rung, a.execID, boundedK,
			summary, proof)))
	if err := harnessSaveEntry(c, links, a.harnessResult, entry); err != nil {
		return err
	}
	data := validation.VObj(
		validation.KV{K: "rung", V: validation.VStr(rung)},
		validation.KV{K: "exec", V: validation.VStr(a.execID)},
		validation.KV{K: "invariant", V: validation.VStr(a.harnessResult)},
		validation.KV{K: "summary", V: validation.VStr(summary)},
	)
	if _, err := c.Log("harness_run", &a.harnessResult, &data); err != nil {
		return err
	}
	if rung == harness.RungProvedBounded {
		fmt.Fprintf(r.Out, "%s: %s (%s, k=%d, %s)\n", a.harnessResult,
			rung, string(kind), *boundedK, a.execID)
	} else {
		fmt.Fprintf(r.Out, "%s: %s (%s, %s)\n", a.harnessResult, rung,
			string(kind), a.execID)
	}
	return nil
}

// harnessField builds the verification.harness object in the brief's key
// order (kind, rung, exec, bounded_k int-or-null, summary, proof). The
// proof key rides ONLY when a sidecar object exists (an attributed
// minicertora line): every other kind — and every unattributed minicertora
// refusal — omits the key entirely rather than writing null.
func harnessField(kind harness.Kind, rung, exec string,
	boundedK *int, summary string, proof validation.Value) validation.KV {
	var bk validation.Value = validation.VNull()
	if boundedK != nil {
		bk = validation.VInt(int64(*boundedK))
	}
	kvs := []validation.KV{
		{K: "kind", V: validation.VStr(string(kind))},
		{K: "rung", V: validation.VStr(rung)},
		{K: "exec", V: validation.VStr(exec)},
		{K: "bounded_k", V: bk},
		{K: "summary", V: validation.VStr(summary)},
	}
	if proof.Kind == validation.Obj {
		kvs = append(kvs, validation.KV{K: "proof", V: proof})
	}
	return validation.KV{K: "harness", V: validation.VObj(kvs...)}
}

// harnessInvEntry is links["invariants"][invID] with presence.
func harnessInvEntry(links validation.Value, invID string) (validation.Value,
	bool) {
	if reg := objAt(links, "invariants"); reg.Kind == validation.Obj {
		for _, kv := range reg.O {
			if kv.K == invID {
				return kv.V, true
			}
		}
	}
	return validation.VNull(), false
}

// harnessSaveEntry writes one entry back through the links store.
func harnessSaveEntry(c *state.Campaign, links validation.Value, invID string,
	entry validation.Value) error {
	reg := objAt(links, "invariants")
	reg.O = validation.SetOrAppend(reg.O, invID, entry)
	links.O = validation.SetOrAppend(links.O, "invariants", reg)
	_, err := invariants.SaveLinks(c, links)
	return err
}

// harnessKindFor resolves the harness kind: --kind wins; otherwise the
// scaffold artifact id HARNESS-<INV>-<kind> read off the harness_scaffold
// events. Zero scaffolds (or two, one per skeleton) without --kind is
// exit 2 — the operator disambiguates, the tool never guesses.
func harnessKindFor(c *state.Campaign, invID, flag string) (harness.Kind,
	error) {
	if flag != "" {
		return harness.Kind(flag), nil
	}
	events, err := c.Events()
	if err != nil {
		return "", err
	}
	prefix := "HARNESS-" + invID + "-"
	var kinds []string
	for _, ev := range events {
		if objStr(objAt(ev, "data"), "artifact_id") == "" ||
			objStr(ev, "type") != "harness_scaffold" {
			continue
		}
		aid := objStr(objAt(ev, "data"), "artifact_id")
		if !strings.HasPrefix(aid, prefix) {
			continue
		}
		suffix := strings.TrimPrefix(aid, prefix)
		if (suffix == string(harness.Halmos) ||
			suffix == string(harness.ForgeFuzz) ||
			suffix == string(harness.MiniCertora)) &&
			!containsStrCLI(kinds, suffix) {
			kinds = append(kinds, suffix)
		}
	}
	switch len(kinds) {
	case 1:
		return harness.Kind(kinds[0]), nil
	case 0:
		return "", t14ExitErr(2, "verify: no harness scaffold for %s "+
			"(scaffold it first with verify --scaffold "+
			"{halmos|forge-fuzz|minicertora} --invariant %s, or pass "+
			"--kind)\n",
			validation.PyReprStr(invID), validation.PyReprStr(invID))
	default:
		return "", t14ExitErr(2, "verify: %s has multiple harness "+
			"scaffolds; pass --kind {halmos|forge-fuzz|minicertora}\n",
			validation.PyReprStr(invID))
	}
}

// harnessExecRecord loads execs/<execID>/exec_record.json (state.AllExecs,
// the reader cmd_execs uses) and reports the exec dir for relative
// stdout_path resolution.
func harnessExecRecord(c *state.Campaign, execID string) (validation.Value,
	string, error) {
	execs, err := state.AllExecs(c)
	if err != nil {
		return validation.VNull(), "", err
	}
	for _, e := range execs {
		if objStr(e, "exec_id") == execID {
			return e, filepath.Join(c.ExecsDir, execID), nil
		}
	}
	return validation.VNull(), "", t14ExitErr(2,
		"verify: no exec %s in this campaign's exec ledger\n",
		validation.PyReprStr(execID))
}

// harnessExecStdout reads the record's stdout file, resolving a relative
// stdout_path against the exec dir and capping the read at 1MB.
func harnessExecStdout(execDir string, rec validation.Value) ([]byte, error) {
	p := objStr(rec, "stdout_path")
	if p == "" {
		return nil, t14ExitErr(2,
			"verify: exec %s has no captured stdout to map\n",
			validation.PyReprStr(objStr(rec, "exec_id")))
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(execDir, p)
	}
	fh, err := os.Open(p)
	if err != nil {
		return nil, t14ExitErr(2,
			"verify: exec %s has no captured stdout to map\n",
			validation.PyReprStr(objStr(rec, "exec_id")))
	}
	defer fh.Close()
	return io.ReadAll(io.LimitReader(fh, harnessStdoutCap))
}

// harnessScaffoldBytes loads the T17 scaffold artifact bytes: the latest
// harness_scaffold event for HARNESS-<INV>-<kind> names the registered
// artifact as its ref; the bytes come back through the artifacts API.
func harnessScaffoldBytes(c *state.Campaign, invID string,
	kind harness.Kind) ([]byte, error) {
	events, err := c.Events()
	if err != nil {
		return nil, err
	}
	want := "HARNESS-" + invID + "-" + string(kind)
	ref := ""
	for _, ev := range events {
		if objStr(ev, "type") != "harness_scaffold" {
			continue
		}
		if objStr(objAt(ev, "data"), "artifact_id") != want {
			continue
		}
		ref = objStr(ev, "ref")
	}
	if ref == "" {
		return nil, t14ExitErr(2, "verify: no harness scaffold for %s "+
			"(scaffold it first with verify --scaffold %s --invariant %s)\n",
			validation.PyReprStr(invID), string(kind),
			validation.PyReprStr(invID))
	}
	art, err := c.Artifact(ref)
	if err != nil {
		return nil, t14ExitErr(2,
			"verify: harness scaffold artifact %s is not registered\n",
			validation.PyReprStr(ref))
	}
	p := objStr(art, "path")
	if !filepath.IsAbs(p) {
		p = filepath.Join(c.Root, p)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, t14ExitErr(2,
			"verify: harness scaffold artifact %s has no readable file\n",
			validation.PyReprStr(ref))
	}
	return raw, nil
}

// harnessTimedOut is the MapRun timedOut bit: the sandbox records exit
// -1 both when the timeout kills the run and when the process never
// started. Either way the run did not complete, so its bytes map to
// inconclusive, never to a rung.
func harnessTimedOut(rec validation.Value) bool {
	if v := objAt(rec, "exit_status"); v.Kind == validation.Int {
		return v.I == -1 && v.Big == ""
	}
	return false
}

// harnessCommand is the exec record's command string ("" when absent).
func harnessCommand(rec validation.Value) string {
	return objStr(rec, "command")
}

// boundFlagRe parses the invocation bound out of an exec command:
// halmos's --loop N, forge's --fuzz-runs N (both `--flag N` and
// `--flag=N`) and minicertora's --loop-bound N. Absent flags mean 0
// ("unstated"): the number only feeds display summaries, a minicertora
// timeout summary and forge's bounded_k fallback — the rung never depends
// on it, so a missed parse degrades to inconclusive-safe text, never to a
// wrong verdict. The boundary classes matter: `--loop` alone must not
// swallow `--loop-bound`'s digits as a separate flag, and `--loopx` must
// not parse at all.
var boundFlagRe = regexp.MustCompile(
	`--(?:loop(?:-bound)?|fuzz-runs)[= ](\d+)`)

// invocationBound is the MapRun k: the bound flag from the exec command,
// or 0 when the command names none.
func invocationBound(command string, kind harness.Kind) int {
	_ = kind
	m := boundFlagRe.FindStringSubmatch(command)
	if m == nil {
		return 0
	}
	n := 0
	for _, c := range []byte(m[1]) {
		n = n*10 + int(c-'0')
		if n > 1<<62 {
			return 0
		}
	}
	return n
}

// harnessMapBound runs the Decision 2b bound check around MapRun:
//
//   - a recorded hash (input_hashes or artifact_hashes) equal to the
//     stored scaffold's sha256 binds the run: MapRun normally;
//   - a harness-named hash entry (H.t.sol / F.t.sol, T17's filenames, or
//     anything harness-named) with a different sha is a scaffold-bound
//     violation: rung inconclusive, the run's output is NOT used;
//   - no hash info at all maps normally with an "(unbound: harness file
//     hash not recorded)" summary suffix — the honest limitation.
//
// bounded_k is set only for proved-bounded (parsed k=<n> else the
// invocation k); every other rung carries null.
//
// The three G8 kinds share the bound check above the mapping seam. Below
// it the decision belongs to the kind: halmos/forge-fuzz go through
// MapRun (minicertora included, for the timedOut branch only), while an
// untimed minicertora run goes through MapMinicertora — its exit status
// and scaffold-pinned rule name are the mapper's business, not the
// dispatcher's. The proof sidecar is non-null exactly when a mapper
// attributed a verdict line; the bound-violation refusal below never maps,
// so it never carries one.
func harnessMapBound(kind harness.Kind, raw []byte, rec validation.Value,
	scaffold []byte, timedOut bool, k, exitStatus int,
	ruleName string) (rung, summary string, proof validation.Value,
	boundedK *int) {
	sum := sha256.Sum256(scaffold)
	hexSum := hex.EncodeToString(sum[:])
	hashes, harnessNamed := harnessRecordedHashes(rec)
	for _, h := range hashes {
		if h == hexSum {
			return harnessMappedKind(kind, raw, timedOut, k, exitStatus,
				ruleName, "")
		}
	}
	if harnessNamed {
		return harness.RungInconclusive,
			"scaffold-bound violation: harness file hash differs " +
				"from stored scaffold", validation.VNull(), nil
	}
	return harnessMappedKind(kind, raw, timedOut, k, exitStatus, ruleName,
		" (unbound: harness file hash not recorded)")
}

// harnessMappedKind dispatches one bound run to its kind's mapper: an
// untimed minicertora run through MapMinicertora (exit status + rule
// name), everything else — including a timed-out minicertora run, which
// must never reach the JSONL mapper — through MapRun.
func harnessMappedKind(kind harness.Kind, raw []byte, timedOut bool, k,
	exitStatus int, ruleName, suffix string) (string, string,
	validation.Value, *int) {
	if kind == harness.MiniCertora && !timedOut {
		rung, summary, proof, bk := harness.MapMinicertora(raw, exitStatus,
			ruleName)
		return rung, summary + suffix, proof, bk
	}
	rung, summary, bk := harnessMapped(kind, raw, timedOut, k, suffix)
	return rung, summary, validation.VNull(), bk
}

// harnessMapped runs MapRun and attaches bounded_k for proved-bounded.
func harnessMapped(kind harness.Kind, raw []byte, timedOut bool, k int,
	suffix string) (string, string, *int) {
	rung, summary := harness.MapRun(kind, raw, timedOut, k)
	summary += suffix
	if rung != harness.RungProvedBounded {
		return rung, summary, nil
	}
	bk := harness.BoundK(kind, raw, k)
	return rung, summary, &bk
}

// harnessRecordedHashes collects every recorded file hash from the exec
// record (input_hashes plus artifact_hashes values) and whether any key
// names the harness file (T17's H.t.sol / F.t.sol, the third kind's
// INV.mspec, or anything harness-named — the runs that hashed the file
// they actually executed). The .mspec suffix matters: without it a
// minicertora run that hashed a foreign spec file would read as "no hash
// info" and map normally, which is exactly the bind Decision 2b refuses.
func harnessRecordedHashes(rec validation.Value) (hashes []string,
	harnessNamed bool) {
	for _, key := range []string{"input_hashes", "artifact_hashes"} {
		m := objAt(rec, key)
		if m.Kind != validation.Obj {
			continue
		}
		for _, kv := range m.O {
			if kv.V.Kind == validation.Str && kv.V.S != "" {
				hashes = append(hashes, kv.V.S)
			}
			base := strings.ToLower(filepath.Base(kv.K))
			if base == "h.t.sol" || base == "f.t.sol" ||
				strings.HasSuffix(base, ".mspec") ||
				strings.Contains(base, "harness") {
				harnessNamed = true
			}
		}
	}
	return hashes, harnessNamed
}

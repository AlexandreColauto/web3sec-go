// mitigscan.go: G5 — structural-defense (soundness) scanner, ackscan sibling.
//
// Where ackscan asks "did the owner already acknowledge this code?",
// mitigscan asks "does a structural defense cover the flagged code?" A
// finding whose flagged function runs behind a reentrancy guard, orders
// effects before interactions (CEI), binds its authorization with EIP-712,
// or pays out through a pull pattern is less likely to be a live,
// bounty-grade hole: the defense is evidence the flagged flow was hardened.
// ScanMitigations scans the pinned source of the finding's affected-file
// function region (the file + region from affected[0]; the region is the
// function whose name the mechanism text mentions, else the whole file) for
// four deterministic regex-over-source patterns — NO AST, NO inference —
// and, on a hit, records finding.dedup_meta.mitigation_present, a
// JSON-encoded string {pattern,file,line,evidence} with all-string values
// (the string discipline dodges the dedup_meta additionalProperties
// string-only wall, same as corroborated_by).
//
// Pattern law (first match wins, ordered list, stable id strings):
//
//  1. "guard-modifier" — the flagged function signature contains
//     nonReentrant|nonReentrantBefore|nonReentrantAfter|lockRequired|
//     onlyWhenUnlocked, or the body opens with a lock check
//     (if (locked) revert / assert(!locked)) while the same file
//     declares a lock boolean written true and false.
//  2. "cei-order" — in the function body, the LAST storage write
//     (\w+(\[...\])?\s*(=|+=|-=) on a non-local line) occurs BEFORE the
//     first external interaction
//     (.call{| .call(| .send(| .transfer(| delegatecall| staticcall),
//     with BOTH sides present (no interaction, no credit) and no
//     for(/while( loop in the region (loops disqualify regex-level
//     proof).
//  3. "eip712-binding" — the file contains DOMAIN_SEPARATOR|
//     _hashTypedDataV4|typehash|0x1901 (case-insensitive for the hex).
//  4. "pull-pattern" — the file declares a claim-style function
//     (function (claim|withdraw|redeem|sweep)\w*\() AND the flagged flow
//     writes a user-scoped balance (balances?[...]=|owed[...])
//     rather than pushing funds.
//
// A clean no-hit is a successful scan (hit=false): RecordMitigationScan
// then CLEARS a previously stored record, so a re-scan is idempotent. A
// scan that could not run at all (no source pin, missing snapshot, no
// resolvable anchor) returns an error and leaves the finding untouched —
// the same fail-open posture as ackscan, so golden campaigns whose pinned
// source is absent see zero new bytes.
//
// The scan NEVER writes bounty.*, NEVER touches in_code_ack, and NEVER
// changes status: it owns dedup_meta.mitigation_present alone.
package findings

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"websec/internal/state"
	"websec/internal/validation"
)

// MitigPatternOrder is the pattern law: first match wins, in this order.
// The ids are stable (consumers — Task 14 risk demotion — match on them).
var MitigPatternOrder = []string{
	"guard-modifier",
	"cei-order",
	"eip712-binding",
	"pull-pattern",
}

// mitigPresent is the JSON shape stored (string-encoded) in
// dedup_meta.mitigation_present. All values are strings; Line is decimal.
type mitigPresent struct {
	Pattern  string `json:"pattern"`
	File     string `json:"file"`
	Line     string `json:"line"`
	Evidence string `json:"evidence"`
}

// MitigRecord encodes a mitigation hit as the dedup_meta.mitigation_present
// string value. Evidence is trimmed to <=120 chars.
func MitigRecord(pattern, file string, line int, evidence string) string {
	ev := strings.TrimSpace(evidence)
	if len([]rune(ev)) > 120 {
		ev = string([]rune(ev)[:120])
	}
	raw, _ := json.Marshal(mitigPresent{
		Pattern:  pattern,
		File:     file,
		Line:     strconv.Itoa(line),
		Evidence: ev,
	})
	return string(raw)
}

// ParseMitigationPresent decodes a mitigation_present string value (the
// consumption-side helper). ok=false when s is not a well-formed record.
func ParseMitigationPresent(s string) (pattern, file, line,
	evidence string, ok bool) {
	var m mitigPresent
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return "", "", "", "", false
	}
	if m.Pattern == "" || m.File == "" || m.Line == "" {
		return "", "", "", "", false
	}
	if _, err := strconv.Atoi(m.Line); err != nil {
		return "", "", "", "", false
	}
	return m.Pattern, m.File, m.Line, m.Evidence, true
}

// ScanMitigations scans the pinned source for structural defenses covering
// the finding's flagged region. Returns (hit, record, err): hit=true with
// the mitigation_present string on a hit; hit=false with Null on a clean
// scan; err (with hit=false, Null) when no scan could run — the caller
// then records nothing.
func ScanMitigations(c *state.Campaign, f validation.Value) (bool,
	validation.Value, error) {
	root, err := ackSourceRoot(c, f)
	if err != nil {
		return false, validation.VNull(), err
	}
	anchors := ackCollectAnchors(c, f, root)
	if len(anchors) == 0 {
		return false, validation.VNull(), fmt.Errorf(
			"no scannable anchor (need affected[].lines, or a function " +
				"resolvable in the pin)")
	}
	// The flagged file is the first anchor's (affected[0] resolves first,
	// in entry order): the first anchor whose file reads wins; a file
	// missing from the pin is unresolvable, not a failure.
	var lines []string
	var rel string
	for _, a := range anchors {
		p := a.file
		if !filepath.IsAbs(p) {
			p = filepath.Join(root, p)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		lines = strings.Split(string(raw), "\n")
		rel = ackRelPath(root, p)
		break
	}
	if lines == nil {
		return false, validation.VNull(), nil
	}
	mech := mitigMechanismText(f)
	start, end := mitigRegionFor(lines, mech)
	raw := strings.Join(lines, "\n")
	for _, id := range MitigPatternOrder {
		var line int
		var evidence string
		var hit bool
		switch id {
		case "guard-modifier":
			line, evidence, hit = mitigGuard(lines, raw, start, end)
		case "cei-order":
			line, evidence, hit = mitigCEI(lines, start, end)
		case "eip712-binding":
			line, evidence, hit = mitigEIP712(lines)
		case "pull-pattern":
			line, evidence, hit = mitigPull(lines, raw, start, end)
		}
		if hit {
			return true,
				validation.VStr(MitigRecord(id, rel, line, evidence)), nil
		}
	}
	return false, validation.VNull(), nil
}

// RecordMitigationScan is the scan-and-record half: it runs
// ScanMitigations, stamps the finding.mitigation_scanned event, and — when
// the result differs from the stored record — updates
// finding.dedup_meta.mitigation_present (a hit replaces it, a clean no-hit
// clears it). H5: the stringly record's digest is mirrored onto the affected
// entry it cites (affected[].citations.mitigation_present) — a hit stamps
// the mirror, a clean scan clears it with the record. A scan that cannot run
// returns its error and touches neither the finding nor the log. It never
// writes bounty.*, never touches in_code_ack, never changes status.
func RecordMitigationScan(c *state.Campaign, findingID string) (bool, error) {
	f, err := LoadFinding(c, findingID)
	if err != nil {
		return false, err
	}
	hit, rec, err := ScanMitigations(c, f)
	if err != nil {
		return false, err
	}
	if hit {
		dm := validation.ObjAt(f, "dedup_meta")
		if dm.Kind != validation.Obj {
			dm = validation.VObj()
		}
		dm.O = validation.SetOrAppend(dm.O, "mitigation_present", rec)
		f.O = validation.SetOrAppend(f.O, "dedup_meta", dm)
		// H5: mirror the record's digest onto the affected entry it cites
		// (affected[].citations.mitigation_present), so the stringly
		// record is machine-checkable. A record that does not parse was
		// never written by this function; skip the mirror rather than
		// invent a citation.
		if _, file, _, _, ok := ParseMitigationPresent(rec.S); ok {
			f = StampMitigationCitation(f, file, rec.S)
		}
	} else if cur, ok := fieldAt(validation.ObjAt(f, "dedup_meta"),
		"mitigation_present"); ok && cur.Kind != validation.Null {
		dm := validation.ObjAt(f, "dedup_meta")
		kept := make([]validation.KV, 0, len(dm.O))
		for _, kv := range dm.O {
			if kv.K != "mitigation_present" {
				kept = append(kept, kv)
			}
		}
		dm.O = kept
		f.O = validation.SetOrAppend(f.O, "dedup_meta", dm)
		// H5: the mirror goes with the record — a clean scan must not
		// leave a citation behind.
		f = ClearMitigationCitation(f)
	}
	// r40b P3 sweep: the mitigation stamp without its event lets a scan
	// "cover" a finding twice with one ledger row (the ackscan twin, which
	// took this door in the r18 P2 sweep). Unwind.
	data := validation.VObj(
		validation.KV{K: "finding_id", V: validation.VStr(findingID)},
		validation.KV{K: "hit", V: validation.VBool(hit)},
		validation.KV{K: "mitigation", V: rec},
	)
	if err := SaveThenLog(c, &f, func() error {
		_, lerr := c.Log("finding.mitigation_scanned", &findingID, &data)
		return lerr
	}); err != nil {
		return false, err
	}
	return hit, nil
}

// mitigMechanismText gathers the finding's mechanism prose — every string
// under root_cause and exploit_mechanism — which names the flagged
// function for region scoping.
func mitigMechanismText(f validation.Value) string {
	var sb strings.Builder
	var walk func(v validation.Value)
	walk = func(v validation.Value) {
		switch v.Kind {
		case validation.Str:
			sb.WriteString(v.S)
			sb.WriteString("\n")
		case validation.Obj:
			for _, kv := range v.O {
				walk(kv.V)
			}
		case validation.Arr:
			for _, e := range v.A {
				walk(e)
			}
		}
	}
	walk(validation.ObjAt(f, "root_cause"))
	walk(validation.ObjAt(f, "exploit_mechanism"))
	return sb.String()
}

// mitigFuncDef finds `function name(` definitions (Solidity) in file order.
var mitigFuncDef = regexp.MustCompile(
	`(?m)^[ \t]*function\s+(\w+)[ \t]*\(`)

// mitigMentions reports whether the mechanism prose names fn as a word
// ("deposits" must not count as mentioning "deposit").
func mitigMentions(mech, fn string) bool {
	ok, _ := regexp.MatchString(`\b`+regexp.QuoteMeta(fn)+`\b`, mech)
	return ok
}

// mitigRegionFor scopes the scan: the body of the first defined function
// whose name the mechanism text mentions (def line through the line before
// the next def, or EOF); else the whole file. Lines are 1-based inclusive.
func mitigRegionFor(lines []string, mech string) (start, end int) {
	type def struct {
		name string
		line int
	}
	var defs []def
	for i, ln := range lines {
		if m := mitigFuncDef.FindStringSubmatch(ln); m != nil {
			defs = append(defs, def{name: m[1], line: i + 1})
		}
	}
	for di, d := range defs {
		if d.name == "" || !mitigMentions(mech, d.name) {
			continue
		}
		end := len(lines)
		if di+1 < len(defs) {
			end = defs[di+1].line - 1
		}
		return d.line, end
	}
	return 1, len(lines)
}

var mitigGuardNames = regexp.MustCompile(`nonReentrantBefore|` +
	`nonReentrantAfter|nonReentrant|lockRequired|onlyWhenUnlocked`)

var mitigLockCheck = regexp.MustCompile(`if\s*\(\s*locked\s*\)\s*revert|` +
	`assert\s*\(\s*!\s*locked\s*\)`)

var mitigLockTrue = regexp.MustCompile(`\blocked\s*=\s*true\b`)
var mitigLockFalse = regexp.MustCompile(`\blocked\s*=\s*false\b`)

// mitigGuard implements "guard-modifier": the flagged function signature
// carries a guard modifier, or the body opens with a lock check while the
// file declares a lock boolean written true and false.
func mitigGuard(lines []string, raw string, start, end int) (int, string,
	bool) {
	// The signature: the def line through the first line holding `{`
	// (multi-line signatures), capped to the region.
	sigEnd := start
	for i := start; i <= end && i <= start+8; i++ {
		sigEnd = i
		if strings.Contains(lines[i-1], "{") {
			break
		}
	}
	sig := strings.Join(lines[start-1:sigEnd], "\n")
	if mitigGuardNames.MatchString(sig) {
		for i := start; i <= sigEnd; i++ {
			if mitigGuardNames.MatchString(lines[i-1]) {
				return i, lines[i-1], true
			}
		}
		return start, sig, true
	}
	// The lock-check variant: the body must OPEN with the check (first 8
	// lines past the signature) and the file must write the lock both
	// ways.
	for i := sigEnd + 1; i <= end && i <= sigEnd+8; i++ {
		if mitigLockCheck.MatchString(lines[i-1]) &&
			mitigLockTrue.MatchString(raw) &&
			mitigLockFalse.MatchString(raw) {
			return i, lines[i-1], true
		}
	}
	return 0, "", false
}

var mitigInteract = regexp.MustCompile(`\.call\{|\.call\(|\.send\(|` +
	`\.transfer\(|delegatecall|staticcall`)

// mitigLocalDecl marks local declaration lines, whose `=` is not a state
// write (any line carrying a type keyword).
var mitigLocalDecl = regexp.MustCompile(`\b(uint\d*|int\d*|address|` +
	`bool|bytes\d*|mapping|string)\b`)

// mitigWriteHead matches an identifier or index-assignment head; the
// operator itself is vetted by mitigLineIsWrite (comparisons — ==, !=,
// <=, >=, => — are not writes). The head allows any run of index groups
// (balances[a][b] = 0) and nesting up to three levels (deposits[rs[i]] = 0,
// grid[a[b[c]]] += 1) — RE2 has no recursion, and Solidity cannot meaningfully
// index deeper than a doubly-nested mapping.
var mitigWriteHead = regexp.MustCompile(
	`\w+(?:\[(?:[^\[\]]|\[(?:[^\[\]]|\[[^\[\]]*\])*\])*\])*` +
		`\s*(\+=|-=|=)`)

// mitigLineIsWrite reports whether line holds a storage write: an
// assignment operator that is not part of a comparison, on a line that is
// not a local declaration.
func mitigLineIsWrite(line string) bool {
	if mitigLocalDecl.MatchString(line) {
		return false
	}
	for _, loc := range mitigWriteHead.FindAllStringSubmatchIndex(line, -1) {
		opS, opE := loc[2], loc[3]
		op := line[opS:opE]
		if op == "+=" || op == "-=" {
			return true
		}
		// Bare `=`: reject ==, !=, <=, >=, => (and =<, =! for symmetry).
		if opS > 0 {
			if c := line[opS-1]; c == '=' || c == '!' ||
				c == '<' || c == '>' {
				continue
			}
		}
		if opE < len(line) {
			if c := line[opE]; c == '=' || c == '>' || c == '<' {
				continue
			}
		}
		return true
	}
	return false
}

// mitigLoopHead marks loop statements: loop-safety can't be proved over
// regex-level source, so any loop inside the region disqualifies cei-order
// outright (a pull pattern inside a loop must never read as CEI-clean).
var mitigLoopHead = regexp.MustCompile(`\bfor\s*\(|\bwhile\s*\(`)

// mitigCEI implements "cei-order": the region holds BOTH a storage write
// and an external interaction, the LAST write precedes the FIRST
// interaction, and the region contains no loop. Either side absent means
// no statement about order — no hit (an interaction that never happens
// earns no CEI credit); a loop means ordering can't be proved here.
func mitigCEI(lines []string, start, end int) (int, string, bool) {
	lastWrite, firstInteract := 0, 0
	for i := start; i <= end; i++ {
		ln := lines[i-1]
		if mitigLoopHead.MatchString(ln) {
			return 0, "", false
		}
		if mitigInteract.MatchString(ln) && firstInteract == 0 {
			firstInteract = i
		}
		if mitigLineIsWrite(ln) {
			lastWrite = i
		}
	}
	hasWrite, hasCall := lastWrite != 0, firstInteract != 0
	if !hasWrite || !hasCall || lastWrite >= firstInteract {
		return 0, "", false
	}
	return lastWrite,
		"last write at L" + strconv.Itoa(lastWrite) +
			" precedes call at L" + strconv.Itoa(firstInteract), true
}

var mitigEIP712Re = regexp.MustCompile(
	`DOMAIN_SEPARATOR|_hashTypedDataV4|typehash`)
var mitigEIP712HexRe = regexp.MustCompile(`(?i)0x1901`)

// mitigEIP712 implements "eip712-binding": file scope (the digest binding
// may live outside the flagged function). Case-insensitive for the hex
// only, as specified.
func mitigEIP712(lines []string) (int, string, bool) {
	for i, ln := range lines {
		if mitigEIP712Re.MatchString(ln) || mitigEIP712HexRe.MatchString(ln) {
			return i + 1, ln, true
		}
	}
	return 0, "", false
}

var mitigClaimFn = regexp.MustCompile(
	`function\s+(claim|withdraw|redeem|sweep)\w*\(`)

// mitigBalanceWrite matches a user-scoped balance write in the flagged
// flow: balances?[...]=(…)|owed[...]. Comparison operators are vetted the
// same way as CEI writes.
var mitigBalanceHead = regexp.MustCompile(
	`balances?(\[[^\]]*\])?\s*(\+=|-=|=)`)
var mitigOwed = regexp.MustCompile(`\bowed\s*\[`)

func mitigLineIsBalanceWrite(line string) bool {
	if mitigLocalDecl.MatchString(line) {
		return false
	}
	for _, loc := range mitigBalanceHead.FindAllStringSubmatchIndex(line,
		-1) {
		opS, opE := loc[4], loc[5]
		op := line[opS:opE]
		if op == "+=" || op == "-=" {
			return true
		}
		if opS > 0 {
			if c := line[opS-1]; c == '=' || c == '!' ||
				c == '<' || c == '>' {
				continue
			}
		}
		if opE < len(line) {
			if c := line[opE]; c == '=' || c == '>' || c == '<' {
				continue
			}
		}
		return true
	}
	return mitigOwed.MatchString(line)
}

// mitigPull implements "pull-pattern": the file declares a claim-style
// function AND the flagged flow writes a user-scoped balance rather than
// pushing funds.
func mitigPull(lines []string, raw string, start, end int) (int, string,
	bool) {
	if !mitigClaimFn.MatchString(raw) {
		return 0, "", false
	}
	for i := start; i <= end; i++ {
		if mitigLineIsBalanceWrite(lines[i-1]) {
			return i, lines[i-1], true
		}
	}
	return 0, "", false
}

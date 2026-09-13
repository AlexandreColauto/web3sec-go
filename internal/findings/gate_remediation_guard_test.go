package findings_test

// gate_remediation_guard_test.go: the wave-N T1 pin-vs-reality guard. A
// remediation hint is operator-facing copy of a command, and copy drifts from
// the parser silently — the `critic-verdict` entry told operators to run
// `webv2 verdict <fid> confirmed '<reasoning>' --actor <you>` for months
// while cmd_verdict.go accepted neither that positional shape nor --actor.
//
// The guard reads the CLI dispatch registry (cli.CommandNames) instead of
// grepping the command sources: a hint that opens `webv2 <verb>` may only
// name a verb the dispatcher really has, and every `--flag` a hint prints
// must be one the verb's parser accepts (remediationFlags, seeded from the
// parsers themselves).
//
// I-5 closed two holes: the verb check looked only at fields[0]/fields[1], so
// a COMPOUND hint (`evidence-floor`, `evidence-floor-unreachable`) smuggled
// its later commands — and their typos — past the guard; and nothing checked
// flags at all, so `--bogus` was as invisible as a misspelled verb. Both
// checks now run over EVERY `webv2` occurrence in an entry, each occurrence
// judged as its own segment (the verb token and the tokens up to the next
// `webv2`), and both are exercised against deliberately broken catalogs
// (TestGateRemediationGuardCatchesMutations) so the guard cannot pass by
// checking nothing.

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"websec/internal/cli"
	"websec/internal/findings"
)

// remediationSegment is one `webv2 <verb> ...` run inside a catalog entry:
// the verb it names ("" when the next token is absent, a flag or a
// metavariable) and every token belonging to that run.
type remediationSegment struct {
	verb   string
	tokens []string
}

// remediationSegments splits a catalog entry at every `webv2` token, so a
// compound hint is checked one command at a time instead of by its first
// word.
func remediationSegments(entry string) []remediationSegment {
	fields := strings.Fields(entry)
	var segs []remediationSegment
	for i, f := range fields {
		if f != "webv2" {
			continue
		}
		end := len(fields)
		for j := i + 1; j < len(fields); j++ {
			if fields[j] == "webv2" {
				end = j
				break
			}
		}
		seg := remediationSegment{tokens: fields[i+1 : end]}
		if len(seg.tokens) > 0 {
			next := seg.tokens[0]
			if !strings.HasPrefix(next, "-") && !strings.HasPrefix(next, "<") {
				seg.verb = next
			}
		}
		segs = append(segs, seg)
	}
	return segs
}

// remediationFlagSet is a small set constructor for the tables below.
func remediationFlagSet(names ...string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return set
}

// remediationFlags is the accepted `--flag` vocabulary per verb, read off the
// ACTUAL parsers — never guessed from the usage lines (which are themselves
// copy that can drift):
//
//	verdict          cmd_verdict.go    --verdict --reason --outlook --outlook-reason
//	recall           cmd_recall.go     --finding --mode --note
//	mint             cmd_mint.go       --exec --description --tier --type --verify-reruns
//	floors           cmd_floors.go     --json --actor --reason
//	impact           cmd_impact.go     --unpriceable --ceiling --reason --actor
//	                                   --extractable --max-loss --required-capital
//	                                   --artifact --description --reversibility
//	snap             cmd_snap.go       --dry-run --json --deployment --chain --exclude
//	shield           cmd_shield.go     --extraction --reason --actor
//	invariant-verify cmd_invariant_verify.go
//	                                   --artifact --exec
//	sequence         cmd_sequence.go   --finding --workdir --exec
//	exec             cmd_exec.go       --dry-run --command --profile --workdir
//	                                   --finding --timeout --env
//	ladder           cmd_ladder.go     --capital --ratio --name --description
//	                                   --axes --removes --note --reason --exec --actor
//	immunize         cmd_immunize.go   --poc-exec --patch --mutations --bypass --actor
//	price            cmd_price.go      --source --as-of --actor
//
// The first nine are the verbs today's GATE_REMEDIATION entries name. exec,
// ladder, immunize and price are seeded because they are the command families
// this catalog's copy has historically drawn on (evidence/repro/ladder
// remediation): with them in the table, a future hint that names one fails
// only on a genuinely wrong flag, never on missing coverage.
//
// A verb the catalog names but this table does not cover is a FAILURE, not a
// skip: an uncovered verb would make the flag check blind for that hint.
var remediationFlags = map[string]map[string]bool{
	"verdict": remediationFlagSet("--verdict", "--reason", "--outlook",
		"--outlook-reason"),
	"recall": remediationFlagSet("--finding", "--mode", "--note"),
	"mint": remediationFlagSet("--exec", "--description", "--tier", "--type",
		"--verify-reruns"),
	"floors": remediationFlagSet("--json", "--actor", "--reason"),
	"impact": remediationFlagSet("--unpriceable", "--ceiling", "--reason",
		"--actor", "--extractable", "--max-loss", "--required-capital",
		"--artifact", "--description", "--reversibility"),
	"snap": remediationFlagSet("--dry-run", "--json", "--deployment", "--chain",
		"--exclude"),
	"shield":           remediationFlagSet("--extraction", "--reason", "--actor"),
	"invariant-verify": remediationFlagSet("--artifact", "--exec"),
	"sequence":         remediationFlagSet("--finding", "--workdir", "--exec"),
	"exec": remediationFlagSet("--dry-run", "--command", "--profile",
		"--workdir", "--finding", "--timeout", "--env"),
	"ladder": remediationFlagSet("--capital", "--ratio", "--name",
		"--description", "--axes", "--removes", "--note", "--reason", "--exec",
		"--actor"),
	"immunize": remediationFlagSet("--poc-exec", "--patch", "--mutations",
		"--bypass", "--actor"),
	"price": remediationFlagSet("--source", "--as-of", "--actor"),
}

// remediationReporter is the failure sink the two checks write to: *testing.T
// in the real tests, a recorder in the mutation check.
type remediationReporter interface {
	Errorf(format string, args ...any)
}

// checkRemediationVerbs is the verb half of the guard over one catalog: every
// `webv2 <verb>` occurrence must name a dispatched command. It returns how
// many verbs it checked, so a caller can refuse to pass vacuously.
func checkRemediationVerbs(t remediationReporter, catalog map[string]string) int {
	verbs := map[string]bool{}
	for _, name := range cli.CommandNames() {
		verbs[name] = true
	}
	named := 0
	for check, entry := range catalog {
		for _, seg := range remediationSegments(entry) {
			if seg.verb == "" {
				continue // a flag, a metavariable, or no token at all
			}
			named++
			if !verbs[seg.verb] {
				t.Errorf("GATE_REMEDIATION[%q] tells the operator to run %q, "+
					"which the CLI does not dispatch: %q", check, seg.verb, entry)
			}
		}
	}
	return named
}

// checkRemediationFlags is the flag half of the guard over one catalog: every
// `--flag` token in a `webv2 X` segment must be in X's accepted set. It
// returns how many flag tokens it checked.
func checkRemediationFlags(t remediationReporter, catalog map[string]string) int {
	checked := 0
	for check, entry := range catalog {
		for _, seg := range remediationSegments(entry) {
			if seg.verb == "" {
				continue
			}
			allowed, ok := remediationFlags[seg.verb]
			if !ok {
				t.Errorf("no flag table entry for GATE_REMEDIATION[%q] verb %q "+
					"— seed remediationFlags from the parser so its flags are "+
					"checked", check, seg.verb)
				continue
			}
			seen := map[string]bool{}
			for _, tok := range seg.tokens {
				flag := flagToken(tok)
				if flag == "" || seen[flag] {
					continue
				}
				seen[flag] = true
				checked++
				if !allowed[flag] {
					t.Errorf("GATE_REMEDIATION[%q] tells the operator to run "+
						"`webv2 %s ... %s`, which %s does not accept (accepted: "+
						"%s)", check, seg.verb, flag, seg.verb,
						strings.Join(sortedFlags(allowed), " "))
				}
			}
		}
	}
	return checked
}

func TestGateRemediationVerbsAreDispatched(t *testing.T) {
	if len(cli.CommandNames()) == 0 {
		t.Fatal("CLI dispatch registry is empty — this guard would pass vacuously")
	}
	if checkRemediationVerbs(t, findings.GATE_REMEDIATION) == 0 {
		t.Fatal("no GATE_REMEDIATION entry names a `webv2 <verb>` command — " +
			"this guard has gone blind to the catalog")
	}
	// A compound hint must have been seen in FULL: the two known multi-verb
	// recoveries name more than one command, and if the scan collapsed to the
	// first token their later verbs would never be checked. Assert the scan
	// itself is not blind rather than trusting the count above.
	for _, check := range []string{"evidence-floor", "evidence-floor-unreachable"} {
		segs := remediationSegments(findings.GATE_REMEDIATION[check])
		if len(segs) < 2 {
			t.Errorf("GATE_REMEDIATION[%q] should name more than one `webv2` "+
				"command, but the scan found %d segment(s): %q",
				check, len(segs), findings.GATE_REMEDIATION[check])
		}
	}

	// cmd_verdict.go: `webv2 verdict <campaign> <finding> --verdict V
	// --reason R` — two POSITIONALS (the campaign is not optional), both
	// flags required, and `--actor` is not a recognized argument (it fails
	// as "unrecognized arguments: --actor").
	hint := findings.GATE_REMEDIATION["critic-verdict"]
	fields := strings.Fields(hint)
	if len(fields) < 4 || strings.HasPrefix(fields[2], "-") ||
		strings.HasPrefix(fields[3], "-") {
		t.Errorf("critic-verdict remediation %q must name the campaign and "+
			"the finding positionally (`webv2 verdict <campaign> <finding> "+
			"...`)", hint)
	}
	for _, want := range []string{"--verdict", "--reason"} {
		if !strings.Contains(hint, want) {
			t.Errorf("critic-verdict remediation %q misses required flag %s",
				hint, want)
		}
	}
	if strings.Contains(hint, "--actor") {
		t.Errorf("critic-verdict remediation %q names --actor, which "+
			"cmd_verdict.go rejects", hint)
	}
}

func TestGateRemediationFlagsAreAccepted(t *testing.T) {
	if len(findings.GATE_REMEDIATION) == 0 {
		t.Fatal("GATE_REMEDIATION is empty — this guard would pass vacuously")
	}
	if checkRemediationFlags(t, findings.GATE_REMEDIATION) == 0 {
		t.Fatal("no `--flag` token was checked across GATE_REMEDIATION — " +
			"this guard has gone blind to the flag copy")
	}
}

// recorder collects Errorf calls so a mutation probe can assert that the
// guard REJECTED a deliberately broken catalog without failing the run.
type recorder struct{ msgs []string }

func (r *recorder) Errorf(format string, args ...any) {
	r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
}

// TestGateRemediationGuardCatchesMutations is the non-vacuous check: the very
// same checks are run over catalogs that are known-broken, and each must
// report at least one error. This is the in-process form of the brief's
// "temporarily write `webv2 complet` / `--bogus`, run, restore" probe — it
// catches the same two copy bugs permanently instead of once by hand.
func TestGateRemediationGuardCatchesMutations(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry string
		why   string
	}{
		{"misspelled second verb",
			"webv2 mint <fid> --exec <EXEC-ID>   (or webv2 complet <c> <fid>)",
			"a compound hint's later verb is checked, not just its first"},
		{"bogus flag",
			"webv2 mint <fid> --exec <EXEC-ID> --bogus",
			"an unknown flag is refused"},
		{"flag borrowed across segments",
			"webv2 floors set --verdict confirmed   or webv2 mint <fid> --exec <E>",
			"a segment may only use its OWN verb's flags"},
		{"uncovered verb",
			"webv2 execs --json",
			"a verb with no flag table entry fails instead of skipping"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			catalog := map[string]string{"probe-mutation": tc.entry}
			var rec recorder
			verbs := checkRemediationVerbs(&rec, catalog)
			flags := checkRemediationFlags(&rec, catalog)
			if verbs == 0 && flags == 0 {
				t.Fatalf("the guard checked nothing in %q for %q", tc.entry, tc.why)
			}
			if len(rec.msgs) == 0 {
				t.Fatalf("the guard ACCEPTED the broken catalog %q — %s",
					tc.entry, tc.why)
			}
		})
	}
}

// flagToken normalizes a printed flag token to its bare switch: `--tier T3`
// and `--tier=T3` are the same option. It returns "" for a token that is not
// a flag.
func flagToken(tok string) string {
	if !strings.HasPrefix(tok, "--") {
		return ""
	}
	if i := strings.IndexByte(tok, '='); i >= 0 {
		return tok[:i]
	}
	return tok
}

// sortedFlags renders an accepted set deterministically, so a failure message
// does not depend on map iteration order.
func sortedFlags(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

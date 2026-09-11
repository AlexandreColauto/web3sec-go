package defihacklabs

// Port of tests/test_datasets.py's DeFiHackLabs half: the synthetic-shape
// unit tests plus the skipif-gated integration pass over the real clones.
// The fixture tree is built the way the Python tests build theirs (tmp_path,
// verbatim incidents.json / rootcause_data.json shapes).

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"websec/internal/ingest"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

func kv(k string, v validation.Value) validation.KV { return validation.KV{K: k, V: v} }

func obj(kvs ...validation.KV) validation.Value { return validation.VObj(kvs...) }

func arr(items ...validation.Value) validation.Value { return validation.VArr(items...) }

func ptrText(p *string) string {
	if p == nil {
		return "<nil>"
	}
	return *p
}

func text(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return ""
}

// binemonIncident is the Python `_binemon_incident` (verbatim incidents.json
// shape, recon §1.1).
func binemonIncident() validation.Value {
	return obj(
		kv("date", validation.VStr("20240311")),
		kv("name", validation.VStr("Binemon")),
		kv("type", validation.VStr("Precision Loss")),
		kv("Lost", validation.VFloat(413000.0)),
		kv("lossType", validation.VStr("USD")),
		kv("Contract", validation.VStr("src/test/2024-03/Binemon_exp.sol")),
		kv("chain", validation.VStr("BSC")),
	)
}

// binemonRCA is the Python `_binemon_rca` (prose shortened — the tests pin
// joining/truncation, not the 1.5 KB original).
func binemonRCA() validation.Value {
	return obj(
		kv("type", validation.VStr("Access Control")),
		kv("date", validation.VStr("2024-03-11")),
		kv("rootCause", validation.VStr(
			"Binemon's BIN token exposes a public `sweepTokenForMarketing()` "+
				"function with no access control. Because it is permissionless, "+
				"the attacker called it repeatedly in a tight loop, pushing the "+
				"contract's holdings into the PancakeSwap pool and distorting "+
				"the reserves for profit.")),
		kv("loss", validation.VStr("~0.2 $BNB")),
		kv("pocLink", validation.VStr(
			"https://github.com/SunWeb3Sec/DeFiHackLabs/blob/"+
				"2baf1a43c44d6cb3ce17a678701784fbe7edabad"+
				"/src/test/2024-03/Binemon_exp.sol")),
		kv("images", arr(validation.VStr("images/image%2070.png"))),
		kv("Lost", validation.VStr("$413.0K")),
	)
}

func writeJSON(t *testing.T, path string, v validation.Value) {
	t.Helper()
	if err := validation.WriteJson(path, v, ""); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeText(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// sampleTree is the Python `_sample_tree`: synthetic explorer + PoC clones in
// the exact source formats. Four incidents: Binemon (Contract-path hit,
// commit-pinned pocLink), Geb (empty Contract, name-stem fallback hit,
// multi-label RCA type), and a WXC collision pair (drifted Contract repaired
// via the `_exp` variant on one row; genuinely PoC-less on the other).
func sampleTree(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	explorer := filepath.Join(base, "explorer")
	if err := os.MkdirAll(explorer, 0o755); err != nil {
		t.Fatal(err)
	}
	incidents := arr(
		binemonIncident(),
		obj(kv("date", validation.VStr("20260902")),
			kv("name", validation.VStr("Geb")),
			kv("type", validation.VStr("Access Control Bypass")),
			kv("Lost", validation.VFloat(5.9436)),
			kv("lossType", validation.VStr("ETH")),
			kv("Contract", validation.VStr("")),
			kv("chain", validation.VStr("Ethereum"))),
		obj(kv("date", validation.VStr("20250811")),
			kv("name", validation.VStr("WXC")),
			kv("type", validation.VStr("Flash Loan")),
			kv("Lost", validation.VFloat(1000.0)),
			kv("lossType", validation.VStr("USD")),
			kv("Contract", validation.VStr("src/test/2025-08/WXC_Token")),
			kv("chain", validation.VStr("BSC"))),
		obj(kv("date", validation.VStr("20250811")),
			kv("name", validation.VStr("WXC")),
			kv("type", validation.VStr("Access Control")),
			kv("Lost", validation.VNull()),
			kv("lossType", validation.VStr("USD")),
			kv("Contract", validation.VStr("")),
			kv("chain", validation.VStr("Unknown"))),
	)
	writeJSON(t, filepath.Join(explorer, "incidents.json"), incidents)
	rca := obj(
		// Collision group: both normalize to "geb" — first wins.
		kv("Geb", obj(
			kv("type", validation.VStr("Access Control, Flashloans")),
			kv("date", validation.VStr("2026-09-02")),
			kv("rootCause", validation.VStr(
				"Geb's proxy actions library was registered as a SAFE "+
					"owner, letting anyone execute privileged calls through "+
					"the shared module and drain funds.")),
			kv("loss", validation.VStr("~5.9 ETH")),
			kv("pocLink", validation.VStr("")),
			kv("images", arr()))),
		kv("Geb_", obj(
			kv("type", validation.VStr("Governance Attack")),
			kv("date", validation.VStr("2026-09-02")),
			kv("rootCause", validation.VStr(
				"A decoy record that must never win the join.")),
			kv("loss", validation.VStr("")),
			kv("pocLink", validation.VStr("")),
			kv("images", arr()))),
		kv("Binemon", binemonRCA()),
	)
	writeJSON(t, filepath.Join(explorer, "rootcause_data.json"), rca)
	poc := filepath.Join(base, "poc")
	writeText(t, filepath.Join(poc, "src", "test", "2024-03", "Binemon_exp.sol"),
		"contract Binemon_exp {}")
	writeText(t, filepath.Join(poc, "src", "test", "2026-08", "Geb_exp.sol"),
		"contract Geb_exp {}")
	writeText(t, filepath.Join(poc, "src", "test", "2025-08", "WXC_Token_exp.sol"),
		"contract WXC_Token_exp {}")
	return explorer, poc
}

func loadSample(t *testing.T) []validation.Value {
	t.Helper()
	explorer, poc := sampleTree(t)
	records, err := LoadRecords(&explorer, &poc)
	if err != nil {
		t.Fatalf("LoadRecords: %v", err)
	}
	return records
}

func byID(records []validation.Value) map[string]validation.Value {
	out := map[string]validation.Value{}
	for _, r := range records {
		out[text(at(r, "id"))] = r
	}
	return out
}

func TestDefihacklabsRecordShapeContractHit(t *testing.T) {
	records := loadSample(t)
	var rec validation.Value
	found := false
	for _, r := range records {
		if strings.HasPrefix(text(at(r, "id")), "defihacklabs-20240311") {
			rec, found = r, true
		}
	}
	if !found {
		t.Fatal("no record with id defihacklabs-20240311*")
	}
	if got := text(at(rec, "dataset")); got != "defihacklabs" {
		t.Fatalf("dataset = %q", got)
	}
	// pocLink wins over the blob URL; the pinned commit travels.
	if got, want := text(at(rec, "url")), text(at(binemonRCA(), "pocLink")); got != want {
		t.Fatalf("url = %q want %q", got, want)
	}
	wantProgram := validation.CanonSpaced(obj(
		kv("program", validation.VStr("Binemon")),
		kv("platform", validation.VStr("BNB Chain")),
		kv("chains", arr(validation.VStr("BNB Chain")))))
	if got := validation.CanonSpaced(at(rec, "program")); got != wantProgram {
		t.Fatalf("program = %s want %s", got, wantProgram)
	}
	if got := text(at(rec, "bug_class_label")); got != "Precision Loss" {
		t.Fatalf("bug_class_label = %q (raw, never pre-mapped)", got)
	}
	if got := text(at(rec, "outcome")); got != "confirmed-exploitable" {
		t.Fatalf("outcome = %q", got)
	}
	if at(rec, "severity").Kind != validation.Null {
		t.Fatalf("severity must be None (Lost is magnitude, not severity)")
	}
	if at(rec, "negative").Kind != validation.Bool || at(rec, "negative").B {
		t.Fatal("negative must be False")
	}
	if at(rec, "prior").Kind != validation.Bool || !at(rec, "prior").B {
		t.Fatal("prior must be True")
	}
	wantLoc := validation.CanonSpaced(arr(obj(
		kv("file", validation.VStr("src/test/2024-03/Binemon_exp.sol")))))
	if got := validation.CanonSpaced(at(rec, "locations")); got != wantLoc {
		t.Fatalf("locations = %s want %s", got, wantLoc)
	}
	wantCode := validation.CanonSpaced(obj(
		kv("repo", validation.VStr(RepoURL)),
		kv("commit", validation.VStr("2baf1a43c44d6cb3ce17a678701784fbe7edabad")),
		kv("files", arr(validation.VStr("src/test/2024-03/Binemon_exp.sol")))))
	if got := validation.CanonSpaced(at(rec, "code")); got != wantCode {
		t.Fatalf("code = %s want %s", got, wantCode)
	}
	wantExploit := validation.CanonSpaced(obj(
		kv("poc_path", validation.VStr("src/test/2024-03/Binemon_exp.sol")),
		kv("technique", validation.VStr("Access Control"))))
	if got := validation.CanonSpaced(at(rec, "exploit")); got != wantExploit {
		t.Fatalf("exploit = %s want %s (RCA type, not incidents type)", got, wantExploit)
	}
	if !strings.Contains(text(at(rec, "description")), "sweepTokenForMarketing") {
		t.Fatal("description must carry the RCA prose")
	}
	if rc := len([]rune(text(at(rec, "root_cause")))); rc < 10 || rc > 2000 {
		t.Fatalf("root_cause len = %d", rc)
	}
	if pl := len([]rune(text(at(rec, "pattern")))); pl < 15 || pl > 500 {
		t.Fatalf("pattern len = %d", pl)
	}
	if p := text(at(rec, "partition")); p != "dev" && p != "held-out" {
		t.Fatalf("partition = %q", p)
	}
}

func TestDefihacklabsPocResolutionFallbackVariantAndMiss(t *testing.T) {
	records := loadSample(t)
	by := byID(records)
	geb, ok := by["defihacklabs-20260902-geb"]
	if !ok {
		t.Fatal("missing defihacklabs-20260902-geb")
	}
	if got := text(at(at(geb, "exploit"), "poc_path")); got != "src/test/2026-08/Geb_exp.sol" {
		t.Fatalf("geb poc_path = %q", got)
	}
	// No pocLink: blob/main URL over the resolved path; clone HEAD commit.
	wantURL := RepoURL + "/blob/main/src/test/2026-08/Geb_exp.sol"
	if got := text(at(geb, "url")); got != wantURL {
		t.Fatalf("geb url = %q want %q", got, wantURL)
	}
	if got := text(at(at(geb, "code"), "commit")); got != CloneHead {
		t.Fatalf("geb commit = %q want %q", got, CloneHead)
	}
	// Multi-label RCA type splits into stable-joined pattern atoms.
	if got := text(at(geb, "pattern")); got != "Access Control; Flashloans" {
		t.Fatalf("geb pattern = %q", got)
	}
	var wxcIDs []string
	for id := range by {
		if strings.HasPrefix(id, "defihacklabs-20250811") {
			wxcIDs = append(wxcIDs, id)
		}
	}
	if len(wxcIDs) != 2 {
		t.Fatalf("wxc ids = %v", wxcIDs)
	}
	hit, ok := by["defihacklabs-20250811-wxc-bsc"]
	if !ok {
		t.Fatal("missing defihacklabs-20250811-wxc-bsc")
	}
	if got := text(at(at(hit, "exploit"), "poc_path")); got != "src/test/2025-08/WXC_Token_exp.sol" {
		t.Fatalf("hit poc_path = %q", got)
	}
	var miss validation.Value
	for _, id := range wxcIDs {
		if !strings.Contains(id, "-bsc") {
			miss = by[id]
		}
	}
	if miss.Kind != validation.Obj {
		t.Fatal("missing the PoC-less WXC row")
	}
	if at(at(miss, "exploit"), "poc_path").Kind != validation.Null {
		t.Fatal("miss poc_path must be None")
	}
	if at(miss, "url").Kind != validation.Null {
		t.Fatal("miss url must be None")
	}
	if len(at(miss, "locations").A) != 0 {
		t.Fatal("miss locations must be []")
	}
	if len(at(at(miss, "code"), "files").A) != 0 {
		t.Fatal("miss code.files must be []")
	}
	// No RCA anywhere for WXC: fallback prose still length-compliant.
	if dl := len([]rune(text(at(miss, "description")))); dl < 20 || dl > 10000 {
		t.Fatalf("miss description len = %d", dl)
	}
	if rc := len([]rune(text(at(miss, "root_cause")))); rc < 10 || rc > 2000 {
		t.Fatalf("miss root_cause len = %d", rc)
	}
}

func TestDefihacklabsCollisionIDsAndRCAFirstInFileOrder(t *testing.T) {
	records := loadSample(t)
	var wxc []string
	for _, r := range records {
		if id := text(at(r, "id")); strings.HasPrefix(id, "defihacklabs-20250811") {
			wxc = append(wxc, id)
		}
	}
	sortStrings(wxc)
	// Collision pair: first in (type, Contract, chain) order keeps the bare
	// slug (the Unknown-chain row, type "Access Control"), the BSC row takes
	// the +chain suffix.
	want := []string{"defihacklabs-20250811-wxc", "defihacklabs-20250811-wxc-bsc"}
	if strings.Join(wxc, ",") != strings.Join(want, ",") {
		t.Fatalf("wxc ids = %v want %v", wxc, want)
	}
	seen := map[string]bool{}
	for _, r := range records {
		id := text(at(r, "id"))
		if seen[id] {
			t.Fatalf("duplicate id %q", id)
		}
		seen[id] = true
	}
	if len(seen) != len(records) {
		t.Fatalf("ids %d != records %d", len(seen), len(records))
	}
	geb := byID(records)["defihacklabs-20260902-geb"]
	// "Geb" (first in file order) wins over "Geb_", not vice versa.
	if !strings.Contains(text(at(geb, "description")), "SAFE") {
		t.Fatal("geb description must carry the Geb RCA prose")
	}
	if strings.Contains(text(at(geb, "description")), "decoy") {
		t.Fatal("geb description must not carry the decoy record")
	}
}

func TestDefihacklabsNormalizeChain(t *testing.T) {
	cases := []struct {
		in   string
		want string // "" means None
	}{
		{"BSC", "BNB Chain"},
		{"BNB Chain", "BNB Chain"},
		{"Ethereum", "Ethereum"},
		{"Arbitrum", "Arbitrum"},
		{"Unknown", ""},
		{"None", ""},
		{"Multi-Chain", ""},
		{"5", ""},
		{"80094", ""},
	}
	for _, c := range cases {
		got := NormalizeChain(validation.VStr(c.in))
		if c.want == "" {
			if got != nil {
				t.Fatalf("NormalizeChain(%q) = %q want None", c.in, *got)
			}
			continue
		}
		if got == nil || *got != c.want {
			t.Fatalf("NormalizeChain(%q) = %v want %q", c.in, got, c.want)
		}
	}
	if got := NormalizeChain(validation.VNull()); got != nil {
		t.Fatalf("NormalizeChain(None) = %q want None", *got)
	}
}

func TestDefihacklabsExtractPoclink(t *testing.T) {
	url, path, commit := ExtractPocLink(at(binemonRCA(), "pocLink"))
	if ptrText(url) != text(at(binemonRCA(), "pocLink")) {
		t.Fatalf("url = %v", ptrText(url))
	}
	if ptrText(path) != "src/test/2024-03/Binemon_exp.sol" {
		t.Fatalf("path = %v", ptrText(path))
	}
	if ptrText(commit) != "2baf1a43c44d6cb3ce17a678701784fbe7edabad" {
		t.Fatalf("commit = %v", ptrText(commit))
	}
	url, path, commit = ExtractPocLink(validation.VStr(
		"https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main" +
			"/src/test/2024-03/IT_exp.sol#L4"))
	if !strings.HasSuffix(ptrText(url), "IT_exp.sol") ||
		strings.Contains(ptrText(url), "#L4") {
		t.Fatalf("fragment not stripped: %q", ptrText(url))
	}
	if ptrText(path) != "src/test/2024-03/IT_exp.sol" {
		t.Fatalf("path = %v", ptrText(path))
	}
	if commit != nil {
		t.Fatalf("blob/main pins nothing, got %v", ptrText(commit))
	}
	u, p, c := ExtractPocLink(validation.VStr(""))
	if u != nil || p != nil || c != nil {
		t.Fatalf("empty input must give (None, None, None), got %v %v %v", u, p, c)
	}
}

func TestDefihacklabsClipTextBoundaries(t *testing.T) {
	short := "Small cause."
	if got := ClipText(short, 2000); got != short {
		t.Fatalf("ClipText(short) = %q", got)
	}
	long := strings.TrimSpace("First sentence ends here. " +
		strings.Repeat("Padding words. ", 500))
	clipped := ClipText(long, 200)
	if n := len([]rune(clipped)); n > 200 || n < 10 {
		t.Fatalf("clipped len = %d", n)
	}
	if !strings.HasSuffix(clipped, ".") {
		t.Fatalf("clipped must end on a sentence boundary: %q", clipped[len(clipped)-20:])
	}
}

func TestDefihacklabsAssignPartitionsMath(t *testing.T) {
	// 10 synthetic dated incidents -> ceil(10*0.3) = 3 held-out, the three
	// most recent; ties would break on the unique id.
	records := make([]validation.Value, 0, 10)
	dates := make([]string, 0, 10)
	for i := 1; i <= 10; i++ {
		records = append(records, obj(
			kv("id", validation.VStr(fmt.Sprintf("defihacklabs-202401%02d-p%02d", i, i))),
			kv("partition", validation.VStr("dev"))))
		dates = append(dates, fmt.Sprintf("202401%02d", i))
	}
	AssignPartitions(records, dates)
	var heldOut []string
	dev := 0
	for _, r := range records {
		switch text(at(r, "partition")) {
		case "held-out":
			heldOut = append(heldOut, text(at(r, "id")))
		case "dev":
			dev++
		}
	}
	sortStrings(heldOut)
	want := "defihacklabs-20240108-p08,defihacklabs-20240109-p09," +
		"defihacklabs-20240110-p10"
	if strings.Join(heldOut, ",") != want {
		t.Fatalf("held-out = %v want %s", heldOut, want)
	}
	if dev != 7 {
		t.Fatalf("dev count = %d want 7", dev)
	}
}

func sortStrings(s []string) { sort.Strings(s) }

// useRepoMaps points taxonomy at the repo's map fixtures (byte-identical to
// the reference config/: taxonomy_map.yaml + the three per-dataset maps).
func useRepoMaps(t *testing.T) validation.Value {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..", "..")
	taxonomy.SetConfigDir(filepath.Join(root, "internal", "taxonomy", "testdata"))
	maps, err := taxonomy.LoadMaps([]string{"defihacklabs"})
	if err != nil {
		t.Fatalf("LoadMaps: %v", err)
	}
	return maps
}

func TestDefihacklabsIngestRecordPurePaths(t *testing.T) {
	// ingest_record (pure) accepts adapter output: the resolved record yields
	// an eval case + campaign seed; the PoC-less record yields a case with no
	// poc_path (so ingest() filters its seed) and no crash.
	maps := useRepoMaps(t)
	records := loadSample(t)
	by := byID(records)
	res, err := ingest.IngestRecord(by["defihacklabs-20240311-binemon"], &maps)
	if err != nil {
		t.Fatalf("IngestRecord(binemon): %v", err)
	}
	gold := at(res.EvalCase, "gold")
	if got := text(at(gold, "outcome")); got != "confirmed-exploitable" {
		t.Fatalf("binemon gold outcome = %q", got)
	}
	if got := text(at(gold, "bug_class")); got != "precision-rounding" {
		t.Fatalf("binemon gold bug_class = %q", got)
	}
	if res.CampaignSeed == nil {
		t.Fatal("binemon campaign_seed must not be None")
	}
	wantTax := validation.CanonCompact(arr(
		validation.VStr("precision-rounding"), validation.VBool(true)))
	if got := validation.CanonCompact(at(res.Value(), "taxonomy")); got != wantTax {
		t.Fatalf("binemon taxonomy = %s want %s", got, wantTax)
	}
	geb, err := ingest.IngestRecord(by["defihacklabs-20260902-geb"], &maps)
	if err != nil {
		t.Fatalf("IngestRecord(geb): %v", err)
	}
	if got := text(at(at(geb.EvalCase, "gold"), "bug_class")); got != "access-control" {
		t.Fatalf("geb gold bug_class = %q", got)
	}
	if len(geb.MemoryRows) == 0 {
		t.Fatal("mapped dev priors earn memory rows")
	}
	missID := ""
	for id := range by {
		if strings.HasPrefix(id, "defihacklabs-20250811") &&
			!strings.Contains(id, "bsc") {
			missID = id
		}
	}
	miss, err := ingest.IngestRecord(by[missID], &maps)
	if err != nil {
		t.Fatalf("IngestRecord(miss): %v", err)
	}
	if got := text(at(at(miss.EvalCase, "gold"), "bug_class")); got != "access-control" {
		t.Fatalf("miss gold bug_class = %q", got)
	}
	if at(at(by[missID], "exploit"), "poc_path").Kind != validation.Null {
		t.Fatal("miss record poc_path must be None")
	}
}

// The four `Integration*` tests that read the real 2.5 GB dataset clones
// (930 records + 700 PoCs under data/datasets/, repointed by WEBV2_POC_ROOT)
// were DELETED in Wave J Task 5, not converted: the data is third-party
// research material that this repository does not vendor, and the Python
// `needs_clones` skipif they carried meant they had never run in the default
// gate here — four tests that always SKIP are a lie about coverage, not
// coverage. Everything they exercised is exercised against the synthetic
// clone tree above (sampleTree): LoadRecords, the partition assignment, the
// ingest_record shape contract, and PoC-path resolution. Same precedent as
// the F2b twin-harness deletions.

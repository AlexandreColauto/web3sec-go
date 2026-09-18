// Package defihacklabs ports webv2.datasets.defihacklabs: the DeFiHackLabs +
// Incident Explorer adapter, incidents into the common ingest shape.
//
// WHY (verbatim intent): the ground-truth unit here is a real, executed
// on-chain exploit, not an audit opinion — so every record is
// confirmed-exploitable AND a capability prior (prior=True with the RCA atomic
// labels as pattern). The source dialect is messy three ways: (1) metadata
// lives in the explorer clone (incidents.json: 930 uniform rows;
// rootcause_data.json: 767 prose RCA records keyed by protocol name, joined by
// normalized name with first-in-file-order wins on the 29 collision groups);
// (2) PoCs are flat Foundry files (src/test/<YYYY-MM>/<Name>_exp.sol)
// cross-referenced by the Contract field, a commit-pinned pocLink, or a
// normalized-stem fallback — 794/930 resolve, 136 have prose but no PoC;
// (3) dates decide the leakage partition (ascending sort, most recent
// ceil(30%) held-out) and Lost is a loss magnitude, never a severity (so
// severity is None). This module owns all of that dialect so webv2.ingest only
// sees clean common-shape records; campaign seeds (records with a resolvable
// PoC) are the Phase A launch list.
package defihacklabs

import (
	"errors"
	"path/filepath"
	"regexp"

	"websec/internal/ingest"
	"websec/internal/taxonomy"
	"websec/internal/validation"
)

const (
	// Dataset is DATASET.
	Dataset = "defihacklabs"
	// ProgramKey is the campaign-known program key for the published
	// prior-knowledge rows.
	ProgramKey = "defihacklabs-prior-knowledge|other|-"
	// RepoURL is REPO_URL.
	RepoURL = "https://github.com/SunWeb3Sec/DeFiHackLabs"
	// CloneHead / ExplorerHead are the shallow-clone HEADs at recon time: the
	// only commit the on-disk PoC files are known to correspond to.
	CloneHead    = "6b882d98fca8cffee723a817796b5e57d2df2d18"
	ExplorerHead = "e46aa8fa326a6e1e0116ad4367ece2b4ccae2281"
	// HeldOutRatio is the leakage partition ratio: date-ascending sort, most
	// recent ceil(30%) held-out.
	HeldOutRatio   = 0.3
	DescriptionMax = 10000
	RootCauseMin   = 10
	RootCauseMax   = 2000
)

// RepoRoot is taxonomy.REPO_ROOT (the tree above src/webv2). A Go binary has
// no source-relative root, so the dataset paths are cwd-relative exactly like
// corpus.PocRoot; WEBV2_POC_ROOT (SetRoots) repoints them for the harness.
var RepoRoot = ""

func rootPath(parts ...string) string {
	return filepath.Join(append([]string{RepoRoot}, parts...)...)
}

// The three dataset roots, Python's EXPLORER_DIR / INCIDENTS_FILE /
// ROOTCAUSE_FILE / POC_ROOT.
var (
	ExplorerDir   = rootPath("data", "datasets", "DeFiHackLabs-Incident-Explorer")
	IncidentsFile = filepath.Join(ExplorerDir, "incidents.json")
	RootCauseFile = filepath.Join(ExplorerDir, "rootcause_data.json")
	PocRoot       = rootPath("data", "datasets", "DeFiHackLabs")
)

// SetRoots is the golden harness's WEBV2_POC_ROOT patch: the reference
// sitecustomize repoints EXPLORER_DIR/INCIDENTS_FILE/ROOTCAUSE_FILE at
// <base>/explorer and POC_ROOT at <base>/DeFiHackLabs, so the Go twin must
// resolve the same three roots from the same one variable.
func SetRoots(base string) {
	ExplorerDir = filepath.Join(base, "explorer")
	IncidentsFile = filepath.Join(ExplorerDir, "incidents.json")
	RootCauseFile = filepath.Join(ExplorerDir, "rootcause_data.json")
	PocRoot = filepath.Join(base, "DeFiHackLabs")
}

// CloneAbsentError is Python's FileNotFoundError from load_records: the
// explorer clone (or one of its two files) is absent. The corpus seam treats
// it as the documented absent-data signal.
type CloneAbsentError struct{ Path string }

func (e *CloneAbsentError) Error() string {
	return "defihacklabs explorer clone absent: " + e.Path
}

// ErrCloneAbsent matches every CloneAbsentError (errors.Is).
var ErrCloneAbsent = errors.New("defihacklabs explorer clone absent")

// Is reports the sentinel so errors.Is(err, ErrCloneAbsent) holds.
func (e *CloneAbsentError) Is(target error) bool { return target == ErrCloneAbsent }

var (
	// _FULL_SHA.
	fullSHARe = regexp.MustCompile(`^[0-9a-f]{40}$`)
	// _POCLINK_REF (Python \Z -> Go \z, strict end of text).
	pocLinkRefRe = regexp.MustCompile(`/(?:blob|tree)/([^/]+)/(.+?)(?:#.*)?\z`)
	// normalize_name's strip class.
	nonAlnumRe = regexp.MustCompile(`[^a-z0-9]+`)
	// normalize_chain's raw-id test.
	allDigitsRe = regexp.MustCompile(`^[0-9]+$`)
)

// chainAliases is _CHAIN_ALIASES.
var chainAliases = map[string]string{
	"ethereum":            "Ethereum",
	"mainnet":             "Ethereum",
	"eth":                 "Ethereum",
	"bsc":                 "BNB Chain",
	"bnb chain":           "BNB Chain",
	"binance smart chain": "BNB Chain",
	"arbitrum":            "Arbitrum",
	"base":                "Base",
	"polygon":             "Polygon",
	"avalanche":           "Avalanche",
	"optimism":            "Optimism",
	"solana":              "Solana",
	"fantom":              "Fantom",
	"linea":               "Linea",
	"blast":               "Blast",
	"gnosis":              "Gnosis",
	"cronos":              "Cronos",
	"mantle":              "Mantle",
	"moonriver":           "Moonriver",
	"maya":                "Maya",
	"mayachain":           "Maya",
	"sei":                 "Sei",
	"taiko":               "Taiko",
	"hedera":              "Hedera",
	"aztec":               "Aztec",
}

// noChain is _NO_CHAIN: the non-chain markers carrying no chain signal.
var noChain = map[string]bool{
	"": true, "unknown": true, "none": true,
	"multi-chain": true, "multichain": true,
}

// IngestOptions are ingest's keyword arguments.
type IngestOptions struct {
	Records    *[]validation.Value
	Maps       *validation.Value
	ProgramKey *string
	Tier       string
}

// Ingest is ingest: load, ingest_record each, publish. Every record becomes an
// eval case (the held-out slice is the incident benchmark); records with a
// resolvable PoC additionally yield campaign seeds (the Phase A launch list).
// Memory rows materialize only for taxonomy-mapped priors on the dev slice —
// publish_ingested holds held-out rows eval-only. tier selects the publish
// target (tests must NEVER call this against the real stores).
func Ingest(opts IngestOptions) (validation.Value, error) {
	records := opts.Records
	if records == nil {
		loaded, err := LoadRecords(nil, nil)
		if err != nil {
			return validation.VNull(), err
		}
		records = &loaded
	}
	maps := opts.Maps
	if maps == nil {
		m, err := taxonomy.LoadMaps([]string{"defihacklabs"})
		if err != nil {
			return validation.VNull(), err
		}
		maps = &m
	}
	programKey := ProgramKey
	if opts.ProgramKey != nil {
		programKey = *opts.ProgramKey
	}
	tier := opts.Tier
	if tier == "" {
		tier = "global"
	}
	results := make([]ingest.Result, 0, len(*records))
	for _, record := range *records {
		res, err := ingest.IngestRecord(record, maps)
		if err != nil {
			return validation.VNull(), err
		}
		results = append(results, res)
	}
	var seeds []validation.Value
	for i, res := range results {
		rec := (*records)[i]
		if at(at(rec, "exploit"), "poc_path").Kind == validation.Null {
			continue
		}
		if res.CampaignSeed != nil {
			seeds = append(seeds, *res.CampaignSeed)
		}
	}
	summary, err := ingest.PublishIngested(results, Dataset, &programKey, tier)
	if err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		validation.KV{K: "records", V: validation.VArr(*records...)},
		validation.KV{K: "results", V: validation.VArr(resultValues(results)...)},
		validation.KV{K: "campaign_seeds", V: validation.VArr(seeds...)},
		validation.KV{K: "publish", V: summary.Value()},
	), nil
}

// resultValues renders the ingest results as Python's list of dicts.
func resultValues(results []ingest.Result) []validation.Value {
	out := make([]validation.Value, len(results))
	for i, r := range results {
		out[i] = r.Value()
	}
	return out
}

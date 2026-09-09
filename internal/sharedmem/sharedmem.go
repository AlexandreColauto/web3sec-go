// Package sharedmem is a 1:1 port of webv2/shared_memory.py: the
// cross-campaign store of DERIVED knowledge (capability signatures of
// CONFIRMED findings/CHAINs plus human-approved memory rows), in two tiers
// (root + user-global), with a hash-chained manifest, a sanctioned
// scope-change operation, a derived advisory recall, and a verifier.
package sharedmem

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"websec/internal/capabilities"
	"websec/internal/chainengine"
	"websec/internal/findings"
	"websec/internal/learning"
	"websec/internal/state"
	"websec/internal/validation"
)

// StoreDirname is _STORE_DIRNAME.
const StoreDirname = "shared-memory"

const (
	sigsName     = "signatures.json"
	memName      = "memory.json"
	manifestName = "manifest.json"
)

// PublishableStatuses is _PUBLISHABLE_STATUSES.
var PublishableStatuses = []string{"CONFIRMED", "CHAIN"}

// ApprovedMemory is _APPROVED_MEMORY.
var ApprovedMemory = []string{"human-approved", "promoted"}

// Scopes is _SCOPES.
var Scopes = []string{"program", "global"}

// ---- store locations + IO --------------------------------------------------

// StoreDir is store_dir: the ROOT-tier store (shared by every campaign
// under this root).
func StoreDir(root string) string {
	return filepath.Join(root, StoreDirname)
}

// GlobalStoreDir is global_store_dir: the USER-GLOBAL tier.
// $WEBV2_GLOBAL_MEMORY_DIR overrides the location.
func GlobalStoreDir() string {
	if override := os.Getenv("WEBV2_GLOBAL_MEMORY_DIR"); override != "" {
		if strings.HasPrefix(override, "~") {
			home, err := os.UserHomeDir()
			if err == nil {
				override = filepath.Join(home, strings.TrimPrefix(override, "~"))
			}
		}
		return override
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".webv2", StoreDirname)
	}
	return filepath.Join(home, ".webv2", StoreDirname)
}

// StoreDirs is store_dirs: every store a campaign under `root` reads from,
// in precedence order (root tier first), deduped by resolved path.
func StoreDirs(root string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, d := range []string{StoreDir(root), GlobalStoreDir()} {
		key := resolvePath(d)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, d)
	}
	return out
}

func resolvePath(p string) string {
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		return real
	}
	return p
}

func sigsPath(store string) string     { return filepath.Join(store, sigsName) }
func memPath(store string) string      { return filepath.Join(store, memName) }
func manifestPath(store string) string { return filepath.Join(store, manifestName) }

// loadList is _load_list.
func loadList(path string) ([]validation.Value, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	data, err := validation.ReadJson(path)
	if err != nil {
		return nil, err
	}
	if data.Kind != validation.Arr {
		return nil, fmt.Errorf("%s must be a list", filepath.Base(path))
	}
	return data.A, nil
}

func tierSignatures(store string) ([]validation.Value, error) {
	return loadList(sigsPath(store))
}

func tierMemory(store string) ([]validation.Value, error) {
	return loadList(memPath(store))
}

func tierManifest(store string) ([]validation.Value, error) {
	return loadList(manifestPath(store))
}

// recordHash is _record_hash: sha256 over the sorted-keys, ASCII-safe JSON
// of the record body (record_hash itself excluded).
func recordHash(record validation.Value) string {
	body := validation.VObj()
	for _, kv := range record.O {
		if kv.K == "record_hash" {
			continue
		}
		body.O = append(body.O, kv)
	}
	sum := sha256.Sum256([]byte(validation.CanonSpaced(body)))
	return hex.EncodeToString(sum[:])
}

// manifestAppend is _manifest_append: append a HASH-CHAINED record.
func manifestAppend(store string, record validation.Value) (validation.Value, error) {
	manifest, err := tierManifest(store)
	if err != nil {
		return validation.VNull(), err
	}
	prev := strings.Repeat("0", 64)
	for i := len(manifest) - 1; i >= 0; i-- {
		if h, ok := fieldAt(manifest[i], "record_hash"); ok {
			prev = pyStr(h)
			break
		}
	}
	rec := validation.VObj()
	rec.O = append(rec.O, record.O...)
	rec.O = append(rec.O, kv("prev_hash", validation.VStr(prev)))
	rec.O = append(rec.O, kv("record_hash", validation.VStr(recordHash(rec))))
	manifest = append(manifest, rec)
	if err := validation.WriteJson(manifestPath(store),
		validation.VArr(manifest...), ""); err != nil {
		return validation.VNull(), err
	}
	return rec, nil
}

// merge is _merge: concatenate tiers in precedence order, dedupe by key;
// with preferGlobal a scope=global copy wins over a scope=program one.
func merge(rows [][]validation.Value, keyOf func(validation.Value) string,
	preferGlobal bool) []validation.Value {
	out := []validation.Value{}
	index := map[string]int{}
	for _, rowset := range rows {
		for _, r := range rowset {
			k := keyOf(r)
			if i, ok := index[k]; ok {
				if preferGlobal && objStr(r, "scope") == "global" &&
					objStr(out[i], "scope") != "global" {
					out[i] = r
				}
				continue
			}
			index[k] = len(out)
			out = append(out, r)
		}
	}
	return out
}

// LoadSignatures is load_signatures: capability signatures across every
// tier this campaign can see.
func LoadSignatures(root string) ([]validation.Value, error) {
	sets := [][]validation.Value{}
	for _, d := range StoreDirs(root) {
		ts, err := tierSignatures(d)
		if err != nil {
			return nil, err
		}
		sets = append(sets, ts)
	}
	return merge(sets, sigKey, true), nil
}

// LoadSharedMemory is load_shared_memory: approved memory rows across every
// tier, deduped by memory_id. It is the corpus/findings seam target.
func LoadSharedMemory(root string) ([]validation.Value, error) {
	sets := [][]validation.Value{}
	for _, d := range StoreDirs(root) {
		tm, err := tierMemory(d)
		if err != nil {
			return nil, err
		}
		sets = append(sets, tm)
	}
	return merge(sets, func(w validation.Value) string {
		return objStr(objAt(w, "row"), "memory_id")
	}, true), nil
}

// LoadManifest is load_manifest: publish/scope records across every tier,
// ordered by time.
func LoadManifest(root string) ([]validation.Value, error) {
	merged := []validation.Value{}
	for _, d := range StoreDirs(root) {
		tm, err := tierManifest(d)
		if err != nil {
			return nil, err
		}
		merged = append(merged, tm...)
	}
	sort.SliceStable(merged, func(i, j int) bool {
		ai, aj := objStr(merged[i], "at"), objStr(merged[j], "at")
		if ai != aj {
			return ai < aj
		}
		return objStr(merged[i], "record_id") < objStr(merged[j], "record_id")
	})
	return merged, nil
}

// fileSha256 is _file_sha256: "" when the file does not exist.
func fileSha256(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return validation.Sha256Hex(raw)
}

// StoreView is store_view: counts + program keys present.
func StoreView(root string) (validation.Value, error) {
	sigs, err := LoadSignatures(root)
	if err != nil {
		return validation.VNull(), err
	}
	mems, err := LoadSharedMemory(root)
	if err != nil {
		return validation.VNull(), err
	}
	tiers := []validation.Value{}
	globalDir := GlobalStoreDir()
	for _, d := range StoreDirs(root) {
		ts, err := tierSignatures(d)
		if err != nil {
			return validation.VNull(), err
		}
		tm, err := tierMemory(d)
		if err != nil {
			return validation.VNull(), err
		}
		tier := "root"
		if filepath.Clean(d) == filepath.Clean(globalDir) {
			tier = "global"
		}
		_, statErr := os.Stat(d)
		globalRows := 0
		for _, r := range append(append([]validation.Value{}, ts...), tm...) {
			if objStr(r, "scope") == "global" {
				globalRows++
			}
		}
		man, err := tierManifest(d)
		if err != nil {
			return validation.VNull(), err
		}
		tiers = append(tiers, validation.VObj(
			kv("dir", validation.VStr(d)),
			kv("tier", validation.VStr(tier)),
			kv("exists", validation.VBool(statErr == nil)),
			kv("signature_count", validation.VInt(int64(len(ts)))),
			kv("memory_count", validation.VInt(int64(len(tm)))),
			kv("global_scope_rows", validation.VInt(int64(globalRows))),
			kv("publish_records", validation.VInt(int64(len(man))))))
	}
	programs := map[string]struct{}{}
	for _, s := range sigs {
		programs[objStr(s, "program_key")] = struct{}{}
	}
	for _, m := range mems {
		if k := objStr(m, "program_key"); k != "" {
			programs[k] = struct{}{}
		}
	}
	globalRows := 0
	for _, m := range mems {
		if objStr(m, "scope") == "global" {
			globalRows++
		}
	}
	manifest, err := LoadManifest(root)
	if err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		kv("store", validation.VStr(StoreDir(root))),
		kv("global_store", validation.VStr(GlobalStoreDir())),
		kv("signature_count", validation.VInt(int64(len(sigs)))),
		kv("memory_count", validation.VInt(int64(len(mems)))),
		kv("global_scope_memory_rows", validation.VInt(int64(globalRows))),
		kv("publish_records", validation.VInt(int64(len(manifest)))),
		kv("programs", strArr(sortedKeys(programs))),
		kv("tiers", validation.VArr(tiers...))), nil
}

// ---- program identity ------------------------------------------------------

// programKey is _program_key.
func programKey(policy validation.Value) (string, validation.Value, error) {
	program := strings.TrimSpace(objStr(policy, "program"))
	platform := strings.TrimSpace(objStr(policy, "platform"))
	var platformV validation.Value = validation.VNull()
	if platform != "" {
		platformV = validation.VStr(platform)
	}
	chains := strList(objAt(policy, "chains"))
	sort.Strings(chains)
	if program == "" {
		return "", validation.VNull(), errors.New(
			"policy has no program name — cannot derive a program key")
	}
	platformPart := platform
	if platformPart == "" {
		platformPart = "-"
	}
	key := program + "|" + platformPart + "|" + strings.Join(chains, ",")
	return key, validation.VObj(
		kv("program", validation.VStr(program)),
		kv("platform", platformV),
		kv("chains", strArr(chains))), nil
}

// ProgramKeyOf is program_key_of: the campaign's program identity, from its
// loaded bounty policy.
func ProgramKeyOf(c *state.Campaign) (string, validation.Value, error) {
	st, err := c.State()
	if err != nil {
		return "", validation.VNull(), err
	}
	policyPath := objStr(st, "policy_path")
	if policyPath == "" {
		return "", validation.VNull(), noPolicyErr(c)
	}
	if _, err := os.Stat(policyPath); err != nil {
		return "", validation.VNull(), noPolicyErr(c)
	}
	policy, err := validation.ReadJson(policyPath)
	if err != nil {
		return "", validation.VNull(), err
	}
	return programKey(policy)
}

func noPolicyErr(c *state.Campaign) error {
	return fmt.Errorf("%s: no policy loaded — run scope(policy_path=...) "+
		"before sharing or recalling", c.CampaignID)
}

// ---- signature derivation (pure) -------------------------------------------

// terminalOf is _terminal_of: the first sorted granted terminal capability.
func terminalOf(granted []string) *string {
	sorted := append([]string{}, granted...)
	sort.Strings(sorted)
	for _, cap := range sorted {
		if capabilities.IsTerminal(cap) {
			return &cap
		}
	}
	return nil
}

// CodeSourced is code_sourced: the union of granted labels over every live
// finding in the campaign.
func CodeSourced(c *state.Campaign) (map[string]struct{}, error) {
	out := map[string]struct{}{}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return nil, err
	}
	for _, f := range all {
		if s := objStr(f, "status"); s == "DUPLICATE" || s == "OUT_OF_SCOPE" {
			continue
		}
		for _, lab := range capabilities.Granted(f) {
			out[lab] = struct{}{}
		}
	}
	return out, nil
}

// DeriveSignature is derive_signature: the capability-level signature of a
// finding/chain, from the EXPLICIT capability lists only.
func DeriveSignature(f validation.Value, key string, program validation.Value,
	campaignID string, codeSourced map[string]struct{}) validation.Value {
	caps := objAt(f, "capabilities")
	if caps.Kind != validation.Obj {
		caps = validation.VObj()
	}
	granted := sortedStrings(capabilities.NormalizeLabels(
		strList(objAt(caps, "granted"))))
	required := sortedStrings(capabilities.NormalizeLabels(
		strList(objAt(caps, "required"))))
	codeSourcedRequired := []string{}
	for _, r := range required {
		if _, ok := codeSourced[r]; ok {
			codeSourcedRequired = append(codeSourcedRequired, r)
		}
	}
	terminal := terminalOf(granted)
	terminalStr := ""
	if terminal != nil {
		terminalStr = *terminal
	}
	csig := findings.TextSignature("sig|" + key + "|" + strings.Join(granted, ",") +
		"|" + strings.Join(required, ",") + "|" + terminalStr)
	class := "unknown"
	if rc := objAt(f, "root_cause"); rc.Kind == validation.Obj {
		if c := objStr(rc, "class"); c != "" {
			class = c
		}
	}
	return validation.VObj(
		kv("program_key", validation.VStr(key)),
		kv("program", program),
		kv("bug_class", validation.VStr(class)),
		kv("granted", strArr(granted)),
		kv("required", strArr(required)),
		kv("code_sourced_required", strArr(codeSourcedRequired)),
		kv("terminal", strOrNull(terminal)),
		kv("capability_signature", validation.VStr(csig)),
		kv("title", objAt(f, "title")),
		kv("source", validation.VObj(
			kv("campaign_id", validation.VStr(campaignID)),
			kv("finding_id", validation.VStr(objStr(f, "finding_id"))))))
}

// sigKey is _sig_key.
func sigKey(sig validation.Value) string {
	src := objAt(sig, "source")
	return objStr(sig, "program_key") + "\x00" +
		objStr(sig, "capability_signature") + "\x00" +
		objStr(src, "campaign_id") + "\x00" + objStr(src, "finding_id")
}

// ---- publish ---------------------------------------------------------------

// PublishCampaign is publish_campaign: explicit, logged, actor-attributed,
// idempotent.
func PublishCampaign(c *state.Campaign, actor string,
	toGlobal bool) (validation.Value, error) {
	if actor == "" {
		return validation.VNull(), errors.New("publish requires a recorded " +
			"actor — cross-campaign sharing is a boundary-crossing act")
	}
	key, program, err := ProgramKeyOf(c)
	if err != nil {
		return validation.VNull(), err
	}
	store := StoreDir(c.Root)
	tier := "root"
	if toGlobal {
		store = GlobalStoreDir()
		tier = "global"
	}
	sigs, err := tierSignatures(store)
	if err != nil {
		return validation.VNull(), err
	}
	mems, err := tierMemory(store)
	if err != nil {
		return validation.VNull(), err
	}
	sigKeys := map[string]struct{}{}
	for _, s := range sigs {
		sigKeys[sigKey(s)] = struct{}{}
	}
	memIDs := map[string]struct{}{}
	for _, m := range mems {
		memIDs[objStr(objAt(m, "row"), "memory_id")] = struct{}{}
	}
	cs, err := CodeSourced(c)
	if err != nil {
		return validation.VNull(), err
	}
	sigsAdded, publishableFindings := 0, 0
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return validation.VNull(), err
	}
	for _, f := range all {
		if !inList(objStr(f, "status"), PublishableStatuses) {
			continue
		}
		publishableFindings++
		sig := DeriveSignature(f, key, program, c.CampaignID, cs)
		if _, ok := sigKeys[sigKey(sig)]; ok {
			continue
		}
		full := validation.VObj()
		full.O = append(full.O, kv("signature_id",
			validation.VStr("SIG-"+idTail(8))))
		full.O = append(full.O, sig.O...)
		full.O = append(full.O, kv("created_at", validation.VStr(state.NowIso())))
		if err := validation.Validate(full, "shared_signature", 1); err != nil {
			return validation.VNull(), err
		}
		sigs = append(sigs, full)
		sigKeys[sigKey(full)] = struct{}{}
		sigsAdded++
	}
	memAdded, approvedRows := 0, 0
	rows, err := learning.AllMemory(c)
	if err != nil {
		return validation.VNull(), err
	}
	for _, m := range rows {
		if !inList(objStr(m, "promotion_status"), ApprovedMemory) {
			continue
		}
		approvedRows++
		mid := objStr(m, "memory_id")
		if _, ok := memIDs[mid]; ok {
			continue
		}
		// Leakage-partition guard (dataset-ingestion sprint, constraint 4).
		partition := objStr(m, "partition")
		if partition == "" {
			partition = "dev"
		}
		if partition != "dev" {
			return validation.VNull(), fmt.Errorf("%s has partition %s: "+
				"'held-out'/'training' rows never enter the shared store "+
				"(leakage-partition constraint 4)", mid, validation.PyReprStr(partition))
		}
		wrapper := validation.VObj(
			kv("program_key", validation.VStr(key)),
			kv("published_at", validation.VStr(state.NowIso())),
			kv("row", m))
		if err := validation.Validate(wrapper, "shared_memory_row", 1); err != nil {
			return validation.VNull(), err
		}
		if err := validation.Validate(m, "memory", 1); err != nil {
			return validation.VNull(), err
		}
		mems = append(mems, wrapper)
		memIDs[mid] = struct{}{}
		memAdded++
	}
	if err := writeStore(store, sigs, mems); err != nil {
		return validation.VNull(), err
	}
	record := validation.VObj(
		kv("record_id", validation.VStr("PUB-"+idTail(8))),
		kv("campaign_id", validation.VStr(c.CampaignID)),
		kv("program_key", validation.VStr(key)),
		kv("actor", validation.VStr(actor)),
		kv("at", validation.VStr(state.NowIso())),
		kv("tier", validation.VStr(tier)),
		kv("signatures_added", validation.VInt(int64(sigsAdded))),
		kv("memory_added", validation.VInt(int64(memAdded))),
		kv("signatures_sha256", validation.VStr(fileSha256(sigsPath(store)))),
		kv("memory_sha256", validation.VStr(fileSha256(memPath(store)))))
	record, err = manifestAppend(store, record)
	if err != nil {
		return validation.VNull(), err
	}
	rid := objStr(record, "record_id")
	data := validation.VObj(
		kv("program_key", validation.VStr(key)),
		kv("signatures_added", validation.VInt(int64(sigsAdded))),
		kv("memory_added", validation.VInt(int64(memAdded))),
		kv("tier", validation.VStr(tier)),
		kv("actor", validation.VStr(actor)))
	if _, err := c.Log("shared.published", &rid, &data); err != nil {
		return validation.VNull(), err
	}
	var noop validation.Value = validation.VNull()
	if sigsAdded == 0 && memAdded == 0 {
		reasons := []string{}
		if publishableFindings == 0 {
			reasons = append(reasons, "no CONFIRMED finding or CHAIN to "+
				"publish (only confirmed knowledge crosses)")
		} else {
			reasons = append(reasons, fmt.Sprintf("all %d publishable "+
				"finding(s) already have a signature in the %s store",
				publishableFindings, tier))
		}
		if approvedRows == 0 {
			reasons = append(reasons, "no human-approved memory row for this program")
		} else {
			reasons = append(reasons, fmt.Sprintf("all %d approved memory "+
				"row(s) are already published to the %s store", approvedRows, tier))
		}
		next := []string{}
		if publishableFindings == 0 {
			next = append(next, "webv2 move "+c.CampaignID+" <F-...> "+
				"CONFIRMED --reason '...'")
		}
		if approvedRows == 0 {
			next = append(next, "webv2 memory "+c.CampaignID+
				" --approve MEM-... --by NAME")
		}
		noop = validation.VObj(
			kv("reasons", strArr(reasons)),
			kv("next", strArr(next)))
	}
	return validation.VObj(
		kv("record_id", validation.VStr(rid)),
		kv("program_key", validation.VStr(key)),
		kv("signatures_added", validation.VInt(int64(sigsAdded))),
		kv("memory_added", validation.VInt(int64(memAdded))),
		kv("tier", validation.VStr(tier)),
		kv("store", validation.VStr(store)),
		kv("noop", noop)), nil
}

// writeStore is _write_store.
func writeStore(store string, sigs, mems []validation.Value) error {
	if err := os.MkdirAll(store, 0o755); err != nil {
		return err
	}
	if err := validation.WriteJson(sigsPath(store), validation.VArr(sigs...), ""); err != nil {
		return err
	}
	return validation.WriteJson(memPath(store), validation.VArr(mems...), "")
}

// ---- scope -----------------------------------------------------------------

// SetScope is set_scope: the sanctioned visibility change. programKey == ""
// means "every row in the tier" (Python: program_key=None).
func SetScope(root, scope, actor, programKey string, tier string) (validation.Value, error) {
	if !inList(scope, Scopes) {
		return validation.VNull(), fmt.Errorf("scope must be one of %s",
			pyTuple(Scopes))
	}
	if actor == "" {
		return validation.VNull(), errors.New("scope changes require a " +
			"recorded actor")
	}
	store := StoreDir(root)
	if tier == "global" {
		store = GlobalStoreDir()
	}
	if _, err := os.Stat(store); err != nil {
		return validation.VNull(), fmt.Errorf("no %s-tier store at %s — "+
			"nothing to re-scope", tier, store)
	}
	sigs, err := tierSignatures(store)
	if err != nil {
		return validation.VNull(), err
	}
	mems, err := tierMemory(store)
	if err != nil {
		return validation.VNull(), err
	}
	sigsChanged, memsChanged := 0, 0
	for i := range sigs {
		if programKey != "" && objStr(sigs[i], "program_key") != programKey {
			continue
		}
		if scopeOf(sigs[i]) == scope {
			continue
		}
		sigs[i] = applyScope(sigs[i], scope)
		if err := validation.Validate(sigs[i], "shared_signature", 1); err != nil {
			return validation.VNull(), err
		}
		sigsChanged++
	}
	for i := range mems {
		if programKey != "" && objStr(mems[i], "program_key") != programKey {
			continue
		}
		if scopeOf(mems[i]) == scope {
			continue
		}
		mems[i] = applyScope(mems[i], scope)
		if err := validation.Validate(mems[i], "shared_memory_row", 1); err != nil {
			return validation.VNull(), err
		}
		memsChanged++
	}
	if err := writeStore(store, sigs, mems); err != nil {
		return validation.VNull(), err
	}
	recordKey := programKey
	if recordKey == "" {
		recordKey = "*"
	}
	record := validation.VObj(
		kv("record_id", validation.VStr("SCP-"+idTail(8))),
		kv("action", validation.VStr("scope.changed")),
		kv("tier", validation.VStr(tier)),
		kv("scope", validation.VStr(scope)),
		kv("program_key", validation.VStr(recordKey)),
		kv("actor", validation.VStr(actor)),
		kv("at", validation.VStr(state.NowIso())),
		kv("signatures_updated", validation.VInt(int64(sigsChanged))),
		kv("memory_updated", validation.VInt(int64(memsChanged))),
		kv("signatures_sha256", validation.VStr(fileSha256(sigsPath(store)))),
		kv("memory_sha256", validation.VStr(fileSha256(memPath(store)))))
	record, err = manifestAppend(store, record)
	if err != nil {
		return validation.VNull(), err
	}
	return validation.VObj(
		kv("record_id", validation.VStr(objStr(record, "record_id"))),
		kv("tier", validation.VStr(tier)),
		kv("scope", validation.VStr(scope)),
		kv("program_key", validation.VStr(recordKey)),
		kv("signatures_updated", validation.VInt(int64(sigsChanged))),
		kv("memory_updated", validation.VInt(int64(memsChanged))),
		kv("store", validation.VStr(store))), nil
}

// scopeOf is (row.get("scope") or "program").
func scopeOf(row validation.Value) string {
	if s := objStr(row, "scope"); s != "" {
		return s
	}
	return "program"
}

// applyScope sets scope=global (in place when present, else appended) or
// removes the key (absent == program).
func applyScope(row validation.Value, scope string) validation.Value {
	out := validation.VObj()
	for _, item := range row.O {
		if item.K == "scope" {
			if scope == "global" {
				out.O = append(out.O, kv("scope", validation.VStr("global")))
			}
			continue
		}
		out.O = append(out.O, item)
	}
	if scope == "global" {
		if _, ok := fieldAt(out, "scope"); !ok {
			out.O = append(out.O, kv("scope", validation.VStr("global")))
		}
	}
	return out
}

// ---- recall ----------------------------------------------------------------

// candidateProvides is _candidate_provides.
func candidateProvides(c *state.Campaign, candidate validation.Value) (map[string]struct{}, error) {
	pin := objStr(objAt(candidate, "snapshot_ids"), "source")
	provides := map[string]struct{}{}
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return nil, err
	}
	for _, f := range all {
		if s := objStr(f, "status"); s == "DUPLICATE" || s == "OUT_OF_SCOPE" {
			continue
		}
		if objStr(objAt(f, "snapshot_ids"), "source") != pin {
			continue
		}
		for _, lab := range capabilities.Granted(f) {
			provides[lab] = struct{}{}
		}
	}
	return provides, nil
}

// kwOverlap is _kw_overlap: words longer than 3 code points shared.
func kwOverlap(a, b string) bool {
	wa := map[string]struct{}{}
	for _, w := range learning.ReSplit(a) {
		if utf8.RuneCountInString(w) > 3 {
			wa[w] = struct{}{}
		}
	}
	for _, w := range learning.ReSplit(b) {
		if utf8.RuneCountInString(w) > 3 {
			if _, ok := wa[w]; ok {
				return true
			}
		}
	}
	return false
}

// Recall is recall: the derived, advisory cross-campaign query.
func Recall(c *state.Campaign, candidateID string) (validation.Value, error) {
	cand, err := findings.LoadFinding(c, candidateID)
	if err != nil {
		return validation.VNull(), err
	}
	candClass := objStr(objAt(cand, "root_cause"), "class")
	candGranted := map[string]struct{}{}
	for _, lab := range capabilities.Granted(cand) {
		candGranted[lab] = struct{}{}
	}
	provides, err := candidateProvides(c, cand)
	if err != nil {
		return validation.VNull(), err
	}
	key, _, keyErr := ProgramKeyOf(c)
	hasKey := keyErr == nil
	if !hasKey {
		key = ""
	}
	visible := func(rowKey string) bool {
		if !hasKey {
			return false
		}
		return rowKey == key
	}
	sigs, err := LoadSignatures(c.Root)
	if err != nil {
		return validation.VNull(), err
	}
	matches := []validation.Value{}
	for _, s := range sigs {
		if objStr(s, "scope") != "global" && !visible(objStr(s, "program_key")) {
			continue
		}
		if objStr(objAt(s, "source"), "campaign_id") == c.CampaignID {
			continue
		}
		sigGranted := strList(objAt(s, "granted"))
		var sim validation.Value = validation.VNull()
		if len(candGranted) > 0 || len(sigGranted) > 0 {
			overlap, union := 0, 0
			for lab := range candGranted {
				union++
				if inList(lab, sigGranted) {
					overlap++
				}
			}
			for _, lab := range sigGranted {
				if _, ok := candGranted[lab]; !ok {
					union++
				}
			}
			if union > 0 {
				sim = validation.VFloat(validation.PyRound(
					float64(overlap)/float64(union), 3))
			}
		}
		classMatch := candClass == objStr(s, "bug_class")
		if !classMatch && simOf(sim) <= 0 {
			continue
		}
		dependsSet := map[string]struct{}{}
		source := objAt(s, "code_sourced_required")
		if source.Kind != validation.Arr {
			source = objAt(s, "required")
		}
		for _, lab := range strList(source) {
			if inList(lab, chainengine.AttackerBaseline) {
				continue
			}
			dependsSet[lab] = struct{}{}
		}
		missing := []string{}
		for lab := range dependsSet {
			if _, ok := provides[lab]; !ok {
				missing = append(missing, lab)
			}
		}
		sort.Strings(missing)
		stillProvided := []string{}
		for lab := range dependsSet {
			if _, ok := provides[lab]; ok {
				stillProvided = append(stillProvided, lab)
			}
		}
		sort.Strings(stillProvided)
		dependsSorted := sortedKeys(dependsSet)
		advisory := []string{}
		if len(missing) > 0 {
			advisory = append(advisory, fmt.Sprintf("the confirmed primitive "+
				"%s required %s; the candidate's snapshot reality no longer "+
				"provides %s — a patch may have removed exactly those",
				objStr(objAt(s, "source"), "finding_id"),
				pyReprList(dependsSorted), pyReprList(missing)))
		} else {
			advisory = append(advisory, "every capability the confirmed "+
				"primitive depended on is still provided by the candidate's "+
				"snapshot reality — treat the primitive as still live here")
		}
		matches = append(matches, validation.VObj(
			kv("signature_id", objAt(s, "signature_id")),
			kv("source", objAt(s, "source")),
			kv("title", objAt(s, "title")),
			kv("bug_class", objAt(s, "bug_class")),
			kv("class_match", validation.VBool(classMatch)),
			kv("similarity", sim),
			kv("primitive_depended_on", strArr(dependsSorted)),
			kv("still_provided", strArr(stillProvided)),
			kv("missing", strArr(missing)),
			kv("terminal", objAt(s, "terminal")),
			kv("advisory", validation.VStr(strings.Join(advisory, " ")))))
	}
	sort.SliceStable(matches, func(i, j int) bool {
		mi, mj := !objAt(matches[i], "class_match").B,
			!objAt(matches[j], "class_match").B
		if mi != mj {
			return !mi
		}
		si, sj := simOf(objAt(matches[i], "similarity")),
			simOf(objAt(matches[j], "similarity"))
		if si != sj {
			return si > sj
		}
		return len(objAt(matches[i], "missing").A) <
			len(objAt(matches[j], "missing").A)
	})
	shared, err := LoadSharedMemory(c.Root)
	if err != nil {
		return validation.VNull(), err
	}
	memHits := []validation.Value{}
	for _, w := range shared {
		if objStr(w, "scope") != "global" && !visible(objStr(w, "program_key")) {
			continue
		}
		m := objAt(w, "row")
		if objStr(m, "campaign_id") == c.CampaignID {
			continue
		}
		text := candClass + " " + objStr(cand, "title") + " " +
			objStr(objAt(cand, "root_cause"), "description")
		bugClass := objStr(m, "bug_class")
		if (bugClass != "" && bugClass == candClass) ||
			kwOverlap(objStr(m, "pattern"), text) {
			memHits = append(memHits, validation.VObj(
				kv("memory_id", objAt(m, "memory_id")),
				kv("status", objAt(m, "status")),
				kv("kind", objAt(m, "kind")),
				kv("pattern", objAt(m, "pattern")),
				kv("bug_class", objAt(m, "bug_class")),
				kv("source_campaign", objAt(m, "campaign_id"))))
		}
	}
	sort.SliceStable(memHits, func(i, j int) bool {
		return objStr(memHits[i], "memory_id") < objStr(memHits[j], "memory_id")
	})
	prefix := ""
	var programKeyV validation.Value = validation.VNull()
	if !hasKey {
		prefix = "no program identity (policy not loaded) — only " +
			"global-scope rows recalled; "
	} else {
		programKeyV = validation.VStr(key)
	}
	return validation.VObj(
		kv("candidate_id", validation.VStr(candidateID)),
		kv("candidate_class", validation.VStr(candClass)),
		kv("program_key", programKeyV),
		kv("shared_signatures", validation.VArr(matches...)),
		kv("shared_memory", validation.VArr(memHits...)),
		kv("note", validation.VStr(prefix+"derived, advisory cross-campaign "+
			"query — nothing stored, no status moves; capabilities come from "+
			"the candidate's own snapshot reality, the store only records "+
			"what primitives depend on"))), nil
}

// ---- verification ----------------------------------------------------------

// verifyTier is _verify_tier.
func verifyTier(store string) validation.Value {
	if _, err := os.Stat(store); err != nil {
		return validation.VObj(
			kv("dir", validation.VStr(store)),
			kv("exists", validation.VBool(false)),
			kv("ok", validation.VBool(true)),
			kv("problems", validation.VArr()),
			kv("signature_count", validation.VInt(0)),
			kv("memory_count", validation.VInt(0)),
			kv("publish_records", validation.VInt(0)))
	}
	problems := []string{}
	sigs, err := tierSignatures(store)
	if err != nil {
		problems = append(problems, err.Error())
		sigs = nil
	}
	mems, err := tierMemory(store)
	if err != nil {
		problems = append(problems, err.Error())
		mems = nil
	}
	manifest, err := tierManifest(store)
	if err != nil {
		problems = append(problems, err.Error())
		manifest = nil
	}
	for i, s := range sigs {
		if err := validation.Validate(s, "shared_signature", 1); err != nil {
			problems = append(problems, fmt.Sprintf("signatures[%d]: %s", i, err))
		}
	}
	for i, w := range mems {
		if err := validation.Validate(w, "shared_memory_row", 1); err != nil {
			problems = append(problems, fmt.Sprintf("memory[%d]: %s", i, err))
			continue
		}
		if err := validation.Validate(objAt(w, "row"), "memory", 1); err != nil {
			problems = append(problems, fmt.Sprintf("memory[%d]: %s", i, err))
		}
	}
	if len(manifest) > 0 {
		last := manifest[len(manifest)-1]
		if fileSha256(sigsPath(store)) != objStr(last, "signatures_sha256") {
			problems = append(problems, "signatures.json does not match the "+
				"last publish record's hash — the store was modified outside "+
				"`publish`")
		}
		if fileSha256(memPath(store)) != objStr(last, "memory_sha256") {
			problems = append(problems, "memory.json does not match the last "+
				"publish record's hash — the store was modified outside `publish`")
		}
		expected := strings.Repeat("0", 64)
		for _, r := range manifest {
			if _, ok := fieldAt(r, "record_hash"); !ok {
				continue // legacy record: readable, not part of the chain
			}
			rid := objStr(r, "record_id")
			if rid == "" {
				rid = "?"
			}
			if objStr(r, "prev_hash") != expected {
				problems = append(problems, fmt.Sprintf("manifest %s: "+
					"prev_hash breaks the chain", rid))
			}
			if recordHash(r) != objStr(r, "record_hash") {
				problems = append(problems, fmt.Sprintf("manifest %s: "+
					"record_hash does not recompute (record edited?)", rid))
			}
			expected = objStr(r, "record_hash")
		}
	} else if len(sigs) > 0 || len(mems) > 0 {
		problems = append(problems, "data present but no publish record — the "+
			"store was not created by `publish`")
	}
	return validation.VObj(
		kv("dir", validation.VStr(store)),
		kv("exists", validation.VBool(true)),
		kv("ok", validation.VBool(len(problems) == 0)),
		kv("problems", strArr(problems)),
		kv("signature_count", validation.VInt(int64(len(sigs)))),
		kv("memory_count", validation.VInt(int64(len(mems)))),
		kv("publish_records", validation.VInt(int64(len(manifest)))))
}

// VerifySharedStore is verify_shared_store: verify EVERY tier this campaign
// can see (root + user-global).
func VerifySharedStore(root string) (validation.Value, error) {
	tiers := []validation.Value{}
	problems := []string{}
	present := []validation.Value{}
	for _, d := range StoreDirs(root) {
		t := verifyTier(d)
		tiers = append(tiers, t)
		for _, p := range objAt(t, "problems").A {
			problems = append(problems, d+": "+p.S)
		}
		if objAt(t, "exists").B {
			present = append(present, t)
		}
	}
	if len(present) == 0 {
		return validation.VObj(
			kv("exists", validation.VBool(false)),
			kv("ok", validation.VBool(true)),
			kv("problems", validation.VArr()),
			kv("signature_count", validation.VInt(0)),
			kv("memory_count", validation.VInt(0)),
			kv("publish_records", validation.VInt(0)),
			kv("tiers", validation.VArr(tiers...)),
			kv("note", validation.VStr("no shared store yet — nothing "+
				"published (root or global tier)"))), nil
	}
	total := func(field string) int64 {
		var n int64
		for _, t := range present {
			n += objAt(t, field).I
		}
		return n
	}
	return validation.VObj(
		kv("exists", validation.VBool(true)),
		kv("ok", validation.VBool(len(problems) == 0)),
		kv("problems", strArr(problems)),
		kv("signature_count", validation.VInt(total("signature_count"))),
		kv("memory_count", validation.VInt(total("memory_count"))),
		kv("publish_records", validation.VInt(total("publish_records"))),
		kv("tiers", validation.VArr(tiers...))), nil
}

// ---- migration -------------------------------------------------------------

// MigrateStripField is migrate_strip_field: manifest-logged removal of a
// dead field from every stored row. Idempotent.
func MigrateStripField(root, field, actor, reason string) (validation.Value, error) {
	tiersOut := []validation.Value{}
	records := []validation.Value{}
	for _, store := range StoreDirs(root) {
		path := memPath(store)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		wrappers, err := loadList(path)
		if err != nil {
			return validation.VNull(), err
		}
		stripped := 0
		newWrappers := []validation.Value{}
		for _, w := range wrappers {
			row := validation.VObj()
			had := false
			for _, item := range objAt(w, "row").O {
				if item.K == field {
					had = true
					continue
				}
				row.O = append(row.O, item)
			}
			if had {
				stripped++
			}
			next := validation.VObj()
			for _, item := range w.O {
				if item.K == "row" {
					next.O = append(next.O, kv("row", row))
					continue
				}
				next.O = append(next.O, item)
			}
			newWrappers = append(newWrappers, next)
		}
		if stripped == 0 {
			tiersOut = append(tiersOut, validation.VObj(
				kv("dir", validation.VStr(store)),
				kv("rows_stripped", validation.VInt(0))))
			continue
		}
		if err := validation.WriteJson(path, validation.VArr(newWrappers...), ""); err != nil {
			return validation.VNull(), err
		}
		record, err := manifestAppend(store, validation.VObj(
			kv("op", validation.VStr("field-strip")),
			kv("field", validation.VStr(field)),
			kv("actor", validation.VStr(actor)),
			kv("reason", validation.VStr(reason)),
			kv("rows_stripped", validation.VInt(int64(stripped))),
			kv("at", validation.VStr(state.NowIso())),
			kv("file_hashes", validation.VObj(
				kv("memory.json", validation.VStr(fileSha256(path))))),
			kv("signatures_sha256", validation.VStr(fileSha256(sigsPath(store)))),
			kv("memory_sha256", validation.VStr(fileSha256(memPath(store))))))
		if err != nil {
			return validation.VNull(), err
		}
		records = append(records, record)
		tiersOut = append(tiersOut, validation.VObj(
			kv("dir", validation.VStr(store)),
			kv("rows_stripped", validation.VInt(int64(stripped)))))
	}
	return validation.VObj(
		kv("tiers", validation.VArr(tiersOut...)),
		kv("manifest_records", validation.VArr(records...))), nil
}

// ---- helpers ---------------------------------------------------------------

func objAt(v validation.Value, key string) validation.Value {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V
		}
	}
	return validation.VNull()
}

func fieldAt(v validation.Value, key string) (validation.Value, bool) {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}

func objStr(v validation.Value, key string) string {
	f := objAt(v, key)
	if f.Kind == validation.Str {
		return f.S
	}
	return ""
}

func kv(k string, v validation.Value) validation.KV {
	return validation.KV{K: k, V: v}
}

func strArr(items []string) validation.Value {
	out := make([]validation.Value, 0, len(items))
	for _, s := range items {
		out = append(out, validation.VStr(s))
	}
	return validation.VArr(out...)
}

func strList(v validation.Value) []string {
	out := make([]string, 0, len(v.A))
	for _, e := range v.A {
		if e.Kind == validation.Str {
			out = append(out, e.S)
		}
	}
	return out
}

func strOrNull(s *string) validation.Value {
	if s == nil {
		return validation.VNull()
	}
	return validation.VStr(*s)
}

func inList(s string, list []string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStrings(items []string) []string {
	out := append([]string{}, items...)
	sort.Strings(out)
	return out
}

func simOf(v validation.Value) float64 {
	if v.Kind == validation.Flt {
		return v.F
	}
	if v.Kind == validation.Int {
		return float64(v.I)
	}
	return 0
}

func pyStr(v validation.Value) string {
	if v.Kind == validation.Str {
		return v.S
	}
	return validation.CanonCompact(v)
}

// pyTuple renders a Python tuple literal: ('a', 'b').
func pyTuple(items []string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, validation.PyReprStr(it))
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// pyReprList is Python's list repr of strings: ['a', 'b'].
func pyReprList(items []string) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, validation.PyReprStr(it))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// idTail is new_id('x', n).split('-')[1].
func idTail(n int) string {
	return strings.SplitN(state.NewID("x", n), "-", 2)[1]
}

package probes

// symmetry.go — IMPROVEMENTS C2: the primitive matrix.
//
// The reference custody-primitive probe asks ONE question per contract: "does a
// recovery path pay out of its own balance while the forward path burns or
// mints?" (probe_custody.go). The systematic question underneath it is asked
// per contract FAMILY: for each inheritance group and each custody direction
// (deposit | withdrawal | drop | recover | other) and asset class (native |
// erc20 | share), which primitive does each member perform — and where do
// siblings disagree?
//
// That is exactly the shape of the morph campaign's G-02: the L1 gateway
// siblings credit deposits one way and move the asset back on the drop path
// another way, and the family-level question "who funds the difference?" was
// never computed. The per-contract probe can only see one side at a time.
//
// Everything here is deterministic over the structural index: the verb table
// is the same one probe_custody.go uses (shared package-level sets), the
// families are union-find over the index's `inherits` edges, and the
// divergences are sorted by (family, direction, asset, kind, observed site), so
// the same index renders byte-identical output.

import (
	"regexp"
	"sort"
	"strings"

	"websec/internal/validation"
)

// ---- directions -----------------------------------------------------------

// symmetryDirection is one (name, pattern) pair. Order decides: "drop" is a
// recovery word and must win over the generic withdrawal verbs.
type symmetryDirection struct {
	name string
	re   *regexp.Regexp
}

var symmetryDirectionTable = []symmetryDirection{
	{"drop", regexp.MustCompile(`(?i)^(_?on)?drop`)},
	{"recover", regexp.MustCompile(
		`(?i)^(refund|recover|rescue|emergency|claim|withdraw.*fail|force.*withdraw)`)},
	{"withdrawal", regexp.MustCompile(
		`(?i)^(_?withdraw|unstake|unlock|exit|redeem|release|_?burn)`)},
	{"deposit", regexp.MustCompile(
		`(?i)^(_?deposit|stake|lock|join|supply|_?mint|bridge|provide|add.*liquidity)`)},
}

// symmetryDirectionOf is the direction a function name serves, or "other"
// when it moves custody without matching a known verb.
func symmetryDirectionOf(function string) string {
	for _, d := range symmetryDirectionTable {
		if d.re.MatchString(function) {
			return d.name
		}
	}
	return "other"
}

// ---- cells ----------------------------------------------------------------

// symCell is one (direction, asset, primitive) performed by one function.
type symCell struct {
	Direction string
	Asset     string
	Primitive string
	Contract  string
	Function  string
	Line      int
}

// symMemberIsTestDouble reports whether a family member contract node is a
// test double (its declaring file classifies as one). Test harnesses are not
// custody members: their mint/burn cells are fixture noise that fills the
// per-axis emit quota ahead of real pairings. Reuses srcclass via
// IsTestDoublePath — the same rule collapse.go already applies when folding.
func symMemberIsTestDouble(cnode validation.Value) bool {
	return IsTestDoublePath(vStr(cnode, "path"))
}

// symAssetOf refines the asset label from a call's receiver: the verb table
// above collapses every token call to "erc20", which made an ERC-1155/721
// gateway disagree with an ERC-20 gateway over the same verb. Receiver-name
// matching is deliberately shallow — the indexed call string already carries
// the interface name.
// ponytail: receiver substring (1155/721); a per-interface kind table only if
// a mislabeled receiver ever shows up in a campaign.
func symAssetOf(call, def string) string {
	recv := call
	if i := lastIndexByte(recv, '.'); i >= 0 {
		recv = recv[:i]
	}
	rl := lower(recv)
	switch {
	case strings.Contains(rl, "1155"):
		return "erc1155"
	case strings.Contains(rl, "721"):
		return "erc721"
	}
	return def
}

// symmetryCells reads the custody primitives of one function node into
// (direction, asset, primitive) cells. The verb table is shared with
// probe_custody.go (mintCalls/burnCalls/payCalls/inCalls); the `direction`
// comes from the function name and the asset class from the primitive itself.
func symmetryCells(contract, function string, line int, node validation.Value) []symCell {
	type hit struct {
		primitive string
		asset     string
	}
	hits := []hit{}
	for _, call := range vStrList(node, "calls_internal") {
		low := lower(call)
		switch {
		case inSet(mintCalls, low):
			hits = append(hits, hit{"mint", "share"})
		case inSet(burnCalls, low):
			hits = append(hits, hit{"burn", "share"})
		}
	}
	for _, call := range vStrList(node, "calls_external") {
		low := lower(call)
		method := low
		if i := lastIndexByte(low, '.'); i >= 0 {
			method = low[i+1:]
		}
		switch {
		case inSet(mintCalls, method):
			hits = append(hits, hit{"mint", symAssetOf(low, "erc20")})
		case inSet(burnCalls, method):
			hits = append(hits, hit{"burn", symAssetOf(low, "erc20")})
		case hasPrefix(low, "low-level."), method == "sendvalue", method == "transfereth":
			hits = append(hits, hit{"send-native", "native"})
		case inSet(payCalls, method):
			hits = append(hits, hit{"transfer-out", symAssetOf(low, "erc20")})
		case inSet(inCalls, method):
			hits = append(hits, hit{"transfer-in", symAssetOf(low, "erc20")})
		}
	}
	seen := map[string]struct{}{}
	out := []symCell{}
	direction := symmetryDirectionOf(function)
	for _, h := range hits {
		key := direction + "\x00" + h.asset + "\x00" + h.primitive + "\x00" + contract
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, symCell{Direction: direction, Asset: h.asset,
			Primitive: h.primitive, Contract: contract, Function: function,
			Line: line})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return symCellKey(out[i]) < symCellKey(out[j])
	})
	return out
}

// dedupeSymCells folds the copies of one defining function that each member's
// closure re-lists (an inherited function must not count once per inheritor).
func dedupeSymCells(cells []symCell) []symCell {
	seen := map[string]struct{}{}
	out := []symCell{}
	for _, c := range cells {
		key := symCellKey(c)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return symCellKey(out[i]) < symCellKey(out[j]) })
	return out
}

// symCellKey is the total order over cells used everywhere (determinism).
func symCellKey(c symCell) string {
	return strings.Join([]string{c.Direction, c.Asset, c.Primitive, c.Contract,
		c.Function, itoa(c.Line)}, "\x00")
}

// ---- families -------------------------------------------------------------

// symFamily is one inheritance group: a name (the lexicographically smallest
// root's contract name, as the enforcement table names families) and its
// members.
type symFamily struct {
	Name    string
	Members []string
}

// symmetryFamilies is union-find over the index's `inherits` edges, restricted
// to contract/interface/library nodes, rendered as sorted families.
func symmetryFamilies(index validation.Value) []symFamily {
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		p, ok := parent[x]
		if !ok || p == x {
			parent[x] = x
			return x
		}
		root := find(p)
		parent[x] = root
		return root
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra == rb {
			return
		}
		if rb < ra {
			ra, rb = rb, ra
		}
		parent[rb] = ra
	}
	idName := map[string]string{}
	byName := map[string]string{}
	for _, n := range contractNodes(index) {
		id := vStr(n, "id")
		name := vStr(n, "name")
		if name == "" {
			continue
		}
		idName[id] = name
		if prev, ok := byName[name]; !ok || id < prev {
			byName[name] = id
		}
		find(id)
	}
	for _, e := range vList(index, "edges") {
		if e.Kind != validation.Obj || vStr(e, "rel") != "inherits" {
			continue
		}
		to := vStr(e, "to")
		if i := strings.LastIndex(to, "#"); i >= 0 {
			to = to[i+1:]
		}
		if id, ok := byName[to]; ok {
			union(vStr(e, "from"), id)
		}
	}
	groups := map[string][]string{}
	for id := range parent {
		root := find(id)
		groups[root] = append(groups[root], idName[id])
	}
	out := []symFamily{}
	for root, members := range groups {
		name := idName[root]
		if name == "" {
			name = members[0]
		}
		sort.Strings(members)
		out = append(out, symFamily{Name: name, Members: members})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ---- divergence -----------------------------------------------------------

// Symmetry divergence kinds.
const (
	// SymMemberDisagreement: two members of one family perform different
	// primitives for the same (direction, asset).
	SymMemberDisagreement = "member-disagreement"
	// SymFundingMismatch: a forward path credits the asset (mint / transfer-in)
	// while a recovery path moves it out (transfer-out / send-native) for the
	// same asset — the G-02 shape ("who funds the difference?").
	SymFundingMismatch = "funding-mismatch"
)

// symDivergence is one family-level disagreement, carrying both ends.
type symDivergence struct {
	Kind          string
	Family        string
	Direction     string
	Asset         string
	Expected      string
	ExpectedAsset string
	Observed      string
	ExpCell       symCell
	ObsCell       symCell
	Members       []string
}

func symDivKey(d symDivergence) string {
	return strings.Join([]string{d.Family, d.Direction, d.Asset, d.Kind,
		d.Expected, d.Observed, d.ExpCell.Contract, d.ExpCell.Function,
		itoa(d.ExpCell.Line), d.ObsCell.Contract, d.ObsCell.Function,
		itoa(d.ObsCell.Line)}, "\x00")
}

// divergenceCap bounds the divergences carried per family; the stats publish
// the true count next to it so a cap never hides work.
const divergenceCap = 8

// symmetryDivergencesOf computes the divergences inside one family from its
// members' cells.
func symmetryDivergencesOf(family string, cells []symCell) []symDivergence {
	out := []symDivergence{}
	// R1: member disagreement — same (direction, asset), different primitive.
	byColumn := map[string][]symCell{}
	for _, c := range cells {
		key := c.Direction + "\x00" + c.Asset
		byColumn[key] = append(byColumn[key], c)
	}
	columns := make([]string, 0, len(byColumn))
	for k := range byColumn {
		columns = append(columns, k)
	}
	sort.Strings(columns)
	for _, key := range columns {
		group := byColumn[key]
		prims := map[string][]symCell{}
		for _, c := range group {
			prims[c.Primitive] = append(prims[c.Primitive], c)
		}
		if len(prims) < 2 {
			continue
		}
		names := sortedKeys(prims)
		expected := names[0]
		for _, other := range names[1:] {
			e := prims[expected][0]
			for _, o := range prims[other] {
				out = append(out, symDivergence{Kind: SymMemberDisagreement,
					Family: family, Direction: e.Direction, Asset: e.Asset,
					Expected: expected, Observed: other, ExpCell: e, ObsCell: o,
					Members: symMemberLabels(prims[expected], prims[other])})
			}
		}
	}
	// R2: custody mismatch — the reference probe's own discriminator, lifted to
	// the family: a forward path MINTS or BURNS (the member never holds the
	// asset) while a recovery path pays the asset out of its own balance
	// (transfer-out / send-native). The clean case — a forward path that HOLDS
	// custody with transfer-in and pays it back out — is self-consistent and
	// stays silent.
	credit := []symCell{}
	debit := []symCell{}
	for _, c := range cells {
		recovery := c.Direction == "drop" || c.Direction == "recover"
		switch {
		case inSet(map[string]struct{}{"mint": {}, "burn": {}}, c.Primitive):
			if c.Direction == "deposit" {
				credit = append(credit, c)
			}
		case inSet(map[string]struct{}{"transfer-out": {}, "send-native": {}}, c.Primitive):
			if recovery {
				debit = append(debit, c)
			}
		}
	}
	sort.SliceStable(credit, func(i, j int) bool { return symCellKey(credit[i]) < symCellKey(credit[j]) })
	sort.SliceStable(debit, func(i, j int) bool { return symCellKey(debit[i]) < symCellKey(debit[j]) })
	for _, cr := range credit {
		for _, db := range debit {
			out = append(out, symDivergence{Kind: SymFundingMismatch,
				Family: family, Direction: db.Direction, Asset: db.Asset,
				Expected: cr.Primitive, ExpectedAsset: cr.Asset,
				Observed: db.Primitive, ExpCell: cr, ObsCell: db,
				Members: symMemberLabels([]symCell{cr}, []symCell{db})})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return symDivKey(out[i]) < symDivKey(out[j]) })
	return out
}

// symMemberLabels renders "Contract.function" for two cell groups, deduped.
func symMemberLabels(a, b []symCell) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, group := range [][]symCell{a, b} {
		for _, c := range group {
			label := c.Contract + "." + c.Function
			if _, dup := seen[label]; dup {
				continue
			}
			seen[label] = struct{}{}
			out = append(out, label)
		}
	}
	sort.Strings(out)
	return out
}

// ---- the matrix -----------------------------------------------------------

// PrimitiveMatrix is IMPROVEMENTS C2: families × (direction, asset) → the
// custody primitive each member performs, plus the divergences between them.
// Pure over the index.
func PrimitiveMatrix(index validation.Value) validation.Value {
	fns := functionNodes(index)
	families := []validation.Value{}
	flat := []symDivergence{}
	cells, members, sites := 0, 0, 0
	for _, fam := range symmetryFamilies(index) {
		memberSet := map[string]struct{}{}
		for _, m := range fam.Members {
			memberSet[m] = struct{}{}
		}
		famCells := []symCell{}
		for _, cnode := range contractNodes(index) {
			cname := vStr(cnode, "name")
			if _, ok := memberSet[cname]; !ok {
				continue
			}
			if symMemberIsTestDouble(cnode) {
				continue
			}
			for _, e := range vObjList(cnode, "contract_closure") {
				node, ok := fns[nodeID(e)]
				if !ok {
					continue
				}
				fn := vStr(e, "name")
				line := vInt(e, "line")
				got := symmetryCells(vStr(e, "defining_contract"), fn, line, node)
				if len(got) == 0 {
					continue
				}
				sites++
				famCells = append(famCells, got...)
			}
		}
		famCells = dedupeSymCells(famCells)
		if len(famCells) == 0 {
			continue
		}
		members += len(fam.Members)
		cells += len(famCells)
		divs := symmetryDivergencesOf(fam.Name, famCells)
		flat = append(flat, divs...)
		families = append(families, validation.VObj(
			kv("name", validation.VStr(fam.Name)),
			kv("members", validation.StrArr(fam.Members)),
			kv("cells", symCellValues(famCells)),
			kv("divergences", symDivergenceValues(divs)),
			kv("divergence_total", validation.VInt(int64(len(divs))))))
	}
	flatSorted := append([]symDivergence(nil), flat...)
	sort.SliceStable(flatSorted, func(i, j int) bool {
		return symDivKey(flatSorted[i]) < symDivKey(flatSorted[j])
	})
	return validation.VObj(
		kv("families", validation.VArr(families...)),
		kv("divergences", symDivergenceValues(flatSorted)),
		kv("stats", validation.VObj(
			kv("families", validation.VInt(int64(len(families)))),
			kv("members", validation.VInt(int64(members))),
			kv("sites", validation.VInt(int64(sites))),
			kv("cells", validation.VInt(int64(cells))),
			kv("divergences", validation.VInt(int64(len(flatSorted)))),
			kv("member_disagreements", validation.VInt(int64(countDivKind(flatSorted, SymMemberDisagreement)))),
			kv("funding_mismatches", validation.VInt(int64(countDivKind(flatSorted, SymFundingMismatch)))),
		)))
}

// countDivKind counts the divergences of one kind.
func countDivKind(divs []symDivergence, kind string) int {
	n := 0
	for _, d := range divs {
		if d.Kind == kind {
			n++
		}
	}
	return n
}

// symCellValues renders cells for the CLI matrix.
func symCellValues(cells []symCell) validation.Value {
	out := []validation.Value{}
	for _, c := range cells {
		out = append(out, validation.VObj(
			kv("direction", validation.VStr(c.Direction)),
			kv("asset", validation.VStr(c.Asset)),
			kv("primitive", validation.VStr(c.Primitive)),
			kv("contract", validation.VStr(c.Contract)),
			kv("function", validation.VStr(c.Function)),
			kv("line", validation.VInt(int64(c.Line)))))
	}
	return validation.VArr(out...)
}

// symDivergenceValues renders divergences, carrying both ends and a question.
func symDivergenceValues(divs []symDivergence) validation.Value {
	out := []validation.Value{}
	for _, d := range divs {
		out = append(out, validation.VObj(
			kv("kind", validation.VStr(d.Kind)),
			kv("family", validation.VStr(d.Family)),
			kv("direction", validation.VStr(d.Direction)),
			kv("asset", validation.VStr(d.Asset)),
			kv("expected", validation.VStr(d.Expected)),
			kv("expected_asset", validation.VStr(d.ExpectedAsset)),
			kv("observed", validation.VStr(d.Observed)),
			kv("expected_site", symSiteValue(d.ExpCell)),
			kv("observed_site", symSiteValue(d.ObsCell)),
			kv("members", validation.StrArr(d.Members)),
			kv("question", validation.VStr(symQuestion(d)))))
	}
	return validation.VArr(out...)
}

// symSiteValue renders one end of a divergence.
func symSiteValue(c symCell) validation.Value {
	return validation.VObj(
		kv("contract", validation.VStr(c.Contract)),
		kv("function", validation.VStr(c.Function)),
		kv("line", validation.VInt(int64(c.Line))))
}

// SymQuestion is the question a divergence renders (exported so the CLI, the
// surface row and the tests all phrase it the same way).
func SymQuestion(d symDivergence) string { return symQuestion(d) }

// payoutFundingQuestion is the forced question every funding-mismatch row
// carries: the matrix shows the primitive divergence, but the miss that
// matters is the payout path — what credits the balance the payout draws
// from. The framework cannot know deployment funding; it can refuse to let
// the question go unasked.
const payoutFundingQuestion = " Who funds the observed payout — name the " +
	"primitive that credits the paying balance for this asset; if none " +
	"exists, the payout draws from an unfunded balance."

func symQuestion(d symDivergence) string {
	switch d.Kind {
	case SymFundingMismatch:
		return sprintf("%s: the forward path %s::%s#%d %s (%s) while %s::%s#%d "+
			"moves %s out with %s on the %s path — who funds the difference?"+
			payoutFundingQuestion,
			d.Family, d.ExpCell.Contract, d.ExpCell.Function, d.ExpCell.Line,
			d.Expected, d.ExpectedAsset, d.ObsCell.Contract, d.ObsCell.Function,
			d.ObsCell.Line, d.Asset, d.Observed, d.Direction)
	default:
		return sprintf("%s: siblings disagree on %s %s — %s::%s#%d %s while "+
			"%s::%s#%d %s — which of them is the custody model?",
			d.Family, d.Direction, d.Asset, d.ExpCell.Contract,
			d.ExpCell.Function, d.ExpCell.Line, d.Expected, d.ObsCell.Contract,
			d.ObsCell.Function, d.ObsCell.Line, d.Observed)
	}
}

// ---- surface rows ---------------------------------------------------------

// symmetryRawRows builds the custody-primitive rows for a family's
// divergences. The rows ride the existing custody-primitive axis and probe id
// (so dispositions, anchors and the schema keep working); they are prepended
// into the raw list only when the caller opts in.
func symmetryRawRows(index, model validation.Value) ([]validation.Value, map[string]validation.Value) {
	fns := functionNodes(index)
	// (contract, function) -> the node that implements it, so a divergence
	// row carries the same tier/gate modifiers the per-contract probe would
	// have given the site.
	byCF := map[string]validation.Value{}
	for _, cnode := range contractNodes(index) {
		cname := vStr(cnode, "name")
		for _, e := range vObjList(cnode, "contract_closure") {
			if node, ok := fns[nodeID(e)]; ok {
				byCF[cname+"\x00"+vStr(e, "name")] = node
			}
		}
	}
	out := []validation.Value{}
	extras := map[string]validation.Value{}
	for _, famVal := range vObjList(PrimitiveMatrix(index), "families") {
		divs := vObjList(famVal, "divergences")
		if len(divs) > divergenceCap {
			divs = divs[:divergenceCap]
		}
		members := vStrList(famVal, "members")
		// The family's forward (deposit) functions, rendered in the reference
		// probe's `forward` slot so the row reads as a custody row.
		fwd := map[string]struct{}{}
		for _, c := range vObjList(famVal, "cells") {
			if vStr(c, "direction") == "deposit" {
				fwd[vStr(c, "function")] = struct{}{}
			}
		}
		forward := sortedStrSet(fwd)
		for _, d := range divs {
			obs := vGet(d, "observed_site")
			exp := vGet(d, "expected_site")
			contract := vStr(obs, "contract")
			function := vStr(obs, "function")
			line := vInt(obs, "line")
			mods := []string{}
			if node, ok := byCF[contract+"\x00"+function]; ok {
				mods = nodeModifiers(node)
			}
			// `custody` is a schema enum (mints|burns) and the divergence's
			// expected primitive is often neither. Emitting such a value makes
			// `probes run --emit` abort on its own artifact, so the key is
			// omitted when the primitive has no schema value — the row's
			// identity falls back to `observed` (idSlots), and expected/
			// observed still ride the extras map below.
			extra := []validation.KV{
				kv("base", vGet(exp, "contract")),
				kv("base_line", vGet(exp, "line")),
				kv("base_function", vGet(exp, "function")),
			}
			if label := symCustodyLabel(vStr(d, "expected")); label != "" {
				extra = append(extra, kv("custody", validation.VStr(label)))
			}
			extra = append(extra,
				kv("forward", validation.StrArr(forward)),
				kv("inherited", validation.VBool(false)),
				kv("observed", vGet(d, "observed")),
				kv("family", vGet(d, "family")),
				kv("direction", vGet(d, "direction")),
				kv("asset", vGet(d, "asset")),
				kv("divergence", vGet(d, "kind")),
				kv("members", validation.StrArr(members)),
				kv("divergence_question", vGet(d, "question")))
			row := rawRow(contract, function, line,
				vStr(d, "direction")+":"+vStr(d, "asset"), TierOfGate(mods, model),
				GateLabel(mods, model), 4, function, extra...)
			out = append(out, row)
			// finalize copies only the probe's declared fields, so the
			// divergence extras ride a row_id -> dict map into the post-pass.
			withProbe := copyObj(row)
			vSet(&withProbe, "probe", validation.VStr("custody-primitive"))
			extras[RowIDFor(withProbe)] = validation.VObj(
				kv("family", vGet(d, "family")),
				kv("direction", vGet(d, "direction")),
				kv("asset", vGet(d, "asset")),
				kv("divergence", vGet(d, "kind")),
				kv("expected", vGet(d, "expected")),
				kv("expected_asset", vGet(d, "expected_asset")),
				kv("observed", vGet(d, "observed")),
				kv("base_function", vGet(exp, "function")),
				kv("members", validation.StrArr(members)),
				kv("why", vGet(d, "question")))
		}
	}
	return out, extras
}

// symCustodyLabel is the reference probe's `custody` vocabulary ("burns" /
// "mints"): a credit primitive named the way the custody row names the
// forward path. Any other primitive has no schema value — probe_surface's
// custody enum is exactly ["burns", "mints"] — so it maps to "", and the
// caller omits the key rather than write a value the schema rejects.
func symCustodyLabel(primitive string) string {
	switch primitive {
	case "mint":
		return "mints"
	case "burn":
		return "burns"
	}
	return ""
}

// attachSymmetry stamps the divergence extras onto the finalized rows that
// carry them (finalize copies only the probe's declared fields, so the
// family/direction/asset/observed set is set here, after the row shape is
// frozen). The `why` becomes the divergence question, so the operator reads the
// family disagreement rather than the single-contract custody template.
func attachSymmetry(rows []validation.Value,
	extras map[string]validation.Value) []validation.Value {
	for i := range rows {
		ex, ok := extras[vStr(rows[i], "row_id")]
		if !ok {
			continue
		}
		for _, field := range []string{"family", "direction", "asset",
			"divergence", "expected", "expected_asset", "observed",
			"base_function", "members"} {
			vSet(&rows[i], field, vGet(ex, field))
		}
		if q := vStr(ex, "why"); q != "" {
			vSet(&rows[i], "why", validation.VStr(q))
		}
	}
	return rows
}

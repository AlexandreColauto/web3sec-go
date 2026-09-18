package probes

import (
	"sort"
	"strings"

	"websec/internal/validation"
)

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

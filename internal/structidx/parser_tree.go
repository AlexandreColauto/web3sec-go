// parser_tree.go: the source-tree walk and per-contract indexing that build the node/edge graph.

package structidx

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
	"websec/internal/solscope"
)

// ---- the tree --------------------------------------------------------------

type treeResult struct {
	nodes         []*idxNode
	edges         []idxEdge
	solidityFiles int64
	otherFiles    int64
}

// collectFiles is the `**/*` + exclude-set + Path-order walk.
//
// H4: the exclude set is solscope's shared constant — the same one the
// post-patch scope walk uses, so the index surface and the scope surface
// cannot drift apart.
func collectFiles(root string) ([]string, error) {
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && solscope.IsExcluded(name) {
				return fs.SkipDir
			}
			return nil
		}
		// Regular files only: a dangling symlink (or FIFO/socket/device
		// file) is not a dir, so it would reach os.ReadFile below and abort
		// the whole index build.
		if !d.Type().IsRegular() {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
			if solscope.IsExcluded(part) {
				return nil
			}
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool {
		return partsLess(files[i], files[j], root)
	})
	return files, nil
}

// partsLess reproduces Python's PurePath ordering (compare the parts tuple).
func partsLess(a, b, root string) bool {
	ra, _ := filepath.Rel(root, a)
	rb, _ := filepath.Rel(root, b)
	pa := strings.Split(filepath.ToSlash(ra), "/")
	pb := strings.Split(filepath.ToSlash(rb), "/")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return len(pa) < len(pb)
}

// IndexTree is _index_tree: nodes + edges for one source tree, campaign-free.
func IndexTree(snapshotRoot string) (*treeResult, error) {
	files, err := collectFiles(snapshotRoot)
	if err != nil {
		return nil, err
	}
	res := &treeResult{}
	var generic []string
	for _, path := range files {
		rel, _ := filepath.Rel(snapshotRoot, path)
		rel = filepath.ToSlash(rel)
		if filepath.Ext(path) != ".sol" {
			generic = append(generic, rel)
			continue
		}
		res.solidityFiles++
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		text := validUTF8Replace(string(raw))
		indexFile(text, rel, res)
	}
	res.otherFiles = int64(len(generic))
	return res, nil
}

func validUTF8Replace(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "\uFFFD")
}

type contractRec struct {
	kind      string
	name      string
	cid       string
	inherits  []string
	line      int64
	body      string
	bodyLine0 int64
}

func indexFile(text, rel string, res *treeResult) {
	contractVars := map[string][]string{}
	allFnNames := map[string]bool{}
	contracts := []contractRec{}
	for _, caps := range pyContract.findAll(text) {
		g1s, g1e, _ := capsGroup(caps, 1)
		g2s, g2e, _ := capsGroup(caps, 2)
		g3s, g3e, has3 := capsGroup(caps, 3)
		kind := text[g1s:g1e]
		name := text[g2s:g2e]
		openIdx := strings.IndexByte(text[caps[0]:], '{') + caps[0]
		closeIdx := matchBrace(text, openIdx)
		body := ""
		if closeIdx > 0 {
			body = text[openIdx+1 : closeIdx]
		}
		inherits := []string{}
		if has3 {
			for _, x := range strings.Split(text[g3s:g3e], ",") {
				t := strings.TrimSpace(x)
				if t == "" {
					continue
				}
				inherits = append(inherits, strings.Split(t, "(")[0])
			}
		}
		line := countNL(text, 0, caps[0]) + 1
		cid := rel + "#" + name
		contracts = append(contracts, contractRec{kind: kind, name: name,
			cid: cid, inherits: inherits, line: line, body: body,
			bodyLine0: countNL(text, 0, openIdx)})
		nodeLine := line
		res.nodes = append(res.nodes, &idxNode{id: cid, kind: kind, name: name,
			path: rel, line: &nodeLine})
		for _, parent := range inherits {
			res.edges = append(res.edges, idxEdge{from: cid,
				rel: "inherits", to: "*#" + parent})
		}
		stripped := stripFunctionBodies(body)
		varsHere := []string{}
		for _, sm := range pyState.findAll(stripped) {
			s, e, ok := capsGroup(sm, 1)
			if !ok {
				continue
			}
			v := stripped[s:e]
			if v != "" && !builtinSet[v] {
				varsHere = append(varsHere, v)
				res.nodes = append(res.nodes, &idxNode{
					id: cid + "." + v, kind: "state-variable", name: v,
					path: rel, line: nil})
			}
		}
		contractVars[name] = varsHere
		for _, mm := range filterLeadingB(body,
			reModifier.FindAllStringSubmatchIndex(body, -1)) {
			mname := body[mm[2]:mm[3]]
			open2 := strings.IndexByte(body[mm[0]:], '{') + mm[0]
			close2 := matchBrace(body, open2)
			modLine := line + countNL(body, 0, mm[0])
			res.nodes = append(res.nodes, &idxNode{
				id: cid + "." + mname, kind: "modifier", name: mname,
				path: rel, line: &modLine})
			if close2 > 0 {
				allFnNames[mname] = true
			}
		}
		for _, d := range iterFunctions(body) {
			allFnNames[d.name] = true
		}
		for _, kw := range []string{"constructor", "receive", "fallback"} {
			for range iterSpecials(body, kw) {
				allFnNames[kw] = true
			}
		}
	}
	for _, c := range contracts {
		indexContract(c, rel, contractVars, allFnNames, res)
	}
}

func indexContract(c contractRec, rel string,
	contractVars map[string][]string, allFnNames map[string]bool,
	res *treeResult) {
	body := c.body
	decls := iterFunctions(body)
	for _, kw := range []string{"constructor", "receive", "fallback"} {
		decls = append(decls, iterSpecials(body, kw)...)
	}
	type modBody struct {
		name string
		body string
	}
	modifierBodies := []modBody{}
	for _, mm := range reModifier.FindAllStringSubmatchIndex(body, -1) {
		mOpen := strings.IndexByte(body[mm[0]:], '{') + mm[0]
		mClose := matchBrace(body, mOpen)
		if mClose > 0 {
			modifierBodies = append(modifierBodies, modBody{
				name: body[mm[2]:mm[3]], body: body[mOpen+1 : mClose]})
		}
	}
	for _, d := range decls {
		closeIdx := matchBrace(body, d.openIdx)
		fbody := ""
		if closeIdx > 0 {
			fbody = body[d.openIdx+1 : closeIdx]
		}
		fbodyOwn := fbody
		for _, mb := range modifierBodies {
			if _, ok := wordBoundaryRe(mb.name).search(d.attrs+" "+fbody, 0); ok {
				fbody += mb.body
			}
		}
		defaultVis := "internal"
		if c.kind == "interface" {
			defaultVis = "external"
		} else if d.name == "constructor" || d.name == "receive" ||
			d.name == "fallback" {
			defaultVis = "public"
		}
		vis, mods := parseAttrs(d.attrs, defaultVis)
		fid := c.cid + "." + d.name
		fline := c.bodyLine0 + countNL(body, 0, d.openIdx) + 1
		n := &idxNode{id: fid, kind: "function", name: d.name, path: rel,
			line: &fline, visibility: vis,
			isEntry: vis == "external" || vis == "public", mods: mods}
		if !d.special && (vis == "external" || vis == "public") {
			sel := d.name + "(" + paramTypes(d.params) + ")"
			n.selector = &sel
		}
		n.guards = extractGuards(fbodyOwn, fline)
		n.uses = extractUses(fbodyOwn, fline, paramNames(d.params))
		for _, v := range contractVars[c.name] {
			if _, ok := wordBoundaryRe(v).search(fbody, 0); ok {
				n.reads = append(n.reads, v)
				if _, ok := stateWriteRe(v).search(fbody, 0); ok {
					n.writes = append(n.writes, v)
				}
			}
		}
		for _, ci := range filterLeadingB(fbody,
			reCallee.FindAllStringSubmatchIndex(fbody, -1)) {
			callee := fbody[ci[2]:ci[3]]
			if builtinSet[callee] {
				continue
			}
			if allFnNames[callee] {
				n.callsInt = append(n.callsInt, callee)
				res.edges = append(res.edges, idxEdge{from: fid,
					rel: "calls", to: c.cid + "." + callee})
			}
		}
		// External calls in STATEMENT ORDER (C2), deduped by (method, line).
		type call struct {
			pos  int
			tgt  string
			meth string
		}
		calls := []call{}
		for _, em := range pyExtCall.findAll(fbody) {
			ts, te, _ := capsGroup(em, 1)
			ms, me, _ := capsGroup(em, 2)
			tgt, meth := fbody[ts:te], fbody[ms:me]
			if builtinSet[tgt] || extCallSkip[tgt] {
				continue
			}
			if em[0] >= 4 && fbody[em[0]-4:em[0]] == "msg." {
				continue
			}
			calls = append(calls, call{em[0], tgt, meth})
		}
		for _, cc := range iterCastCalls(fbody) {
			if builtinSet[cc.recv] {
				continue
			}
			calls = append(calls, call{cc.pos, cc.recv, cc.meth})
		}
		sort.SliceStable(calls, func(i, j int) bool {
			return calls[i].pos < calls[j].pos
		})
		seenCalls := map[string]bool{}
		for _, cl := range calls {
			site := cl.meth + "\x00" + itoa(fline+countNL(fbody, 0, cl.pos))
			if seenCalls[site] {
				continue
			}
			seenCalls[site] = true
			n.callsExt = append(n.callsExt, cl.tgt+"."+cl.meth)
			res.edges = append(res.edges, idxEdge{from: fid, rel: "calls",
				to: "*#" + cl.tgt + "." + cl.meth})
		}
		for _, lm := range pyLowCall.findAll(fbody) {
			s, e, _ := capsGroup(lm, 1)
			kind := fbody[s:e]
			label := "low-level." + kind
			if kind == "delegatecall" {
				n.deleg = append(n.deleg, label)
				res.edges = append(res.edges, idxEdge{from: fid,
					rel: "delegatecalls", to: "*#" + label})
			} else {
				n.callsExt = append(n.callsExt, label)
				res.edges = append(res.edges, idxEdge{from: fid,
					rel: "calls", to: "*#" + label})
			}
		}
		if n.isEntry {
			res.edges = append(res.edges, idxEdge{from: c.cid,
				rel: "extends-interface", to: fid})
		}
		res.nodes = append(res.nodes, n)
	}
}

// dedupeNodes is the first-wins id dedupe.
func dedupeNodes(nodes []*idxNode) []*idxNode {
	seen := map[string]bool{}
	out := make([]*idxNode, 0, len(nodes))
	for _, n := range nodes {
		if seen[n.id] {
			continue
		}
		seen[n.id] = true
		out = append(out, n)
	}
	return out
}

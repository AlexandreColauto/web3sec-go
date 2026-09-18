// relations_cluster.go: root-cause clustering — a DERIVED view, never
// stored.
package relations

import (
	"slices"
	"sort"
	"strings"
	"websec/internal/findings"
	"websec/internal/immunize"
	"websec/internal/state"
	"websec/internal/validation"
)

// ---- root-cause clustering (a DERIVED view, never stored) -----------------

var clusterStatuses = []string{"CONFIRMED", "CHAIN"}

// affectedSignature is _affected_signature.
func affectedSignature(f validation.Value) []string {
	parts := map[string]struct{}{}
	for _, a := range validation.ObjAt(f, "affected").A {
		path := strings.TrimSpace(validation.ObjStr(a, "path"))
		if path == "" {
			continue
		}
		fn := strings.TrimSpace(validation.ObjStr(a, "function"))
		if fn != "" {
			parts[path+"::"+fn] = struct{}{}
		} else {
			parts[path] = struct{}{}
		}
	}
	return validation.SortedKeys(parts)
}

// rootCauseByClass groups the findings by trimmed root_cause.class, keeping
// only CONFIRMED/CHAIN findings with a non-empty class.
func rootCauseByClass(all []validation.Value) map[string][]validation.Value {
	byClass := map[string][]validation.Value{}
	for _, f := range all {
		if !slices.Contains(clusterStatuses, validation.ObjStr(f, "status")) {
			continue
		}
		cls := strings.TrimSpace(validation.ObjStr(validation.ObjAt(f, "root_cause"), "class"))
		if cls == "" {
			continue
		}
		byClass[cls] = append(byClass[cls], f)
	}
	return byClass
}

// rootCauseSubclusters splits one class's members by affected-location
// signature, in the locked signature order.
func rootCauseSubclusters(members []validation.Value) []validation.Value {
	sigOrder := []string{}
	sub := map[string][]validation.Value{}
	for _, f := range members {
		key := strings.Join(affectedSignature(f), "\x00")
		if _, ok := sub[key]; !ok {
			sigOrder = append(sigOrder, key)
		}
		sub[key] = append(sub[key], f)
	}
	sort.SliceStable(sigOrder, func(i, j int) bool {
		si := strings.Split(sigOrder[i], "\x00")
		sj := strings.Split(sigOrder[j], "\x00")
		if len(si) != len(sj) {
			return len(si) < len(sj)
		}
		return strings.Join(si, "\x00") < strings.Join(sj, "\x00")
	})
	subclusters := []validation.Value{}
	for _, key := range sigOrder {
		fs := sub[key]
		sig := affectedSignature(fs[0])
		locations := sig
		if len(locations) == 0 {
			locations = []string{"(no affected location recorded)"}
		}
		ids := []string{}
		immunized := []string{}
		for _, f := range fs {
			fid := validation.ObjStr(f, "finding_id")
			ids = append(ids, fid)
			if immunize.IsImmunized(f) {
				immunized = append(immunized, fid)
			}
		}
		sort.Strings(immunized)
		subclusters = append(subclusters, validation.VObj(
			kv("locations", validation.StrArr(locations)),
			kv("finding_ids", validation.StrArr(ids)),
			kv("immunized", validation.StrArr(immunized))))
	}
	return subclusters
}

// rootCauseAttested lists the caused_by edges between two members of the
// cluster.
func rootCauseAttested(rels []validation.Value,
	memberIDs map[string]struct{}) []validation.Value {
	attested := []validation.Value{}
	for _, r := range rels {
		if validation.ObjStr(r, "kind") != "caused_by" {
			continue
		}
		src, dst := validation.ObjAt(r, "src"), validation.ObjAt(r, "dst")
		_, sOK := memberIDs[validation.ObjStr(src, "id")]
		_, dOK := memberIDs[validation.ObjStr(dst, "id")]
		if sOK && dOK {
			attested = append(attested, validation.VObj(
				kv("src", validation.VStr(validation.ObjStr(src, "id"))),
				kv("dst", validation.VStr(validation.ObjStr(dst, "id"))),
				kv("actor", validation.ObjAt(r, "actor"))))
		}
	}
	return attested
}

// rootCauseCluster builds one class's cluster object from its (id-sorted)
// members.
func rootCauseCluster(cls string, members, rels []validation.Value) validation.Value {
	sort.SliceStable(members, func(i, j int) bool {
		return validation.ObjStr(members[i], "finding_id") < validation.ObjStr(members[j], "finding_id")
	})
	memberIDs := map[string]struct{}{}
	for _, f := range members {
		memberIDs[validation.ObjStr(f, "finding_id")] = struct{}{}
	}
	subclusters := rootCauseSubclusters(members)
	rc := validation.ObjAt(members[0], "root_cause")
	attested := rootCauseAttested(rels, memberIDs)
	memberIDsList := []string{}
	for _, f := range members {
		memberIDsList = append(memberIDsList, validation.ObjStr(f, "finding_id"))
	}
	return validation.VObj(
		kv("class", validation.VStr(cls)),
		kv("description", validation.VStr(head300(validation.ObjStr(rc, "description")))),
		kv("mechanism", validation.ObjAt(rc, "mechanism")),
		kv("members", validation.StrArr(memberIDsList)),
		kv("subclusters", validation.VArr(subclusters...)),
		kv("attested_causation", validation.VArr(attested...)))
}

// RootCauseClusters is root_cause_clusters.
func RootCauseClusters(c *state.Campaign) (validation.Value, error) {
	all, err := findings.LoadAllFindings(c)
	if err != nil {
		return validation.VNull(), err
	}
	byClass := rootCauseByClass(all)
	rels, err := LoadRelations(c)
	if err != nil {
		return validation.VNull(), err
	}
	classes := make([]string, 0, len(byClass))
	for cls := range byClass {
		classes = append(classes, cls)
	}
	sort.Strings(classes)
	clusters := []validation.Value{}
	for _, cls := range classes {
		members := byClass[cls]
		if len(members) < 2 {
			continue
		}
		clusters = append(clusters, rootCauseCluster(cls, members, rels))
	}
	return validation.VObj(
		kv("clusters", validation.VArr(clusters...)),
		kv("note", validation.VStr("derived view — recomputed from finding "+
			"metadata on every call; only human-attested caused_by edges are "+
			"stored (the relations graph)"))), nil
}

// Verification of every visible store tier: schema validation plus
// hash-chain and publish-record integrity.

package sharedmem

import (
	"fmt"
	"os"
	"strings"

	"websec/internal/validation"
)

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
		if err := validation.Validate(validation.ObjAt(w, "row"), "memory", 1); err != nil {
			problems = append(problems, fmt.Sprintf("memory[%d]: %s", i, err))
		}
	}
	if len(manifest) > 0 {
		last := manifest[len(manifest)-1]
		if fileSha256(sigsPath(store)) != validation.ObjStr(last, "signatures_sha256") {
			problems = append(problems, "signatures.json does not match the "+
				"last publish record's hash — the store was modified outside "+
				"`publish`")
		}
		if fileSha256(memPath(store)) != validation.ObjStr(last, "memory_sha256") {
			problems = append(problems, "memory.json does not match the last "+
				"publish record's hash — the store was modified outside `publish`")
		}
		expected := strings.Repeat("0", 64)
		for _, r := range manifest {
			if _, ok := fieldAt(r, "record_hash"); !ok {
				continue // legacy record: readable, not part of the chain
			}
			rid := validation.ObjStr(r, "record_id")
			if rid == "" {
				rid = "?"
			}
			if validation.ObjStr(r, "prev_hash") != expected {
				problems = append(problems, fmt.Sprintf("manifest %s: "+
					"prev_hash breaks the chain", rid))
			}
			if recordHash(r) != validation.ObjStr(r, "record_hash") {
				problems = append(problems, fmt.Sprintf("manifest %s: "+
					"record_hash does not recompute (record edited?)", rid))
			}
			expected = validation.ObjStr(r, "record_hash")
		}
	} else if len(sigs) > 0 || len(mems) > 0 {
		problems = append(problems, "data present but no publish record — the "+
			"store was not created by `publish`")
	}
	return validation.VObj(
		kv("dir", validation.VStr(store)),
		kv("exists", validation.VBool(true)),
		kv("ok", validation.VBool(len(problems) == 0)),
		kv("problems", validation.StrArr(problems)),
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
		for _, p := range validation.ObjAt(t, "problems").A {
			problems = append(problems, d+": "+p.S)
		}
		if validation.ObjAt(t, "exists").B {
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
			n += validation.ObjAt(t, field).I
		}
		return n
	}
	return validation.VObj(
		kv("exists", validation.VBool(true)),
		kv("ok", validation.VBool(len(problems) == 0)),
		kv("problems", validation.StrArr(problems)),
		kv("signature_count", validation.VInt(total("signature_count"))),
		kv("memory_count", validation.VInt(total("memory_count"))),
		kv("publish_records", validation.VInt(total("publish_records"))),
		kv("tiers", validation.VArr(tiers...))), nil
}

// store_view: read-only counts and program keys of the store.

package sharedmem

import (
	"os"
	"path/filepath"

	"websec/internal/validation"
)

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
			if validation.ObjStr(r, "scope") == "global" {
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
		programs[validation.ObjStr(s, "program_key")] = struct{}{}
	}
	for _, m := range mems {
		if k := validation.ObjStr(m, "program_key"); k != "" {
			programs[k] = struct{}{}
		}
	}
	globalRows := 0
	for _, m := range mems {
		if validation.ObjStr(m, "scope") == "global" {
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
		kv("programs", validation.StrArr(validation.SortedKeys(programs))),
		kv("tiers", validation.VArr(tiers...))), nil
}

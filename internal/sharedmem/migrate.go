// Manifest-logged migrations over the stored rows.

package sharedmem

import (
	"os"

	"websec/internal/state"
	"websec/internal/validation"
)

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
			for _, item := range validation.ObjAt(w, "row").O {
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

// set_scope: the sanctioned visibility change and its row rewrites.

package sharedmem

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"websec/internal/state"
	"websec/internal/validation"
)

// ---- scope -----------------------------------------------------------------

// SetScope is set_scope: the sanctioned visibility change. programKey == ""
// means "every row in the tier" (Python: program_key=None).
func SetScope(root, scope, actor, programKey string, tier string) (validation.Value, error) {
	if !slices.Contains(Scopes, scope) {
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
		if programKey != "" && validation.ObjStr(sigs[i], "program_key") != programKey {
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
		if programKey != "" && validation.ObjStr(mems[i], "program_key") != programKey {
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
		kv("record_id", validation.VStr(validation.ObjStr(record, "record_id"))),
		kv("tier", validation.VStr(tier)),
		kv("scope", validation.VStr(scope)),
		kv("program_key", validation.VStr(recordKey)),
		kv("signatures_updated", validation.VInt(int64(sigsChanged))),
		kv("memory_updated", validation.VInt(int64(memsChanged))),
		kv("store", validation.VStr(store))), nil
}

// scopeOf is (row.get("scope") or "program").
func scopeOf(row validation.Value) string {
	if s := validation.ObjStr(row, "scope"); s != "" {
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

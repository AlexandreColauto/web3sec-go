package sharedmem

// seams.go exports the tier primitives webv2.ingest uses (Python reaches
// them as module-private SM._tier_memory / _write_store / _manifest_append /
// _file_sha256 / _program_key). The bodies stay in sharedmem.go — these are
// thin aliases so the port keeps ONE implementation of the store discipline.

import (
	"path/filepath"

	"websec/internal/validation"
)

// SignaturesPath is _sigs_path.
func SignaturesPath(store string) string { return filepath.Join(store, sigsName) }

// MemoryPath is _mem_path.
func MemoryPath(store string) string { return filepath.Join(store, memName) }

// ManifestPath is _manifest_path.
func ManifestPath(store string) string { return filepath.Join(store, manifestName) }

// TierSignatures is _tier_signatures.
func TierSignatures(store string) ([]validation.Value, error) {
	return tierSignatures(store)
}

// TierMemory is _tier_memory.
func TierMemory(store string) ([]validation.Value, error) { return tierMemory(store) }

// WriteStore is _write_store.
func WriteStore(store string, sigs, mems []validation.Value) error {
	return writeStore(store, sigs, mems)
}

// FileSha256 is _file_sha256 ("" when the file does not exist).
func FileSha256(path string) string { return fileSha256(path) }

// ManifestAppend is _manifest_append (hash-chained).
func ManifestAppend(store string, record validation.Value) (validation.Value, error) {
	return manifestAppend(store, record)
}

// ProgramKey is _program_key: the store key plus its normalized policy dict.
func ProgramKey(policy validation.Value) (string, validation.Value, error) {
	return programKey(policy)
}

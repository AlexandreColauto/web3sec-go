// Prompt-pack concern: resolving a stage's prompt onto the embedded pack and
// its on-disk mirrors (resolve_prompt, prompt_inventory, unmapped_prompts).
package adapter

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"websec/assets"
	"websec/internal/validation"
)

// promptFS maps the repo-relative prompt path onto the embedded pack.
func promptFS(rel string) (fs.FS, string, bool) {
	switch {
	case strings.HasPrefix(rel, "prompts_legacy/"):
		return assets.LegacyPromptsFS, "prompts_legacy/" +
			strings.TrimPrefix(rel, "prompts_legacy/"), true
	case strings.HasPrefix(rel, "prompts/"):
		return assets.PromptsFS, rel, true
	}
	return nil, "", false
}

// PromptText returns the embedded bytes of a repo-relative prompt path.
func PromptText(rel string) (string, error) {
	fsys, name, ok := promptFS(rel)
	if !ok {
		return "", fmt.Errorf("prompt file missing for stage prompt %s", rel)
	}
	raw, err := fs.ReadFile(fsys, name)
	if err != nil {
		return "", fmt.Errorf("prompt file missing: %s", rel)
	}
	return string(raw), nil
}

// PromptPath is resolve_prompt(): the on-disk path of a stage's prompt.
// Python resolves REPO_ROOT/<rel>; the Go port serves the embedded mirror and
// returns its on-disk path when present (the path the operator can read).
func PromptPath(stage string) (string, error) {
	_, rel, err := StageConfig(stage)
	if err != nil {
		return "", err
	}
	if rel == "" {
		if KnownStage(stage) {
			return "", fmt.Errorf("stage %s is deterministic — no prompt; "+
				"the code runs this stage", validation.PyReprStr(stage))
		}
		return "", fmt.Errorf("unknown stage %s; known stages: %s",
			validation.PyReprStr(stage), strings.Join(StageIDs(), ", "))
	}
	if _, err := PromptText(rel); err != nil {
		return "", fmt.Errorf("prompt file missing for stage %s: %s",
			validation.PyReprStr(stage), filepath.Join(RepoRoot, rel))
	}
	// Python resolves REPO_ROOT/<rel> because prompts/ sits at its repo root.
	// The Go repo keeps the pack under assets/ (go:embed cannot reach outside
	// the embedding package), so try the Python layout first — a tree that
	// mirrors it — then the embed mirror. Either way the returned path names
	// a file the operator can read.
	for _, disk := range []string{filepath.Join(RepoRoot, rel),
		filepath.Join(RepoRoot, "assets", rel)} {
		if _, err := os.Stat(disk); err == nil {
			if abs, err := filepath.Abs(disk); err == nil {
				return abs, nil
			}
			return disk, nil
		}
	}
	// No on-disk mirror (a deployed binary): the embedded prompt is the
	// source, so name it by its repo-relative path.
	return rel, nil
}

// PromptInventory is prompt_inventory(): stage -> resolved prompt path (Null
// for deterministic stages). Order follows STAGES.
func PromptInventory() (validation.Value, error) {
	out := validation.VObj()
	for _, s := range Stages {
		_, rel, err := StageConfig(s.ID)
		if err != nil {
			return validation.VNull(), err
		}
		if rel == "" {
			out.O = append(out.O, validation.KV{K: s.ID, V: validation.VNull()})
			continue
		}
		disk := filepath.Join(RepoRoot, rel)
		p := rel
		if _, err := os.Stat(disk); err == nil {
			if abs, err := filepath.Abs(disk); err == nil {
				p = abs
			}
		}
		out.O = append(out.O, validation.KV{K: s.ID, V: validation.VStr(p)})
	}
	return out, nil
}

// UnmappedPrompts is unmapped_prompts(): prompt files no stage routes to.
func UnmappedPrompts() ([]string, error) {
	mapped := map[string]bool{}
	inv, err := PromptInventory()
	if err != nil {
		return nil, err
	}
	for _, kv := range inv.O {
		if kv.V.Kind == validation.Str {
			mapped[filepath.Base(kv.V.S)] = true
		}
	}
	loose := []string{}
	for _, dir := range []struct {
		fsys fs.FS
		rel  string
	}{{assets.PromptsFS, "prompts"}, {assets.LegacyPromptsFS, "prompts_legacy"}} {
		entries, err := fs.ReadDir(dir.fsys, dir.rel)
		if err != nil {
			continue
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".md") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			// README.md is pack metadata; 02_protocol_model.md is
			// intentionally orphaned by feedback-triage A4 — the
			// protocol-model stage now routes to the current
			// prompts/37 knowledge-graph prompt.
			if n == "README.md" || n == "02_protocol_model.md" ||
				mapped[n] {
				continue
			}
			loose = append(loose, dir.rel+"/"+n)
		}
	}
	return loose, nil
}

// mustRel resolves a stage's prompt path, panicking only on a routing config
// that named a prompt for a deterministic/unknown stage (unreachable after
// PromptPath succeeded).
func mustRel(stage string) string {
	_, rel, err := StageConfig(stage)
	if err != nil || rel == "" {
		return ""
	}
	return rel
}

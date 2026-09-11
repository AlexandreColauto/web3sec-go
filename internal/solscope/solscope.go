// Package solscope owns the source-walk vocabulary shared by every consumer
// that must cover exactly the same Solidity surface.
//
// H4: structidx's index walk (internal/structidx/parser.go) and the G11
// post-patch scope walk (internal/reproduction/postpatch_scope.go) each
// carried their own copy of the excluded-directory set — the same five
// names, maintained by hand in two places. A change to one would have
// drifted the index surface from the scope surface silently. The set lives
// here now: one constant, both walkers, no import cycle (this package
// depends on nothing).
package solscope

// excludedDirs is the directory-name blacklist (the walk's exclude set):
// version control, dependencies, Python bytecode and build output. A
// directory whose NAME is in this set is out of scope, at any depth.
var excludedDirs = map[string]bool{".git": true, "node_modules": true,
	"__pycache__": true, "cache": true, "out": true}

// IsExcluded reports whether a directory NAME (a single path component, not
// a path) belongs to the shared exclude set.
func IsExcluded(name string) bool { return excludedDirs[name] }

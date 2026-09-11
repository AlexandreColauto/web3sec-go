package assets

import "embed"

// TaxonomyFS is the G2 data pack: class_weights.json (schema-validated by
// internal/classweights; drift-tested against taxonomy.CanonicalClasses()).
//
//go:embed taxonomy
var TaxonomyFS embed.FS

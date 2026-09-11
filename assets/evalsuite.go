package assets

import (
	"embed"
	"fmt"

	"websec/internal/jval"
)

// EvalSuiteFS is the G4 gold-eval pack: cases.json (evaluation_case
// instances) + src/*.sol planted fixtures. Manifest-pinned; presence is
// asserted by assets/evalsuite_test.go, consumers go through
// LoadEvalCases — nobody fs.Walks this at score time.
//
//go:embed evalsuite/cases.json evalsuite/src
var EvalSuiteFS embed.FS

// LoadEvalCases parses cases.json (ordered) and returns the case objects.
// The element type is spelled jval.Value: it IS validation.Value (a type
// alias — no conversion needed), but this package cannot import validation
// back (validation reads its schemas from package assets, so the edge
// would cycle). Schema validation is the CALLER'S gate
// (assets/evalsuite_test.go runs validation.Validate over every row);
// this function only guarantees parse + shape (array, non-empty).
func LoadEvalCases() ([]jval.Value, error) {
	raw, err := EvalSuiteFS.ReadFile("evalsuite/cases.json")
	if err != nil {
		return nil, err
	}
	doc, err := jval.ParseOrdered(raw)
	if err != nil {
		return nil, err
	}
	if doc.Kind != jval.Arr {
		return nil, fmt.Errorf("evalsuite cases.json must be an array")
	}
	return doc.A, nil
}

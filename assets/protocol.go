package assets

import "embed"

// ProtocolFS holds the checked-in operator-facts example: a schema-valid
// operator_facts document that shows both shapes (a DNS fact on a url
// component, a dependency fact on a path component) and is validated by the
// protocolgraph test suite. It is an example, never a default: nothing reads
// it at run time.
//
//go:embed protocol/*.json
var ProtocolFS embed.FS

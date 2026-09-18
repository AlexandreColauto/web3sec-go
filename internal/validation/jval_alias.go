// jval_alias.go: re-exports of the leaf ordered-JSON value layer.
//
// The Value/KV model, its constructors, the canonical serializers and the
// ordered parser live in internal/jval (a leaf package) because package
// assets must build ordered values without importing validation
// (validation reads its schemas from assets — the edge would cycle).
// Every name below is a TYPE ALIAS or a forwarding variable, so
// validation.Value IS jval.Value: no conversion, no behavior change, and
// every existing caller compiles untouched.

package validation

import "websec/internal/jval"

// Value-model aliases (internal/jval/value.go).
type (
	Kind  = jval.Kind
	Value = jval.Value
	KV    = jval.KV
)

const (
	Null = jval.Null
	Bool = jval.Bool
	Int  = jval.Int
	Flt  = jval.Flt
	Str  = jval.Str
	Arr  = jval.Arr
	Obj  = jval.Obj
)

var (
	VNull             = jval.VNull
	VBool             = jval.VBool
	VInt              = jval.VInt
	VBigInt           = jval.VBigInt
	VFloat            = jval.VFloat
	VStr              = jval.VStr
	VArr              = jval.VArr
	VObj              = jval.VObj
	IntText           = jval.IntText
	FromAny           = jval.FromAny
	Canon             = jval.Canon
	CanonSpaced       = jval.CanonSpaced
	CanonCompact      = jval.CanonCompact
	DumpsOrdered      = jval.DumpsOrdered
	DumpIndented      = jval.DumpIndented
	DumpIndentedASCII = jval.DumpIndentedASCII
	WriteU4           = jval.WriteU4
	PythonFloat       = jval.PythonFloat
)

// Ordered-parser alias (internal/jval/parse.go).
var ParseOrdered = jval.ParseOrdered

// KV-list surgery aliases (internal/jval/kvutil.go).
var (
	SetOrAppend = jval.SetOrAppend
	SetDefault  = jval.SetDefault
)

// Value field-accessor aliases (internal/jval/accessors.go).
var (
	ObjAt  = jval.ObjAt
	ObjStr = jval.ObjStr
	StrArr = jval.StrArr
	HasKey = jval.HasObjKey
	AsObj  = jval.AsObj
)

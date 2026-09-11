package srcclass

// WHY: the classifier is only worth having if its PRECEDENCE is pinned down.
// Two published surfaces read it — the probe ranking (is this row a second
// site, or scaffolding?) and the scorecard's audit-surface composition (how
// many of the "153 files" are actually implementation?) — and a precedence
// regression would move both numbers silently in opposite directions. The
// table below therefore states the rule as a path -> role pair with the reason
// spelled out per row, and the tests around it assert the parts a table cannot:
// that all five classes are reachable, that the return value is always a
// declared class, and that the scaffolding predicate agrees with Classify.

import "testing"

// classifyCases is the rule, one row per decision the package makes. The `why`
// column is the point: a reader must be able to see which rule WON when two
// rules both apply.
var classifyCases = []struct {
	path string
	want Class
	why  string
}{
	// Precedence test-double > library: a mock is scaffolding wherever it has
	// been vendored to.
	{"lib/mock/MockToken.sol", TestDouble, "mock/ dir beats lib/ dir"},
	{"lib/MockToken.sol", TestDouble, "mock- file beats lib/ dir"},
	{"node_modules/mocks/Rollup.sol", TestDouble, "mock/ dir beats node_modules/ dir"},

	// Precedence test-double > interface: a test double of an interface is
	// still a test double.
	{"test/IFoo.sol", TestDouble, "test/ dir beats the IName convention"},
	{"contracts/tests/interfaces/IToken.sol", TestDouble, "test/ dir beats interfaces/ dir"},

	// The interface convention: I + capital letter, or the aggregate file.
	{"contracts/IName.sol", Interface, "I followed by a capital"},
	{"contracts/Index.sol", Implementation, "I followed by a lowercase n"},
	{"contracts/Internal.sol", Implementation, "I followed by a lowercase n"},
	{"contracts/I.sol", Implementation, "too short to be the convention"},
	{"contracts/Interfaces.sol", Interface, "the Interfaces.sol aggregate"},

	// Interface DIRECTORIES are matched per segment, so a path recorded from
	// the pin root behaves like the same path under src/.
	{"src/interfaces/Token.sol", Interface, "interfaces/ segment"},
	{"interfaces/Token.sol", Interface, "interfaces/ is the FIRST segment"},
	{"src/interface/Token.sol", Interface, "interface/ segment"},
	{"src/abstract/Base.sol", Interface, "abstract/ segment"},

	// Library: vendored or shared code.
	{"lib/Foo.sol", Library, "lib/"},
	{"libs/Foo.sol", Library, "libs/"},
	{"libraries/Foo.sol", Library, "libraries/"},
	{"external/Foo.sol", Library, "external/"},
	{"vendor/Foo.sol", Library, "vendor/"},
	{"node_modules/Foo.sol", Library, "node_modules/"},
	{"forge-std/Foo.sol", Library, "forge-std/"},
	{"@openzeppelin/Foo.sol", Library, "@openzeppelin/"},
	{"src/@openzeppelin/contracts/Foo.sol", Library, "@openzeppelin/ nested"},

	// Test doubles by directory and by file name.
	{"contracts/Rollup.t.sol", TestDouble, "foundry .t.sol test"},
	{"contracts/MockFoo.sol", TestDouble, "mock- prefix"},
	{"contracts/FooMock.sol", TestDouble, "-mock suffix"},
	{"contracts/Mockingbird.sol", TestDouble, "the prefix rule is textual: any Mock* file counts"},
	{"contracts/harness/Harness.sol", TestDouble, "harness/ dir"},
	{"contracts/fixtures/Foo.sol", TestDouble, "fixtures/ dir"},
	{"contracts/tests/Foo.sol", TestDouble, "tests/ dir"},
	{"contracts/Mocks/Foo.sol", TestDouble, "segment match is case-insensitive"},

	// Implementation: everything a finding has to live in to be about the
	// product.
	{"contracts/Foo.sol", Implementation, "ordinary contract"},
	{"Foo.sol", Implementation, "no directory at all"},
	{"contracts/l1/rollup/Rollup.sol", Implementation, "deep real path"},
	{"src/libraries-of-mine/Foo.sol", Implementation, "a library segment is the whole name, not a prefix"},
	{"weird/unexpected/dir/Thing.sol", Implementation, "a .sol under a directory the rules do not name is still code"},
	{"", Implementation, "empty path"},

	// Other: not solidity at all. The .sol gate runs BEFORE the directory
	// rules, so a config, doc or data file is never counted as audit
	// surface even when it sits where solidity is vendored or tested.
	{"foundry.toml", Other, "build config is not solidity"},
	{"README.md", Other, "docs are not solidity"},
	{"data.json", Other, "data is not solidity"},
	{"lib/README.md", Other, "the .sol gate beats the library dir rule"},
	{"test/data.json", Other, "the .sol gate beats the test-double dir rule"},
	{"contracts/interfaces/abi.json", Other, "the .sol gate beats the interface dir rule"},
}

// TestClassifySurfaceRole is the table above, run.
func TestClassifySurfaceRole(t *testing.T) {
	for _, c := range classifyCases {
		if got := Classify(c.path); got != c.want {
			t.Errorf("Classify(%q) = %q, want %q (%s)", c.path, got, c.want, c.why)
		}
	}
}

// TestClassifyTableCoversEveryClass guards the table itself: a table that
// forgot, say, Library could stay green while the library rule rotted.
func TestClassifyTableCoversEveryClass(t *testing.T) {
	seen := map[Class]bool{}
	for _, c := range classifyCases {
		seen[c.want] = true
	}
	if len(seen) != len(Classes) {
		t.Errorf("table covers %d of %d classes: %v", len(seen), len(Classes), seen)
	}
	for _, class := range Classes {
		if !seen[class] {
			t.Errorf("no table row expects %q", class)
		}
	}
}

// TestClassifyAlwaysReturnsADeclaredClass pins the other half of "exactly one
// of five": the value is one the reporting layer knows how to print.
func TestClassifyAlwaysReturnsADeclaredClass(t *testing.T) {
	declared := map[Class]bool{}
	for _, class := range Classes {
		declared[class] = true
	}
	for _, c := range classifyCases {
		if got := Classify(c.path); !declared[got] {
			t.Errorf("Classify(%q) = %q, which is not in Classes", c.path, got)
		}
	}
}

// TestClassifyNormalizesPathSeparators: the same file recorded by a Windows
// checkout is the same file.
func TestClassifyNormalizesPathSeparators(t *testing.T) {
	cases := []struct{ a, b string }{
		{`test\IFoo.sol`, "test/IFoo.sol"},
		{"lib/MockToken.sol/", "/lib/MockToken.sol"},
		{`contracts\mock\MockRollup.sol`, "contracts/mock/MockRollup.sol"},
	}
	for _, c := range cases {
		if got, want := Classify(c.a), Classify(c.b); got != want {
			t.Errorf("Classify(%q) = %q, Classify(%q) = %q; want the same",
				c.a, got, c.b, want)
		}
	}
}

// TestIsTestDoubleAgreesWithClassify keeps the probe-facing predicate and the
// scorecard-facing classifier from drifting: IsTestDouble is the Classify
// answer, not a second rule.
func TestIsTestDoubleAgreesWithClassify(t *testing.T) {
	for _, c := range classifyCases {
		want := c.want == TestDouble
		if got := IsTestDouble(c.path); got != want {
			t.Errorf("IsTestDouble(%q) = %v, Classify = %q (%s)",
				c.path, got, c.want, c.why)
		}
	}
}

// TestClassValuesAreTheOutputContract: these strings reach a --json view.
func TestClassValuesAreTheOutputContract(t *testing.T) {
	want := map[Class]string{
		Implementation: "implementation",
		TestDouble:     "test-double",
		Library:        "library",
		Interface:      "interface",
		Other:          "other",
	}
	if len(want) != len(Classes) {
		t.Fatalf("declared %d classes, Classes has %d", len(want), len(Classes))
	}
	for class, s := range want {
		if string(class) != s {
			t.Errorf("class value = %q, want %q", string(class), s)
		}
	}
}

// TestClassesReportingOrderIsComplete: implementation first is the number an
// operator reads, so the order is part of the contract.
func TestClassesReportingOrderIsComplete(t *testing.T) {
	want := []Class{Implementation, TestDouble, Library, Interface, Other}
	if len(Classes) != len(want) {
		t.Fatalf("Classes = %v, want %v", Classes, want)
	}
	for i := range want {
		if Classes[i] != want[i] {
			t.Fatalf("Classes = %v, want %v", Classes, want)
		}
	}
	seen := map[Class]bool{}
	for _, class := range Classes {
		if seen[class] {
			t.Errorf("Classes repeats %q", class)
		}
		seen[class] = true
	}
}

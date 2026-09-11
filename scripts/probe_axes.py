#!/usr/bin/env python3
"""The probe-axis gate list — ONE source of truth (H8).

`scripts/golden-run.py` used to carry a hand-copied `SURFACE2_AXES` literal
of the same six names `scripts/check-golden.py` enforced in
`EXPECTED_PROBE_AXES`: a seventh axis (or a rename) could be added to one
side and not the other, and the rot gate would keep passing on the stale
copy. The table lives here now and both scripts import it.

The Go side (`internal/probes/axis_coverage_test.go`) parses this file with
the same regex it used on check-golden.py, so the registry -> gate edge is
still machine-checked: a probe landed without widening the gate fails the
default suite.

Axis name -> the state a green golden run must reach on it:

  "rows"  — the axis emits at least one row (its fixture is present, its
            detector fires, the surface assembly keeps it)
  "blind" — the axis examines sites and publishes BLIND keys, but no row
            (the legitimate silent state: `probes blank` citing one of those
            keys is what closes it)

Either way `sites` must be >= 1: `no-sites` means the detector saw nothing
at all, which is exactly the C2/F6 blind spot — an axis whose regression no
other gate can see.

Note for readers editing this file: `check-golden.py` reads it at import
time, and `golden-run.py` derives its per-axis assertion order from the
table's insertion order. Keep the table's exact shape — the table is named
EXPECTED_PROBE_AXES, annotated as a dict of axis to state, and opened with a
brace at the end of the assignment line — because the Go cross-check
(internal/probes/axis_coverage_test.go) parses it with a regex anchored on
that form. Do not repeat that shape anywhere else in this file: the regex
takes the FIRST match.
"""
from __future__ import annotations

EXPECTED_PROBE_AXES: dict[str, str] = {
    "accumulator-skew": "blind",
    "enforcement-timing": "blind",
    "guard-short-circuit": "rows",
    "incentive-inversion": "rows",
    "liveness": "rows",
    "primitive-symmetry": "rows",
}

# The axes the P5 surface2 recipe must carry >=1 ROW on: EVERY registered
# axis, in table order (the surface2 corpus is the buggy-family corpus, so no
# axis is legitimately blind there — only the P4 campaign needs the two blind
# axes for `probes blank`'s keys). Derived here, never a second literal:
# adding a seventh axis widens the recipe's assertion too.
SURFACE2_AXES: tuple[str, ...] = tuple(EXPECTED_PROBE_AXES)

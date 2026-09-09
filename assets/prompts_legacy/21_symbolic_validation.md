# Stage 21 — Targeted Symbolic Validation

Use Halmos or another available symbolic tool only when there is a precise question that symbolic reasoning can answer.

## Objective

Answer targeted questions such as:

- can this state be reached?
- can an unauthorized actor satisfy this condition?
- can the invariant be violated for some satisfiable input?
- can this signature condition be bypassed under these constraints?

Do not run expensive symbolic analysis on every contract simply because the tool exists.

## Procedure

1. State the exact hypothesis/question.
2. Identify the minimum relevant contracts/functions/state.
3. Formalize the property or satisfiability question.
4. Run symbolic analysis.
5. Interpret satisfiable/unsatisfiable results carefully.
6. If satisfiable, produce a concrete witness or translate it into an executable test.
7. Record limitations and assumptions.

## Output

Store symbolic artifacts/evidence under `audit/pocs/` and/or `audit/traces/`.
Update the hypothesis with the exact symbolic question and result.

# Claim sources (operator hand-written)

All spec files were authored by the operator (controller session) against the
grammar as the tool accepts it; none are shipped app templates. Key facts
established by this run:

- Mapping reads `st[key]` parse ONLY in call-argument position; require/assert
  lvalues -> malformed-spec (7 first-round rejections).
- `with { msg.value = x; }` overrides work (corpus-pinned); bare payable calls
  bind zero value.
- A Solidity STRING LITERAL anywhere in the contract (require(.., "msg")) makes
  the tool report a rule-LESS `rejected-feature: string literal in an
  expression is out of scope` abort envelope -> rule-less -> unmapped bucket.
- Donation classes (ES06/ES11) are expressible ONLY via post-state
  requirements or free-mint analogues (require supply > 0; assert
  pool*1e18/supply == k) -> see flashloan_free + the ES11 solver-timeout.

Twins used: MintFreeC.sol (free-mint donation analogue, storage-write-only),
CleanB.sol (ES17+total), EscrowB.sol (ES17+total), ES11b.sol (require->assert
semantic-preserving twin; probe was inconclusive and was NOT scored).
ES12 file name (SignatureReplay) is the evalsuite's own; LegacyVault mapping was
my error and that case stayed unscored (no file).
## Join mechanics (ORIGINAL PRE-RESCORE READING — superseded; see the retraction below and scorecard.tsv for the current 7-column table)

Both donation twins name their rule `donation_keeps_rate`; the tool prints no
target field on rule-bearing lines, so a rule-keyed class map can tie that
name only once. The scored map therefore ties ES06's rule-LESS abort envelope
by file stem (VTokenDonation -> CASE-000000000006, refused=unsupported-feature)
and MintInflation's envelope likewise (stem -> CASE-00000000000b); the
`donation_keeps_rate` rule row maps to ES11. (Historical note: at authoring time the donation line appeared unjoined; the committed rescore ties all 12 lines and the unjoin narrative belongs to the pre-M instrument — kept for provenance, corrected by the retraction below.)

## What the run shows (final table in scorecard.tsv)

- detected 2 (ES02 authorization, ES13 flash-loan), proven_silence 0,
  refused 7 (5x rejected-feature incl. the string-literal abort + packed
  storage + array type; 2x unsupported-feature), [pre-rescore tally — the 7-column rescore ties all 12 lines, 0 unjoined; see the note above and the retraction below],
  untied cases 9 (reentrancy x3, oracle, sig-replay, bridge x2, cross-chain,
  liquidation — classes where no claim was authored this pass).
- clean control ES17: PROVEN on the total-accounting claim. RETRACTION
  (M run-2): an earlier note here claimed ES17's gold row made that "no
  signal" and spoke of gold-label drift. WRONG — `cases.json` marks
  CASE-000000000011 (contract Escrow) `confirmed-not-exploitable`: it IS the
  clean control, and a 7-column rescore puts it at `clean_agreed 1`. No label
  drift existed; the drift was in my reading.

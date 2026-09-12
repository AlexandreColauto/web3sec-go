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
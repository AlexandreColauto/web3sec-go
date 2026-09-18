package planner

// reconcile.go — FIX-6: lens-closure falsifiability. The operator's G-02
// post-mortem: the L-04 attestation let them quote the symmetry table and
// narrate 42 divergences as benign duals, while the matrix had already named
// the mismatch ("burn deposit vs transfer-out drop — who funds the
// difference?") and the reconciliation passed without a single file#L cite.
// `webv2 answered` already refuses a probe-row reason that names nothing from
// the row's own surface entry; that falsifiability pressure was never applied
// to lens attestations. The gate: closing the primitive-symmetry lens
// reconciles every funding-mismatch / member-disagreement divergence row in
// the current surface — per member, a `primitive:Symbol#L<line>` cite whose
// symbol appears on the row's own surface entry, or the id of a filed finding
// that records the answer. Rows left uncited/unattached refuse the
// attestation, naming the offending rows and the two legal exits.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"websec/internal/findings"
	"websec/internal/state"
	"websec/internal/validation"
)

// Local mirrors of probes.SymFundingMismatch / probes.SymMemberDisagreement:
// the planner must not import the probes package (probes wires the planner —
// the import would cycle), so the divergence kinds are duplicated here the
// same way RolePrivilegeSurface deliberately duplicates its derivation.
const (
	symFundingMismatch    = "funding-mismatch"
	symMemberDisagreement = "member-disagreement"
)

// reconcilePrimitives is the custody-primitive vocabulary the matrix itself
// speaks (symmetry.go's primitive cells): the tokens a funding cite may name.
// Kept in sorted order for the refusal message.
var reconcilePrimitives = []string{"burn", "mint", "send-native",
	"transfer-in", "transfer-out"}

// reconcileCiteRe is the shape of one per-member funding cite:
// `primitive:Symbol#L<line>`. The primitive token is validated against
// reconcilePrimitives by the gate (so the refusal can name the vocabulary);
// the Symbol is checked against the row's own surface entry for the same
// reason.
var reconcileCiteRe = regexp.MustCompile(`^([^:#]+):([^#]+)#L([0-9]+)$`)

// ParseReconcile parses --reconcile into records: `ROWID=VALUE`, separated by
// ';'. VALUE is either a finding id (F-<12 hex digits>) — the finding exit —
// or one or more `primitive:Symbol#L<line>` cites separated by '|' — the
// per-member funding cite. Parse checks the SHAPE only; whether a cite names
// the row's own symbols is the gate's question, asked against the row's
// surface entry, so a fabricated cite is answered there with the row's own
// symbol list in hand.
func ParseReconcile(spec *string) ([]validation.Value, error) {
	if spec == nil || *spec == "" {
		return nil, nil
	}
	out := []validation.Value{}
	for _, part := range strings.Split(*spec, ";") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		id, value, _ := strings.Cut(part, "=")
		id = strings.TrimSpace(id)
		value = strings.TrimSpace(value)
		if id == "" || value == "" {
			return nil, errValue("--reconcile entry " +
				validation.PyReprStr(part) + " must be ROWID=VALUE — the " +
				"divergence row's row_id, then either a filed finding id " +
				"(F-<12 hex digits>) or one or more " +
				"primitive:Symbol#L<line> cites separated by |")
		}
		rec := validation.VObj(
			kv("row_id", validation.VStr(id)),
			kv("cites", validation.VArr()),
			kv("finding", validation.VNull()),
		)
		if findingRefPattern.MatchString(value) {
			rec.O = validation.SetOrAppend(rec.O, "finding",
				validation.VStr(value))
			out = append(out, rec)
			continue
		}
		for _, seg := range strings.Split(value, "|") {
			seg = strings.TrimSpace(seg)
			if seg == "" {
				continue
			}
			if !reconcileCiteRe.MatchString(seg) {
				return nil, errValue("--reconcile cite " +
					validation.PyReprStr(seg) + " for row " +
					validation.PyReprStr(id) + " is not " +
					"primitive:Symbol#L<line> — e.g. " +
					"transfer-out:L2Gateway.drop#L77, or attach the row to " +
					"a filed finding: ROWID=F-<12 hex digits>")
			}
			cites := listOf(rec, "cites")
			cites = append(cites, validation.VStr(seg))
			rec.O = validation.SetOrAppend(rec.O, "cites",
				validation.VArr(cites...))
		}
		if len(listOf(rec, "cites")) == 0 {
			return nil, errValue("--reconcile entry for row " +
				validation.PyReprStr(id) + " records no cite — value " +
				validation.PyReprStr(value) + " is empty")
		}
		out = append(out, rec)
	}
	return out, nil
}

// divergenceRows is the surface's funding-mismatch / member-disagreement rows
// in surface order — the rows a primitive-symmetry attestation reconciles.
func divergenceRows(surface validation.Value) []validation.Value {
	out := []validation.Value{}
	for _, row := range listOf(surface, "rows") {
		switch validation.ObjStr(row, "divergence") {
		case symFundingMismatch, symMemberDisagreement:
			out = append(out, row)
		}
	}
	return out
}

// checkLensReconciliation is the FIX-6 gate behind MarkLens: closing a
// primitive-symmetry lens reconciles every divergence row in the current
// surface. An attestation is accepted only when each row carries either a
// per-member funding cite (every member of the row named by some cite whose
// symbol appears on the row's own surface entry) or the id of a filed
// finding. A campaign with no probe artifact has nothing to reconcile — the
// grandfather case, the same exemption every probe gate applies.
//
// It returns the reconciliation records the attestation may RECORD — the
// freshly supplied ones, validated here, in the order given — so a record
// never lands on the lens entry without having been checked against the row
// it names. A --reconcile entry naming a row that is not a divergence row in
// the current surface is refused (a record that checks nothing is how the
// gate would rot).
//
// Reconciliations recorded by an EARLIER attestation of the same lens stay
// legal (a re-attestation is not a fresh audit): a fresh --reconcile overrides
// the stored record for the rows it names, and stored records are trusted as
// written — they were validated by this gate when they landed.
func checkLensReconciliation(campaign *state.Campaign, lensEntry validation.Value,
	opts LensOpts) ([]validation.Value, error) {
	fresh := orNil(opts.Reconcile)
	surface, err := PB().CampaignSurface(campaign)
	if err != nil {
		return nil, err
	}
	if surface == nil {
		if len(fresh) > 0 {
			return nil, errValue("--reconcile names rows the campaign cannot " +
				"check: the campaign has no probe surface, so there is " +
				"nothing to reconcile — run `webv2 probes " +
				campaign.CampaignID + " run --emit` first, or close without " +
				"--reconcile")
		}
		return nil, nil
	}
	rows := divergenceRows(*surface)
	rowByID := map[string]validation.Value{}
	for _, row := range rows {
		rowByID[validation.ObjStr(row, "row_id")] = row
	}
	// a fresh record must name a divergence row in THIS surface
	for _, rec := range fresh {
		rid := validation.ObjStr(rec, "row_id")
		if _, ok := rowByID[rid]; !ok {
			return nil, errValue("--reconcile names " +
				validation.PyReprStr(rid) + ", which is not a funding-mismatch " +
				"or member-disagreement divergence row in the current surface " +
				"— the surface's divergence row(s): " + joinRowTokens(rows) +
				"; read the row ids off `webv2 symmetry " + campaign.CampaignID +
				" --json` or the surface itself")
		}
	}
	if len(fresh) > 0 {
		for _, rec := range fresh {
			row := rowByID[validation.ObjStr(rec, "row_id")]
			if reason := validateReconcileRecord(campaign, row, rec); reason != "" {
				lid := validation.ObjStr(lensEntry, "id")
				return nil, errValue("lens " + lid + " attests " +
					"primitive-symmetry over 1 unreconciled divergence " +
					"row(s) — " + reconcileWhat(row, reason) +
					". Every funding-mismatch / member-disagreement row must " +
					"be reconciled with the funding primitive per member: " +
					"--reconcile 'RID=primitive:Symbol#L<line>|...' " +
					"(primitive: " + strings.Join(reconcilePrimitives, "|") +
					"; Symbol must appear on the row's own surface entry) — " +
					"or attached to a filed finding: " +
					"--reconcile 'RID=F-<12 hex digits>'.")
			}
		}
	}
	// coverage: every divergence row is either freshly reconciled or carried
	// on a reconciliation an earlier attestation of this lens recorded
	byID := map[string]validation.Value{}
	for _, rec := range listOf(lensEntry, "reconciliation") {
		byID[validation.ObjStr(rec, "row_id")] = rec
	}
	for _, rec := range fresh {
		byID[validation.ObjStr(rec, "row_id")] = rec
	}
	var bad []string
	for _, row := range rows {
		rid := validation.ObjStr(row, "row_id")
		if _, ok := byID[rid]; !ok {
			bad = append(bad, reconcileWhat(row,
				"no reconciliation on record — the row's own surface names: "+
					strings.Join(RowSymbols(row), ", ")))
		}
	}
	if len(bad) == 0 {
		if opts.Reconcile != nil {
			return fresh, nil
		}
		return nil, nil
	}
	lid := validation.ObjStr(lensEntry, "id")
	return nil, errValue("lens " + lid + " attests primitive-symmetry over " +
		itoa(len(bad)) + " unreconciled divergence row(s) — " +
		strings.Join(bad, "; ") + ". Every funding-mismatch / " +
		"member-disagreement row must be reconciled with the funding " +
		"primitive per member: --reconcile 'RID=primitive:Symbol#L<line>|...' " +
		"(primitive: " + strings.Join(reconcilePrimitives, "|") +
		"; Symbol must appear on the row's own surface entry) — or attached " +
		"to a filed finding: --reconcile 'RID=F-<12 hex digits>'.")
}

// rowToken is the identity of one divergence row in a refusal message:
// row_id (kind, family direction:asset).
func rowToken(row validation.Value) string {
	rid := validation.ObjStr(row, "row_id")
	if rid == "" {
		rid = "<no row_id>"
	}
	return rid + " (" + validation.ObjStr(row, "divergence") + ", " +
		validation.ObjStr(row, "family") + " " + validation.ObjStr(row, "direction") + ":" +
		validation.ObjStr(row, "asset") + ")"
}

// joinRowTokens renders the surface's divergence rows as identity tokens for
// a refusal message.
func joinRowTokens(rows []validation.Value) string {
	if len(rows) == 0 {
		return "none"
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, rowToken(row))
	}
	return strings.Join(out, ", ")
}

// orNil is a nil []validation.Value as an empty slice.
func orNil(v *[]validation.Value) []validation.Value {
	if v == nil {
		return nil
	}
	return *v
}

// reconcileWhat renders one offending row for the refusal: its identity from
// the row's own surface entry, then the precise reason it is unreconciled.
func reconcileWhat(row validation.Value, reason string) string {
	return rowToken(row) + ": " + reason
}

// validateReconcileRecord checks one freshly supplied reconciliation record
// against its surface row. It returns "" when the record is a legal exit;
// otherwise it returns the reason the record does not reconcile the row.
func validateReconcileRecord(campaign *state.Campaign, row,
	rec validation.Value) string {
	if finding := validation.ObjStr(rec, "finding"); finding != "" {
		if !findingRefPattern.MatchString(finding) {
			return "--reconcile " + validation.PyReprStr(finding) +
				" is not a finding id (F-<12 hex digits>)"
		}
		if _, err := os.Stat(filepath.Join(campaign.FindingsDir,
			finding+".json")); err != nil {
			return "--reconcile " + finding + " does not exist in this " +
				"campaign — a divergence may be attached to a real filed " +
				"finding, never to a citation that was invented or mistyped"
		}
		// FIX-C: the finding exit attaches a live divergence to a LIVE
		// finding — the same rule checkConsequenceFlags applies to --finding.
		// A terminal finding (DISPROVED, OUT_OF_SCOPE, INFORMATIONAL,
		// DUPLICATE, SUPERSEDED) records a question that is already answered;
		// attaching an unresolved row to it reconciles nothing.
		f, err := findings.LoadFinding(campaign, finding)
		if err != nil {
			return "--reconcile " + finding + " cannot be loaded (" +
				err.Error() + ") — a divergence may be attached to a real " +
				"filed finding only"
		}
		if status := validation.ObjStr(f, "status"); status != "" {
			if _, terminal := findings.TERMINAL[status]; terminal {
				return "--reconcile " + finding + " names a " + status +
					" finding — a terminal finding records nothing about a " +
					"divergence that is still unresolved. Attach a live " +
					"finding (one that is not DISPROVED, OUT_OF_SCOPE, " +
					"INFORMATIONAL, DUPLICATE or SUPERSEDED), or cite the " +
					"funding primitive per member"
			}
		}
		return ""
	}
	cites := listOf(rec, "cites")
	if len(cites) == 0 {
		return "records neither a per-member cite nor a filed finding id"
	}
	symbols := RowSymbols(row)
	memberNamed := map[string]bool{}
	for _, c := range cites {
		cite := pyStr(c)
		m := reconcileCiteRe.FindStringSubmatch(cite)
		if m == nil {
			return "cite " + validation.PyReprStr(cite) + " is not " +
				"primitive:Symbol#L<line>"
		}
		primitive, symbol := m[1], m[2]
		if !inList(primitive, reconcilePrimitives) {
			return "cite " + validation.PyReprStr(cite) + " names " +
				validation.PyReprStr(primitive) + ", which is not a custody " +
				"primitive the matrix speaks (vocabulary: " +
				strings.Join(reconcilePrimitives, ", ") + ")"
		}
		if len(symbols) > 0 && namesSymbol(symbol, symbols) == "" {
			return "cite " + validation.PyReprStr(cite) + " names no symbol " +
				"from the row's own surface entry (the row names: " +
				strings.Join(symbols, ", ") + ")"
		}
		low := strings.ToLower(symbol)
		for _, member := range listOf(row, "members") {
			label := pyStr(member)
			if label != "" && strings.Contains(low, strings.ToLower(label)) {
				memberNamed[label] = true
			}
		}
	}
	var missing []string
	for _, member := range listOf(row, "members") {
		if label := pyStr(member); label != "" && !memberNamed[label] {
			missing = append(missing, label)
		}
	}
	if len(missing) > 0 {
		return "the cites do not name the funding primitive per member " +
			"(missing: " + strings.Join(missing, ", ") + ")"
	}
	return ""
}

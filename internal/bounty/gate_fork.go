// The mainnet-fork-poc gate check (check11): the PoC must have RUN on
// the pinned fork.

package bounty

import (
	"websec/internal/validation"
)

// forkPocBlockerFallback and forkPocBlockerPrefix build check11's blocker.
// The status seam already knows WHY the fork PoC is not proven (no fork
// evidence at all vs. evidence without a verified sequence run), so the
// blocker carries that reason verbatim instead of the constant. The fallback
// stays for a status that fails without a reason of its own.
const (
	forkPocBlockerFallback = "no proven mainnet fork PoC (the latest required step)"
	forkPocBlockerPrefix   = "no proven mainnet fork PoC: "
)

// check11 is mainnet-fork-poc — the LATEST REQUIRED STEP: the PoC must have
// RUN on the pinned mainnet fork. A unit harness proves the semantics; only
// the fork proves mainnet.
//
// The check row keeps the seam's own reason; the blocker repeats it so the
// operator reading `gate` sees the same precise status `prove` shows.
func (g *gate) check11() error {
	findingID := validation.ObjStr(g.f, "finding_id")
	ok, why, err := forkPocStatusFunc(g.campaign, findingID)
	if err != nil {
		return err
	}
	if ok {
		g.add("mainnet-fork-poc", "pass", why, "")
		return nil
	}
	rows, err := waiversFunc(g.campaign, "mainnet-fork-poc")
	if err != nil {
		return err
	}
	for _, w := range rows {
		subject := validation.ObjStr(w, "subject")
		if subject != "*" && subject != findingID {
			continue
		}
		g.add("mainnet-fork-poc", "pass", "waived by "+validation.PyStr(validation.ObjAt(w, "actor"))+
			": "+headRunes(validation.PyStr(validation.ObjAt(w, "reason")), 80), "")
		return nil
	}
	g.add("mainnet-fork-poc", "fail", why, "")
	blocker := forkPocBlockerFallback
	if why != "" {
		blocker = forkPocBlockerPrefix + why
	}
	g.blockers = append(g.blockers, blocker)
	return nil
}

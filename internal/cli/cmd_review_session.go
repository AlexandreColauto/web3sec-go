package cli

// cmd_review_session: `webv2 review-session {start|end} [campaign]
// [--actor A] [--artifact A]... [--loc N]` — the operator's measured review session
// (framework-plan-v1.6 Part 1). The ~60-minute / 400-line budget is a soft
// target whose effect on catch rate is correlatable only if the sessions are
// measured, so the verb writes both ends to the ledger.
//
// The campaign positional is OPTIONAL: a session is stored in
// campaign_state.review_sessions, so an operator with one campaign under root
// can omit it, and an operator with several names the one they are reviewing.
// An ambiguous root is refused rather than guessed at. `end` carries no session-id positional
// either — one session may be open at a time, so the open row IS the session
// being closed, and `end` with nothing open is the exit-2 refusal.

import (
	"fmt"
	"strconv"
	"strings"

	"websec/internal/reviewsession"
	"websec/internal/state"
	"websec/internal/validation"
)

// reviewSessionArgs is the parsed command line.
type reviewSessionArgs struct {
	action    string
	campaign  string
	actor     string
	artifacts []string
	loc       int64
}

func runReviewSession(root string, args []string, r *Runner) int {
	return t14Dispatch(root, r, func() error {
		return reviewSessionCmd(root, args, r)
	})
}

func reviewSessionCmd(root string, args []string, r *Runner) error {
	if helpRequested(r.Out, "review-session", args) {
		return nil
	}
	a, err := parseReviewSession(args)
	if err != nil {
		return err
	}
	c, err := reviewSessionCampaign(root, a.campaign)
	if err != nil {
		return err
	}
	if a.action == "start" {
		return reviewSessionStart(c, a, r)
	}
	return reviewSessionEnd(c, a, r)
}

// parseReviewSession is the argparse layer: one positional ({start|end}) and
// the three options, in the house hand-rolled loop (cmd_assume.go's shape).
func parseReviewSession(args []string) (*reviewSessionArgs, error) {
	a := &reviewSessionArgs{}
	var pos, extras []string
	for i := 0; i < len(args); i++ {
		consumed, handled, err := reviewSessionFlag(args, i, a)
		if err != nil {
			return nil, err
		}
		if handled {
			i += consumed
			continue
		}
		if len(pos) < 2 {
			pos = append(pos, args[i])
			continue
		}
		extras = append(extras, args[i])
	}
	return reviewSessionChecked(a, pos, extras)
}

// reviewSessionChecked is the post-parse validation, in argparse's order:
// missing positional, invalid choice, then unrecognized arguments.
func reviewSessionChecked(a *reviewSessionArgs, pos, extras []string) (*reviewSessionArgs, error) {
	if len(pos) == 0 {
		return nil, reviewSessionArgErr(
			"the following arguments are required: action")
	}
	a.action = pos[0]
	if a.action != "start" && a.action != "end" {
		return nil, reviewSessionArgErr("argument action: invalid choice: %s "+
			"(choose from 'start', 'end')", validation.PyReprStr(a.action))
	}
	if len(pos) > 1 {
		a.campaign = pos[1]
	}
	if len(extras) > 0 {
		return nil, t14Unrecognized(strings.Join(extras, " "))
	}
	return a, nil
}

// reviewSessionFlag consumes one option token: --actor, --artifact
// (repeatable, so a session names every artifact it covered), --loc, each in
// both the "--flag V" and "--flag=V" spellings.
func reviewSessionFlag(args []string, i int, a *reviewSessionArgs) (int, bool, error) {
	name, inline, hasInline := splitFlag(args[i])
	switch name {
	case "--actor":
		return reviewSessionFlagStr(args, i, inline, hasInline, &a.actor)
	case "--artifact":
		return reviewSessionFlagList(args, i, inline, hasInline, &a.artifacts)
	case "--loc":
		return reviewSessionFlagLoc(args, i, inline, hasInline, a)
	}
	if looksLikeOption(args[i]) {
		return 0, true, t14Unrecognized(args[i])
	}
	return 0, false, nil
}

func reviewSessionFlagStr(args []string, i int, inline string, hasInline bool,
	dst *string) (int, bool, error) {
	v, consumed, err := reviewSessionVal(args, i, inline, hasInline)
	if err != nil {
		return 0, true, err
	}
	*dst = v
	return consumed, true, nil
}

func reviewSessionFlagList(args []string, i int, inline string, hasInline bool,
	dst *[]string) (int, bool, error) {
	v, consumed, err := reviewSessionVal(args, i, inline, hasInline)
	if err != nil {
		return 0, true, err
	}
	*dst = append(*dst, v)
	return consumed, true, nil
}

func reviewSessionFlagLoc(args []string, i int, inline string, hasInline bool,
	a *reviewSessionArgs) (int, bool, error) {
	v, consumed, err := reviewSessionVal(args, i, inline, hasInline)
	if err != nil {
		return 0, true, err
	}
	n, nerr := reviewSessionLoc(v)
	if nerr != nil {
		return 0, true, nerr
	}
	a.loc = n
	return consumed, true, nil
}

// reviewSessionVal is the value of a --flag token in either spelling.
func reviewSessionVal(args []string, i int, inline string, hasInline bool) (string, int, error) {
	if hasInline {
		return inline, 0, nil
	}
	v, ok := flagValue(args, i)
	if !ok {
		return "", 0, reviewSessionArgErr("argument %s: expected one argument",
			args[i])
	}
	return v, 1, nil
}

func reviewSessionLoc(raw string) (int64, error) {
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, reviewSessionArgErr("argument --loc: invalid int value: %s",
			validation.PyReprStr(raw))
	}
	return n, nil
}

// reviewSessionArgErr renders an argparse failure against the verb's own
// usage line, so help, usage and refusals cannot disagree about the signature.
func reviewSessionArgErr(format string, args ...any) error {
	return t14ArgparseErr(helpUsageText("review-session"), "review-session",
		format, args...)
}

// reviewSessionCampaign resolves the session's campaign: the verb has no
// campaign positional, so it takes the named campaign, or the only one under
// root when none is named, and refuses a root with none or several — a review
// session recorded against the wrong campaign is a measurement of the wrong
// operator context.
//
// The positional is optional rather than absent because the projection lives in
// `campaign_state.review_sessions`: a session is stored per campaign, so an
// operator holding more than one campaign must be able to say which. Without
// it the verb is unusable on any root holding two campaigns.
func reviewSessionCampaign(root, want string) (*state.Campaign, error) {
	if want != "" {
		return t14Open(root, want)
	}
	cids, err := state.ListCampaigns(root)
	if err != nil {
		return nil, err
	}
	if len(cids) != 1 {
		return nil, t14ExitErr(2, "review-session needs a campaign: name one "+
			"(`review-session start <campaign>`), or keep exactly one under "+
			"%s — found %d%s\n", root, len(cids), reviewSessionFound(cids))
	}
	return state.Open(root, cids[0])
}

func reviewSessionFound(cids []string) string {
	if len(cids) == 0 {
		return ""
	}
	return ": " + strings.Join(cids, ", ")
}

func reviewSessionStart(c *state.Campaign, a *reviewSessionArgs, r *Runner) error {
	row, err := reviewsession.Start(c, a.actor, a.artifacts)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(r.Out, "review session %s started — actor %s, "+
		"%d artifact(s) covered, clock %s\n",
		validation.ObjStr(row, "session_id"), validation.ObjStr(row, "actor"),
		len(validation.ObjAt(row, "artifacts_covered").A),
		validation.ObjStr(row, "started_at")); err != nil {
		return err
	}
	return nil
}

func reviewSessionEnd(c *state.Campaign, a *reviewSessionArgs, r *Runner) error {
	open, ok := reviewsession.Open(c)
	if !ok {
		return t14ExitErr(2, "no open review session in campaign %s\n",
			c.CampaignID)
	}
	sid := validation.ObjStr(open, "session_id")
	row, err := reviewsession.End(c, sid, a.actor, a.loc)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(r.Out, "review session %s ended — %d lines "+
		"(actor %s)\n", sid, objInt(row, "loc"),
		validation.ObjStr(row, "closed_by")); err != nil {
		return err
	}
	return nil
}

func init() {
	register(command{ord: 93, name: "review-session",
		line: `review-session {start|end} [campaign] [--actor A] [--artifact A]... [--loc N]   record an operator review session`,
		run:  runReviewSession})
}

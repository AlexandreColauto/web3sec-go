// cmd_price: `webv2 price <campaign> {set,table} [asset] [usd] [--source S]
// [--as-of T] [--actor A]` — the campaign asset-price table (G): every USD
// figure in a finding must name the row it was computed from. Append-only;
// the latest row for an asset is the effective price. cli.py cmd_price
// verbatim.
package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"websec/internal/pricing"
	"websec/internal/validation"
)

const t26PriceUsage = `usage: webv2 price [-h] [--source SOURCE] [--as-of AS_OF] [--actor ACTOR]
                   campaign {set,table} [asset] [usd]
`

const t26PriceHelp = t26PriceUsage + `
positional arguments:
  campaign
  {set,table}
  asset
  usd

options:
  -h, --help       show this help message and exit
  --source SOURCE  where the price came from (set)
  --as-of AS_OF    price timestamp (set)
  --actor ACTOR    who set it (set)
`

// priceArgs is the parsed command line. usd is nil when the positional is
// absent (argparse nargs="?").
type priceArgs struct {
	campaign string
	action   string
	asset    string
	usd      *float64
	source   string
	asOf     string
	actor    string
}

func runPrice(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		a, err := parsePrice(args, r)
		if err != nil || a == nil {
			return err
		}
		c, err := t14Open(root, a.campaign)
		if err != nil {
			return err
		}
		if a.action == "set" {
			// argparse hands cmd_price None for a missing positional; the
			// reference then fails inside set_price with these two messages.
			if a.asset == "" || strings.TrimSpace(a.asset) == "" {
				return errors.New("asset symbol required")
			}
			if a.usd == nil {
				return errors.New("usd must be a positive number, got None")
			}
			row, err := pricing.SetPrice(c, a.asset, *a.usd, a.source, a.asOf,
				a.actor)
			if err != nil {
				return err
			}
			src := a.source
			if len([]rune(src)) > 50 {
				src = string([]rune(src)[:50])
			}
			fmt.Fprintf(r.Out, "price row %s: %s @ $%s (source: %s)\n",
				objStr(row, "price_id"), a.asset,
				pyMoney2(*a.usd), src)
			return nil
		}
		table, err := pricing.LoadTable(c)
		if err != nil {
			return err
		}
		rows := objAt(table, "prices").A
		if len(rows) == 0 {
			fmt.Fprint(r.Out, "(price table empty — `webv2 price "+c.CampaignID+" "+
				"set <asset> <usd> --source ...`)\n")
			return nil
		}
		for _, row := range rows {
			src := objStr(row, "source")
			if len([]rune(src)) > 40 {
				src = string([]rune(src)[:40])
			}
			fmt.Fprintf(r.Out, "%s  %s $%s  as of %s  src: %s\n",
				objStr(row, "price_id"), pyLeft(objStr(row, "asset"), 12),
				pyRight(pyMoney2(objFlt(row, "usd")), 14),
				objStr(row, "as_of"), src)
		}
		return nil
	})
}

// parsePrice is the argparse layer: campaign + price_action (choices), then
// the optional asset/usd positionals.
func parsePrice(args []string, r *Runner) (*priceArgs, error) {
	a := &priceArgs{}
	var pos []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-h" || arg == "--help" {
			fmt.Fprint(r.Out, t26PriceHelp)
			return nil, nil
		}
		name, val, hasVal := splitFlag(arg)
		switch name {
		case "--source", "--as-of", "--actor":
			if !hasVal {
				if i+1 >= len(args) {
					return nil, t14ArgparseErr(t26PriceUsage, "price",
						"argument %s: expected one argument", name)
				}
				val = args[i+1]
				i++
			}
		default:
			if strings.HasPrefix(arg, "-") && !isNegNumberCLI(arg) {
				return nil, t14Unrecognized(arg)
			}
			pos = append(pos, arg)
			continue
		}
		switch name {
		case "--source":
			a.source = val
		case "--as-of":
			a.asOf = val
		case "--actor":
			a.actor = val
		}
	}
	if len(pos) == 0 {
		return nil, t14ArgparseErr(t26PriceUsage, "price",
			"the following arguments are required: campaign, price_action")
	}
	if len(pos) == 1 {
		return nil, t14ArgparseErr(t26PriceUsage, "price",
			"the following arguments are required: price_action")
	}
	a.campaign = pos[0]
	a.action = pos[1]
	if a.action != "set" && a.action != "table" {
		return nil, t14ArgparseErr(t26PriceUsage, "price",
			"argument price_action: invalid choice: %s (choose from 'set', "+
				"'table')", validation.PyReprStr(a.action))
	}
	if len(pos) > 2 {
		a.asset = pos[2]
	}
	if len(pos) > 3 {
		f, err := strconv.ParseFloat(strings.TrimSpace(pos[3]), 64)
		if err != nil {
			return nil, t14ArgparseErr(t26PriceUsage, "price",
				"argument usd: invalid float value: %s",
				validation.PyReprStr(pos[3]))
		}
		a.usd = &f
	}
	if len(pos) > 4 {
		return nil, t14Unrecognized(strings.Join(pos[4:], " "))
	}
	return a, nil
}

// pyMoney2 is Python's f"${x:,.2f}" without the leading $ (the call sites add
// it).
func pyMoney2(f float64) string { return t14Money(f) }

func init() {
	register(command{ord: 57, name: "price",
		line: "price <campaign> {set,table} [asset] [usd]  the asset-price table",
		run:  runPrice})
}

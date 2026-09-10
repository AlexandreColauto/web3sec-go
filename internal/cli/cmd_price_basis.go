// cmd_price_basis: `webv2 price-basis <campaign> <finding> <price_id>` —
// pin a finding's USD figures to a price-table row (G): the receipt that says
// where the $ came from. cli.py cmd_price_basis verbatim.
package cli

import (
	"fmt"
	"strings"

	"websec/internal/findings"
	"websec/internal/pricing"
	"websec/internal/validation"
)

const t26PriceBasisUsage = `usage: webv2 price-basis [-h] campaign finding price_id
`

const t26PriceBasisHelp = t26PriceBasisUsage + `
positional arguments:
  campaign
  finding
  price_id

options:
  -h, --help  show this help message and exit
`

func runPriceBasis(root string, args []string, r *Runner) int {
	ensureSeams()
	return t14Dispatch(root, r, func() error {
		var pos []string
		for _, a := range args {
			if a == "-h" || a == "--help" {
				fmt.Fprint(r.Out, t26PriceBasisHelp)
				return nil
			}
			if strings.HasPrefix(a, "-") && !isNegNumberCLI(a) {
				return t14Unrecognized(a)
			}
			pos = append(pos, a)
		}
		if len(pos) < 3 {
			missing := []string{"campaign", "finding", "price_id"}[len(pos):]
			return t14ArgparseErr(t26PriceBasisUsage, "price-basis",
				"the following arguments are required: %s",
				strings.Join(missing, ", "))
		}
		if len(pos) > 3 {
			return t14Unrecognized(strings.Join(pos[3:], " "))
		}
		c, err := t14Open(root, pos[0])
		if err != nil {
			return err
		}
		row, err := pricing.PriceRow(c, pos[2])
		if err != nil {
			return err
		}
		if row == nil {
			return t14ExitErr(2, "price row %s not found in the price table "+
				"(set it first: `webv2 price %s set ...`)\n", pos[2], pos[0])
		}
		f, err := findings.LoadFinding(c, pos[1])
		if err != nil {
			return err
		}
		// f.setdefault("economic_impact", {})["price_basis"] = price_id
		ei, ok := lookupKey(f, "economic_impact")
		if !ok {
			ei = validation.VObj()
		}
		ei.O = validation.SetOrAppend(ei.O, "price_basis", validation.VStr(pos[2]))
		f.O = validation.SetOrAppend(f.O, "economic_impact", ei)
		if err := findings.SaveFinding(c, &f); err != nil {
			return err
		}
		data := validation.VObj(validation.KV{K: "price_basis",
			V: validation.VStr(pos[2])})
		if _, err := c.Log("finding.price_basis", &pos[1], &data); err != nil {
			return err
		}
		fmt.Fprintf(r.Out, "%s: price basis pinned to %s (%s @ $%s)\n",
			pos[1], pos[2], objStr(*row, "asset"),
			t14Money(objFlt(*row, "usd")))
		return nil
	})
}

// lookupKey distinguishes an absent key from a present null (Python's
// setdefault only fires when the key is missing).
func lookupKey(v validation.Value, key string) (validation.Value, bool) {
	for _, kv := range v.O {
		if kv.K == key {
			return kv.V, true
		}
	}
	return validation.VNull(), false
}

func init() {
	register(command{ord: 58, name: "price-basis",
		line: "price-basis <campaign> <finding> <price_id>  pin USD figures to a price row",
		run:  runPriceBasis})
}

package cli

// cmd_p3_help: the byte-exact `--help` blocks for the P3 commands, captured
// from the live Python CLI with COLUMNS=80 (argparse wraps to the terminal
// width; the golden environment pins 80).

// indexHelp is argparse's `webv2 index --help` output, byte-exact.
const indexHelp = `usage: webv2 index [-h] --src SRC [--json] campaign

positional arguments:
  campaign

options:
  -h, --help  show this help message and exit
  --src SRC   source tree to index
  --json
`

// sinksHelp is argparse's `webv2 sinks --help` output, byte-exact.
const sinksHelp = `usage: webv2 sinks [-h] --src SRC [--json] campaign

positional arguments:
  campaign

options:
  -h, --help  show this help message and exit
  --src SRC   source tree to slice
  --json
`

// forkdiffHelp is argparse's `webv2 forkdiff --help` output, byte-exact.
const forkdiffHelp = `usage: webv2 forkdiff [-h] --src SRC [--json] campaign

positional arguments:
  campaign

options:
  -h, --help  show this help message and exit
  --src SRC   source tree to fingerprint
  --json
`

// baselineHelp is argparse's `webv2 baseline --help` output, byte-exact.
const baselineHelp = `usage: webv2 baseline [-h] {add,list,remove} ...

positional arguments:
  {add,list,remove}

options:
  -h, --help         show this help message and exit
`

// baselineAddHelp is argparse's `webv2 baseline add --help` output, byte-exact.
const baselineAddHelp = `usage: webv2 baseline add [-h] --path PATH [--source-url SOURCE_URL]
                          [--license LICENSE]
                          name

positional arguments:
  name

options:
  -h, --help            show this help message and exit
  --path PATH
  --source-url SOURCE_URL
  --license LICENSE
`

// baselineListHelp is argparse's `webv2 baseline list --help` output, byte-exact.
const baselineListHelp = `usage: webv2 baseline list [-h]

options:
  -h, --help  show this help message and exit
`

// baselineRemoveHelp is argparse's `webv2 baseline remove --help` output, byte-exact.
const baselineRemoveHelp = `usage: webv2 baseline remove [-h] name

positional arguments:
  name

options:
  -h, --help  show this help message and exit
`

/**
 * dependency-cruiser -- hidden coupling layer.
 * Ships DISABLED in entropy_gate.py (enabled_by_default: false), so `disable`
 * is not the lever -- switch it on with:
 *     [languages.javascript]
 *     enable = ["dependency-cruiser"]
 * Do that once the layering below matches reality (otherwise it fails on day
 * one, which is how gates get bypassed).
 */
module.exports = {
  forbidden: [
    {
      name: "no-circular",
      comment: "Circular imports are the single strongest entropy signal.",
      severity: "error",
      from: {},
      to: { circular: true },
    },
    {
      name: "no-orphans",
      comment: "Unreachable modules -- dead weight.",
      severity: "warn",
      from: { orphan: true, pathNot: ["\\.d\\.ts$", "(^|/)\\.[^/]+\\.(js|cjs|mjs|ts|json)$"] },
      to: {},
    },
    {
      name: "no-ui-to-data",
      comment: "Presentation must not reach into the data layer sideways.",
      severity: "error",
      from: { path: "^src/ui" },
      to: { path: "^src/data" },
    },
    {
      name: "no-domain-to-infra",
      comment: "Domain code must not depend on infrastructure directly.",
      severity: "error",
      from: { path: "^src/domain" },
      to: { path: "^src/infra" },
    },
  ],
  options: {
    doNotFollow: { path: "node_modules" },
    exclude: { path: "(^|/)(node_modules|dist|build|coverage)" },
    tsPreCompilationDeps: true,
    combinedDependencies: false,
  },
};


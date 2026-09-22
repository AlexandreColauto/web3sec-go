// ESLint 9 flat config -- entropy edition.
// {cyclomatic} etc. are substituted from [thresholds] in .entropy-gate.toml at
// `entropy-gate init` time -- edit the config, re-run init, don't hand-edit.
//
// The entropy rules below are "warn" on purpose: they are advisory while you
// write code and fatal at commit time, because the gate runs eslint with
// --max-warnings=0. Do not remove that flag from the eslint check in
// entropy_gate.py -- without it eslint exits 0 on a warn-only run and this
// whole layer silently passes.
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import sonarjs from "eslint-plugin-sonarjs";

export default tseslint.config(
  {
    ignores: [
      "node_modules/**",
      "dist/**",
      "build/**",
      "coverage/**",
      "**/*.generated.*",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  sonarjs.configs.recommended,
  {
    languageOptions: {
      // `console` exists in every JS runtime. Without this, no-undef (an ERROR)
      // fires on a debug console.log that no-console below only means to WARN
      // about -- and at commit time that difference blocks the commit.
      globals: { console: "readonly" },
    },
    rules: {
      complexity: ["warn", { max: { cyclomatic } }],
      "max-depth": ["warn", { max: { nesting } }],
      "max-lines": ["warn", { max: { file_lines }, skipBlankLines: true, skipComments: true }],
      "max-lines-per-function": [
        "warn",
        { max: { function_lines }, skipBlankLines: true, skipComments: true },
      ],
      "max-params": ["warn", { max: { params } }],
      "max-nested-callbacks": ["warn", { max: { nesting } }],

      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": [
        "warn",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-empty-function": "warn",

      "no-console": ["warn", { allow: ["warn", "error"] }],
      "no-warning-comments": ["warn", { terms: ["todo", "fixme", "hack", "xxx"], location: "start" }],
      "sonarjs/cognitive-complexity": ["warn", { cognitive }],
      "sonarjs/no-duplicate-string": ["warn", { threshold: 3 }],
      "sonarjs/no-identical-functions": "warn",
      "sonarjs/no-redundant-jump": "warn",
      "sonarjs/no-useless-catch": "warn",
    },
  },
  {
    // Config files are CommonJS; without this the gate's own templates
    // (.dependency-cruiser.cjs) fail with "'module' is not defined".
    files: ["**/*.cjs"],
    languageOptions: {
      globals: { module: "writable", require: "readonly", __dirname: "readonly" },
    },
  },
  {
    files: [
      "**/*.test.ts", "**/*.test.tsx", "**/*.spec.ts",
      "**/*.test.js", "**/*.test.jsx", "**/*.spec.js", "**/*.spec.jsx",
    ],
    rules: {
      "max-lines-per-function": "off",
      "max-lines": "off",
      "@typescript-eslint/no-explicit-any": "off",
    },
  },
);


# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.0] - 2025-01-15

### Added
- SARIF v2.1.0 output format (`--sarif` flag) for GitHub Code Scanning integration
- `fmt` command — auto-format Rego files (trailing whitespace, tabs→spaces, spacing normalization, blank line management)
- `summary` command — multi-file severity breakdown with per-file stats and top rules
- `--min-severity` flag for severity-based filtering (high/medium/low)
- `--max-errors <n>` flag to control CI failure threshold
- Config file support (`.k8s-policy-checkrc` or `.k8s-policy-check.json`) with key=value and JSON formats
- Inline suppression comments (`# k8s-policy-check-disable`, `-disable-line`, `-disable-file`)
- Per-rule severity overrides via inline comments
- ConstraintTemplate YAML validation (`lintConstraintTemplate`)
- Auto-fix mode (`--fix`) with `--dry-run` support

### Fixed
- CLI version mismatch (was 1.5.0, now correctly reports 1.6.0)
- Config file values were ignored when CLI defaults were set (minSeverity/maxErrors always had defaults, blocking config merge)
- Dead `severityIcon` variable in `generateSummary()` removed
- `summary` command computed `formatSummary()` twice — now computed once

## [1.5.0] - 2025-01-10

### Added
- Auto-fix capabilities: remove `print()`, remove deprecated `import future.keywords`, fix `default allow := true`, add missing `package` declarations
- Programmatic API exports: `fixRegoFile`, `loadConfig`, `fmtRegoSource`, `fmtRegoFile`

## [1.0.0] - 2025-01-05

### Added
- Initial release
- Linter for OPA/Gatekeeper Rego policies
- 8 built-in rules: no-package, dangerous-default-allow, hardcoded-secret, no-print, missing-violation, deprecated-import, package-naming, missing-rule-doc
- CLI with `--json` output for CI/automation
- Programmatic API: `lintRegoFile`, `formatReport`, `filterBySeverity`

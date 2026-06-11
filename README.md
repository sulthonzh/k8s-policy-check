# k8s-policy-check

> Lint and validate OPA/Gatekeeper Rego policies for Kubernetes

Because writing Rego is hard enough — you shouldn't have to manually catch security footguns too.

## Why

OPA and Gatekeeper policies are powerful, but easy to get wrong. A `default allow := true` or a hardcoded secret can blow past your security posture in production. `k8s-policy-check` catches these issues before they ship.

## Install

```bash
npm install -g @sulthonzh/k8s-policy-check
```

## Usage

```bash
# Check specific files
k8s-policy-check policies/*.rego

# Check entire directory
k8s-policy-check ./policies/

# CI mode — fail if any errors found
k8s-policy-check ./policies/ && echo "Policies OK"
```

## CLI Options

```bash
k8s-policy-check [options] <paths...>

Options:
  --json              Output as JSON (for CI/automation)
  --min-severity      Minimum severity to report: high, medium, low (default: low)
  --max-errors <n>    Max allowed errors before failing (default: 0)
  --no-color          Disable colored output
  --fix               Auto-fix issues where possible
  --dry-run           Show what would be fixed without writing (use with --fix)
```

### Auto-fix mode

```bash
# Fix issues automatically
k8s-policy-check --fix ./policies/

# Preview what would be fixed
k8s-policy-check --fix --dry-run ./policies/
```

What `--fix` can do:
- Remove `print()` calls
- Remove deprecated `import future.keywords`
- Change `default allow := true` to `false`
- Add missing `package` declarations

### Config file

Create `.k8s-policy-checkrc` in your project root (key=value or JSON):

```
# .k8s-policy-checkrc
minSeverity=medium
maxErrors=5
fix=true
```

Or JSON:

```json
{
  "minSeverity": "high",
  "maxErrors": 0
}
```

CLI flags override config file values.

### Severity filtering

Every finding has a severity: **high**, **medium**, or **low**. Use `--min-severity` to control what gets reported:

```bash
# Only show high-severity issues (for strict CI gates)
k8s-policy-check --min-severity high ./policies/

# Show high + medium (default for most teams)
k8s-policy-check --min-severity medium ./policies/
```

You can also override severity per-line with inline comments:

```rego
print("debugging")  # k8s-policy-check-severity: low
```

## What it checks

| Rule | Level | Severity | What it catches |
|------|-------|----------|----------------|
| `no-package` | Error | High | Missing package declaration |
| `dangerous-default-allow` | Error | High | `default allow := true` |
| `hardcoded-secret` | Error | High | Hardcoded passwords/tokens/keys |
| `no-print` | Error | Medium | `print()` in production policies |
| `missing-violation` | Warn | Medium | No `violation` or `warn` rules (Gatekeeper) |
| `deprecated-import` | Warn | Low | `import future.keywords` (deprecated) |
| `package-naming` | Warn | Low | Non-standard package naming |
| `missing-rule-doc` | Info | Low | Rules without preceding comments |

## Example output

```
📋 bad.rego (8 lines)
  ❌ 🔴 L4 [dangerous-default-allow] Default allow = true is dangerous
  ❌ 🔴 L6 [hardcoded-secret] Possible hardcoded secret in policy
  ❌ 🟡 L9 [no-print] print() should not be used in production policies
✅ good.rego — clean

3 findings: 3 errors, 0 warnings, 0 info
❌ Policy check FAILED
```

Severity icons: 🔴 high · 🟡 medium · 🟢 low

## Programmatic API

```js
import { lintRegoFile, formatReport, filterBySeverity } from '@sulthonzh/k8s-policy-check';

const results = lintRegoFile('./policies/require-labels.rego');

// Filter to high-severity only
const highOnly = filterBySeverity(results.findings, 'high');

const report = formatReport([results], 'medium'); // minSeverity filter
console.log(report.output);
```

## License

MIT

## Inline suppression

Suppress specific findings with inline comments — similar to ESLint's `eslint-disable`:

```rego
# k8s-policy-check-disable dangerous-default-allow
default allow := true
```

Or suppress all rules on the next line:

```rego
# k8s-policy-check-disable
default allow := true
```

Suppress on the same line (trailing comment):

```rego
print("debugging")  # k8s-policy-check-disable-line no-print
```

Suppress for the entire file:

```rego
# k8s-policy-check-disable-file
package test.foo

default allow := true
```

Or suppress a specific rule for the entire file:

```rego
# k8s-policy-check-disable-file no-print
package test.foo
```

Suppressed findings are counted but not reported in output.

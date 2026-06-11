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

## What it checks

| Rule | Level | What it catches |
|------|-------|----------------|
| `no-package` | Error | Missing package declaration |
| `dangerous-default-allow` | Error | `default allow := true` |
| `no-print` | Error | `print()` in production policies |
| `hardcoded-secret` | Error | Hardcoded passwords/tokens/keys |
| `deprecated-import` | Warn | `import future.keywords` (deprecated) |
| `missing-violation` | Warn | No `violation` or `warn` rules (Gatekeeper) |
| `package-naming` | Warn | Non-standard package naming |
| `missing-rule-doc` | Info | Rules without preceding comments |

## Example output

```
📋 bad.rego (8 lines)
  ❌ L4 [dangerous-default-allow] Default allow = true is dangerous
  ❌ L6 [hardcoded-secret] Possible hardcoded secret in policy
  ❌ L9 [no-print] print() should not be used in production policies
✅ good.rego — clean

3 findings: 3 errors, 0 warnings, 0 info
❌ Policy check FAILED
```

## Programmatic API

```js
import { lintRegoFile, formatReport } from '@sulthonzh/k8s-policy-check';

const results = lintRegoFile('./policies/require-labels.rego');
const report = formatReport([results]);
console.log(report.output);
```

## License

MIT

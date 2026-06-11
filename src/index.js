import { readFileSync } from 'node:fs';
import { basename } from 'node:path';

/**
 * @sulthonzh/k8s-policy-check
 * Lint and validate OPA/Gatekeeper Rego policies for Kubernetes
 */

export const RULE_LEVELS = { ERROR: 'error', WARN: 'warn', INFO: 'info' };

export const SEVERITY = { HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };

/**
 * Map each built-in rule to a default severity level.
 * Users can override via inline comments: # k8s-policy-check-severity: <high|medium|low>
 */
export const RULE_SEVERITY = {
  'dangerous-default-allow': SEVERITY.HIGH,
  'hardcoded-secret': SEVERITY.HIGH,
  'no-package': SEVERITY.HIGH,
  'no-print': SEVERITY.MEDIUM,
  'missing-violation': SEVERITY.MEDIUM,
  'package-naming': SEVERITY.LOW,
  'deprecated-import': SEVERITY.LOW,
  'missing-rule-doc': SEVERITY.LOW,
  'read-error': SEVERITY.HIGH,
  // ConstraintTemplate rules
  'not-constraint-template': SEVERITY.HIGH,
  'missing-template-name': SEVERITY.HIGH,
  'incomplete-template': SEVERITY.MEDIUM,
  'missing-targets': SEVERITY.LOW,
};

function resolveSeverity(rule, lineContent) {
  if (lineContent) {
    const override = lineContent.match(/k8s-policy-check-severity:\s*(high|medium|low)/i);
    if (override) return override[1].toLowerCase();
  }
  return RULE_SEVERITY[rule] || SEVERITY.MEDIUM;
}

export function lintRegoFile(filePath) {
  const content = readFileSync(filePath, 'utf-8');
  const findings = [];
  const lines = content.split('\n');

  // Rule: Package declaration required
  if (!content.includes('package ')) {
    findings.push({ rule: 'no-package', level: RULE_LEVELS.ERROR, severity: SEVERITY.HIGH, message: 'Missing package declaration', line: 1 });
  }

  // Rule: Package name should follow kubernetes convention
  const pkgMatch = content.match(/^package\s+(\S+)/m);
  if (pkgMatch) {
    const pkgName = pkgMatch[1];
    const pkgLine = lines.findIndex(l => l.startsWith('package ')) + 1;
    if (pkgName.includes(' ') || !pkgName.includes('.')) {
      findings.push({ rule: 'package-naming', level: RULE_LEVELS.WARN, severity: SEVERITY.LOW, message: `Package "${pkgName}" should use dot-notation (e.g., k8s.policies.name)`, line: pkgLine });
    }
  }

  // Rule: Warn on 'import future.keywords' (deprecated pattern)
  content.split('\n').forEach((line, i) => {
    if (line.includes('import future.keywords')) {
      findings.push({ rule: 'deprecated-import', level: RULE_LEVELS.WARN, severity: resolveSeverity('deprecated-import', line), message: 'future.keywords import is deprecated in modern OPA', line: i + 1 });
    }
  });

  // Rule: Every rule should have a comment explaining purpose
  let lastCommentLine = -1;
  lines.forEach((line, i) => {
    const isRule = /^\s*\w+\s*(?:\[|{|:=|:\s*)/.test(line) && !line.trim().startsWith('#') && !line.includes('package ') && !line.includes('import ');
    if (isRule && i > 0 && !lines[i - 1].trim().startsWith('#') && lastCommentLine < i - 1) {
      if (!line.startsWith(' ') && !line.startsWith('\t')) {
        findings.push({ rule: 'missing-rule-doc', level: RULE_LEVELS.INFO, severity: resolveSeverity('missing-rule-doc', line), message: `Rule at line ${i + 1} lacks a preceding comment`, line: i + 1 });
      }
    }
    if (line.trim().startsWith('#')) lastCommentLine = i;
  });

  // Rule: No print() in production policies
  lines.forEach((line, i) => {
    if (/\bprint\s*\(/.test(line)) {
      findings.push({ rule: 'no-print', level: RULE_LEVELS.ERROR, severity: resolveSeverity('no-print', line), message: 'print() should not be used in production policies', line: i + 1 });
    }
  });

  // Rule: Hardcoded secrets/values
  lines.forEach((line, i) => {
    if (/(?:password|secret|token|api_key|apikey)\s*(:=|:)\s*"[^"]+"/i.test(line)) {
      findings.push({ rule: 'hardcoded-secret', level: RULE_LEVELS.ERROR, severity: resolveSeverity('hardcoded-secret', line), message: 'Possible hardcoded secret in policy', line: i + 1 });
    }
  });

  // Rule: Default allow rules are dangerous
  lines.forEach((line, i) => {
    if (/^default\s+allow\s*:=?\s*true/m.test(line.trim())) {
      findings.push({ rule: 'dangerous-default-allow', level: RULE_LEVELS.ERROR, severity: resolveSeverity('dangerous-default-allow', line), message: 'Default allow = true is dangerous', line: i + 1 });
    }
  });

  // Rule: Prefer 'violation' naming for Gatekeeper
  if (content.includes('package ') && !content.includes('violation') && !content.includes('warn')) {
    findings.push({ rule: 'missing-violation', level: RULE_LEVELS.WARN, severity: SEVERITY.MEDIUM, message: 'Gatekeeper policies should define violation or warn rules', line: 1 });
  }

  return { file: filePath, filename: basename(filePath), findings, totalLines: lines.length };
}

export function lintConstraintTemplate(yamlContent) {
  const findings = [];

  if (!yamlContent.includes('kind: ConstraintTemplate')) {
    findings.push({ rule: 'not-constraint-template', level: RULE_LEVELS.ERROR, severity: SEVERITY.HIGH, message: 'File is not a ConstraintTemplate' });
    return findings;
  }

  if (!yamlContent.match(/metadata:\s*\n\s+name:/)) {
    findings.push({ rule: 'missing-template-name', level: RULE_LEVELS.ERROR, severity: SEVERITY.HIGH, message: 'ConstraintTemplate missing metadata.name' });
  }

  if (!yamlContent.includes('spec:') || !yamlContent.includes('kind:')) {
    findings.push({ rule: 'incomplete-template', level: RULE_LEVELS.WARN, severity: SEVERITY.MEDIUM, message: 'ConstraintTemplate may be missing spec.crd.spec.names.kind' });
  }

  if (!yamlContent.includes('targets:')) {
    findings.push({ rule: 'missing-targets', level: RULE_LEVELS.WARN, severity: SEVERITY.LOW, message: 'ConstraintTemplate missing spec.targets — default target is assumed' });
  }

  return findings;
}

export function filterBySeverity(findings, minSeverity) {
  if (!minSeverity) return findings;
  const threshold = SEVERITY_ORDER[minSeverity.toLowerCase()];
  if (threshold === undefined) return findings;
  return findings.filter(f => (SEVERITY_ORDER[f.severity] ?? 1) <= threshold);
}

export function formatReport(results, minSeverity) {
  const { ERROR, WARN, INFO } = RULE_LEVELS;
  let errors = 0, warnings = 0, infos = 0;
  let output = '';

  const severityIcon = { high: '🔴', medium: '🟡', low: '🟢' };

  for (const result of results) {
    const filtered = minSeverity ? filterBySeverity(result.findings, minSeverity) : result.findings;
    if (filtered.length === 0) {
      output += `✅ ${result.filename} — clean\n`;
      continue;
    }
    output += `📋 ${result.filename} (${result.totalLines} lines)\n`;
    for (const f of filtered) {
      const levelIcon = f.level === ERROR ? '❌' : f.level === WARN ? '⚠️' : 'ℹ️';
      const sevIcon = severityIcon[f.severity] || '⚪';
      output += `  ${levelIcon} ${sevIcon} L${f.line || '?'} [${f.rule}] ${f.message}\n`;
      if (f.level === ERROR) errors++;
      else if (f.level === WARN) warnings++;
      else infos++;
    }
  }

  const total = errors + warnings + infos;
  output += `\n${total} findings: ${errors} errors, ${warnings} warnings, ${infos} info\n`;
  output += errors > 0 ? '❌ Policy check FAILED\n' : '✅ Policy check PASSED\n';
  return { output, errors, warnings, infos, passed: errors === 0 };
}

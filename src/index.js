import { readFileSync } from 'node:fs';
import { basename } from 'node:path';

/**
 * @sulthonzh/k8s-policy-check
 * Lint and validate OPA/Gatekeeper Rego policies for Kubernetes
 */

export const RULE_LEVELS = { ERROR: 'error', WARN: 'warn', INFO: 'info' };

export function lintRegoFile(filePath) {
  const content = readFileSync(filePath, 'utf-8');
  const findings = [];
  const lines = content.split('\n');

  // Rule: Package declaration required
  if (!content.includes('package ')) {
    findings.push({ rule: 'no-package', level: RULE_LEVELS.ERROR, message: 'Missing package declaration', line: 1 });
  }

  // Rule: Package name should follow kubernetes convention (e.g., package.k8s.name)
  const pkgMatch = content.match(/^package\s+(\S+)/m);
  if (pkgMatch) {
    const pkgName = pkgMatch[1];
    const pkgLine = lines.findIndex(l => l.startsWith('package ')) + 1;
    if (pkgName.includes(' ') || !pkgName.includes('.')) {
      findings.push({ rule: 'package-naming', level: RULE_LEVELS.WARN, message: `Package "${pkgName}" should use dot-notation (e.g., k8s.policies.name)`, line: pkgLine });
    }
  }

  // Rule: Warn on 'import future.keywords' (deprecated pattern)
  content.split('\n').forEach((line, i) => {
    if (line.includes('import future.keywords')) {
      findings.push({ rule: 'deprecated-import', level: RULE_LEVELS.WARN, message: 'future.keywords import is deprecated in modern OPA', line: i + 1 });
    }
  });

  // Rule: Every rule should have a comment explaining purpose
  let lastCommentLine = -1;
  lines.forEach((line, i) => {
    const isRule = /^\s*\w+\s*(?:\[|{|:=|:\s*)/.test(line) && !line.trim().startsWith('#') && !line.includes('package ') && !line.includes('import ');
    if (isRule && i > 0 && !lines[i - 1].trim().startsWith('#') && lastCommentLine < i - 1) {
      // Only flag top-level rules (no indent)
      if (!line.startsWith(' ') && !line.startsWith('\t')) {
        findings.push({ rule: 'missing-rule-doc', level: RULE_LEVELS.INFO, message: `Rule at line ${i + 1} lacks a preceding comment`, line: i + 1 });
      }
    }
    if (line.trim().startsWith('#')) lastCommentLine = i;
  });

  // Rule: No print() in production policies
  lines.forEach((line, i) => {
    if (/\bprint\s*\(/.test(line)) {
      findings.push({ rule: 'no-print', level: RULE_LEVELS.ERROR, message: 'print() should not be used in production policies', line: i + 1 });
    }
  });

  // Rule: Hardcoded secrets/values
  lines.forEach((line, i) => {
    if (/(?:password|secret|token|api_key|apikey)\s*(:=|:)\s*"[^"]+"/i.test(line)) {
      findings.push({ rule: 'hardcoded-secret', level: RULE_LEVELS.ERROR, message: 'Possible hardcoded secret in policy', line: i + 1 });
    }
  });

  // Rule: Default allow rules are dangerous
  lines.forEach((line, i) => {
    if (/^default\s+allow\s*:=?\s*true/m.test(line.trim())) {
      findings.push({ rule: 'dangerous-default-allow', level: RULE_LEVELS.ERROR, message: 'Default allow = true is dangerous', line: i + 1 });
    }
  });

  // Rule: Prefer 'violation' naming for Gatekeeper
  if (content.includes('package ') && !content.includes('violation') && !content.includes('warn')) {
    findings.push({ rule: 'missing-violation', level: RULE_LEVELS.WARN, message: 'Gatekeeper policies should define violation or warn rules', line: 1 });
  }

  return { file: filePath, filename: basename(filePath), findings, totalLines: lines.length };
}

export function lintConstraintTemplate(yamlContent) {
  const findings = [];

  if (!yamlContent.includes('kind: ConstraintTemplate')) {
    findings.push({ rule: 'not-constraint-template', level: RULE_LEVELS.ERROR, message: 'File is not a ConstraintTemplate' });
    return findings;
  }

  // Check for missing metadata.name
  if (!yamlContent.match(/metadata:\s*\n\s+name:/)) {
    findings.push({ rule: 'missing-template-name', level: RULE_LEVELS.ERROR, message: 'ConstraintTemplate missing metadata.name' });
  }

  // Check for missing spec.crd.spec.names.kind
  if (!yamlContent.includes('spec:') || !yamlContent.includes('kind:')) {
    findings.push({ rule: 'incomplete-template', level: RULE_LEVELS.WARN, message: 'ConstraintTemplate may be missing spec.crd.spec.names.kind' });
  }

  // Check for missing targets
  if (!yamlContent.includes('targets:')) {
    findings.push({ rule: 'missing-targets', level: RULE_LEVELS.WARN, message: 'ConstraintTemplate missing spec.targets — default target is assumed' });
  }

  return findings;
}

export function formatReport(results) {
  const { ERROR, WARN, INFO } = RULE_LEVELS;
  let errors = 0, warnings = 0, infos = 0;
  let output = '';

  for (const result of results) {
    if (result.findings.length === 0) {
      output += `✅ ${result.filename} — clean\n`;
      continue;
    }
    output += `📋 ${result.filename} (${result.totalLines} lines)\n`;
    for (const f of result.findings) {
      const icon = f.level === ERROR ? '❌' : f.level === WARN ? '⚠️' : 'ℹ️';
      output += `  ${icon} L${f.line || '?'} [${f.rule}] ${f.message}\n`;
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

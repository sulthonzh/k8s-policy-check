import { readFileSync, writeFileSync, existsSync } from 'node:fs';
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



// ── Inline suppression support ──────────────────────────────────────

/**
 * Parse inline suppression comments from Rego source.
 *
 * Supported patterns:
 *   # k8s-policy-check-disable              — suppress all rules for the next line
 *   # k8s-policy-check-disable <rule>       — suppress a specific rule for the next line
 *   # k8s-policy-check-disable-line         — suppress all rules on the same line (trailing comment)
 *   # k8s-policy-check-disable-line <rule>  — suppress a specific rule on the same line
 *   # k8s-policy-check-disable-file         — suppress all rules for the entire file
 *   # k8s-policy-check-disable-file <rule>  — suppress a specific rule for the entire file
 *
 * Returns { fileRules: Set<string|null>, lineRules: Map<number, Set<string|null>> }
 *   null in Set means "all rules suppressed"
 */
export function parseSuppressions(lines) {
  const fileRules = new Set();   // null = all rules, string = specific rule
  const lineRules = new Map();   // lineNum → Set<rule|null>

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // File-level suppression
    const fileMatch = line.match(/k8s-policy-check-disable-file(?:\s+(\S+))?/);
    if (fileMatch) {
      fileRules.add(fileMatch[1] || null);
      continue;
    }

    // Next-line suppression
    const nextMatch = line.match(/k8s-policy-check-disable(?:\s+(\S+))?$/);
    if (nextMatch && !line.match(/k8s-policy-check-disable-line/)) {
      const target = i + 2; // next line (1-indexed)
      if (!lineRules.has(target)) lineRules.set(target, new Set());
      lineRules.get(target).add(nextMatch[1] || null);
      continue;
    }

    // Same-line suppression (trailing comment on the actual code line)
    const sameMatch = line.match(/k8s-policy-check-disable-line(?:\s+(\S+))?/);
    if (sameMatch) {
      const target = i + 1; // current line (1-indexed)
      if (!lineRules.has(target)) lineRules.set(target, new Set());
      lineRules.get(target).add(sameMatch[1] || null);
    }
  }

  return { fileRules, lineRules };
}

function isSuppressed(rule, lineNum, suppressions) {
  // Check file-level suppression
  if (suppressions.fileRules.has(null)) return true;
  if (suppressions.fileRules.has(rule)) return true;

  // Check line-level suppression
  const lineSet = suppressions.lineRules.get(lineNum);
  if (!lineSet) return false;
  if (lineSet.has(null)) return true;
  if (lineSet.has(rule)) return true;

  return false;
}

export function lintRegoFile(filePath) {
  const content = readFileSync(filePath, 'utf-8');
  const findings = [];
  const lines = content.split('\n');
  const suppressions = parseSuppressions(lines);

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

  // Apply suppression filters
  const filtered = findings.filter(f => !isSuppressed(f.rule, f.line, suppressions));

  return { file: filePath, filename: basename(filePath), findings: filtered, totalLines: lines.length, suppressed: findings.length - filtered.length };
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

/**
 * Generate a summary report across multiple files.
 * Returns structured data suitable for CI dashboards and human reading.
 */
export function generateSummary(allResults, minSeverity) {
  const severityIcon = { high: '🔴', medium: '🟡', low: '🟢' };
  const severityCounts = { high: 0, medium: 0, low: 0 };
  const fileStats = [];
  let totalFindings = 0;
  let totalErrors = 0;
  let totalWarnings = 0;
  let totalInfo = 0;
  let cleanFiles = 0;
  let dirtyFiles = 0;
  const ruleBreakdown = {};

  for (const result of allResults) {
    const filtered = minSeverity ? filterBySeverity(result.findings, minSeverity) : result.findings;
    const fileErrorCount = filtered.filter(f => f.level === RULE_LEVELS.ERROR).length;
    const fileWarnCount = filtered.filter(f => f.level === RULE_LEVELS.WARN).length;
    const fileInfoCount = filtered.filter(f => f.level === RULE_LEVELS.INFO).length;
    totalErrors += fileErrorCount;
    totalWarnings += fileWarnCount;
    totalInfo += fileInfoCount;
    totalFindings += filtered.length;

    if (filtered.length === 0) { cleanFiles++; } else { dirtyFiles++; }

    for (const f of filtered) {
      severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
      ruleBreakdown[f.rule] = (ruleBreakdown[f.rule] || 0) + 1;
    }

    fileStats.push({
      file: result.filename,
      lines: result.totalLines,
      findings: filtered.length,
      errors: fileErrorCount,
      warnings: fileWarnCount,
      info: fileInfoCount,
      topRules: filtered.map(f => f.rule),
    });
  }

  return {
    files: { total: allResults.length, clean: cleanFiles, withIssues: dirtyFiles },
    findings: { total: totalFindings, errors: totalErrors, warnings: totalWarnings, info: totalInfo },
    severity: severityCounts,
    rules: Object.entries(ruleBreakdown).sort((a, b) => b[1] - a[1]),
    fileStats,
    passed: totalErrors === 0,
  };
}

export function formatSummary(allResults, minSeverity) {
  const s = generateSummary(allResults, minSeverity);
  const severityIcon = { high: '🔴', medium: '🟡', low: '🟢' };
  let out = '';

  out += '═══ k8s-policy-check summary ═══\n\n';
  out += `Files scanned : ${s.files.total} (${s.files.clean} clean, ${s.files.withIssues} with issues)\n`;
  out += `Total findings: ${s.findings.total} — ${s.findings.errors} errors, ${s.findings.warnings} warnings, ${s.findings.info} info\n\n`;

  // Severity breakdown
  if (s.findings.total > 0) {
    out += 'Severity breakdown:\n';
    for (const [sev, count] of Object.entries(s.severity)) {
      if (count > 0) out += `  ${severityIcon[sev] || '⚪'} ${sev}: ${count}\n`;
    }
    out += '\n';

    // Top rules
    out += 'Top rules:\n';
    for (const [rule, count] of s.rules.slice(0, 5)) {
      out += `  ${rule}: ${count}\n`;
    }
    out += '\n';

    // Per-file summary
    out += 'Per-file:\n';
    for (const f of s.fileStats) {
      const icon = f.errors > 0 ? '❌' : f.findings > 0 ? '⚠️' : '✅';
      const detail = f.findings > 0 ? ` (${f.errors}E/${f.warnings}W/${f.info}I)` : '';
      out += `  ${icon} ${f.file}: ${f.findings} finding${f.findings !== 1 ? 's' : ''}${detail}\n`;
    }
    out += '\n';
  }

  out += s.passed ? '✅ PASSED — no errors\n' : '❌ FAILED — errors found\n';
  return { output: out, ...s };
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

// ── Config file support ──────────────────────────────────────────────

/**
 * Load config from .k8s-policy-checkrc (JSON or key=value lines).
 * Looks in cwd and parent directories up to git root.
 */
export function loadConfig(cwd = process.cwd()) {
  const configNames = ['.k8s-policy-checkrc', '.k8s-policy-check.json'];
  let dir = cwd;
  for (let i = 0; i < 10; i++) {
    for (const name of configNames) {
      const path = `${dir}/${name}`;
      if (existsSync(path)) {
        try {
          const raw = readFileSync(path, 'utf-8').trim();
          if (raw.startsWith('{')) return JSON.parse(raw);
          // key=value format
          const cfg = {};
          for (const line of raw.split('\n')) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;
            const eqIdx = trimmed.indexOf('=');
            if (eqIdx > 0) {
              const key = trimmed.slice(0, eqIdx).trim();
              let val = trimmed.slice(eqIdx + 1).trim();
              // coerce booleans and numbers
              if (val === 'true') val = true;
              else if (val === 'false') val = false;
              else if (/^\d+$/.test(val)) val = Number(val);
              cfg[key] = val;
            }
          }
          return cfg;
        } catch {
          return {};
        }
      }
    }
    const parent = dir.replace(/\/[^/]+$/, '');
    if (parent === dir) break;
    dir = parent;
  }
  return {};
}

// ── Fix mode ─────────────────────────────────────────────────────────

/**
 * Auto-fix certain lint issues in a Rego file.
 * Returns { fixes: [...], fixed: <new content or null> }
 */
export function fixRegoFile(filePath) {
  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');
  const fixes = [];
  let modified = false;

  const newLines = [];
  let packageName = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let newLine = line;

    // Fix: remove print() calls
    if (/\bprint\s*\(/.test(line) && !line.trim().startsWith('#')) {
      // If the whole line is just a print call, skip it
      if (/^\s*print\s*\(.+\)\s*$/.test(line)) {
        fixes.push({ rule: 'no-print', line: i + 1, action: 'removed print() call' });
        modified = true;
        continue;
      }
      // If print is part of a larger expression, comment it out
      newLine = line.replace(/\bprint\s*\([^)]*\)/, 'true /* print removed */');
      fixes.push({ rule: 'no-print', line: i + 1, action: 'commented out print()' });
      modified = true;
    }

    // Fix: remove deprecated future.keywords imports
    if (line.includes('import future.keywords') && !line.trim().startsWith('#')) {
      fixes.push({ rule: 'deprecated-import', line: i + 1, action: 'removed deprecated future.keywords import' });
      modified = true;
      continue;
    }

    // Fix: default allow := true → default allow := false
    if (/^default\s+allow\s*:=?\s*true/.test(line.trim())) {
      newLine = line.replace(/(default\s+allow\s*:=?\s*)true/, '$1false');
      fixes.push({ rule: 'dangerous-default-allow', line: i + 1, action: 'changed default allow from true to false' });
      modified = true;
    }

    newLines.push(newLine);

    // Track package name for potential auto-add
    const pkgMatch = line.match(/^package\s+(\S+)/);
    if (pkgMatch) packageName = pkgMatch[1];
  }

  // Fix: add missing package declaration
  if (!packageName && !content.includes('package ')) {
    // Use filename as hint for package name
    const hint = basename(filePath).replace('.rego', '').replace(/_/g, '.');
    newLines.unshift(`package ${hint}`);
    newLines.unshift('# Auto-added by k8s-policy-check --fix');
    fixes.push({ rule: 'no-package', line: 1, action: `added package declaration: package ${hint}` });
    modified = true;
  }

  return {
    fixes,
    fixed: modified ? newLines.join('\n') : null,
  };
}

// ── Rego formatter ──────────────────────────────────────────────────

/**
 * Format a Rego source string with consistent style.
 *
 * Rules applied:
 *   1. Trim trailing whitespace from every line
 *   2. Normalize blank lines (collapse multiple blanks to max 1)
 *   3. Ensure single blank line before top-level rules (package, import, default, rule definitions)
 *   4. Consistent spacing around := and : (assignment / rule head)
 *   5. Consistent spacing inside { } blocks — no spacing for single-item sets
 *   6. Ensure file ends with a single newline
 *   7. Fix inconsistent indentation (tabs → 4 spaces)
 *
 * Returns the formatted string.
 */
export function fmtRegoSource(content) {
  let lines = content.split('\n');

  // 1. Trim trailing whitespace
  lines = lines.map(l => l.replace(/\s+$/, ''));

  // 2. Tabs → 4 spaces
  lines = lines.map(l => l.replace(/\t/g, '    '));

  // 3. Consistent spacing around := (assignment)
  //    "x:=y" → "x := y",  "x :=  y" → "x := y"
  lines = lines.map(l => {
    // Skip comments
    const trimmed = l.trim();
    if (trimmed.startsWith('#')) return l;

    // Fix := spacing (but not inside strings — rough heuristic)
    let result = l;
    // "foo:=bar" → "foo := bar"
    result = result.replace(/(\S)\s*:=\s*(\S)/g, (m, pre, post) => `${pre} := ${post}`);
    // "foo :=  bar" → already handled above
    return result;
  });

  // 4. Consistent spacing after commas in function args / lists
  lines = lines.map(l => {
    if (l.trim().startsWith('#')) return l;
    // "foo(a,b,c)" → "foo(a, b, c)"  but not inside strings (rough)
    return l.replace(/,\s{2,}/g, ', ').replace(/,([^\s#])/g, ', $1');
  });

  // 5. Normalize blank lines — collapse consecutive blanks
  const normalized = [];
  for (const line of lines) {
    if (line.trim() === '' && normalized.length > 0 && normalized[normalized.length - 1].trim() === '') {
      continue;
    }
    normalized.push(line);
  }
  lines = normalized;

  // 6. Ensure blank line before top-level declarations (package, import, default, rule)
  //    But only if previous non-blank line is not itself a top-level declaration
  const result = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Top-level declaration patterns
    const isTopLevel = /^(package |import |default |[^ \t][\w]+[\[{ ])/.test(trimmed) && !trimmed.startsWith('#');

    if (isTopLevel && result.length > 0) {
      // Check if there's already a blank line before
      const prevNonBlank = [...result].reverse().find(l => l.trim() !== '');
      if (prevNonBlank !== undefined) {
        const prevTrimmed = prevNonBlank.trim();
        const prevIsTopLevel = /^(package |import |default |[^ \t][\w]+[\[{ ])/.test(prevTrimmed) && !prevTrimmed.startsWith('#');
        // Don't add blank line between consecutive imports or between package and first import
        const bothImports = trimmed.startsWith('import ') && prevTrimmed.startsWith('import ');
        const pkgAndImport = trimmed.startsWith('import ') && prevTrimmed.startsWith('package ');
        const pkgAndDefault = trimmed.startsWith('default ') && prevTrimmed.startsWith('package ');
        // Add blank line before top-level rules, but not between package/import/default groups
        const isGroup = bothImports || pkgAndImport || pkgAndDefault;
        if (!isGroup) {
          if (result[result.length - 1].trim() !== '') {
            result.push('');
          }
        }
      }
    }

    result.push(line);
  }

  // 7. Ensure file ends with exactly one newline, no trailing blanks
  while (result.length > 0 && result[result.length - 1].trim() === '') result.pop();
  result.push('');

  return result.join('\n');
}

/**
 * Format a Rego file in place. Returns { changed, diff } summary.
 */
export function fmtRegoFile(filePath) {
  const content = readFileSync(filePath, 'utf-8');
  const formatted = fmtRegoSource(content);
  return {
    changed: content !== formatted,
    formatted,
    original: content,
  };
}

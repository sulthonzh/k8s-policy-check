import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, unlinkSync } from 'node:fs';
import { lintRegoFile, lintConstraintTemplate, formatReport, filterBySeverity, SEVERITY, RULE_SEVERITY } from '../src/index.js';

describe('lintRegoFile', () => {
  it('catches dangerous default allow', () => {
    const result = lintRegoFile('test/fixtures/bad.rego');
    assert.ok(result.findings.find(f => f.rule === 'dangerous-default-allow'));
  });

  it('catches hardcoded secrets', () => {
    const result = lintRegoFile('test/fixtures/bad.rego');
    assert.ok(result.findings.find(f => f.rule === 'hardcoded-secret'));
  });

  it('catches print() usage', () => {
    const result = lintRegoFile('test/fixtures/bad.rego');
    assert.ok(result.findings.find(f => f.rule === 'no-print'));
  });

  it('passes a clean policy', () => {
    const result = lintRegoFile('test/fixtures/good.rego');
    assert.equal(result.findings.filter(f => f.level === 'error').length, 0);
  });

  it('warns on missing violation/warn rules', () => {
    const result = lintRegoFile('test/fixtures/warn.rego');
    assert.ok(result.findings.find(f => f.rule === 'missing-violation'));
  });

  it('flags no-package', () => {
    writeFileSync('/tmp/no-pkg-test.rego', 'allow { true }\n');
    const result = lintRegoFile('/tmp/no-pkg-test.rego');
    unlinkSync('/tmp/no-pkg-test.rego');
    assert.ok(result.findings.find(f => f.rule === 'no-package'));
  });
});

describe('severity', () => {
  it('every finding has a severity field', () => {
    const result = lintRegoFile('test/fixtures/bad.rego');
    for (const f of result.findings) {
      assert.ok(['high', 'medium', 'low'].includes(f.severity), `finding ${f.rule} missing severity`);
    }
  });

  it('dangerous-default-allow is high severity', () => {
    const result = lintRegoFile('test/fixtures/bad.rego');
    const f = result.findings.find(f => f.rule === 'dangerous-default-allow');
    assert.equal(f.severity, 'high');
  });

  it('hardcoded-secret is high severity', () => {
    const result = lintRegoFile('test/fixtures/bad.rego');
    const f = result.findings.find(f => f.rule === 'hardcoded-secret');
    assert.equal(f.severity, 'high');
  });

  it('no-print is medium severity', () => {
    const result = lintRegoFile('test/fixtures/bad.rego');
    const f = result.findings.find(f => f.rule === 'no-print');
    assert.equal(f.severity, 'medium');
  });

  it('RULE_SEVERITY has entry for every built-in rule', () => {
    const builtInRules = [
      'dangerous-default-allow', 'hardcoded-secret', 'no-package', 'no-print',
      'missing-violation', 'package-naming', 'deprecated-import', 'missing-rule-doc',
    ];
    for (const rule of builtInRules) {
      assert.ok(RULE_SEVERITY[rule], `missing severity for ${rule}`);
    }
  });
});

describe('filterBySeverity', () => {
  const findings = [
    { rule: 'a', severity: 'high' },
    { rule: 'b', severity: 'medium' },
    { rule: 'c', severity: 'low' },
  ];

  it('returns all for minSeverity=low', () => {
    assert.equal(filterBySeverity(findings, 'low').length, 3);
  });

  it('filters to high+medium for minSeverity=medium', () => {
    assert.equal(filterBySeverity(findings, 'medium').length, 2);
  });

  it('filters to high only for minSeverity=high', () => {
    assert.equal(filterBySeverity(findings, 'high').length, 1);
    assert.equal(filterBySeverity(findings, 'high')[0].rule, 'a');
  });

  it('returns all when no minSeverity', () => {
    assert.equal(filterBySeverity(findings, null).length, 3);
  });
});

describe('formatReport', () => {
  it('returns passed when no errors', () => {
    const report = formatReport([{ filename: 'a.rego', findings: [], totalLines: 10 }]);
    assert.equal(report.passed, true);
  });

  it('returns failed when errors exist', () => {
    const report = formatReport([{ filename: 'a.rego', findings: [{ rule: 'x', level: 'error', severity: 'high', message: 'bad', line: 1 }], totalLines: 10 }]);
    assert.equal(report.passed, false);
    assert.equal(report.errors, 1);
  });

  it('respects minSeverity filter', () => {
    const report = formatReport([{
      filename: 'a.rego',
      findings: [
        { rule: 'x', level: 'error', severity: 'high', message: 'bad', line: 1 },
        { rule: 'y', level: 'warn', severity: 'low', message: 'meh', line: 2 },
      ],
      totalLines: 10,
    }], 'high');
    assert.equal(report.errors, 1);
    assert.equal(report.warnings, 0); // low filtered out
  });
});

describe('lintConstraintTemplate', () => {
  it('flags non-template files', () => {
    const findings = lintConstraintTemplate('kind: Something\n');
    assert.equal(findings[0].rule, 'not-constraint-template');
  });

  it('warns on missing targets', () => {
    const yaml = 'kind: ConstraintTemplate\nmetadata:\n  name: test\nspec:\n  crd:\n    spec:\n      names:\n        kind: Test\n';
    const findings = lintConstraintTemplate(yaml);
    assert.ok(findings.find(f => f.rule === 'missing-targets'));
  });

  it('constraint template findings have severity', () => {
    const findings = lintConstraintTemplate('kind: Something\n');
    for (const f of findings) {
      assert.ok(['high', 'medium', 'low'].includes(f.severity));
    }
  });
});

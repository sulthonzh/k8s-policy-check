import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { lintRegoFile, lintConstraintTemplate, formatReport } from '../src/index.js';

describe('lintRegoFile', () => {
  it('catches dangerous default allow', () => {
    const result = lintRegoFile('test/fixtures/bad.rego');
    const rule = result.findings.find(f => f.rule === 'dangerous-default-allow');
    assert.ok(rule, 'should find dangerous default allow');
  });

  it('catches hardcoded secrets', () => {
    const result = lintRegoFile('test/fixtures/bad.rego');
    const rule = result.findings.find(f => f.rule === 'hardcoded-secret');
    assert.ok(rule, 'should find hardcoded secret');
  });

  it('catches print() usage', () => {
    const result = lintRegoFile('test/fixtures/bad.rego');
    const rule = result.findings.find(f => f.rule === 'no-print');
    assert.ok(rule, 'should find print() call');
  });

  it('passes a clean policy', () => {
    const result = lintRegoFile('test/fixtures/good.rego');
    const errors = result.findings.filter(f => f.level === 'error');
    assert.equal(errors.length, 0, 'good policy should have no errors');
  });

  it('warns on missing violation/warn rules', () => {
    const result = lintRegoFile('test/fixtures/warn.rego');
    const rule = result.findings.find(f => f.rule === 'missing-violation');
    assert.ok(rule, 'should warn about missing violation rule');
  });
});

describe('formatReport', () => {
  it('returns passed when no errors', () => {
    const report = formatReport([{ filename: 'a.rego', findings: [], totalLines: 10 }]);
    assert.equal(report.passed, true);
  });

  it('returns failed when errors exist', () => {
    const report = formatReport([{ filename: 'a.rego', findings: [{ rule: 'x', level: 'error', message: 'bad', line: 1 }], totalLines: 10 }]);
    assert.equal(report.passed, false);
    assert.equal(report.errors, 1);
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
    const target = findings.find(f => f.rule === 'missing-targets');
    assert.ok(target, 'should warn about missing targets');
  });
});

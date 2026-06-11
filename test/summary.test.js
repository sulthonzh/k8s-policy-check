import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { lintRegoFile, generateSummary, formatSummary, filterBySeverity } from '../src/index.js';

describe('generateSummary', () => {
  it('returns clean summary for passing files', () => {
    const results = [lintRegoFile('test/fixtures/good.rego')];
    const s = generateSummary(results);
    assert.equal(s.files.total, 1);
    assert.equal(s.files.clean, 1);
    assert.equal(s.files.withIssues, 0);
    assert.equal(s.findings.total, 0);
    assert.equal(s.passed, true);
  });

  it('counts errors and warnings from bad files', () => {
    const results = [lintRegoFile('test/fixtures/bad.rego')];
    const s = generateSummary(results);
    assert.equal(s.files.withIssues, 1);
    assert.ok(s.findings.errors > 0);
    assert.equal(s.passed, false);
  });

  it('breaks down by severity', () => {
    const results = [lintRegoFile('test/fixtures/bad.rego')];
    const s = generateSummary(results);
    assert.ok(s.severity.high > 0);
  });

  it('lists top rules', () => {
    const results = [lintRegoFile('test/fixtures/bad.rego')];
    const s = generateSummary(results);
    assert.ok(s.rules.length > 0);
    assert.ok(typeof s.rules[0][0] === 'string');
    assert.ok(typeof s.rules[0][1] === 'number');
  });

  it('aggregates across multiple files', () => {
    const results = [
      lintRegoFile('test/fixtures/good.rego'),
      lintRegoFile('test/fixtures/bad.rego'),
    ];
    const s = generateSummary(results);
    assert.equal(s.files.total, 2);
    assert.equal(s.files.clean, 1);
    assert.equal(s.files.withIssues, 1);
  });

  it('respects min-severity filter', () => {
    const results = [lintRegoFile('test/fixtures/bad.rego')];
    const s = generateSummary(results, 'high');
    const sAll = generateSummary(results);
    assert.ok(s.findings.total <= sAll.findings.total);
  });

  it('includes per-file stats', () => {
    const results = [lintRegoFile('test/fixtures/bad.rego')];
    const s = generateSummary(results);
    assert.equal(s.fileStats.length, 1);
    assert.ok(s.fileStats[0].file.includes('.rego'));
    assert.ok(s.fileStats[0].lines > 0);
  });
});

describe('formatSummary', () => {
  it('outputs formatted text', () => {
    const results = [lintRegoFile('test/fixtures/bad.rego')];
    const report = formatSummary(results);
    assert.ok(report.output.includes('k8s-policy-check summary'));
    assert.ok(report.output.includes('Files scanned'));
    assert.ok(report.output.includes('FAILED'));
    assert.equal(report.passed, false);
  });

  it('shows PASSED for clean files', () => {
    const results = [lintRegoFile('test/fixtures/good.rego')];
    const report = formatSummary(results);
    assert.ok(report.output.includes('PASSED'));
    assert.equal(report.passed, true);
  });

  it('includes severity breakdown when findings exist', () => {
    const results = [lintRegoFile('test/fixtures/bad.rego')];
    const report = formatSummary(results);
    assert.ok(report.output.includes('Severity breakdown'));
    assert.ok(report.output.includes('Per-file'));
  });

  it('skips detail sections when no findings', () => {
    const results = [lintRegoFile('test/fixtures/good.rego')];
    const report = formatSummary(results);
    assert.ok(!report.output.includes('Severity breakdown'));
    assert.ok(!report.output.includes('Per-file'));
  });
});

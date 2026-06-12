import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateSarif } from '../src/sarif.js';
import { lintRegoFile } from '../src/index.js';

function results(sarif) { return sarif.runs[0].results; }
function rules(sarif) { return sarif.runs[0].tool.driver.rules; }

describe('generateSarif', () => {
  it('produces valid SARIF structure', () => {
    const linted = [lintRegoFile('test/fixtures/bad.rego')];
    const sarif = generateSarif(linted);

    assert.equal(sarif.version, '2.1.0');
    assert.ok(sarif.$schema);
    assert.equal(sarif.runs.length, 1);

    const run = sarif.runs[0];
    assert.equal(run.tool.driver.name, 'k8s-policy-check');
    assert.ok(run.tool.driver.version);
    assert.ok(run.tool.driver.informationUri);
    assert.ok(Array.isArray(rules(sarif)));
    assert.ok(results(sarif).length > 0, 'should have findings from bad.rego');
  });

  it('maps severity to correct SARIF levels', () => {
    const linted = [lintRegoFile('test/fixtures/bad.rego')];
    const sarif = generateSarif(linted);

    const levels = new Set(results(sarif).map(r => r.level));
    assert.ok(levels.has('error'), 'high severity should map to error');
  });

  it('includes rule metadata in driver.rules', () => {
    const linted = [lintRegoFile('test/fixtures/bad.rego')];
    const sarif = generateSarif(linted);

    for (const rule of rules(sarif)) {
      assert.ok(rule.id, 'rule should have id');
      assert.ok(rule.shortDescription, 'rule should have shortDescription');
      assert.ok(rule.helpUri, 'rule should have helpUri');
    }
  });

  it('includes location with file path and line number', () => {
    const linted = [lintRegoFile('test/fixtures/bad.rego')];
    const sarif = generateSarif(linted);

    for (const result of results(sarif)) {
      assert.ok(result.locations, 'result should have locations');
      assert.equal(result.locations.length, 1);
      const loc = result.locations[0].physicalLocation;
      assert.ok(loc.artifactLocation.uri);
      assert.ok(loc.region.startLine >= 1);
    }
  });

  it('filters by minSeverity', () => {
    const linted = [lintRegoFile('test/fixtures/bad.rego')];
    const all = generateSarif(linted);
    const highOnly = generateSarif(linted, { minSeverity: 'high' });

    assert.ok(results(highOnly).length < results(all).length, 'high-only should have fewer results');
    for (const r of results(highOnly)) {
      assert.equal(r.level, 'error');
    }
  });

  it('handles clean files with no findings', () => {
    const linted = [{
      file: 'test/fixtures/clean.rego',
      filename: 'clean.rego',
      findings: [],
      totalLines: 10,
    }];
    const sarif = generateSarif(linted);

    assert.equal(results(sarif).length, 0);
    assert.equal(rules(sarif).length, 0);
  });

  it('handles multiple files', () => {
    const linted = [
      lintRegoFile('test/fixtures/bad.rego'),
      {
        file: 'test/fixtures/other.rego',
        filename: 'other.rego',
        findings: [{ rule: 'no-package', level: 'error', severity: 'high', message: 'Missing package', line: 1 }],
        totalLines: 5,
      },
    ];
    const sarif = generateSarif(linted);

    const files = new Set(results(sarif).map(r => r.locations[0].physicalLocation.artifactLocation.uri));
    assert.ok(files.size >= 2, 'should have results from multiple files');
  });

  it('deduplicates rules in driver', () => {
    const linted = [
      { file: 'a.rego', filename: 'a.rego', findings: [{ rule: 'no-print', level: 'error', severity: 'medium', message: 'print found', line: 1 }], totalLines: 1 },
      { file: 'b.rego', filename: 'b.rego', findings: [{ rule: 'no-print', level: 'error', severity: 'medium', message: 'print found', line: 2 }], totalLines: 1 },
    ];
    const sarif = generateSarif(linted);

    const printRules = rules(sarif).filter(r => r.id === 'no-print');
    assert.equal(printRules.length, 1, 'no-print rule should appear once');
    assert.equal(results(sarif).length, 2, 'but both results should be present');
  });
});

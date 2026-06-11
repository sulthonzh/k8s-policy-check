import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, unlinkSync, mkdirSync } from 'node:fs';
import { lintRegoFile, parseSuppressions } from '../src/index.js';

const TMP = '/tmp/k8s-pc-suppress-test';

describe('parseSuppressions', () => {
  it('parses next-line disable for all rules', () => {
    const lines = [
      'package test.foo',
      '# k8s-policy-check-disable',
      'default allow := true',
      'allow { true }',
    ];
    const { fileRules, lineRules } = parseSuppressions(lines);
    assert.equal(fileRules.size, 0);
    assert.ok(lineRules.has(3));
    assert.ok(lineRules.get(3).has(null));
  });

  it('parses next-line disable for specific rule', () => {
    const lines = [
      'package test.foo',
      '# k8s-policy-check-disable dangerous-default-allow',
      'default allow := true',
    ];
    const { lineRules } = parseSuppressions(lines);
    assert.ok(lineRules.get(3).has('dangerous-default-allow'));
    assert.ok(!lineRules.get(3).has(null));
  });

  it('parses same-line disable-line', () => {
    const lines = [
      'package test.foo',
      'default allow := true # k8s-policy-check-disable-line',
    ];
    const { lineRules } = parseSuppressions(lines);
    assert.ok(lineRules.has(2));
    assert.ok(lineRules.get(2).has(null));
  });

  it('parses same-line disable-line for specific rule', () => {
    const lines = [
      'package test.foo',
      'print("debug") # k8s-policy-check-disable-line no-print',
    ];
    const { lineRules } = parseSuppressions(lines);
    assert.ok(lineRules.get(2).has('no-print'));
  });

  it('parses file-level disable', () => {
    const lines = [
      '# k8s-policy-check-disable-file',
      'package test.foo',
      'default allow := true',
    ];
    const { fileRules } = parseSuppressions(lines);
    assert.ok(fileRules.has(null));
  });

  it('parses file-level disable for specific rule', () => {
    const lines = [
      '# k8s-policy-check-disable-file no-print',
      'package test.foo',
      'print("debug")',
    ];
    const { fileRules } = parseSuppressions(lines);
    assert.ok(fileRules.has('no-print'));
    assert.ok(!fileRules.has(null));
  });
});

describe('lintRegoFile with suppressions', () => {
  it('suppresses dangerous-default-allow with next-line comment', () => {
    mkdirSync(TMP, { recursive: true });
    const path = `${TMP}/suppress-next.rego`;
    writeFileSync(path, 'package test.foo\n\n# k8s-policy-check-disable\ndefault allow := true\n');
    const result = lintRegoFile(path);
    assert.equal(result.findings.find(f => f.rule === 'dangerous-default-allow'), undefined);
    assert.equal(result.suppressed, 1);
    unlinkSync(path);
  });

  it('suppresses specific rule with inline comment', () => {
    mkdirSync(TMP, { recursive: true });
    const path = `${TMP}/suppress-specific.rego`;
    writeFileSync(path, 'package test.foo\n\n# k8s-policy-check-disable no-print\nprint("debug")\n');
    const result = lintRegoFile(path);
    assert.equal(result.findings.find(f => f.rule === 'no-print'), undefined);
    // package-naming warning may still exist, that's fine
    unlinkSync(path);
  });

  it('suppresses rule on same line with disable-line', () => {
    mkdirSync(TMP, { recursive: true });
    const path = `${TMP}/suppress-sameline.rego`;
    writeFileSync(path, 'package test.foo\n\ndefault allow := true # k8s-policy-check-disable-line\n');
    const result = lintRegoFile(path);
    assert.equal(result.findings.find(f => f.rule === 'dangerous-default-allow'), undefined);
    unlinkSync(path);
  });

  it('file-level suppression hides all findings', () => {
    mkdirSync(TMP, { recursive: true });
    const path = `${TMP}/suppress-file.rego`;
    writeFileSync(path, '# k8s-policy-check-disable-file\npackage test.foo\n\ndefault allow := true\npassword := "secret123"\nprint("oops")\n');
    const result = lintRegoFile(path);
    assert.equal(result.findings.length, 0);
    assert.ok(result.suppressed > 0);
    unlinkSync(path);
  });

  it('file-level suppression for one rule still reports others', () => {
    mkdirSync(TMP, { recursive: true });
    const path = `${TMP}/suppress-file-specific.rego`;
    writeFileSync(path, '# k8s-policy-check-disable-file no-print\npackage test.foo\n\nprint("debug")\ndefault allow := true\n');
    const result = lintRegoFile(path);
    assert.equal(result.findings.find(f => f.rule === 'no-print'), undefined);
    assert.ok(result.findings.find(f => f.rule === 'dangerous-default-allow'));
    unlinkSync(path);
  });

  it('does not suppress unrelated rules', () => {
    mkdirSync(TMP, { recursive: true });
    const path = `${TMP}/suppress-unrelated.rego`;
    writeFileSync(path, 'package test.foo\n\n# k8s-policy-check-disable no-print\ndefault allow := true\n');
    const result = lintRegoFile(path);
    // no-print suppression doesn't affect dangerous-default-allow
    assert.ok(result.findings.find(f => f.rule === 'dangerous-default-allow'));
    unlinkSync(path);
  });
});

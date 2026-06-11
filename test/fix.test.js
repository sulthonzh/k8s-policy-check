import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, unlinkSync, mkdirSync, rmSync } from 'node:fs';
import { fixRegoFile, loadConfig } from '../src/index.js';

const TMP = '/tmp/k8s-pc-fix-test';

describe('fixRegoFile', () => {
  it('removes standalone print() calls', () => {
    const path = `${TMP}/print-test.rego`;
    mkdirSync(TMP, { recursive: true });
    writeFileSync(path, 'package test.foo\n\nprint("debug")\n\nallow { true }\n');
    const result = fixRegoFile(path);
    assert.ok(result.fixed);
    assert.ok(result.fixes.find(f => f.rule === 'no-print'));
    assert.ok(!result.fixed.includes('print('));
    unlinkSync(path);
  });

  it('changes default allow true to false', () => {
    const path = `${TMP}/allow-test.rego`;
    mkdirSync(TMP, { recursive: true });
    writeFileSync(path, 'package test.foo\n\ndefault allow := true\n');
    const result = fixRegoFile(path);
    assert.ok(result.fixed);
    assert.ok(result.fixed.includes('default allow := false'));
    assert.ok(!result.fixed.includes('default allow := true'));
    unlinkSync(path);
  });

  it('removes deprecated future.keywords import', () => {
    const path = `${TMP}/depr-test.rego`;
    mkdirSync(TMP, { recursive: true });
    writeFileSync(path, 'package test.foo\nimport future.keywords.in\n\nallow { true }\n');
    const result = fixRegoFile(path);
    assert.ok(result.fixed);
    assert.ok(!result.fixed.includes('import future.keywords'));
    unlinkSync(path);
  });

  it('adds missing package declaration', () => {
    const path = `${TMP}/no-pkg-test.rego`;
    mkdirSync(TMP, { recursive: true });
    writeFileSync(path, 'allow { true }\n');
    const result = fixRegoFile(path);
    assert.ok(result.fixed);
    assert.ok(result.fixed.includes('package '));
    assert.ok(result.fixes.find(f => f.rule === 'no-package'));
    unlinkSync(path);
  });

  it('returns null when nothing to fix', () => {
    const path = `${TMP}/clean-test.rego`;
    mkdirSync(TMP, { recursive: true });
    writeFileSync(path, 'package test.foo\n\n# Policy comment\nviolation[msg] {\n  msg := "fail"\n}\n');
    const result = fixRegoFile(path);
    assert.equal(result.fixed, null);
    assert.equal(result.fixes.length, 0);
    unlinkSync(path);
  });

  it('handles multiple fixes in one file', () => {
    const path = `${TMP}/multi-test.rego`;
    mkdirSync(TMP, { recursive: true });
    writeFileSync(path, 'package test.foo\nimport future.keywords.in\n\ndefault allow := true\nprint("oops")\n');
    const result = fixRegoFile(path);
    assert.ok(result.fixed);
    assert.ok(result.fixes.length >= 3);
    assert.ok(!result.fixed.includes('print('));
    assert.ok(!result.fixed.includes('import future.keywords'));
    assert.ok(result.fixed.includes('default allow := false'));
    unlinkSync(path);
  });
});

describe('loadConfig', () => {
  it('returns empty object when no config file', () => {
    const cfg = loadConfig('/tmp/nonexistent-dir-xyz');
    assert.deepStrictEqual(cfg, {});
  });

  it('parses key=value format', () => {
    mkdirSync(TMP, { recursive: true });
    writeFileSync(`${TMP}/.k8s-policy-checkrc`, 'minSeverity=high\nmaxErrors=10\n');
    const cfg = loadConfig(TMP);
    assert.equal(cfg.minSeverity, 'high');
    assert.equal(cfg.maxErrors, 10);
    unlinkSync(`${TMP}/.k8s-policy-checkrc`);
  });

  it('parses JSON format', () => {
    mkdirSync(TMP, { recursive: true });
    writeFileSync(`${TMP}/.k8s-policy-check.json`, '{"minSeverity":"medium","fix":true}');
    const cfg = loadConfig(TMP);
    assert.equal(cfg.minSeverity, 'medium');
    assert.equal(cfg.fix, true);
    unlinkSync(`${TMP}/.k8s-policy-check.json`);
  });

  it('ignores comments in key=value format', () => {
    mkdirSync(TMP, { recursive: true });
    writeFileSync(`${TMP}/.k8s-policy-checkrc`, '# comment\nminSeverity=low\n');
    const cfg = loadConfig(TMP);
    assert.equal(cfg.minSeverity, 'low');
    unlinkSync(`${TMP}/.k8s-policy-checkrc`);
  });

  // cleanup
  it('cleanup', () => {
    rmSync(TMP, { recursive: true, force: true });
    assert.ok(true);
  });
});

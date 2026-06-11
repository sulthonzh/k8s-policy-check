import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, unlinkSync, mkdirSync, readFileSync } from 'node:fs';
import { fmtRegoSource, fmtRegoFile } from '../src/index.js';

describe('fmtRegoSource', () => {
  it('trims trailing whitespace', () => {
    const input = 'package foo.bar   \nallow { true }   ';
    const result = fmtRegoSource(input);
    assert.ok(!result.includes('   \n'));
    assert.ok(!result.match(/ \n/));
  });

  it('converts tabs to 4 spaces', () => {
    const input = 'package foo\n\tallow {\n\t\ttrue\n\t}';
    const result = fmtRegoSource(input);
    assert.ok(!result.includes('\t'));
    assert.ok(result.includes('    allow'));
  });

  it('normalizes spacing around :=', () => {
    const input = 'package foo\nx:=y\nallow {\n    a:=b\n}';
    const result = fmtRegoSource(input);
    assert.match(result, /x := y/);
    assert.match(result, /a := b/);
  });

  it('normalizes comma spacing', () => {
    const input = 'package foo\nf(a,b,c) { true }';
    const result = fmtRegoSource(input);
    assert.match(result, /f\(a, b, c\)/);
  });

  it('collapses multiple blank lines', () => {
    const input = 'package foo\n\n\n\nimport data.k8s';
    const result = fmtRegoSource(input);
    assert.ok(!result.includes('\n\n\n'));
  });

  it('ends with single newline', () => {
    const input = 'package foo\nallow { true }\n\n\n';
    const result = fmtRegoSource(input);
    assert.ok(result.endsWith('\n'));
    assert.ok(!result.endsWith('\n\n'));
  });

  it('does not modify comments', () => {
    const input = 'package foo\n# This is a comment with  :=   spaces\nallow { true }';
    const result = fmtRegoSource(input);
    assert.match(result, /# This is a comment with  :=   spaces/);
  });

  it('adds blank line before top-level rule after non-top-level content', () => {
    const input = 'package foo\nallow { true }\nviolation[msg] { msg := "no" }';
    const result = fmtRegoSource(input);
    assert.match(result, /allow \{ true \}\n\nviolation/);
  });

  it('formats a complex Rego file correctly', () => {
    const input = `package k8s.policies.trustedrepos
import data.k8s
# Check if image is from trusted registry
violation[msg]\t{
\tcontainer := input.review.object.spec.containers[_]
\tnot trusted_registry[container.image]
    msg:=sprintf("Untrusted image: %v",[container.image])
}
trusted_registry[img]\t{
\tstartswith(img,"trusted.io/")
}`;
    const result = fmtRegoSource(input);
    assert.ok(!result.includes('\t'));
    assert.match(result, /msg := sprintf/);
    assert.match(result, /"Untrusted image: %v", \[container\.image\]/);
  });
});

describe('fmtRegoFile', () => {
  const TMP = '/tmp/k8s-pc-fmt-test';
  const TMPFILE = `${TMP}/test.rego`;

  it('detects when file needs formatting', () => {
    mkdirSync(TMP, { recursive: true });
    writeFileSync(TMPFILE, 'package foo\nx:=y\n');
    const result = fmtRegoFile(TMPFILE);
    assert.equal(result.changed, true);
    assert.match(result.formatted, /x := y/);
    unlinkSync(TMPFILE);
  });

  it('detects when file is already formatted', () => {
    mkdirSync(TMP, { recursive: true });
    const formatted = 'package foo\n\nallow { true }\n';
    writeFileSync(TMPFILE, formatted);
    const result = fmtRegoFile(TMPFILE);
    assert.equal(result.changed, false);
    unlinkSync(TMPFILE);
  });
});

#!/usr/bin/env node
import { Command } from 'commander';
import { glob } from 'glob';
import { lintRegoFile, formatReport, filterBySeverity, SEVERITY } from './index.js';

const program = new Command();

program
  .name('k8s-policy-check')
  .description('Lint and validate OPA/Gatekeeper Rego policies for Kubernetes')
  .version('1.2.0')
  .argument('<paths...>', 'Rego files or directories to check')
  .option('--no-color', 'Disable colored output')
  .option('--json', 'Output results as JSON (for CI/automation)')
  .option('--max-errors <n>', 'Maximum allowed errors before failing', '0')
  .option('--min-severity <level>', 'Minimum severity to report (high, medium, low)', 'low')
  .action(async (paths, opts) => {
    const files = [];
    for (const p of paths) {
      const matches = await glob(`${p}/**/*.rego`, { ignore: '**/node_modules/**' });
      if (p.endsWith('.rego')) files.push(p);
      files.push(...matches);
    }
    const unique = [...new Set(files)];
    if (unique.length === 0) {
      if (opts.json) { console.log(JSON.stringify({ files: [], findings: 0, passed: true })); }
      else console.log('No .rego files found.');
      process.exit(0);
    }

    const minSev = opts.minSeverity?.toLowerCase();
    const results = unique.map(f => {
      try { return lintRegoFile(f); }
      catch (e) { return { file: f, filename: f, findings: [{ rule: 'read-error', level: 'error', severity: 'high', message: e.message, line: 1 }], totalLines: 0 }; }
    });

    if (opts.json) {
      const report = formatReport(results, minSev);
      const filteredResults = results.map(r => ({
        ...r,
        findings: filterBySeverity(r.findings, minSev),
      }));
      console.log(JSON.stringify({
        files: filteredResults,
        summary: { errors: report.errors, warnings: report.warnings, info: report.infos, passed: report.passed, minSeverity: minSev },
      }, null, 2));
      process.exit(report.errors > parseInt(opts.maxErrors, 10) ? 1 : 0);
    }

    const report = formatReport(results, minSev);
    console.log(report.output);
    process.exit(report.errors > parseInt(opts.maxErrors, 10) ? 1 : 0);
  });

program.parse();

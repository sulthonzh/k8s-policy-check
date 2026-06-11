#!/usr/bin/env node
import { Command } from 'commander';
import { glob } from 'glob';
import { lintRegoFile, formatReport } from './index.js';

const program = new Command();

program
  .name('k8s-policy-check')
  .description('Lint and validate OPA/Gatekeeper Rego policies for Kubernetes')
  .version('1.0.0')
  .argument('<paths...>', 'Rego files or directories to check')
  .option('--no-color', 'Disable colored output')
  .option('--max-errors <n>', 'Maximum allowed errors before failing', '0')
  .action(async (paths, opts) => {
    const files = [];
    for (const p of paths) {
      const matches = await glob(`${p}/**/*.rego`, { ignore: '**/node_modules/**' });
      if (p.endsWith('.rego')) files.push(p);
      files.push(...matches);
    }
    const unique = [...new Set(files)];
    if (unique.length === 0) {
      console.log('No .rego files found.');
      process.exit(0);
    }

    const results = unique.map(f => {
      try { return lintRegoFile(f); }
      catch (e) { return { file: f, filename: f, findings: [{ rule: 'read-error', level: 'error', message: e.message, line: 1 }], totalLines: 0 }; }
    });

    const report = formatReport(results);
    console.log(report.output);
    const maxErrors = parseInt(opts.maxErrors, 10);
    process.exit(report.errors > maxErrors ? 1 : 0);
  });

program.parse();

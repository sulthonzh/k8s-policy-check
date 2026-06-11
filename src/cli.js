#!/usr/bin/env node
import { Command } from 'commander';
import { glob } from 'glob';
import { readFileSync } from 'node:fs';
import { lintRegoFile, formatReport, filterBySeverity, fixRegoFile, loadConfig, SEVERITY } from './index.js';
import { writeFileSync } from 'node:fs';

const program = new Command();

program
  .name('k8s-policy-check')
  .description('Lint and validate OPA/Gatekeeper Rego policies for Kubernetes')
  .version('1.3.0')
  .argument('<paths...>', 'Rego files or directories to check')
  .option('--no-color', 'Disable colored output')
  .option('--json', 'Output results as JSON (for CI/automation)')
  .option('--max-errors <n>', 'Maximum allowed errors before failing', '0')
  .option('--min-severity <level>', 'Minimum severity to report (high, medium, low)', 'low')
  .option('--fix', 'Auto-fix issues where possible (prints, imports, default allow)')
  .option('--dry-run', 'Show what would be fixed without writing files (use with --fix)')
  .action(async (paths, opts) => {
    // Merge config file with CLI opts (CLI takes precedence)
    const config = loadConfig();
    if (config.minSeverity && !opts.minSeverity) opts.minSeverity = config.minSeverity;
    if (config.maxErrors && !opts.maxErrors) opts.maxErrors = String(config.maxErrors);
    if (config.noColor) opts.noColor = true;
    if (config.fix && !opts.fix) opts.fix = config.fix;

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

    // ── Fix mode ──
    if (opts.fix) {
      const allFixes = [];
      for (const f of unique) {
        try {
          const result = fixRegoFile(f);
          if (result.fixes.length > 0) {
            if (opts.dryRun) {
              console.log(`\n🔧 ${f} (dry run — not writing):`);
            } else {
              writeFileSync(f, result.fixed, 'utf-8');
              console.log(`\n🔧 ${f} — fixed:`);
            }
            for (const fix of result.fixes) {
              console.log(`  ✏️  L${fix.line} [${fix.rule}] ${fix.action}`);
            }
            allFixes.push(...result.fixes);
          } else {
            console.log(`✅ ${f} — nothing to fix`);
          }
        } catch (e) {
          console.error(`❌ ${f}: ${e.message}`);
        }
      }
      if (allFixes.length === 0) {
        console.log('\nAll files clean — no fixes needed.');
      } else if (opts.dryRun) {
        console.log(`\n${allFixes.length} fix(es) would be applied. Run without --dry-run to apply.`);
      } else {
        console.log(`\n${allFixes.length} fix(es) applied. Run again to verify.`);
      }
      process.exit(0);
    }

    // ── Lint mode ──
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

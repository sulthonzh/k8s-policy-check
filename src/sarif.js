/**
 * SARIF (Static Analysis Results Interchange Format) output for GitHub Code Scanning.
 * Generates v2.1.0 compatible SARIF from k8s-policy-check results.
 *
 * @see https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import { readFileSync } from 'node:fs';
import { filterBySeverity } from './index.js';

const SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';
const SARIF_VERSION = '2.1.0';

function getPackageVersion() {
  try {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf-8'));
    return pkg.version || '0.0.0';
  } catch {
    return '0.0.0';
  }
}

/**
 * Map k8s-policy-check severity to SARIF level.
 */
function severityToSarifLevel(severity) {
  switch (severity) {
    case 'high': return 'error';
    case 'medium': return 'warning';
    case 'low': return 'note';
    default: return 'warning';
  }
}

/**
 * Generate SARIF output from lint results.
 *
 * @param {Array} results - Array of lintRegoFile() results
 * @param {object} [opts] - Options
 * @param {string} [opts.minSeverity] - Minimum severity filter
 * @returns {object} SARIF document
 */
export function generateSarif(results, opts = {}) {
  const minSev = opts.minSeverity;
  const version = getPackageVersion();

  const ruleIndex = new Map();
  const sarifResults = [];

  for (const result of results) {
    const findings = minSev ? filterBySeverity(result.findings, minSev) : result.findings;

    for (const f of findings) {
      if (!ruleIndex.has(f.rule)) {
        ruleIndex.set(f.rule, {
          id: f.rule,
          shortDescription: { text: f.message },
          properties: {
            'k8s-policy-check/severity': f.severity || 'medium',
            'k8s-policy-check/level': f.level || 'warn',
          },
          helpUri: 'https://github.com/sulthonzh/k8s-policy-check#rules',
        });
      }

      sarifResults.push({
        ruleId: f.rule,
        ruleIndex: [...ruleIndex.keys()].indexOf(f.rule),
        level: severityToSarifLevel(f.severity),
        message: { text: f.message },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: result.file,
                uriBaseId: '%SRCROOT%',
              },
              region: {
                startLine: f.line || 1,
              },
            },
          },
        ],
      });
    }
  }

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: 'k8s-policy-check',
            version,
            semanticVersion: version,
            informationUri: 'https://github.com/sulthonzh/k8s-policy-check',
            rules: [...ruleIndex.values()],
          },
        },
        results: sarifResults,
      },
    ],
  };
}

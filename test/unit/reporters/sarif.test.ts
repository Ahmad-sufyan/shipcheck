import { describe, expect, it } from 'vitest';
import { renderSarif, SECURITY_SEVERITY } from '../../../src/reporters/sarif.js';
import type { Rule } from '../../../src/types.js';
import { makeFinding, makeResult } from '../../helpers/results.js';
import { testRule } from '../../helpers/rules.js';
import { sarifErrors } from '../../helpers/sarif.js';

const rules: Rule[] = [
  testRule({ id: 'SECRET-006', title: 'Production browser source maps enabled', severity: 'medium', category: 'secrets', cwe: 'CWE-540', references: ['https://nextjs.org/docs'] }),
  testRule({ id: 'AUTHZ-001', title: 'Route without auth', severity: 'critical', category: 'authorization', description: 'Route handlers that never check the session.', fix: 'Check the session.' }),
  testRule({ id: 'SECRET-008', title: 'No startup validation of environment variables', severity: 'info', category: 'secrets', advisory: true }),
  testRule({ id: 'LIVE-001', title: 'Security headers not served', severity: 'medium', category: 'live', source: 'live' }),
];

const findings = [
  makeFinding({ ruleId: 'AUTHZ-001', title: 'Route without auth', severity: 'critical', category: 'authorization', file: 'app/api/admin/route.ts', line: 12, column: 3, explanation: 'Anyone can call this route.' }),
  makeFinding(),
  makeFinding({ ruleId: 'SECRET-008', severity: 'info', file: null, line: null, advisory: true, evidence: 'process.env is read but never validated', explanation: 'Missing env vars fail late.' }),
  makeFinding({ ruleId: 'LIVE-001', severity: 'medium', category: 'live', source: 'live', file: null, line: null, url: 'https://app.example.com/', evidence: 'GET /: missing CSP', explanation: 'Headers are missing.' }),
];

const sarif = (target = 'fixtures/demo-app') => JSON.parse(renderSarif(makeResult(findings, { target: { path: target } }), rules)) as Record<string, any>;

describe('renderSarif', () => {
  it('produces valid SARIF 2.1.0', () => {
    expect(sarifErrors(sarif())).toEqual([]);
    // The validator itself rejects broken documents.
    expect(sarifErrors({ version: '2.1.0' })).not.toEqual([]);
    expect(sarifErrors({ version: '2.1.0', runs: [{ tool: { driver: { name: 'x' } }, results: [{ message: {} }] }] })).not.toEqual([]);
  });

  it('describes every rule with GitHub security-severity and the fix as help', () => {
    const driver = sarif().runs[0].tool.driver;
    expect(driver).toMatchObject({ name: 'shipcheck', version: '0.1.0', informationUri: 'https://github.com/Ahmad-sufyan/shipcheck' });
    expect(driver.rules.map((r: { id: string }) => r.id)).toEqual(['AUTHZ-001', 'LIVE-001', 'SECRET-006', 'SECRET-008']);
    expect(driver.rules[0]).toEqual({
      id: 'AUTHZ-001',
      name: 'RouteWithoutAuth',
      shortDescription: { text: 'Route without auth' },
      fullDescription: { text: 'Route handlers that never check the session.' },
      help: { text: 'Check the session.', markdown: '**Fix:** Check the session.' },
      defaultConfiguration: { level: 'error' },
      properties: { 'security-severity': '9.5', tags: ['security', 'authorization'], precision: 'high', 'problem.severity': 'error' },
    });
    expect(SECURITY_SEVERITY).toEqual({ critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.0' });
    expect(driver.rules[2].properties.tags).toEqual(['security', 'secrets', 'external/cwe/cwe-540']);
  });

  it('maps findings to results with levels, repo-relative locations and stable fingerprints', () => {
    const results = sarif().runs[0].results;
    expect(results[0]).toEqual({
      ruleId: 'AUTHZ-001',
      ruleIndex: 0,
      level: 'error',
      message: { text: 'Anyone can call this route.' },
      locations: [{ physicalLocation: { artifactLocation: { uri: 'fixtures/demo-app/app/api/admin/route.ts', uriBaseId: '%SRCROOT%' }, region: { startLine: 12, startColumn: 3 } } }],
      partialFingerprints: { 'shipcheck/v1': findings[0]!.id },
      properties: expect.objectContaining({ severity: 'critical', confidence: 'high', evidence: findings[0]!.evidence }),
    });
    expect(results.map((r: { level: string }) => r.level)).toEqual(['error', 'warning', 'note', 'warning']);
  });

  it('points project-level findings at package.json and live findings at shipcheck.config.json, with the URL in the message', () => {
    const [, , project, live] = sarif('.').runs[0].results;
    expect(project.locations[0].physicalLocation).toEqual({ artifactLocation: { uri: 'package.json', uriBaseId: '%SRCROOT%' }, region: { startLine: 1 } });
    expect(live.locations[0].physicalLocation).toEqual({ artifactLocation: { uri: 'shipcheck.config.json', uriBaseId: '%SRCROOT%' }, region: { startLine: 1 } });
    expect(live.message.text).toBe('Headers are missing. (https://app.example.com/)');
  });

  it('matches the snapshot', () => {
    const document = sarif();
    document.runs[0].results.forEach((r: { partialFingerprints: unknown }) => (r.partialFingerprints = { 'shipcheck/v1': '<id>' }));
    expect(document).toMatchSnapshot();
  });
});

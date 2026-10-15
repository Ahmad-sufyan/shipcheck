import { describe, expect, it } from 'vitest';
import { renderMarkdown } from '../../../src/reporters/markdown.js';
import { CATEGORIES } from '../../../src/schema.js';
import { makeFinding, makeResult } from '../../helpers/results.js';

describe('renderMarkdown', () => {
  const result = makeResult(
    [
      makeFinding({ ruleId: 'AUTHZ-001', title: 'Route without auth', category: 'authorization', severity: 'critical', file: 'app/api/admin/users/route.ts', line: 12, evidence: 'export async function POST(req: Request) {', cwe: 'CWE-862' }),
      makeFinding(),
      makeFinding({ ruleId: 'HTTP-006', title: 'X-Powered-By header enabled', category: 'http-config', severity: 'low', line: 2, evidence: 'const nextConfig = {', confidence: 'medium' }),
    ],
    { skipped: [{ check: 'B-001', reason: 'requires stack not detected: cloudflare' }], ruleErrors: [{ ruleId: 'X-001', message: 'boom' }] },
  );
  const md = renderMarkdown(result);

  it('starts with the score and grade', () => {
    expect(md.startsWith('# shipcheck report\n')).toBe(true);
    expect(md).toContain(`**Score: ${result.score.value}/100 (${result.score.grade})**`);
    expect(md).toContain('`fixtures/demo-app`');
  });

  it('includes a category table with every category', () => {
    expect(md).toContain('| Category | Score |');
    for (const category of CATEGORIES) expect(md).toContain(`| ${category} | ${result.score.byCategory[category]} |`);
  });

  it('groups findings by severity, most severe first, with location, evidence, explanation and fix', () => {
    const critical = md.indexOf('### Critical');
    const medium = md.indexOf('### Medium');
    const low = md.indexOf('### Low');
    expect(critical).toBeGreaterThan(-1);
    expect(critical).toBeLessThan(medium);
    expect(medium).toBeLessThan(low);
    expect(md).not.toContain('### High');
    expect(md).toContain('#### AUTHZ-001: Route without auth');
    expect(md).toContain('`app/api/admin/users/route.ts:12`');
    expect(md).toContain('```ts\nexport async function POST(req: Request) {\n```');
    expect(md).toContain('```js\nproductionBrowserSourceMaps: true,\n```');
    expect(md).toContain('Anyone can download readable copies of your front-end code.');
    expect(md).toContain('**Fix:** Remove `productionBrowserSourceMaps`.');
    expect(md).toContain('confidence: medium');
  });

  it('lists skipped checks and rule errors', () => {
    expect(md).toContain('## Skipped checks\n\n- `B-001`: requires stack not detected: cloudflare');
    expect(md).toContain('## Rule errors\n\n- `X-001`: boom');
  });

  it('says so when there is nothing to report', () => {
    const empty = renderMarkdown(makeResult());
    expect(empty).toContain('No findings.');
    expect(empty).toContain('## Skipped checks\n\nNone.');
    expect(empty).toContain('## Rule errors\n\nNone.');
  });

  it('uses a fence longer than any backtick run in the evidence', () => {
    const out = renderMarkdown(makeResult([makeFinding({ evidence: 'const q = sql```select 1```' })]));
    expect(out).toContain('````js\nconst q = sql```select 1```\n````');
  });
});

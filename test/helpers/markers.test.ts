import { describe, expect, it } from 'vitest';
import { checkRuleAgainstExpectations, collectMarkers, findingMatchesMarker } from './markers.js';
import { tmpProject } from './context.js';
import { makeFinding } from './results.js';

describe('collectMarkers', () => {
  it('reads //, --, {/* */} and # markers; line is the line after the marker', () => {
    const root = tmpProject({
      'app/api/x/route.ts': ['import x from "y"', '// shipcheck-expect: AUTH-002', 'export async function POST() {}'].join('\n'),
      'components/c.tsx': ['export function C() {', '  return (', '    <div>', '      {/* shipcheck-expect: INPUT-003, XSS-002 */}', '      <div dangerouslySetInnerHTML={{ __html: x }} />', '    </div>', '  )', '}'].join('\n'),
      'supabase/migrations/0001.sql': ['-- shipcheck-expect: AUTHZ-005', 'create table t ();'].join('\n'),
      'wrangler.toml': ['# shipcheck-expect: INFRA-001', 'name = "x"'].join('\n'),
      'node_modules/pkg/index.js': '// shipcheck-expect: NOPE-001\nx',
      '.shipcheck-expect.json': JSON.stringify({ project: ['AUTH-012'] }),
    });
    expect(collectMarkers(root)).toEqual({
      markers: [
        { file: 'app/api/x/route.ts', line: 3, ruleIds: ['AUTH-002'] },
        { file: 'components/c.tsx', line: 5, ruleIds: ['INPUT-003', 'XSS-002'] },
        { file: 'supabase/migrations/0001.sql', line: 2, ruleIds: ['AUTHZ-005'] },
        { file: 'wrangler.toml', line: 2, ruleIds: ['INFRA-001'] },
      ],
      project: ['AUTH-012'],
    });
  });

  it('returns no project expectations without .shipcheck-expect.json', () => {
    expect(collectMarkers(tmpProject({ 'a.ts': 'x' }))).toEqual({ markers: [], project: [] });
  });
});

describe('findingMatchesMarker', () => {
  const marker = { file: 'a.ts', line: 10, ruleIds: ['R-001', 'R-002'] };

  it('matches the same file and rule within the marker line to marker line + 2', () => {
    expect(findingMatchesMarker(makeFinding({ ruleId: 'R-001', file: 'a.ts', line: 10 }), marker)).toBe(true);
    expect(findingMatchesMarker(makeFinding({ ruleId: 'R-002', file: 'a.ts', line: 12 }), marker)).toBe(true);
    expect(findingMatchesMarker(makeFinding({ ruleId: 'R-001', file: 'a.ts', line: 9 }), marker)).toBe(false);
    expect(findingMatchesMarker(makeFinding({ ruleId: 'R-001', file: 'a.ts', line: 13 }), marker)).toBe(false);
    expect(findingMatchesMarker(makeFinding({ ruleId: 'R-003', file: 'a.ts', line: 10 }), marker)).toBe(false);
    expect(findingMatchesMarker(makeFinding({ ruleId: 'R-001', file: 'b.ts', line: 10 }), marker)).toBe(false);
    expect(findingMatchesMarker(makeFinding({ ruleId: 'R-001', file: 'a.ts', line: null }), marker)).toBe(false);
  });
});

describe('checkRuleAgainstExpectations', () => {
  const expectations = {
    markers: [
      { file: 'a.ts', line: 3, ruleIds: ['R-001'] },
      { file: 'b.ts', line: 7, ruleIds: ['R-001', 'R-002'] },
    ],
    project: ['P-001'],
  };

  it('passes when every marker is matched and nothing is unexpected', () => {
    const findings = [makeFinding({ ruleId: 'R-001', file: 'a.ts', line: 4 }), makeFinding({ ruleId: 'R-001', file: 'b.ts', line: 7 })];
    expect(checkRuleAgainstExpectations('R-001', findings, expectations)).toEqual({ unmatchedMarkers: [], unexpectedFindings: [], missingProjectFinding: false });
  });

  it('reports unmatched markers and unexpected findings for the rule only', () => {
    const findings = [makeFinding({ ruleId: 'R-001', file: 'a.ts', line: 20 }), makeFinding({ ruleId: 'R-002', file: 'b.ts', line: 7 })];
    const check = checkRuleAgainstExpectations('R-001', findings, expectations);
    expect(check.unmatchedMarkers).toEqual(expectations.markers);
    expect(check.unexpectedFindings.map((f) => `${f.file}:${f.line}`)).toEqual(['a.ts:20']);
  });

  it('allows findings anywhere for project-level rules but requires at least one', () => {
    expect(checkRuleAgainstExpectations('P-001', [makeFinding({ ruleId: 'P-001', file: null, line: null })], expectations)).toEqual({
      unmatchedMarkers: [],
      unexpectedFindings: [],
      missingProjectFinding: false,
    });
    expect(checkRuleAgainstExpectations('P-001', [], expectations).missingProjectFinding).toBe(true);
  });
});

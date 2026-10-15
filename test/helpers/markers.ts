/**
 * Fixture expectation harness.
 *
 * A comment `shipcheck-expect: RULE-ID[, RULE-ID...]` (as `//`, `--`, `#` or `{/* *\/}`) marks the
 * line immediately below it as a place where those rules must report. Project-level expectations
 * live in `.shipcheck-expect.json` as `{ "project": ["RULE-ID"] }`.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import fg from 'fast-glob';
import type { Finding } from '../../src/types.js';

export interface Marker {
  /** Repo-relative path inside the fixture, forward slashes. */
  file: string;
  /** The line after the marker comment (1-based). */
  line: number;
  ruleIds: string[];
}

export interface Expectations {
  markers: Marker[];
  project: string[];
}

export interface RuleCheck {
  unmatchedMarkers: Marker[];
  unexpectedFindings: Finding[];
  /** A project-level expectation for the rule exists but the rule reported nothing. */
  missingProjectFinding: boolean;
}

export const PROJECT_EXPECTATIONS_FILE = '.shipcheck-expect.json';
const MARKER = /shipcheck-expect:\s*([A-Z][A-Z0-9]*-\d+(?:\s*,\s*[A-Z][A-Z0-9]*-\d+)*)/;
/** A finding matches when it is on the marked line or up to this many lines below it. */
export const MARKER_WINDOW = 2;

export function collectMarkers(dir: string): Expectations {
  const files = fg
    .sync('**/*', { cwd: dir, dot: true, onlyFiles: true, ignore: ['**/node_modules/**', PROJECT_EXPECTATIONS_FILE] })
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  const markers: Marker[] = [];
  for (const file of files) {
    readFileSync(join(dir, file), 'utf8')
      .split(/\r?\n/)
      .forEach((text, index) => {
        const match = MARKER.exec(text);
        if (match?.[1]) markers.push({ file, line: index + 2, ruleIds: match[1].split(/\s*,\s*/) });
      });
  }

  const projectFile = join(dir, PROJECT_EXPECTATIONS_FILE);
  const project = existsSync(projectFile) ? ((JSON.parse(readFileSync(projectFile, 'utf8')) as { project?: string[] }).project ?? []) : [];
  return { markers, project };
}

export function findingMatchesMarker(finding: Finding, marker: Marker): boolean {
  return (
    finding.file === marker.file &&
    marker.ruleIds.includes(finding.ruleId) &&
    finding.line !== null &&
    finding.line >= marker.line &&
    finding.line <= marker.line + MARKER_WINDOW
  );
}

/** Every marker for `ruleId` must be matched; every finding from it must match a marker or a project expectation. */
export function checkRuleAgainstExpectations(ruleId: string, findings: readonly Finding[], expectations: Expectations): RuleCheck {
  const ruleFindings = findings.filter((f) => f.ruleId === ruleId);
  const ruleMarkers = expectations.markers.filter((m) => m.ruleIds.includes(ruleId));
  const projectLevel = expectations.project.includes(ruleId);
  return {
    unmatchedMarkers: ruleMarkers.filter((m) => !ruleFindings.some((f) => findingMatchesMarker(f, m))),
    unexpectedFindings: projectLevel ? [] : ruleFindings.filter((f) => !ruleMarkers.some((m) => findingMatchesMarker(f, m))),
    missingProjectFinding: projectLevel && ruleFindings.length === 0,
  };
}

/** Every rule id that appears in a marker or a project expectation, sorted. */
export function expectedRuleIds(expectations: Expectations): string[] {
  const ids = new Set([...expectations.markers.flatMap((m) => m.ruleIds), ...expectations.project]);
  return [...ids].sort();
}

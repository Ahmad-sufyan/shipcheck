#!/usr/bin/env node
// Regenerates src/packs/nextjs-supabase/data/min-secure-versions.json from the GitHub Advisory Database.
// Usage: node scripts/update-min-secure-versions.mjs   (needs an authenticated `gh` CLI; network required)
//
// For every package and major version, the minimum secure version is the highest first-patched version
// among high/critical advisories whose vulnerable range overlaps that major. When a range spans a whole
// major without an in-major fix, the minimum lands in a later major (meaning: no fixed release in this line).
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';

const PACKAGES = ['next', 'react', 'react-dom', '@supabase/ssr', '@supabase/supabase-js'];
const MAJORS = { next: [12, 13, 14, 15, 16] };
const SEVERITIES = new Set(['high', 'critical']);
const OUT = new URL('../src/packs/nextjs-supabase/data/min-secure-versions.json', import.meta.url);
const checkedOn = new Date().toISOString().slice(0, 10);

const parse = (v) => {
  const [core, pre] = v.split('-', 2);
  const [major, minor, patch] = core.split('.').map(Number);
  return { major, minor, patch, pre: pre ?? null };
};
const compare = (a, b) => {
  const x = parse(a);
  const y = parse(b);
  for (const k of ['major', 'minor', 'patch']) if (x[k] !== y[k]) return x[k] - y[k];
  if (x.pre === y.pre) return 0;
  if (x.pre === null) return 1;
  if (y.pre === null) return -1;
  return x.pre < y.pre ? -1 : 1;
};
/** Whether `range` ("= 1.2.3" or ">= a, < b") contains any version of `major`. */
const overlapsMajor = (range, major) => {
  const lo = `${major}.0.0-0`;
  const hi = `${major + 1}.0.0-0`;
  let min = '0.0.0-0';
  let max = '99999.0.0';
  for (const part of range.split(',').map((p) => p.trim())) {
    const [, op, version] = /^(>=|>|<=|<|=)\s*(\S+)$/.exec(part) ?? [];
    if (op === '=') return compare(version, lo) >= 0 && compare(version, hi) < 0;
    if (op === '>=' || op === '>') min = version;
    if (op === '<' || op === '<=') max = version;
  }
  return compare(min, hi) < 0 && compare(max, lo) > 0;
};

const gh = (pkg) =>
  JSON.parse(execFileSync('gh', ['api', '-X', 'GET', 'advisories', '-f', 'ecosystem=npm', '-f', `affects=${pkg}`, '-f', 'per_page=100', '--paginate', '--slurp'], { encoding: 'utf8' })).flat();

const entries = [];
for (const pkg of PACKAGES) {
  const advisories = gh(pkg).filter((a) => !a.withdrawn_at && SEVERITIES.has(a.severity));
  for (const major of MAJORS[pkg] ?? []) {
    let best;
    for (const advisory of advisories) {
      for (const v of advisory.vulnerabilities) {
        const fixed = v.first_patched_version;
        if (v.package.name !== pkg || !fixed || parse(fixed).pre || !overlapsMajor(v.vulnerable_version_range, major)) continue;
        const rank = (a) => (a.severity === 'critical' ? 1 : 0);
        const order = best ? compare(fixed, best.fixed) || rank(advisory) - rank(best.advisory) || (advisory.ghsa_id < best.advisory.ghsa_id ? 1 : -1) : 1;
        const better = order > 0;
        if (better) best = { fixed, advisory };
      }
    }
    if (best) {
      entries.push({
        package: pkg,
        major,
        minVersion: best.fixed,
        advisory: [best.advisory.ghsa_id, best.advisory.cve_id].filter(Boolean).join(' / '),
        severity: best.advisory.severity,
        summary: best.advisory.summary,
        source: best.advisory.html_url,
        checkedOn,
      });
    }
  }
}
writeFileSync(OUT, `${JSON.stringify(entries, null, 2)}\n`);
console.log(entries.map((e) => `${e.package}@${e.major}: >= ${e.minVersion} (${e.advisory})`).join('\n'));

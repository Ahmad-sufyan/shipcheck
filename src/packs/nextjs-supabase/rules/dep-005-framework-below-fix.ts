import MIN_SECURE from '../data/min-secure-versions.json' with { type: 'json' };
import type { RawFinding, Rule } from '../../../types.js';
import { compareVersions, lockedPackages } from '../analysis/lockfile.js';

interface MinSecureVersion {
  package: string;
  major: number;
  minVersion: string;
  advisory: string;
  severity: string;
  summary: string;
  source: string;
  checkedOn: string;
}

const ENTRIES: readonly MinSecureVersion[] = MIN_SECURE;

export const dep005: Rule = {
  id: 'DEP-005',
  title: 'Framework below its security fix',
  category: 'dependencies',
  severity: 'high',
  confidence: 'high',
  stacks: [],
  description:
    'Compares the lockfile versions of next, react, react-dom, @supabase/ssr and @supabase/supabase-js with the bundled ' +
    'per-major minimum secure versions (src/packs/nextjs-supabase/data/min-secure-versions.json, built from the GitHub ' +
    'Advisory Database by scripts/update-min-secure-versions.mjs). Works offline, unlike DEP-001. Only packages and majors ' +
    'with a high or critical advisory are listed; the finding shows the date the data was checked.',
  explanation: 'The framework version you install is older than the release that fixed a high or critical security advisory.',
  fix: 'Upgrade to the minimum version shown or later.',
  falsePositiveNote: 'The data is a snapshot (see checkedOn); a newer advisory may raise the minimum, and backported fixes in private forks are not recognised.',
  cwe: 'CWE-1395',
  references: ['https://github.com/advisories', 'https://nextjs.org/blog'],
  run(ctx) {
    const findings: RawFinding[] = [];
    const seen = new Set<string>();
    for (const locked of lockedPackages(ctx)) {
      const major = Number.parseInt(locked.version, 10);
      const entry = ENTRIES.find((e) => e.package === locked.name && e.major === major);
      if (!entry || compareVersions(locked.version, entry.minVersion) >= 0 || seen.has(`${locked.name}@${locked.version}`)) continue;
      seen.add(`${locked.name}@${locked.version}`);
      findings.push({
        file: locked.file,
        line: locked.line,
        evidence: `${locked.name}@${locked.version} is below ${entry.minVersion}`,
        explanation:
          `${entry.advisory} (${entry.severity}): ${entry.summary}. ${locked.name} ${entry.minVersion} is the first release that fixes it` +
          `${Number.parseInt(entry.minVersion, 10) !== major ? `; there is no fixed ${major}.x release` : ''}. Source: ${entry.source}, checked on ${entry.checkedOn}.`,
        fix: `Upgrade ${locked.name} to ${entry.minVersion} or later.`,
      });
    }
    return findings;
  },
};

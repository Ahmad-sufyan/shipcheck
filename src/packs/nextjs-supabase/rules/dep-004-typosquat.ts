import POPULAR from '../data/popular-packages.json' with { type: 'json' };
import type { RawFinding, Rule } from '../../../types.js';

const POPULAR_NAMES: readonly string[] = POPULAR.packages;
const POPULAR_SET = new Set(POPULAR_NAMES);
const MIN_LENGTH = 4;

/** Optimal string alignment distance: insertions, deletions, substitutions and adjacent transpositions. */
export function editDistance(a: string, b: string): number {
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)));
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i]![j] = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i]![j] = Math.min(d[i]![j]!, d[i - 2]![j - 2]! + 1);
    }
  }
  return d[a.length]![b.length]!;
}

function lookalike(name: string): string | undefined {
  if (name.length < MIN_LENGTH || POPULAR_SET.has(name)) return undefined;
  return POPULAR_NAMES.find((popular) => popular.length >= MIN_LENGTH && Math.abs(popular.length - name.length) <= 1 && editDistance(name, popular) === 1);
}

function lineOf(text: string, needle: string): number {
  const index = text.split(/\r?\n/).findIndex((line) => line.includes(needle));
  return index === -1 ? 1 : index + 1;
}

export const dep004: Rule = {
  id: 'DEP-004',
  title: 'Typosquat-like dependency',
  category: 'dependencies',
  severity: 'low',
  confidence: 'low',
  advisory: true,
  stacks: [],
  description:
    'Advisory: reports direct dependencies whose name is one edit (insertion, deletion, substitution or swap of adjacent ' +
    'characters) away from a package in the bundled list of popular packages, without being on that list itself. Names ' +
    'shorter than 4 characters are skipped.',
  explanation:
    'Attackers publish packages with names one typo away from popular ones (lodahs for lodash) that run malicious install ' +
    'scripts or steal environment variables. A mistyped install command is enough to pull one in.',
  fix: 'Check the package on npmjs.com (publisher, downloads, repository). If it is a typo, uninstall it, install the intended package and rotate any secrets present on machines that installed it.',
  falsePositiveNote: 'Some legitimate packages have names close to popular ones; dismiss the finding once verified.',
  cwe: 'CWE-1357',
  references: ['https://docs.npmjs.com/threats-and-mitigations#by-typosquatting--dependency-confusion'],
  run(ctx) {
    const pkg = ctx.packageJson;
    if (!pkg) return [];
    const text = ctx.readText(pkg.file);
    const findings: RawFinding[] = [];
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      const deps = pkg.data[field];
      if (!deps || typeof deps !== 'object') continue;
      for (const [name, range] of Object.entries(deps as Record<string, unknown>)) {
        const target = lookalike(name);
        if (!target) continue;
        const evidence = `${JSON.stringify(name)}: ${JSON.stringify(range)}`;
        findings.push({ file: pkg.file, line: lineOf(text, `${JSON.stringify(name)}:`), evidence, explanation: `"${name}" is one character away from the popular package "${target}".` });
      }
    }
    return findings;
  },
};

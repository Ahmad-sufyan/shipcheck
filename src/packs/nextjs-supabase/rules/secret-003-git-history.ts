import { runGitleaks } from '../../../adapters/gitleaks.js';
import type { RawFinding, Rule } from '../../../types.js';

export const secret003: Rule = {
  id: 'SECRET-003',
  title: 'Secret in git history',
  category: 'secrets',
  severity: 'critical',
  confidence: 'medium',
  source: 'tool:gitleaks',
  stacks: [],
  timeoutMs: 250_000,
  description:
    'Runs `gitleaks git` (with --redact) over the commit history of the scan root and reports each secret whose file and ' +
    'gitleaks rule no longer match anything in the working tree, as found by `gitleaks dir`; secrets still present are ' +
    'reported by SECRET-004 instead. Findings name the file, line and commit, never the secret. Skipped when gitleaks ' +
    'is not installed or the project is not a git repository.',
  explanation:
    'Deleting a secret from the code does not remove it from git: anyone who can clone the repository (everyone, if it is ' +
    'public) can check out the old commit and use the key.',
  fix:
    'Rotate the key first; that is the only fix that matters once a secret was pushed. Then, if needed, rewrite history ' +
    'with git filter-repo and force-push, and ask collaborators to re-clone.',
  falsePositiveNote: 'gitleaks can flag test fixtures or example values; allowlist them in a .gitleaks.toml or with a .gitleaksignore fingerprint.',
  cwe: 'CWE-540',
  references: ['https://github.com/gitleaks/gitleaks', 'https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository'],
  async run(ctx) {
    if (!ctx.tools) return [];
    const history = await runGitleaks(ctx.root, 'git', ctx.tools);
    if (!history.ok) {
      ctx.skip?.('SECRET-003', history.reason);
      return [];
    }
    const tree = await runGitleaks(ctx.root, 'dir', ctx.tools);
    if (!tree.ok) {
      ctx.skip?.('SECRET-003', `could not compare history with the working tree: ${tree.reason}`);
      return [];
    }
    const present = new Set(tree.value.map((leak) => `${leak.file}\0${leak.ruleId}`));
    const seen = new Set<string>();
    const findings: RawFinding[] = [];
    for (const leak of history.value) {
      if (present.has(`${leak.file}\0${leak.ruleId}`)) continue;
      const commit = (leak.commit ?? '').slice(0, 7) || 'unknown';
      const key = `${leak.file}\0${leak.ruleId}\0${leak.startLine}\0${commit}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const date = leak.date ? ` (${leak.date.slice(0, 10)})` : '';
      findings.push({
        evidence: `${leak.ruleId} in ${leak.file}:${leak.startLine}, commit ${commit}${date}`,
        explanation: `${leak.description || 'A secret'} It was added in commit ${commit} and is no longer in the working tree, but anyone with the repository can still read it from history.`,
        source: 'tool:gitleaks',
      });
    }
    return findings;
  },
};

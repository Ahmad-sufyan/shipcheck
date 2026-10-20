import type { RawFinding, Rule } from '../../../types.js';
import { lockedPackages } from '../analysis/lockfile.js';

const LIFECYCLE_SCRIPTS = ['preinstall', 'install', 'postinstall', 'prepare'] as const;
/** Downloads, inline code execution, encoded payloads and remote URLs. */
const SUSPICIOUS = /\b(?:curl|wget|Invoke-WebRequest|iwr|Invoke-Expression|iex)\b|\bnode\s+(?:-e|--eval|-p|--print)\b|\bbase64\b|\beval\b|https?:\/\//i;

function lineOf(text: string, needle: string): number {
  const index = text.split(/\r?\n/).findIndex((line) => line.includes(needle));
  return index === -1 ? 1 : index + 1;
}

export const dep003: Rule = {
  id: 'DEP-003',
  title: 'Suspicious install script',
  category: 'dependencies',
  severity: 'high',
  confidence: 'medium',
  stacks: [],
  description:
    "Reports the root package.json's preinstall, install, postinstall and prepare scripts when they run curl, wget, " +
    '`node -e`, base64, eval or contain a URL (high), and, as an info advisory, direct dependencies whose lockfile entry ' +
    'says they run an install script (npm lockfiles record hasInstallScript).',
  explanation:
    'Lifecycle scripts run automatically on every `npm install`, on developer machines and in CI, with access to ' +
    'environment secrets. Downloading and executing remote code there is a common supply-chain attack and hides what ' +
    'actually runs.',
  fix:
    'Remove remote downloads from lifecycle scripts (vendor or pin the tool as a dependency instead), review dependencies ' +
    'that run install scripts, and consider `npm ci --ignore-scripts` or pnpm `onlyBuiltDependencies` in CI.',
  falsePositiveNote: 'Build steps like `prisma generate` or `husky` are not flagged; packages such as sharp or esbuild legitimately need install scripts.',
  cwe: 'CWE-506',
  references: ['https://docs.npmjs.com/cli/using-npm/scripts#life-cycle-scripts', 'https://pnpm.io/settings#onlybuiltdependencies'],
  run(ctx) {
    const findings: RawFinding[] = [];
    const pkg = ctx.packageJson;
    const scripts = pkg?.data.scripts;
    if (pkg && scripts && typeof scripts === 'object') {
      const text = ctx.readText(pkg.file);
      for (const name of LIFECYCLE_SCRIPTS) {
        const script = (scripts as Record<string, unknown>)[name];
        if (typeof script !== 'string' || !SUSPICIOUS.test(script)) continue;
        findings.push({ file: pkg.file, line: lineOf(text, JSON.stringify(name)), evidence: `${JSON.stringify(name)}: ${JSON.stringify(script)}` });
      }
    }
    for (const locked of lockedPackages(ctx)) {
      if (!locked.direct || !locked.hasInstallScript) continue;
      findings.push({ file: locked.file, line: locked.line, evidence: `${locked.name}@${locked.version} runs an install script`, severity: 'info', advisory: true, confidence: 'medium' });
    }
    return findings;
  },
};

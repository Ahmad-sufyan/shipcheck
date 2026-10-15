import { lineAt } from '../../../context/files.js';
import type { RawFinding, Rule } from '../../../types.js';

export const http006PoweredBy: Rule = {
  id: 'HTTP-006',
  title: 'X-Powered-By header enabled',
  category: 'http-config',
  severity: 'low',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'Next.js adds an `X-Powered-By: Next.js` header to every response unless `poweredByHeader: false` is set in next.config. ' +
    'The rule reads next.config.{js,mjs,ts,mts} statically and reports when the option is absent or not literally `false`. ' +
    'Limitations: a value computed at runtime is reported with medium confidence; when the config object spreads another object ' +
    '(`...base`) that might set the option, confidence drops to medium; a config that cannot be resolved statically (for example ' +
    'one imported from another module) is skipped and listed under skipped checks.',
  explanation:
    'Your app tells every visitor that it runs on Next.js. That is not a vulnerability by itself, but it helps attackers pick ' +
    'which framework-specific bugs to try first, and hiding it costs nothing.',
  fix: 'Set `poweredByHeader: false` in your next.config file, for example `const nextConfig = { poweredByHeader: false }`.',
  falsePositiveNote:
    'A CDN or reverse proxy in front of the app may already strip the header. LIVE-001 confirms what production actually sends.',
  cwe: 'CWE-200',
  references: [
    'https://nextjs.org/docs/app/api-reference/config/next-config-js/poweredByHeader',
    'https://owasp.org/www-project-secure-headers/',
  ],
  run(ctx) {
    const config = ctx.nextConfig;
    if (!config) return [];
    const option = config.options.poweredByHeader;
    if (option && !option.dynamic && option.value === false) return [];

    const text = ctx.readText(config.file);
    const line = option?.line ?? config.objectLine;
    const finding: RawFinding = { file: config.file, line, evidence: lineAt(text, line).trim() };
    if (option?.dynamic || (!option && config.hasSpread)) finding.confidence = 'medium';
    return [finding];
  },
};

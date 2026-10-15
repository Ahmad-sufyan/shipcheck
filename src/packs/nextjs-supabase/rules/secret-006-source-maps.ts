import { lineAt } from '../../../context/files.js';
import type { RawFinding, Rule } from '../../../types.js';

export const secret006SourceMaps: Rule = {
  id: 'SECRET-006',
  title: 'Production browser source maps enabled',
  category: 'secrets',
  severity: 'medium',
  confidence: 'high',
  stacks: ['nextjs-app-router'],
  description:
    'With `productionBrowserSourceMaps: true`, `next build` writes .map files next to the client bundles and Next.js serves ' +
    'them publicly, exposing the original client-side source. The rule reports the option when it is literally `true` in ' +
    'next.config, and with low confidence when its value is computed at runtime. Limitations: custom webpack `devtool` ' +
    'settings and error-tracker upload plugins are not inspected.',
  explanation:
    'Anyone can download readable copies of your front-end code from production, including comments, internal API paths ' +
    'and feature flags. That makes it much easier to find logic flaws or secrets that were accidentally bundled into client code.',
  fix:
    'Remove `productionBrowserSourceMaps` (it defaults to false). If you need readable production stack traces, upload the ' +
    'source maps privately to your error tracker during the build and delete them from the build output instead of serving them.',
  falsePositiveNote:
    'Intentional for open-source apps whose code is public anyway; turn the rule off in shipcheck.config.json in that case.',
  cwe: 'CWE-540',
  references: ['https://nextjs.org/docs/app/api-reference/config/next-config-js/productionBrowserSourceMaps'],
  run(ctx) {
    const config = ctx.nextConfig;
    const option = config?.options.productionBrowserSourceMaps;
    if (!config || !option) return [];
    if (!option.dynamic && option.value !== true) return [];

    const finding: RawFinding = { file: config.file, line: option.line, evidence: lineAt(ctx.readText(config.file), option.line).trim() };
    if (option.dynamic) finding.confidence = 'low';
    return [finding];
  },
};

import type { Rule } from '../../../types.js';
import { cloudflareZone } from '../analysis/cloudflare-zone.js';

export const infra002: Rule = {
  id: 'INFRA-002',
  title: 'Cloudflare Always Use HTTPS is off',
  category: 'infra',
  severity: 'medium',
  confidence: 'high',
  stacks: [],
  timeoutMs: 60_000,
  description:
    'With --cloudflare and a read-only CLOUDFLARE_API_TOKEN, reads the zone setting always_use_https and reports "off". ' +
    'Without them it is skipped (INFRA-001 carries the single "unverified" advisory for Cloudflare projects).',
  explanation: 'Cloudflare serves plain HTTP requests instead of redirecting them to HTTPS, so first visits and old links travel unencrypted.',
  fix: 'Turn on SSL/TLS > Edge Certificates > Always Use HTTPS (or redirect at the origin) and send HSTS.',
  falsePositiveNote: 'An origin that redirects HTTP to HTTPS itself is safe; LIVE-002 confirms the behaviour.',
  cwe: 'CWE-319',
  references: ['https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/'],
  async run(ctx) {
    const zone = await cloudflareZone(ctx);
    if (zone.status !== 'report') {
      if (zone.status === 'skipped' || ctx.stacks.has('cloudflare')) ctx.skip?.('INFRA-002', zone.reason);
      return [];
    }
    const { alwaysUseHttps, zone: info, problems } = zone.report;
    if (alwaysUseHttps === undefined) {
      ctx.skip?.('INFRA-002', problems.find((p) => p.startsWith('always_use_https')) ?? 'the always_use_https setting could not be read');
      return [];
    }
    return alwaysUseHttps === 'off' ? [{ evidence: `Cloudflare zone ${info.name}: Always Use HTTPS is off` }] : [];
  },
};

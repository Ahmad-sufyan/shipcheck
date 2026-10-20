import type { Rule } from '../../../types.js';
import { cloudflareZone } from '../analysis/cloudflare-zone.js';

export const infra001: Rule = {
  id: 'INFRA-001',
  title: 'Cloudflare SSL/TLS mode is Flexible or Off',
  category: 'infra',
  severity: 'high',
  confidence: 'high',
  stacks: [],
  timeoutMs: 60_000,
  description:
    'With --cloudflare and a read-only CLOUDFLARE_API_TOKEN, reads the zone SSL/TLS encryption mode (GET ' +
    '/zones/{id}/settings/ssl) for live.url or the wrangler routes and reports "off" or "flexible". Without the flag or ' +
    'the token, a project on the Cloudflare stack gets one info advisory saying the mode (and Always Use HTTPS) was not ' +
    'verified. scan never touches the network unless --cloudflare is passed.',
  explanation:
    'In Flexible mode Cloudflare talks to your origin over plain HTTP, so traffic is unencrypted between Cloudflare and ' +
    'the server even though visitors see a padlock; Off disables HTTPS entirely.',
  fix: 'Set SSL/TLS encryption mode to Full (strict) in the Cloudflare dashboard (SSL/TLS > Overview) once the origin has a valid certificate; Workers and Pages origins already qualify.',
  falsePositiveNote: 'Zones whose records are not proxied (grey cloud) do not use this setting; dismiss the finding for them.',
  cwe: 'CWE-319',
  references: ['https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/'],
  async run(ctx) {
    const zone = await cloudflareZone(ctx);
    if (zone.status === 'unverified') {
      if (!ctx.stacks.has('cloudflare')) return [];
      return [
        {
          evidence: `Cloudflare SSL/TLS mode and Always Use HTTPS unverified: ${zone.reason}`,
          severity: 'info',
          confidence: 'low',
          advisory: true,
          explanation: 'This project deploys to Cloudflare, but the zone settings that decide whether traffic is encrypted end to end were not checked.',
          fix: 'Create an API token with Zone > Zone > Read, Zone > Zone Settings > Read and Zone > Zone WAF > Read, set it as CLOUDFLARE_API_TOKEN and run `shipcheck scan --cloudflare`.',
        },
      ];
    }
    if (zone.status === 'skipped') {
      ctx.skip?.('INFRA-001', zone.reason);
      return [];
    }
    const { ssl, zone: info, problems } = zone.report;
    if (ssl === undefined) {
      ctx.skip?.('INFRA-001', problems.find((p) => p.startsWith('ssl')) ?? 'the ssl setting could not be read');
      return [];
    }
    if (ssl !== 'off' && ssl !== 'flexible') return [];
    return [{ evidence: `Cloudflare zone ${info.name}: SSL/TLS encryption mode is "${ssl}"` }];
  },
};

import type { Rule } from '../../../types.js';
import { cloudflareZone } from '../analysis/cloudflare-zone.js';

export const infra003: Rule = {
  id: 'INFRA-003',
  title: 'No Cloudflare WAF or rate limiting rules',
  category: 'infra',
  severity: 'info',
  confidence: 'medium',
  advisory: true,
  stacks: [],
  timeoutMs: 60_000,
  description:
    'Advisory. With --cloudflare and a read-only CLOUDFLARE_API_TOKEN, reads the zone entrypoint rulesets of the ' +
    'http_request_firewall_custom and http_ratelimit phases and reports the phases that have no enabled rules. ' +
    'Skipped without the flag or the token.',
  explanation: 'The zone has no custom WAF rules or no rate limiting rules, so abusive traffic reaches the app unless the app limits it itself.',
  fix: 'Add a rate limiting rule for authentication paths (for example /api/auth/* and /login, by IP) and custom rules for paths that should never be public.',
  falsePositiveNote: 'Free plans include only one rate limiting rule, and apps that rate limit in code (RATE-001) may not need one.',
  cwe: 'CWE-770',
  references: ['https://developers.cloudflare.com/waf/rate-limiting-rules/', 'https://developers.cloudflare.com/waf/custom-rules/'],
  async run(ctx) {
    const zone = await cloudflareZone(ctx);
    if (zone.status !== 'report') {
      if (zone.status === 'skipped' || ctx.stacks.has('cloudflare')) ctx.skip?.('INFRA-003', zone.reason);
      return [];
    }
    const { firewallRules, rateLimitRules, zone: info } = zone.report;
    const empty = [firewallRules === 0 ? 'custom WAF rules' : '', rateLimitRules === 0 ? 'rate limiting rules' : ''].filter(Boolean);
    return empty.length ? [{ evidence: `Cloudflare zone ${info.name} has no ${empty.join(' and no ')}` }] : [];
  },
};

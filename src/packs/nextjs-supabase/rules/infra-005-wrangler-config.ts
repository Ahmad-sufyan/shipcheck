import type { RawFinding, Rule } from '../../../types.js';
import { findSecrets, isPlaceholder, SECRET_ENV_NAME } from '../analysis/secret-patterns.js';

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** 1-based line of the first `key =` (TOML) or `"key":` (JSON) after `from`; falls back to 1. */
function keyLine(text: string, key: string, from = 0): number {
  const pattern = new RegExp(`^\\s*(?:"${escapeRegex(key)}"|${escapeRegex(key)})\\s*[=:]`);
  const index = text.split(/\r?\n/).findIndex((line, i) => i >= from && pattern.test(line));
  return index === -1 ? 1 : index + 1;
}

/** 0-based index of the line that opens a vars table: `[vars]`, `[env.<name>.vars]`, or a JSON `"vars":` key. */
function varsSectionIndex(text: string, envName: string): number {
  const lines = text.split(/\r?\n/);
  const header = envName ? `[env.${envName}.vars]` : '[vars]';
  const toml = lines.findIndex((line) => line.trim() === header);
  if (toml !== -1) return toml;
  return Math.max(0, lines.findIndex((line) => /"vars"\s*:/.test(line)));
}

function hasRoutes(data: Record<string, unknown>): boolean {
  return (Array.isArray(data.routes) && data.routes.length > 0) || Boolean(data.route);
}

export const infra005: Rule = {
  id: 'INFRA-005',
  title: 'Wrangler configuration exposes secrets or a workers.dev URL',
  category: 'infra',
  severity: 'high',
  confidence: 'medium',
  stacks: [],
  description:
    'Reads wrangler.toml (or wrangler.jsonc / wrangler.json) and reports vars, including per-environment vars, whose name ' +
    'looks secret (SECRET, TOKEN, PASSWORD, API_KEY, PRIVATE, SERVICE_ROLE) or whose value matches a known key format ' +
    '(high), and workers_dev = true next to routes (medium), which keeps the *.workers.dev URL live beside the custom ' +
    'domain. Values never appear in findings.',
  explanation:
    'Wrangler vars are plain text: they are committed with the config and visible in the dashboard, so secrets in them are ' +
    'not secret. A workers.dev URL serves the same Worker outside the zone, without its WAF, rate limiting or Access rules.',
  fix: 'Move secrets to `wrangler secret put <NAME>` (and .dev.vars locally, git-ignored), and set workers_dev = false when the Worker has routes or a custom domain.',
  falsePositiveNote: 'A var with a secret-sounding name but a public value (for example a public key) can be dismissed.',
  cwe: 'CWE-312',
  references: ['https://developers.cloudflare.com/workers/configuration/secrets/', 'https://developers.cloudflare.com/workers/wrangler/configuration/#workersdev'],
  run(ctx) {
    const config = ctx.wranglerToml;
    if (!config || !isObject(config.data)) return [];
    const text = ctx.readText(config.file);
    const findings: RawFinding[] = [];
    const environments: [string, Record<string, unknown>][] = [['', config.data]];
    if (isObject(config.data.env)) {
      for (const [name, env] of Object.entries(config.data.env)) if (isObject(env)) environments.push([name, env]);
    }
    for (const [envName, env] of environments) {
      if (!isObject(env.vars)) continue;
      const section = envName ? `env.${envName}.vars` : 'vars';
      const sectionLine = varsSectionIndex(text, envName);
      for (const [key, value] of Object.entries(env.vars)) {
        const raw = typeof value === 'string' ? value.trim() : '';
        const secret = raw && !isPlaceholder(raw) ? findSecrets(raw)[0] : undefined;
        if (!secret && !SECRET_ENV_NAME.test(key)) continue;
        findings.push({
          file: config.file,
          line: keyLine(text, key, sectionLine),
          evidence: `${section}.${key} = <redacted>`,
          ...(secret ? { confidence: 'high' as const, explanation: `${section}.${key} holds a ${secret.name} in plain text.` } : {}),
        });
      }
    }
    if (config.data.workers_dev === true && hasRoutes(config.data)) {
      findings.push({
        file: config.file,
        line: keyLine(text, 'workers_dev'),
        evidence: 'workers_dev = true alongside routes',
        severity: 'medium',
        confidence: 'high',
        explanation: 'The Worker has routes on your zone but also stays reachable on its *.workers.dev URL, which bypasses the zone WAF, rate limiting and Access policies.',
      });
    }
    return findings;
  },
};

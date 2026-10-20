import type { RawFinding, Severity } from '../../types.js';
import type { LiveCheck, LiveTarget, PlannedStep } from '../context.js';
import { absolute } from '../context.js';
import type { LiveResponse } from '../transport.js';

interface SensitiveFile {
  path: string;
  severity: Severity;
  what: string;
  /** Matched against the body, so soft-404 pages (200 with an HTML "not found") never count. */
  signature: (response: LiveResponse) => boolean;
}

const looksLikeHtml = (text: string) => /^\s*<(?:!doctype|html|head|body)/i.test(text);
const envFile = (r: LiveResponse) => !looksLikeHtml(r.text) && /^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=/m.test(r.text);
const startsWith = (bytes: number[]) => (r: LiveResponse) => bytes.every((byte, i) => r.body[i] === byte);

export const SENSITIVE_FILES: readonly SensitiveFile[] = [
  { path: '/.env', severity: 'critical', what: 'an environment file with KEY=value lines', signature: envFile },
  { path: '/.env.local', severity: 'critical', what: 'an environment file with KEY=value lines', signature: envFile },
  { path: '/.git/config', severity: 'critical', what: 'a git config ([core] section)', signature: (r) => /^\s*\[core\]/m.test(r.text) },
  { path: '/.git/HEAD', severity: 'critical', what: 'a git HEAD (ref: refs/...)', signature: (r) => /^ref: refs\//.test(r.text) },
  { path: '/backup.zip', severity: 'critical', what: 'a zip archive (PK header)', signature: startsWith([0x50, 0x4b, 0x03, 0x04]) },
  { path: '/.DS_Store', severity: 'medium', what: 'a macOS .DS_Store directory listing', signature: startsWith([0x00, 0x00, 0x00, 0x01, 0x42, 0x75, 0x64, 0x31]) },
];

/** The first <script src> on the page that points at the same host. */
export function firstScript(html: string, base: URL): URL | undefined {
  for (const match of html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)/gi)) {
    const url = new URL(match[1]!, base);
    if (url.hostname === base.hostname && /^https?:$/.test(url.protocol)) return url;
  }
  return undefined;
}

function isSourceMap(response: LiveResponse): boolean {
  try {
    const map = JSON.parse(response.text) as { version?: unknown; sources?: unknown };
    return typeof map.version === 'number' && Array.isArray(map.sources);
  } catch {
    return false;
  }
}

export const live005: LiveCheck = {
  id: 'LIVE-005',
  title: 'Sensitive file exposed',
  category: 'live',
  severity: 'critical',
  confidence: 'high',
  stacks: [],
  source: 'live',
  description:
    'Requests /.env, /.env.local, /.git/config, /.git/HEAD, /backup.zip, /.DS_Store and the .map file of the first ' +
    'script referenced by /. A file is reported only when the status is 200 and the body matches its format (KEY= lines, ' +
    'a [core] section, ref: refs/, the zip magic bytes, the .DS_Store magic, or source map JSON with version and sources), ' +
    'so soft-404 pages are ignored. Critical for .env, .git and backups; medium for .DS_Store and source maps. Evidence ' +
    'never includes file contents.',
  explanation: 'A file that should never be public is downloadable from the live site.',
  fix: 'Block dotfiles and backups at the platform or CDN, keep them out of the deploy (public/ and the build output), and rotate any secret that was exposed. Disable production source maps (productionBrowserSourceMaps: false).',
  falsePositiveNote: 'Bodies are matched against each format, so soft-404s do not count; an intentionally public source map can be dismissed.',
  cwe: 'CWE-538',
  references: ['https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information'],
  plan: (target: LiveTarget): PlannedStep[] => [
    ...SENSITIVE_FILES.map((file) => ({ kind: 'http' as const, method: 'GET' as const, target: absolute(target, file.path), purpose: 'LIVE-005 must not be served' })),
    { kind: 'http', method: 'GET', target: `${target.origin.origin}/<first script on />.map`, purpose: 'LIVE-005 source map, if / references a script', conditional: true },
  ],
  async run(ctx) {
    const findings: RawFinding[] = [];
    for (const file of SENSITIVE_FILES) {
      const response = await ctx.client.request('GET', file.path);
      if (response.status === 200 && file.signature(response)) {
        findings.push({ url: response.url, evidence: `GET ${file.path} → HTTP 200, ${file.what}`, severity: file.severity });
      }
    }
    const home = await ctx.home();
    const script = firstScript(home.text, ctx.origin);
    if (script) {
      const map = new URL(`${script.pathname}.map`, ctx.origin);
      const response = await ctx.client.request('GET', map.href);
      if (response.status === 200 && isSourceMap(response)) {
        findings.push({
          url: response.url,
          evidence: `GET ${map.pathname} → HTTP 200, a source map with the original sources`,
          severity: 'medium',
          explanation: 'The production source map is public, so anyone can read the original client-side source code.',
        });
      }
    }
    return findings;
  },
};

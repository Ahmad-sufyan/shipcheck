import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { promises as dns } from 'node:dns';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { dirname, join } from 'node:path';
import type { LiveClient } from './client.js';
import { LiveRefusal, LiveRequestError } from './errors.js';

export const SECRET_FILE = '.shipcheck/live-secret';
export const SECRET_ENV = 'SHIPCHECK_LIVE_SECRET';
export const WELL_KNOWN_PATH = '/.well-known/shipcheck.txt';
export const VERIFICATION_PREFIX = 'shipcheck-site-verification=';
const MAX_SAME_HOST_REDIRECTS = 3;

/** TXT records as node:dns returns them: each record is a list of strings to concatenate. */
export type TxtResolver = (name: string) => Promise<string[][]>;
export const dnsTxtResolver: TxtResolver = (name) => dns.resolveTxt(name);

/** What the site serves: the hex sha256 of the secret, never the secret itself. */
export function hashSecret(secret: string): string {
  return createHash('sha256').update(secret).digest('hex');
}

export interface OwnershipSetup {
  /** False when an existing secret was kept. */
  created: boolean;
  secretFile: string;
  hash: string;
  wellKnownUrl: string;
  wellKnownContent: string;
  dnsName: string;
}

/** An https URL with a hostname (not an IP); live checks and ownership are per hostname. */
export function parseTarget(url: string, { allowLocal = false } = {}): URL {
  let target: URL;
  try {
    target = new URL(url);
  } catch {
    throw new LiveRefusal(`Not a valid URL: ${url}`);
  }
  if (target.protocol !== 'https:' && !(allowLocal && target.protocol === 'http:')) throw new LiveRefusal(`Live checks need an https:// URL; got ${target.protocol}//${target.host}`);
  if (isIP(target.hostname.replace(/^\[|\]$/g, '')) && !allowLocal) throw new LiveRefusal(`Refusing ${target.hostname}: IP address targets are not allowed. Use the site's hostname.`);
  if (target.username || target.password) throw new LiveRefusal('The live URL must not contain a user name or password.');
  return target;
}

function ensureGitignored(root: string): void {
  const file = join(root, '.gitignore');
  const text = existsSync(file) ? readFileSync(file, 'utf8') : '';
  if (text.split(/\r?\n/).some((line) => /^\/?\.shipcheck\/?$/.test(line.trim()))) return;
  writeFileSync(file, `${text}${text && !text.endsWith('\n') ? '\n' : ''}.shipcheck/\n`);
}

/**
 * `shipcheck live init <url>`: creates .shipcheck/live-secret (32 random bytes, hex) unless one exists
 * (or `force`), makes sure git ignores .shipcheck/, and returns what the site has to serve.
 */
export function initOwnership(root: string, url: string, { force = false } = {}): OwnershipSetup {
  const target = parseTarget(url);
  const path = join(root, SECRET_FILE);
  const existing = existsSync(path) ? readFileSync(path, 'utf8').trim() : '';
  const created = force || !existing;
  const secret = created ? randomBytes(32).toString('hex') : existing;
  if (created) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${secret}\n`, { mode: 0o600 });
  }
  ensureGitignored(root);
  const hash = hashSecret(secret);
  return {
    created,
    secretFile: SECRET_FILE,
    hash,
    wellKnownUrl: `https://${target.host}${WELL_KNOWN_PATH}`,
    wellKnownContent: `${VERIFICATION_PREFIX}${hash}`,
    dnsName: `_shipcheck.${target.hostname}`,
  };
}

export function formatSetup(setup: OwnershipSetup): string {
  return [
    setup.created ? `Created ${setup.secretFile} (git-ignored). Keep it private; in CI, store its contents in the ${SECRET_ENV} secret.` : `Using the existing ${setup.secretFile}.`,
    '',
    'Prove you own the site in one of two ways:',
    `  1. Serve this line at ${setup.wellKnownUrl}`,
    `       ${setup.wellKnownContent}`,
    `  2. Or add a DNS TXT record at ${setup.dnsName} with the value`,
    `       ${setup.wellKnownContent}`,
    '',
    'The value is the sha256 hash of the secret; never publish the secret itself.',
  ].join('\n');
}

export function setupHint(url?: string): string {
  return `Run \`shipcheck live init ${url ?? '<url>'}\` and serve the value it prints at ${WELL_KNOWN_PATH} or in a DNS TXT record at _shipcheck.<host>.`;
}

/** The secret from SHIPCHECK_LIVE_SECRET (CI) or .shipcheck/live-secret; refuses with setup instructions otherwise. */
export function loadSecret(root: string, env: Record<string, string | undefined> = process.env, url?: string): string {
  const fromEnv = env[SECRET_ENV]?.trim();
  if (fromEnv) return fromEnv;
  const path = join(root, SECRET_FILE);
  const fromFile = existsSync(path) ? readFileSync(path, 'utf8').trim() : '';
  if (fromFile) return fromFile;
  throw new LiveRefusal(`Live checks are refused until you verify that you own the site: no ${SECRET_FILE} and no ${SECRET_ENV}.\n${setupHint(url)}`);
}

function equalHex(a: string, b: string): boolean {
  const x = Buffer.from(a.toLowerCase());
  const y = Buffer.from(b.toLowerCase());
  return x.length === y.length && timingSafeEqual(x, y);
}

type Check = { ok: true } | { ok: false; reason: string };

/** Looks for `shipcheck-site-verification=<value>` and compares the value with sha256(secret). */
function checkValue(text: string, secret: string, where: string): Check {
  const values = [...text.matchAll(/shipcheck-site-verification=\s*([^\s"]+)/g)].map((m) => m[1]!);
  if (!values.length) return { ok: false, reason: `${where} has no ${VERIFICATION_PREFIX} line` };
  const expected = hashSecret(secret);
  if (values.some((value) => equalHex(value, expected))) return { ok: true };
  if (values.some((value) => value === secret) || text.includes(secret)) {
    return { ok: false, reason: `${where} serves the raw secret instead of its sha256 hash. Anyone can read it there: run \`shipcheck live init --force\` to create a new secret and serve only the hash` };
  }
  return { ok: false, reason: `${where} does not match the sha256 of your secret` };
}

async function checkWellKnown(client: LiveClient, secret: string): Promise<Check> {
  let url = new URL(WELL_KNOWN_PATH, client.origin);
  for (let hop = 0; hop <= MAX_SAME_HOST_REDIRECTS; hop++) {
    let response;
    try {
      response = await client.request('GET', url.href);
    } catch (error) {
      if (error instanceof LiveRequestError) return { ok: false, reason: `${url.href} could not be fetched (${error.message})` };
      throw error;
    }
    if (response.status >= 300 && response.status < 400 && response.headers.location) {
      const next = new URL(response.headers.location, url);
      if (next.hostname !== client.origin.hostname) {
        return { ok: false, reason: `${url.href} redirects to another host (${next.host}); shipcheck does not follow cross-host redirects during verification` };
      }
      url = next;
      continue;
    }
    if (response.status !== 200) return { ok: false, reason: `${url.href} returned HTTP ${response.status}` };
    return checkValue(response.text, secret, url.href);
  }
  return { ok: false, reason: `${WELL_KNOWN_PATH} redirects more than ${MAX_SAME_HOST_REDIRECTS} times` };
}

async function checkDns(hostname: string, secret: string, resolveTxt: TxtResolver): Promise<Check> {
  const name = `_shipcheck.${hostname}`;
  let records: string[][];
  try {
    records = await resolveTxt(name);
  } catch {
    return { ok: false, reason: `no DNS TXT record at ${name}` };
  }
  return checkValue(records.map((chunks) => chunks.join('')).join('\n'), secret, `the DNS TXT record at ${name}`);
}

/**
 * Proves ownership before any check runs: the well-known file first (same-host redirects only), then the
 * DNS TXT record. Throws a LiveRefusal explaining both failures.
 */
export async function verifyOwnership(client: LiveClient, secret: string, options: { resolveTxt?: TxtResolver } = {}): Promise<{ method: 'well-known' | 'dns' }> {
  const wellKnown = await checkWellKnown(client, secret);
  if (wellKnown.ok) return { method: 'well-known' };
  const viaDns = await checkDns(client.origin.hostname, secret, options.resolveTxt ?? dnsTxtResolver);
  if (viaDns.ok) return { method: 'dns' };
  throw new LiveRefusal(`Could not verify that you own ${client.origin.hostname}, so no checks were run:\n  - ${wellKnown.reason}\n  - ${viaDns.reason}\n${setupHint(client.origin.href)}`);
}

import { promises as dns } from 'node:dns';
import { isIP } from 'node:net';
import { LiveRefusal } from './errors.js';

export interface ResolvedAddress {
  address: string;
  family: number;
}

/** Every address a hostname resolves to; injected in tests. */
export type HostResolver = (hostname: string) => Promise<ResolvedAddress[]>;

export const dnsResolver: HostResolver = (hostname) => dns.lookup(hostname, { all: true, verbatim: true });

/** Non-public IPv4 blocks: this network, private, CGNAT, loopback, link-local, IETF and documentation ranges, multicast and reserved. */
const V4_BLOCKS: readonly [string, number][] = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
];

function ipv4Value(ip: string): number | undefined {
  const parts = ip.split('.');
  if (parts.length !== 4 || !parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)) return undefined;
  return parts.reduce((value, part) => value * 256 + Number(part), 0);
}

function v4NonPublic(value: number): boolean {
  return V4_BLOCKS.some(([base, bits]) => {
    const size = 2 ** (32 - bits);
    const start = ipv4Value(base)!;
    return value >= start && value < start + size;
  });
}

/** The 8 groups of an IPv6 address, with an embedded dotted IPv4 tail converted. */
function ipv6Groups(ip: string): number[] | undefined {
  let text = ip.toLowerCase().replace(/%.*$/, '');
  const tail = text.slice(text.lastIndexOf(':') + 1);
  if (tail.includes('.')) {
    const v4 = ipv4Value(tail);
    if (v4 === undefined) return undefined;
    text = `${text.slice(0, text.lastIndexOf(':') + 1)}${Math.floor(v4 / 65536).toString(16)}:${(v4 % 65536).toString(16)}`;
  }
  const halves = text.split('::');
  if (halves.length > 2) return undefined;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const groups = halves.length === 2 ? [...head, ...Array<string>(8 - head.length - rest.length).fill('0'), ...rest] : head;
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return undefined;
  return groups.map((g) => Number.parseInt(g, 16));
}

/** Private, loopback, link-local, unique-local, multicast, documentation and other non-routable addresses. */
export function isNonPublicAddress(ip: string): boolean {
  const v4 = ipv4Value(ip);
  if (v4 !== undefined) return v4NonPublic(v4);
  const g = ipv6Groups(ip);
  if (!g) return true;
  const [g0, g1, g2, g3, g4, g5, g6, g7] = g as [number, number, number, number, number, number, number, number];
  const embeddedV4 = g6 * 65536 + g7;
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0) {
    // ::, ::1, IPv4-compatible and IPv4-mapped (::ffff:a.b.c.d)
    if (g5 === 0xffff) return v4NonPublic(embeddedV4);
    if (g5 === 0) return g6 === 0 || v4NonPublic(embeddedV4);
  }
  if (g0 === 0x64 && g1 === 0xff9b && !g2 && !g3 && !g4 && !g5) return v4NonPublic(embeddedV4); // NAT64
  if ((g0 & 0xfe00) === 0xfc00) return true; // unique local fc00::/7
  if ((g0 & 0xffc0) === 0xfe80) return true; // link-local fe80::/10
  if ((g0 & 0xff00) === 0xff00) return true; // multicast
  if (g0 === 0x2001 && g1 === 0x0db8) return true; // documentation
  return false;
}

/**
 * Resolves `hostname` and returns the address to connect to. IP literals are refused (ownership is
 * verified per hostname), and so is any hostname with a private, loopback or link-local address among
 * its records, unless `allowLocal` (SHIPCHECK_ALLOW_LOCAL=1, used only by tests) is set.
 */
export async function resolvePublicAddress(hostname: string, options: { resolve: HostResolver; allowLocal: boolean }): Promise<ResolvedAddress> {
  const host = hostname.replace(/^\[|\]$/g, '');
  const family = isIP(host);
  if (family) {
    if (!options.allowLocal) throw new LiveRefusal(`Refusing ${host}: IP address targets are not allowed. Use the site's hostname, whose ownership shipcheck can verify.`);
    return { address: host, family };
  }
  let addresses: ResolvedAddress[];
  try {
    addresses = await options.resolve(host);
  } catch {
    addresses = [];
  }
  if (!addresses.length) throw new LiveRefusal(`Refusing ${host}: the hostname could not be resolved.`);
  const internal = addresses.find((a) => isNonPublicAddress(a.address));
  if (internal && !options.allowLocal) {
    throw new LiveRefusal(`Refusing ${host}: it resolves to a private, loopback or link-local address (${internal.address}). shipcheck only probes public sites.`);
  }
  return addresses[0]!;
}

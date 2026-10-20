import { request as httpRequest, type IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import type { LookupFunction } from 'node:net';
import { isIP } from 'node:net';
import type { ResolvedAddress } from './guard.js';

/** Bodies are cut off here; every check only needs the start of a response. */
export const MAX_BODY_BYTES = 1_000_000;

export interface TransportRequest {
  method: 'GET' | 'HEAD' | 'POST';
  url: URL;
  headers: Record<string, string>;
  timeoutMs: number;
  /** The address the guard checked; the connection goes there and nowhere else. */
  address: ResolvedAddress;
}

export interface LiveResponse {
  url: string;
  status: number;
  /** Lower-case names; repeated headers joined with ", " (Set-Cookie is kept apart). */
  headers: Record<string, string>;
  setCookie: string[];
  body: Buffer;
  /** The body as UTF-8 text. */
  text: string;
}

export type Transport = (request: TransportRequest) => Promise<LiveResponse>;

function flattenHeaders(message: IncomingMessage): { headers: Record<string, string>; setCookie: string[] } {
  const headers: Record<string, string> = {};
  let setCookie: string[] = [];
  for (const [name, value] of Object.entries(message.headers)) {
    if (value === undefined) continue;
    if (name === 'set-cookie') setCookie = Array.isArray(value) ? value : [value];
    else headers[name] = Array.isArray(value) ? value.join(', ') : value;
  }
  return { headers, setCookie };
}

/**
 * node:http(s) with the connection pinned to the checked address (a DNS change between the check and
 * the connection cannot redirect it), no agent reuse, no proxy, no redirects and a capped body.
 */
export const nodeTransport: Transport = (request) =>
  new Promise<LiveResponse>((resolve, reject) => {
    const { address, family } = request.address;
    const lookup: LookupFunction = (_hostname, options, callback) => {
      if (options.all) callback(null, [{ address, family }]);
      else callback(null, address, family);
    };
    const send = request.url.protocol === 'https:' ? httpsRequest : httpRequest;
    const hostname = request.url.hostname.replace(/^\[|\]$/g, '');
    const req = send(
      {
        protocol: request.url.protocol,
        hostname,
        port: request.url.port || undefined,
        path: `${request.url.pathname}${request.url.search}`,
        method: request.method,
        headers: { ...request.headers, ...(request.method === 'POST' ? { 'content-length': '0' } : {}) },
        lookup,
        agent: false,
        signal: AbortSignal.timeout(request.timeoutMs),
        ...(request.url.protocol === 'https:' && !isIP(hostname) ? { servername: hostname } : {}),
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        const finish = () => {
          const body = Buffer.concat(chunks).subarray(0, MAX_BODY_BYTES);
          resolve({ url: request.url.href, status: res.statusCode ?? 0, ...flattenHeaders(res), body, text: body.toString('utf8') });
        };
        res.on('data', (chunk: Buffer) => {
          if (size >= MAX_BODY_BYTES) return;
          chunks.push(chunk);
          size += chunk.length;
          if (size >= MAX_BODY_BYTES) {
            res.destroy();
            finish();
          }
        });
        res.on('end', finish);
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    req.end();
  });

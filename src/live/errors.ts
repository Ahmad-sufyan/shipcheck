import { ShipcheckError } from '../core/errors.js';

/** shipcheck will not probe this target at all (unverified ownership, private address, bad config). Exit code 2. */
export class LiveRefusal extends ShipcheckError {
  override name = 'LiveRefusal';
}

/** The run stopped early (budget used up, repeated 5xx); checks that could not finish become skipped entries. */
export class LiveAbort extends Error {
  override name = 'LiveAbort';
}

/** One request failed at the network level (timeout, connection refused, TLS error). */
export class LiveRequestError extends Error {
  override name = 'LiveRequestError';
}

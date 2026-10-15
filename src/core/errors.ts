/** A user-facing error (bad path, bad config). The CLI prints its message and exits 2. */
export class ShipcheckError extends Error {
  override name = 'ShipcheckError';
}

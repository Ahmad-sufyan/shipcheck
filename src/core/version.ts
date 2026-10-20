import pkg from '../../package.json' with { type: 'json' };

export const VERSION: string = pkg.version;
export const REPOSITORY_URL = 'https://github.com/Ahmad-sufyan/shipcheck';
/** Sent with every live request so site owners can tell where the traffic comes from. */
export const USER_AGENT = `shipcheck/${VERSION} (+${REPOSITORY_URL})`;

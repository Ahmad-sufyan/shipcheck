import type { LiveCheck } from '../context.js';
import { live001 } from './live-001-headers.js';
import { live002 } from './live-002-https.js';
import { live003 } from './live-003-rate-limit.js';
import { live004 } from './live-004-protected.js';
import { live005 } from './live-005-sensitive-files.js';
import { live006 } from './live-006-cookies.js';

/**
 * In run order: the cheap checks that share GET / first, then per-path checks, and the rate-limit probe
 * last, so a small budget is spent where it tells the most.
 */
export const LIVE_CHECKS: readonly LiveCheck[] = [live001, live006, live002, live005, live004, live003];

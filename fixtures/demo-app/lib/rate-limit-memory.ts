const WINDOW_MS = 60_000
const LIMIT = 10
// shipcheck-expect: RATE-003
const requests = new Map<string, { count: number; resetAt: number }>()

/** Allows LIMIT requests per minute per client IP. */
export function checkRateLimit(request: Request): boolean {
  // shipcheck-expect: RATE-004
  const ip = request.headers.get('x-forwarded-for') ?? 'anonymous'
  const now = Date.now()
  const entry = requests.get(ip)
  if (!entry || entry.resetAt < now) {
    requests.set(ip, { count: 1, resetAt: now + WINDOW_MS })
    return true
  }
  entry.count += 1
  return entry.count <= LIMIT
}

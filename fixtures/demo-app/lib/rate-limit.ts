const hits = new Map<string, { count: number; resetAt: number }>()

/** Fixed-window limiter keyed by caller; returns false once `limit` requests arrive within `windowMs`. */
export function rateLimit(key: string, limit = 5, windowMs = 60_000): boolean {
  const now = Date.now()
  const entry = hits.get(key)
  if (!entry || entry.resetAt < now) {
    hits.set(key, { count: 1, resetAt: now + windowMs })
    return true
  }
  entry.count += 1
  return entry.count <= limit
}

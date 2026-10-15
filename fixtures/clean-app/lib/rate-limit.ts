import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

/** Shared across serverless instances: state lives in Redis, not in process memory. */
const ratelimit = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(5, '1 m'), prefix: 'acme' })

export async function rateLimit(key: string): Promise<boolean> {
  const { success } = await ratelimit.limit(key)
  return success
}

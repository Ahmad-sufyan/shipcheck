import { createHash, timingSafeEqual } from 'node:crypto'

export function hashPassword(password: string): string {
  // shipcheck-expect: AUTH-001
  return createHash('md5').update(password).digest('hex')
}

export function verifyPassword(password: string, storedHash: string): boolean {
  const candidate = Buffer.from(hashPassword(password), 'hex')
  const expected = Buffer.from(storedHash, 'hex')
  return candidate.length === expected.length && timingSafeEqual(candidate, expected)
}

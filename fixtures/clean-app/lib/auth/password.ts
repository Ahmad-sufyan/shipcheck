import { randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from 'node:crypto'

const KEY_LENGTH = 64
const COST: ScryptOptions = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }

function derive(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, KEY_LENGTH, COST, (error, key) => (error ? reject(error) : resolve(key)))
  })
}

/** Returns `salt:hash`, both hex encoded. */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16)
  const key = await derive(password, salt)
  return `${salt.toString('hex')}:${key.toString('hex')}`
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [saltHex, keyHex] = stored.split(':')
  if (!saltHex || !keyHex) return false
  const expected = Buffer.from(keyHex, 'hex')
  const candidate = await derive(password, Buffer.from(saltHex, 'hex'))
  return candidate.length === expected.length && timingSafeEqual(candidate, expected)
}

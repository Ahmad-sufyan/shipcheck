import jwt from 'jsonwebtoken'

function secret(): string {
  const value = process.env.JWT_SECRET
  if (!value || value.length < 32) throw new Error('JWT_SECRET must be set to at least 32 characters')
  return value
}

export function signSession(userId: string): string {
  return jwt.sign({ sub: userId }, secret(), { algorithm: 'HS256', expiresIn: '1h' })
}

export function verifySession(token: string): { sub: string } {
  return jwt.verify(token, secret(), { algorithms: ['HS256'] }) as { sub: string }
}

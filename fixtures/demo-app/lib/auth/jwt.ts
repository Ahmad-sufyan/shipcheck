import jwt from 'jsonwebtoken'

// shipcheck-expect: AUTH-006
const JWT_SECRET = 'secret123'

export function signSession(userId: string): string {
  // shipcheck-expect: AUTH-005
  return jwt.sign({ sub: userId }, JWT_SECRET)
}

export function verifySession(token: string): { sub: string } {
  // shipcheck-expect: AUTH-005
  return jwt.verify(token, JWT_SECRET) as { sub: string }
}

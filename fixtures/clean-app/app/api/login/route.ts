import { randomUUID } from 'node:crypto'
import { cookies } from 'next/headers'
import { NextResponse } from 'next/server'
import { z } from 'zod'
import { pool } from '@/lib/db'
import { verifyPassword } from '@/lib/auth/password'
import { rateLimit } from '@/lib/rate-limit'

const LoginSchema = z.object({ email: z.email(), password: z.string().min(1).max(200) })
const INVALID_CREDENTIALS = 'Invalid email or password'

export async function POST(request: Request) {
  const ip = request.headers.get('x-forwarded-for') ?? 'unknown'
  if (!rateLimit(`login:${ip}`, 5)) {
    return NextResponse.json({ error: 'Too many attempts, try again later' }, { status: 429 })
  }

  const parsed = LoginSchema.safeParse(await request.json())
  if (!parsed.success) {
    return NextResponse.json({ error: INVALID_CREDENTIALS }, { status: 401 })
  }
  const { email, password } = parsed.data

  const { rows } = await pool.query('select id, password_hash from users where email = $1', [email])
  const user = rows[0]
  const valid = user ? await verifyPassword(password, user.password_hash) : false
  if (!user || !valid) {
    return NextResponse.json({ error: INVALID_CREDENTIALS }, { status: 401 })
  }

  const sessionId = randomUUID()
  await pool.query('insert into sessions (id, user_id, expires_at) values ($1, $2, now() + interval \'8 hours\')', [sessionId, user.id])

  const cookieStore = await cookies()
  cookieStore.set('session', sessionId, { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 60 * 60 * 8 })

  return NextResponse.json({ ok: true })
}

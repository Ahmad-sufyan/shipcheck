import { randomUUID } from 'node:crypto'
import { cookies } from 'next/headers'
import { NextResponse } from 'next/server'
import { z } from 'zod'
import { pool } from '@/lib/db'
import { verifyPassword } from '@/lib/auth/password'

const LoginSchema = z.object({ email: z.email(), password: z.string().min(1) })

// shipcheck-expect: AUTH-002
export async function POST(request: Request) {
  const { email, password } = LoginSchema.parse(await request.json())

  const { rows } = await pool.query('select id, password_hash from users where email = $1', [email])
  const user = rows[0]
  if (!user) {
    // shipcheck-expect: AUTH-003
    return NextResponse.json({ error: 'No user with that email' }, { status: 401 })
  }
  if (!verifyPassword(password, user.password_hash)) {
    return NextResponse.json({ error: 'Wrong password' }, { status: 401 })
  }

  const sessionId = randomUUID()
  await pool.query('insert into sessions (id, user_id) values ($1, $2)', [sessionId, user.id])

  const cookieStore = await cookies()
  // shipcheck-expect: AUTH-004
  cookieStore.set('session', sessionId)

  return NextResponse.json({ ok: true })
}

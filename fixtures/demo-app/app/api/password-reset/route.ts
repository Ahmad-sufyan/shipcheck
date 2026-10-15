import { NextResponse } from 'next/server'
import { z } from 'zod'
import { pool } from '@/lib/db'
import { sendResetEmail } from '@/lib/email'
import { rateLimit } from '@/lib/rate-limit'

const ResetSchema = z.object({ email: z.email() })

export async function POST(request: Request) {
  const ip = request.headers.get('x-forwarded-for') ?? 'unknown'
  if (!rateLimit(`reset:${ip}`, 3)) {
    return NextResponse.json({ error: 'Too many requests' }, { status: 429 })
  }

  const { email } = ResetSchema.parse(await request.json())
  const { rows } = await pool.query('select id from users where email = $1', [email])
  if (rows.length === 0) {
    // shipcheck-expect: AUTH-011
    return NextResponse.json({ error: 'No account with that email' }, { status: 404 })
  }

  // shipcheck-expect: AUTH-010
  const token = Math.random().toString(36).slice(2)
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000)
  await pool.query('insert into password_resets (user_id, token, expires_at) values ($1, $2, $3)', [rows[0].id, token, expiresAt])
  await sendResetEmail(email, token)

  return NextResponse.json({ ok: true })
}

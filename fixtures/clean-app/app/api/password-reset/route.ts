import { createHash, randomBytes } from 'node:crypto'
import { NextResponse } from 'next/server'
import { z } from 'zod'
import { pool } from '@/lib/db'
import { sendResetEmail } from '@/lib/email'
import { rateLimit } from '@/lib/rate-limit'

const ResetSchema = z.object({ email: z.email() })
const GENERIC_RESPONSE = { message: 'If an account exists for that email, a reset link is on its way.' }

export async function POST(request: Request) {
  const ip = request.headers.get('x-forwarded-for') ?? 'unknown'
  if (!rateLimit(`reset:${ip}`, 3)) {
    return NextResponse.json({ error: 'Too many requests' }, { status: 429 })
  }

  const parsed = ResetSchema.safeParse(await request.json())
  if (!parsed.success) {
    return NextResponse.json(GENERIC_RESPONSE)
  }

  const { rows } = await pool.query('select id from users where email = $1', [parsed.data.email])
  if (rows.length > 0) {
    const token = randomBytes(32).toString('base64url')
    const tokenHash = createHash('sha256').update(token).digest('hex')
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000)
    await pool.query('insert into password_resets (user_id, token_hash, expires_at) values ($1, $2, $3)', [rows[0].id, tokenHash, expiresAt])
    await sendResetEmail(parsed.data.email, token)
  }

  return NextResponse.json(GENERIC_RESPONSE)
}

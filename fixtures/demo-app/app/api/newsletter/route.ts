import { NextResponse } from 'next/server'
import { z } from 'zod'
import { pool } from '@/lib/db'
import { checkRateLimit } from '@/lib/rate-limit-memory'

const NewsletterSchema = z.object({ email: z.email() })

export async function POST(request: Request) {
  if (!checkRateLimit(request)) {
    return NextResponse.json({ error: 'Too many requests' }, { status: 429 })
  }
  const { email } = NewsletterSchema.parse(await request.json())
  await pool.query('insert into newsletter_subscribers (email) values ($1) on conflict do nothing', [email])
  return NextResponse.json({ ok: true })
}

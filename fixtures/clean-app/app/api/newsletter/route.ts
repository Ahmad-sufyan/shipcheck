import { NextResponse } from 'next/server'
import { ipAddress } from '@vercel/functions'
import { z } from 'zod'
import { pool } from '@/lib/db'
import { rateLimit } from '@/lib/rate-limit'

const NewsletterSchema = z.object({ email: z.email() })

export async function POST(request: Request) {
  if (!(await rateLimit(`newsletter:${ipAddress(request) ?? 'unknown'}`))) {
    return NextResponse.json({ error: 'Too many requests' }, { status: 429 })
  }
  const parsed = NewsletterSchema.safeParse(await request.json())
  if (!parsed.success) {
    return NextResponse.json({ error: 'Invalid email' }, { status: 400 })
  }
  await pool.query('insert into newsletter_subscribers (email) values ($1) on conflict do nothing', [parsed.data.email])
  return NextResponse.json({ ok: true })
}

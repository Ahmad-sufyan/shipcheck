import { NextResponse } from 'next/server'
import { ipAddress } from '@vercel/functions'
import { z } from 'zod'
import { rateLimit } from '@/lib/rate-limit'
import { createClient } from '@/lib/supabase/server'

const SignupSchema = z.object({ email: z.email(), password: z.string().min(8).max(200) })

export async function POST(request: Request) {
  if (!(await rateLimit(`signup:${ipAddress(request) ?? 'unknown'}`))) {
    return NextResponse.json({ error: 'Too many requests' }, { status: 429 })
  }
  const parsed = SignupSchema.safeParse(await request.json())
  if (!parsed.success) {
    return NextResponse.json({ error: 'Invalid sign-up details' }, { status: 400 })
  }

  const supabase = await createClient()
  const { error } = await supabase.auth.signUp(parsed.data)
  if (error) {
    return NextResponse.json({ error: 'Could not create the account' }, { status: 400 })
  }
  return NextResponse.json({ ok: true })
}

import { NextResponse } from 'next/server'
import { z } from 'zod'
import { createClient } from '@/lib/supabase/server'

const SignupSchema = z.object({ email: z.email(), password: z.string().min(8).max(200) })

// shipcheck-expect: RATE-001
export async function POST(request: Request) {
  const input = SignupSchema.parse(await request.json())
  // shipcheck-expect: DATA-001
  console.log('New signup', { email: input.email, password: input.password })

  const supabase = await createClient()
  const { error } = await supabase.auth.signUp({ email: input.email, password: input.password })
  if (error) {
    return NextResponse.json({ error: 'Could not create the account' }, { status: 400 })
  }
  return NextResponse.json({ ok: true })
}

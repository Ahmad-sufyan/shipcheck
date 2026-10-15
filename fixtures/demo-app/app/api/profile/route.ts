import { NextResponse } from 'next/server'
import { z } from 'zod'
import { createClient } from '@/lib/supabase/server'

const ProfileSchema = z.object({ display_name: z.string().min(1).max(80) })

export async function GET() {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  const { data: profile } = await supabase.from('profiles').select('*').eq('id', user.id).single()
  // shipcheck-expect: DATA-002
  return NextResponse.json(profile)
}

// shipcheck-expect: HTTP-004
export async function POST(request: Request) {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  const input = ProfileSchema.parse(Object.fromEntries(await request.formData()))
  await supabase.from('profiles').update({ display_name: input.display_name }).eq('id', user.id)
  return NextResponse.redirect(new URL('/settings/profile', request.url), 303)
}

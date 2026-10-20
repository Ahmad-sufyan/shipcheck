import { NextResponse } from 'next/server'
import { z } from 'zod'
import { createClient } from '@/lib/supabase/server'

const ProfileSchema = z.object({ display_name: z.string().min(1).max(80) })

/** Form posts must come from our own origin (CSRF defence for cookie-authenticated requests). */
function isSameOrigin(request: Request): boolean {
  const origin = request.headers.get('origin')
  return origin !== null && origin === new URL(request.url).origin
}

export async function GET() {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  const { data: profile } = await supabase.from('profiles').select('id, display_name, avatar_url').eq('id', user.id).single()
  return NextResponse.json(profile)
}

export async function POST(request: Request) {
  if (!isSameOrigin(request)) {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  const parsed = ProfileSchema.safeParse(Object.fromEntries(await request.formData()))
  if (!parsed.success) {
    return NextResponse.json({ error: 'Invalid profile' }, { status: 400 })
  }
  await supabase.from('profiles').update({ display_name: parsed.data.display_name }).eq('id', user.id)
  return NextResponse.redirect(new URL('/settings/profile', request.url), 303)
}

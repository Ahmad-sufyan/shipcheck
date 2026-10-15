import { NextResponse } from 'next/server'
import { deepMerge } from '@/lib/merge'
import { createClient } from '@/lib/supabase/server'

export async function POST(request: Request) {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const body = await request.json()
  const { data: profile } = await supabase.from('profiles').select('settings').eq('id', user.id).single()
  // shipcheck-expect: INPUT-012
  const settings = deepMerge(profile?.settings ?? {}, body)
  await supabase.from('profiles').update({ settings }).eq('id', user.id)

  return NextResponse.json({ settings })
}

import { NextResponse } from 'next/server'
import { z } from 'zod'
import { deepMerge } from '@/lib/merge'
import { createClient } from '@/lib/supabase/server'

const SettingsSchema = z.strictObject({
  theme: z.enum(['light', 'dark', 'system']).optional(),
  notifications: z
    .strictObject({
      email: z.boolean().optional(),
      push: z.boolean().optional(),
    })
    .optional(),
})

export async function POST(request: Request) {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const parsed = SettingsSchema.safeParse(await request.json())
  if (!parsed.success) {
    return NextResponse.json({ error: 'Invalid settings' }, { status: 400 })
  }
  const { data: profile } = await supabase.from('profiles').select('settings').eq('id', user.id).single()
  const settings = deepMerge({ ...(profile?.settings ?? {}) }, parsed.data)
  await supabase.from('profiles').update({ settings }).eq('id', user.id)

  return NextResponse.json({ settings })
}

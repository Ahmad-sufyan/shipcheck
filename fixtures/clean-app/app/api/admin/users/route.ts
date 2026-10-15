import { NextResponse } from 'next/server'
import { z } from 'zod'
import { createClient } from '@/lib/supabase/server'

const CreateUserSchema = z.object({
  email: z.email(),
  displayName: z.string().min(1).max(80),
  role: z.enum(['member', 'admin']),
})

export async function POST(request: Request) {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  const { data: caller } = await supabase.from('profiles').select('role').eq('id', user.id).single()
  if (caller?.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  }

  const parsed = CreateUserSchema.safeParse(await request.json())
  if (!parsed.success) {
    return NextResponse.json({ error: 'Invalid input' }, { status: 400 })
  }
  const { email, displayName, role } = parsed.data
  const { data, error } = await supabase.from('users').insert({ email, display_name: displayName, role }).select('id, email').single()

  if (error) {
    return NextResponse.json({ error: 'Could not create user' }, { status: 400 })
  }
  return NextResponse.json(data, { status: 201 })
}

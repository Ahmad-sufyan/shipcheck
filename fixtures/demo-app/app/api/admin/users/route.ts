import { NextResponse } from 'next/server'
import { createClient } from '@/lib/supabase/server'

// shipcheck-expect: AUTHZ-001
export async function POST(request: Request) {
  // shipcheck-expect: INPUT-010
  const body = await request.json()
  const supabase = await createClient()
  // shipcheck-expect: AUTHZ-008
  const { data, error } = await supabase.from('users').insert(body).select().single()

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 400 })
  }
  return NextResponse.json(data, { status: 201 })
}

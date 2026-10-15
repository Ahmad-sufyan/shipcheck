import { cookies } from 'next/headers'
import { NextResponse } from 'next/server'
import { pool } from '@/lib/db'
import { createClient } from '@/lib/supabase/server'

export async function POST() {
  const supabase = await createClient()
  await supabase.auth.signOut()

  const cookieStore = await cookies()
  const sessionId = cookieStore.get('session')?.value
  if (sessionId) {
    await pool.query('delete from sessions where id = $1', [sessionId])
  }
  cookieStore.delete('session')
  return NextResponse.json({ ok: true })
}

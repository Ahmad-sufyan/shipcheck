import { NextResponse } from 'next/server'
import { pool } from '@/lib/db'
import { createClient } from '@/lib/supabase/server'

export async function GET() {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  try {
    const { rows } = await pool.query('select id, total_cents, status, created_at from orders where user_id = $1', [user.id])
    return NextResponse.json(rows)
  } catch (error) {
    // shipcheck-expect: HTTP-005
    return NextResponse.json({ error: (error as Error).message }, { status: 500 })
  }
}

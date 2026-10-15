import { NextResponse } from 'next/server'
import { pool } from '@/lib/db'

// shipcheck-expect: INTEG-002
export async function GET() {
  const { rowCount } = await pool.query('delete from sessions where expires_at < now()')
  return NextResponse.json({ deleted: rowCount })
}

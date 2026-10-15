import { NextResponse, type NextRequest } from 'next/server'
import { pool } from '@/lib/db'

export async function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.get('q') ?? ''
  // shipcheck-expect: INPUT-001
  const { rows } = await pool.query(`select id, title from posts where title ilike '%${q}%' order by created_at desc limit 20`)
  return NextResponse.json(rows)
}

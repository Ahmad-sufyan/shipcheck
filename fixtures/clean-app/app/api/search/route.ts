import { NextResponse, type NextRequest } from 'next/server'
import { pool } from '@/lib/db'

export async function GET(request: NextRequest) {
  const q = (request.nextUrl.searchParams.get('q') ?? '').slice(0, 100)
  const pattern = `%${q}%`
  const { rows } = await pool.query('select id, title from posts where title ilike $1 order by created_at desc limit 20', [pattern])
  return NextResponse.json(rows)
}

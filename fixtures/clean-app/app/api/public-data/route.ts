import { NextResponse, type NextRequest } from 'next/server'
import { pool } from '@/lib/db'

const ALLOWED_ORIGINS = new Set(['https://acme.example', 'https://www.acme.example'])

export async function GET(request: NextRequest) {
  const origin = request.headers.get('origin')
  const headers: Record<string, string> = { Vary: 'Origin' }
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers['Access-Control-Allow-Origin'] = origin
  }
  const { rows } = await pool.query('select id, title, published_at from posts where published = true order by published_at desc limit 20')
  return NextResponse.json(rows, { headers })
}

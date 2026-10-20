import { NextResponse, type NextRequest } from 'next/server'
import { pool } from '@/lib/db'

export async function GET(request: NextRequest) {
  const origin = request.headers.get('origin') ?? '*'
  const { rows } = await pool.query('select id, title, published_at from posts where published = true order by published_at desc limit 20')
  return NextResponse.json(rows, {
    headers: {
      // shipcheck-expect: HTTP-003
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Credentials': 'true',
    },
  })
}

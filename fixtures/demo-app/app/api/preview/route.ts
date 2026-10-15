import { NextResponse, type NextRequest } from 'next/server'

export async function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl
  // shipcheck-expect: INPUT-007
  const response = await fetch(searchParams.get('url')!)
  const html = await response.text()
  const title = /<title>([^<]*)<\/title>/i.exec(html)?.[1] ?? null
  return NextResponse.json({ title })
}

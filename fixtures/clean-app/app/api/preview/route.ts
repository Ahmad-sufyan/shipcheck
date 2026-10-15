import { NextResponse, type NextRequest } from 'next/server'

const ALLOWED_HOSTS = new Set(['example.com', 'docs.example.com', 'blog.example.com'])

export async function GET(request: NextRequest) {
  let target: URL
  try {
    target = new URL(request.nextUrl.searchParams.get('url') ?? '')
  } catch {
    return NextResponse.json({ error: 'Invalid URL' }, { status: 400 })
  }
  if (target.protocol !== 'https:' || !ALLOWED_HOSTS.has(target.hostname)) {
    return NextResponse.json({ error: 'Host not allowed' }, { status: 400 })
  }

  const response = await fetch(target, { redirect: 'error', signal: AbortSignal.timeout(5000) })
  const html = await response.text()
  const title = /<title>([^<]*)<\/title>/i.exec(html)?.[1] ?? null
  return NextResponse.json({ title })
}

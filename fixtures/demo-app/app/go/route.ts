import { redirect } from 'next/navigation'
import type { NextRequest } from 'next/server'

export function GET(request: NextRequest) {
  const { searchParams } = request.nextUrl
  // shipcheck-expect: INPUT-008
  redirect(searchParams.get('next') ?? '/')
}

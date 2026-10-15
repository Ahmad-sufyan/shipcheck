import { redirect } from 'next/navigation'
import type { NextRequest } from 'next/server'

const DESTINATIONS: Record<string, string> = {
  dashboard: '/dashboard',
  billing: '/dashboard/billing',
  docs: 'https://docs.example.com',
}

export function GET(request: NextRequest) {
  const key = request.nextUrl.searchParams.get('to') ?? 'dashboard'
  redirect(DESTINATIONS[key] ?? '/dashboard')
}

'use client'

// The session lives in an httpOnly cookie managed by Supabase; the browser only keeps a short-lived
// copy of the access token in memory for direct API calls, never in localStorage.
let accessToken: string | null = null

export function saveSession(token: string) {
  accessToken = token
}

export function getSessionToken(): string | null {
  return accessToken
}

export function clearSession() {
  accessToken = null
}

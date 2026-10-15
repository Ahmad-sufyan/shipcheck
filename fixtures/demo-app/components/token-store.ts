'use client'

export function saveSession(token: string) {
  // shipcheck-expect: AUTH-007
  localStorage.setItem('access_token', token)
}

export function getSessionToken(): string | null {
  return localStorage.getItem('access_token')
}

export function clearSession() {
  localStorage.removeItem('access_token')
}

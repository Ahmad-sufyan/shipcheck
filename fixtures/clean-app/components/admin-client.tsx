'use client'

import { useState, type FormEvent } from 'react'

/** Invites a user through the server API, which checks the caller's role; no privileged keys in the browser. */
export function InviteUserForm() {
  const [status, setStatus] = useState<'idle' | 'sent' | 'error'>('idle')

  async function invite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const response = await fetch('/api/admin/users', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: form.get('email'), displayName: form.get('displayName'), role: 'member' }),
    })
    setStatus(response.ok ? 'sent' : 'error')
  }

  return (
    <form onSubmit={invite}>
      <input name="email" type="email" required />
      <input name="displayName" required />
      <button type="submit">Invite</button>
      {status === 'sent' && <p>Invitation sent.</p>}
      {status === 'error' && <p>Could not send the invitation.</p>}
    </form>
  )
}

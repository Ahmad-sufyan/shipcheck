'use client'

import { useEffect, useState } from 'react'

type Stats = { users: number; revenueCents: number }

/** Renders admin stats when the server says the caller may see them; the API enforces the role. */
export function AdminPanel() {
  const [stats, setStats] = useState<Stats | null>(null)

  useEffect(() => {
    fetch('/api/admin/stats')
      .then((response) => (response.ok ? response.json() : null))
      .then(setStats)
  }, [])

  if (!stats) return null
  return (
    <section>
      <h2>Admin</h2>
      <p>
        {stats.users} users, ${(stats.revenueCents / 100).toFixed(2)} revenue
      </p>
    </section>
  )
}

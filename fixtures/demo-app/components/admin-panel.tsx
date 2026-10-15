'use client'

import { useEffect, useState } from 'react'

type Stats = { users: number; revenueCents: number }

export function AdminPanel({ role }: { role: string }) {
  const [stats, setStats] = useState<Stats | null>(null)
  // shipcheck-expect: AUTHZ-004
  const isAdmin = role === 'admin'

  useEffect(() => {
    if (!isAdmin) return
    fetch('/api/admin/stats')
      .then((response) => response.json())
      .then(setStats)
  }, [isAdmin])

  if (!isAdmin) return null
  return (
    <section>
      <h2>Admin</h2>
      {stats ? (
        <p>
          {stats.users} users, ${(stats.revenueCents / 100).toFixed(2)} revenue
        </p>
      ) : (
        <p>Loading...</p>
      )}
    </section>
  )
}

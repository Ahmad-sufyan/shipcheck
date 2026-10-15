'use client'

import { useState } from 'react'
import { createClient } from '@supabase/supabase-js'

// shipcheck-expect: AUTHZ-007
const supabaseAdmin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!)

export function BanUserButton({ userId }: { userId: string }) {
  const [banned, setBanned] = useState(false)

  async function ban() {
    await supabaseAdmin.auth.admin.updateUserById(userId, { ban_duration: '876000h' })
    setBanned(true)
  }

  return (
    <button onClick={ban} disabled={banned}>
      {banned ? 'Banned' : 'Ban user'}
    </button>
  )
}

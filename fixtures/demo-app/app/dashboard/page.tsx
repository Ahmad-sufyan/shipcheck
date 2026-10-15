import { redirect } from 'next/navigation'
import { createClient } from '@/lib/supabase/server'
import { AdminPanel } from '@/components/admin-panel'

export default async function DashboardPage() {
  const supabase = await createClient()
  const {
    data: { user },
  } = await supabase.auth.getUser()
  if (!user) redirect('/login')

  const { data: profile } = await supabase.from('profiles').select('display_name, role').eq('id', user.id).single()

  return (
    <main>
      <h1>Welcome back, {profile?.display_name ?? user.email}</h1>
      <AdminPanel role={profile?.role ?? 'member'} />
    </main>
  )
}

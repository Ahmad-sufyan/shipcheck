import Link from 'next/link'

export default function HomePage() {
  return (
    <main>
      <h1>Acme Invoices</h1>
      <Link href="/dashboard">Go to your dashboard</Link>
    </main>
  )
}

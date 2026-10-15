import { Turnstile } from '@marsidev/react-turnstile'

export default function ContactPage() {
  return (
    <main>
      <h1>Contact us</h1>
      <form action="/api/contact" method="post">
        <input name="name" required />
        <input name="email" type="email" required />
        <textarea name="message" required />
        <Turnstile siteKey={process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY!} />
        <button type="submit">Send</button>
      </form>
    </main>
  )
}

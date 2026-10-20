export default function ContactPage() {
  return (
    <main>
      <h1>Contact us</h1>
      {/* shipcheck-expect: RATE-005 */}
      <form action="/api/contact" method="post">
        <input name="name" required />
        <input name="email" type="email" required />
        <textarea name="message" required />
        <button type="submit">Send</button>
      </form>
    </main>
  )
}

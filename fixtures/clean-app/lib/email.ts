export async function sendResetEmail(email: string, token: string): Promise<void> {
  const link = `${process.env.NEXT_PUBLIC_SITE_URL}/reset-password?token=${encodeURIComponent(token)}`
  await fetch('https://api.mail.example/send', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ to: email, subject: 'Reset your password', text: `Reset your password: ${link}` }),
  })
}

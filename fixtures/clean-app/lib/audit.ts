import 'server-only'
import { pool } from '@/lib/db'

export type AuditAction = 'login' | 'login_failed' | 'logout' | 'password_reset_requested'

/** Append-only record of authentication events for incident response. */
export async function recordAuditEvent(event: { action: AuditAction; userId: string | null; ip: string }): Promise<void> {
  await pool.query('insert into audit_log (action, user_id, ip) values ($1, $2, $3)', [event.action, event.userId, event.ip])
}

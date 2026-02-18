import type { Session, Middleware } from '@stravigor/http'
import JinaManager from '../jina_manager.ts'

/**
 * Require the user to have confirmed their password recently.
 * Returns 423 (Locked) if the confirmation has expired.
 *
 * @example
 * router.delete('/account', auth(), confirmed(), deleteAccountHandler)
 */
export function confirmed(): Middleware {
  return (ctx, next) => {
    const session = ctx.get<Session>('session')
    const confirmedAt = session.get<number>('_jina_confirmed_at')

    if (!confirmedAt) {
      return ctx.json({ message: 'Password confirmation required.' }, 423)
    }

    const timeout = JinaManager.config.confirmation.timeout * 1000
    if (Date.now() - confirmedAt > timeout) {
      return ctx.json({ message: 'Password confirmation has expired.' }, 423)
    }

    return next()
  }
}

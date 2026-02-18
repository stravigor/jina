import type { Session, Middleware } from '@stravigor/http'
import JinaManager from '../jina_manager.ts'

/**
 * Require a completed two-factor challenge for the current session.
 * Returns 403 if the user has 2FA enabled but hasn't completed the challenge.
 *
 * Useful for protecting sensitive routes beyond the initial login.
 *
 * @example
 * router.post('/transfer', auth(), twoFactorChallenge(), transferHandler)
 */
export function twoFactorChallenge(): Middleware {
  return (ctx, next) => {
    const user = ctx.get('user')
    const actions = JinaManager.actions

    // If 2FA is not enabled for this user, let them through
    if (!actions.twoFactorSecretOf) return next()
    const secret = actions.twoFactorSecretOf(user)
    if (!secret) return next()

    // Check if there's still a pending 2FA challenge in the session
    const session = ctx.get<Session>('session')
    if (session.has('_jina_2fa_email')) {
      return ctx.json({ message: 'Two-factor authentication required.' }, 403)
    }

    return next()
  }
}

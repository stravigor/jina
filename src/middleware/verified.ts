import type { Middleware } from '@stravigor/http'
import JinaManager from '../jina_manager.ts'

/**
 * Require the authenticated user to have a verified email address.
 * Returns 403 if the email is not verified.
 *
 * @example
 * router.group({ middleware: [auth(), verified()] }, r => {
 *   r.get('/dashboard', dashboardHandler)
 * })
 */
export function verified(): Middleware {
  return (ctx, next) => {
    const user = ctx.get('user')
    const actions = JinaManager.actions

    if (!actions.isEmailVerified!(user)) {
      return ctx.json({ message: 'Email not verified.' }, 403)
    }

    return next()
  }
}

import { Emitter } from '@stravigor/kernel'
import type { Context } from '@stravigor/http'
import JinaManager from '../jina_manager.ts'
import { verifySignedToken } from '../tokens.ts'
import { JinaEvents } from '../types.ts'

export async function resetPasswordHandler(ctx: Context): Promise<Response> {
  const body = await ctx.body<{
    token?: string
    password?: string
    password_confirmation?: string
  }>()

  // Validate input
  if (!body.token) {
    return ctx.json({ message: 'Token is required.' }, 422)
  }
  if (!body.password || body.password.length < 8) {
    return ctx.json({ message: 'Password must be at least 8 characters.' }, 422)
  }
  if (body.password !== body.password_confirmation) {
    return ctx.json({ message: 'Passwords do not match.' }, 422)
  }

  // Verify token
  let payload: { sub: string | number; typ: string; email: string }
  try {
    payload = verifySignedToken(body.token)
  } catch {
    return ctx.json({ message: 'Invalid or expired reset token.' }, 422)
  }

  if (payload.typ !== 'password-reset') {
    return ctx.json({ message: 'Invalid token type.' }, 422)
  }

  // Find user
  const user = await JinaManager.actions.findById(payload.sub)
  if (!user) {
    return ctx.json({ message: 'Invalid or expired reset token.' }, 422)
  }

  // Verify the email still matches (prevents token reuse after email change)
  if (JinaManager.actions.emailOf(user) !== payload.email) {
    return ctx.json({ message: 'Invalid or expired reset token.' }, 422)
  }

  // Update password
  await JinaManager.actions.updatePassword(user, body.password)

  if (Emitter.listenerCount(JinaEvents.PASSWORD_RESET) > 0) {
    Emitter.emit(JinaEvents.PASSWORD_RESET, { user, ctx }).catch(() => {})
  }

  return ctx.json({ message: 'Password has been reset.' })
}

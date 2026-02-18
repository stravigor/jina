import { encrypt, Emitter } from '@stravigor/kernel'
import type { Context } from '@stravigor/http'
import JinaManager from '../jina_manager.ts'
import { JinaEvents } from '../types.ts'

export async function updatePasswordHandler(ctx: Context): Promise<Response> {
  const body = await ctx.body<{
    current_password?: string
    password?: string
    password_confirmation?: string
  }>()

  // Validate
  if (!body.current_password) {
    return ctx.json({ message: 'Current password is required.' }, 422)
  }
  if (!body.password || body.password.length < 8) {
    return ctx.json({ message: 'New password must be at least 8 characters.' }, 422)
  }
  if (body.password !== body.password_confirmation) {
    return ctx.json({ message: 'Passwords do not match.' }, 422)
  }

  const user = ctx.get('user')
  const hash = JinaManager.actions.passwordHashOf(user)
  const valid = await encrypt.verify(body.current_password, hash)

  if (!valid) {
    return ctx.json({ message: 'Current password is incorrect.' }, 422)
  }

  await JinaManager.actions.updatePassword(user, body.password)

  if (Emitter.listenerCount(JinaEvents.PASSWORD_UPDATED) > 0) {
    Emitter.emit(JinaEvents.PASSWORD_UPDATED, { user, ctx }).catch(() => {})
  }

  return ctx.json({ message: 'Password updated.' })
}

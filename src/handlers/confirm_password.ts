import { encrypt, Emitter } from '@stravigor/kernel'
import type { Context, Session } from '@stravigor/http'
import JinaManager from '../jina_manager.ts'
import { JinaEvents } from '../types.ts'

export async function confirmPasswordHandler(ctx: Context): Promise<Response> {
  const body = await ctx.body<{ password?: string }>()

  if (!body.password) {
    return ctx.json({ message: 'Password is required.' }, 422)
  }

  const user = ctx.get('user')
  const hash = JinaManager.actions.passwordHashOf(user)
  const valid = await encrypt.verify(body.password, hash)

  if (!valid) {
    return ctx.json({ message: 'Invalid password.' }, 422)
  }

  // Store confirmation timestamp in session
  const session = ctx.get<Session>('session')
  session.set('_jina_confirmed_at', Date.now())

  if (Emitter.listenerCount(JinaEvents.PASSWORD_CONFIRMED) > 0) {
    Emitter.emit(JinaEvents.PASSWORD_CONFIRMED, { user, ctx }).catch(() => {})
  }

  return ctx.json({ message: 'Password confirmed.' })
}

import { Emitter } from '@stravigor/kernel'
import { Session } from '@stravigor/http'
import type { Context } from '@stravigor/http'
import JinaManager from '../jina_manager.ts'
import { JinaEvents } from '../types.ts'

export async function logoutHandler(ctx: Context): Promise<Response> {
  const user = ctx.get('user')

  if (Emitter.listenerCount(JinaEvents.LOGOUT) > 0) {
    Emitter.emit(JinaEvents.LOGOUT, { user, ctx }).catch(() => {})
  }

  if (JinaManager.config.mode === 'session') {
    const response = ctx.json({ message: 'Logged out.' })
    return Session.destroy(ctx, response)
  }

  // Token mode: the client should discard the token.
  // Optionally we could revoke the token here, but the auth middleware
  // already attaches the accessToken to the context.
  return ctx.json({ message: 'Logged out.' })
}

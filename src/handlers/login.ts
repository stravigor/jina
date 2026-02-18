import { encrypt, Emitter } from '@stravigor/kernel'
import { AccessToken } from '@stravigor/http'
import type { Context, Session } from '@stravigor/http'
import JinaManager from '../jina_manager.ts'
import { JinaEvents } from '../types.ts'

export async function loginHandler(ctx: Context): Promise<Response> {
  const body = await ctx.body<{ email?: string; password?: string }>()
  const { email, password } = body

  // Validate
  if (!email || !password) {
    return ctx.json({ message: 'Email and password are required.' }, 422)
  }

  // Find user
  const user = await JinaManager.actions.findByEmail(email)
  if (!user) {
    return ctx.json({ message: 'Invalid credentials.' }, 401)
  }

  // Verify password
  const hash = JinaManager.actions.passwordHashOf(user)
  const valid = await encrypt.verify(password, hash)
  if (!valid) {
    return ctx.json({ message: 'Invalid credentials.' }, 401)
  }

  // Two-factor challenge
  if (JinaManager.hasFeature('two-factor') && JinaManager.actions.twoFactorSecretOf) {
    const secret = JinaManager.actions.twoFactorSecretOf(user)
    if (secret) {
      // Store the user email in session for the challenge step
      const session = ctx.get<Session>('session')
      session.set('_jina_2fa_email', email)
      return ctx.json({ two_factor: true })
    }
  }

  return completeLogin(ctx, user)
}

/** Finalize login — authenticate session or issue token. */
export async function completeLogin(ctx: Context, user: unknown): Promise<Response> {
  const config = JinaManager.config

  if (config.mode === 'session') {
    const session = ctx.get<Session>('session')
    session.authenticate(user)
    await session.regenerate()
  }

  if (Emitter.listenerCount(JinaEvents.LOGIN) > 0) {
    Emitter.emit(JinaEvents.LOGIN, { user, ctx }).catch(() => {})
  }

  if (config.mode === 'token') {
    const { token, accessToken } = await AccessToken.create(user, 'login')
    return ctx.json({ user, token, accessToken })
  }

  return ctx.json({ user })
}

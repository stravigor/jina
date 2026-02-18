import { Emitter } from '@stravigor/kernel'
import { AccessToken } from '@stravigor/http'
import type { Context, Session } from '@stravigor/http'
import JinaManager from '../jina_manager.ts'
import { ValidationError } from '../errors.ts'
import { JinaEvents } from '../types.ts'
import { sendVerificationEmail } from './verify_email.ts'

export async function registerHandler(ctx: Context): Promise<Response> {
  const body = await ctx.body<Record<string, unknown>>()
  const { name, email, password, password_confirmation } = body as {
    name?: string
    email?: string
    password?: string
    password_confirmation?: string
  }

  // Validate
  const errors: Record<string, string> = {}
  if (!name || typeof name !== 'string') errors.name = 'Name is required.'
  if (!email || typeof email !== 'string') errors.email = 'Email is required.'
  if (!password || typeof password !== 'string') errors.password = 'Password is required.'
  else if (password.length < 8) errors.password = 'Password must be at least 8 characters.'
  if (password !== password_confirmation) errors.password_confirmation = 'Passwords do not match.'

  if (Object.keys(errors).length > 0) {
    return ctx.json({ message: 'Validation failed.', errors }, 422)
  }

  // Check if email is already taken
  const existing = await JinaManager.actions.findByEmail(email!)
  if (existing) {
    return ctx.json(
      { message: 'Validation failed.', errors: { email: 'Email already taken.' } },
      422
    )
  }

  // Create user
  const user = await JinaManager.actions.createUser({
    name: name!,
    email: email!,
    password: password!,
    ...body,
  })

  const config = JinaManager.config

  // Authenticate
  if (config.mode === 'session') {
    const session = ctx.get<Session>('session')
    session.authenticate(user)
    await session.regenerate()
  }

  // Emit
  if (Emitter.listenerCount(JinaEvents.REGISTERED) > 0) {
    Emitter.emit(JinaEvents.REGISTERED, { user, ctx }).catch(() => {})
  }

  // Auto-send verification email if feature enabled
  if (JinaManager.hasFeature('email-verification')) {
    sendVerificationEmail(user).catch(() => {})
  }

  if (config.mode === 'token') {
    const { token, accessToken } = await AccessToken.create(user, 'registration')
    return ctx.json({ user, token, accessToken }, 201)
  }

  return ctx.json({ user }, 201)
}

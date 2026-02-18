import { Emitter } from '@stravigor/kernel'
import { mail } from '@stravigor/signal'
import { extractUserId } from '@stravigor/database'
import type { Context } from '@stravigor/http'
import JinaManager from '../jina_manager.ts'
import { createSignedToken, verifySignedToken } from '../tokens.ts'
import { JinaEvents } from '../types.ts'

/** Send a verification email for the given user. */
export async function sendVerificationEmail(user: unknown): Promise<void> {
  const config = JinaManager.config
  const actions = JinaManager.actions
  const userId = extractUserId(user)
  const email = actions.emailOf(user)

  const token = createSignedToken(
    { sub: userId, typ: 'email-verify', email },
    config.verification.expiration
  )

  const verifyUrl = `${config.prefix}/email/verify/${encodeURIComponent(token)}`

  await mail
    .to(email)
    .subject('Verify Your Email')
    .template('jina.verify-email', { verifyUrl, expiration: config.verification.expiration })
    .send()
}

/** POST /email/send — resend verification email. */
export async function sendVerificationHandler(ctx: Context): Promise<Response> {
  const user = ctx.get('user')
  const actions = JinaManager.actions

  if (actions.isEmailVerified!(user)) {
    return ctx.json({ message: 'Email already verified.' })
  }

  await sendVerificationEmail(user)
  return ctx.json({ message: 'Verification email sent.' })
}

/** GET /email/verify/:token — verify the email. */
export async function verifyEmailHandler(ctx: Context): Promise<Response> {
  const token = ctx.params.token as string | undefined
  if (!token) {
    return ctx.json({ message: 'Invalid verification link.' }, 422)
  }

  let payload: { sub: string | number; typ: string; email: string }
  try {
    payload = verifySignedToken(token)
  } catch {
    return ctx.json({ message: 'Invalid or expired verification link.' }, 422)
  }

  if (payload.typ !== 'email-verify') {
    return ctx.json({ message: 'Invalid token type.' }, 422)
  }

  const user = await JinaManager.actions.findById(payload.sub)
  if (!user) {
    return ctx.json({ message: 'Invalid verification link.' }, 422)
  }

  // Verify the email still matches
  if (JinaManager.actions.emailOf(user) !== payload.email) {
    return ctx.json({ message: 'Invalid verification link.' }, 422)
  }

  const actions = JinaManager.actions

  if (actions.isEmailVerified!(user)) {
    return ctx.json({ message: 'Email already verified.' })
  }

  await actions.markEmailVerified!(user)

  if (Emitter.listenerCount(JinaEvents.EMAIL_VERIFIED) > 0) {
    Emitter.emit(JinaEvents.EMAIL_VERIFIED, { user, ctx }).catch(() => {})
  }

  return ctx.json({ message: 'Email verified.' })
}

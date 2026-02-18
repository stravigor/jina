import { mail } from '@stravigor/signal'
import { extractUserId } from '@stravigor/database'
import type { Context } from '@stravigor/http'
import JinaManager from '../jina_manager.ts'
import { createSignedToken } from '../tokens.ts'

export async function forgotPasswordHandler(ctx: Context): Promise<Response> {
  const body = await ctx.body<{ email?: string }>()

  if (!body.email) {
    return ctx.json({ message: 'Email is required.' }, 422)
  }

  // Always return success to prevent email enumeration
  const user = await JinaManager.actions.findByEmail(body.email)

  if (user) {
    const config = JinaManager.config
    const userId = extractUserId(user)
    const email = JinaManager.actions.emailOf(user)

    const token = createSignedToken(
      { sub: userId, typ: 'password-reset', email },
      config.passwords.expiration
    )

    const resetUrl = `${ctx.url.origin}${config.prefix}/reset-password?token=${encodeURIComponent(token)}`

    await mail
      .to(email)
      .subject('Reset Your Password')
      .template('jina.reset-password', { resetUrl, expiration: config.passwords.expiration })
      .send()
  }

  return ctx.json({ message: 'If an account exists, a reset link has been sent.' })
}

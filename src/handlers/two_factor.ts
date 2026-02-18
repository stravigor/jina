import { Emitter } from '@stravigor/kernel'
import type { Context, Session } from '@stravigor/http'
import JinaManager from '../jina_manager.ts'
import { JinaEvents } from '../types.ts'
import {
  generateSecret,
  totpUri,
  verifyTotp,
  base32Decode,
  generateRecoveryCodes,
} from '../totp.ts'
import { completeLogin } from './login.ts'

// ---------------------------------------------------------------------------
// POST /two-factor/enable — generate a TOTP secret
// ---------------------------------------------------------------------------

export async function enableTwoFactorHandler(ctx: Context): Promise<Response> {
  const user = ctx.get('user')
  const actions = JinaManager.actions
  const config = JinaManager.config.twoFactor

  // Don't allow re-enabling if already confirmed
  const existingSecret = actions.twoFactorSecretOf!(user)
  if (existingSecret) {
    return ctx.json({ message: 'Two-factor authentication is already enabled.' }, 409)
  }

  const { base32 } = generateSecret()
  const email = actions.emailOf(user)

  const uri = totpUri({
    secret: base32,
    issuer: config.issuer,
    account: email,
    digits: config.digits,
    period: config.period,
  })

  // Store the unconfirmed secret in the session (not persisted to user yet)
  const session = ctx.get<Session>('session')
  session.set('_jina_2fa_secret', base32)

  return ctx.json({ secret: base32, qr_uri: uri })
}

// ---------------------------------------------------------------------------
// POST /two-factor/confirm — confirm 2FA setup with a valid code
// ---------------------------------------------------------------------------

export async function confirmTwoFactorHandler(ctx: Context): Promise<Response> {
  const body = await ctx.body<{ code?: string }>()
  if (!body.code) {
    return ctx.json({ message: 'Verification code is required.' }, 422)
  }

  const user = ctx.get('user')
  const actions = JinaManager.actions
  const config = JinaManager.config.twoFactor

  const session = ctx.get<Session>('session')
  const pendingSecret = session.get<string>('_jina_2fa_secret')
  if (!pendingSecret) {
    return ctx.json({ message: 'No pending two-factor setup. Call enable first.' }, 422)
  }

  // Verify the code against the pending secret
  const secretBytes = base32Decode(pendingSecret)
  const valid = await verifyTotp(secretBytes, body.code, {
    digits: config.digits,
    period: config.period,
  })

  if (!valid) {
    return ctx.json({ message: 'Invalid verification code.' }, 422)
  }

  // Persist the secret to the user
  await actions.setTwoFactorSecret!(user, pendingSecret)

  // Generate recovery codes
  const codes = generateRecoveryCodes(config.recoveryCodes)
  await actions.setRecoveryCodes!(user, codes)

  // Clean up session
  session.forget('_jina_2fa_secret')

  if (Emitter.listenerCount(JinaEvents.TWO_FACTOR_ENABLED) > 0) {
    Emitter.emit(JinaEvents.TWO_FACTOR_ENABLED, { user, ctx }).catch(() => {})
  }

  return ctx.json({ message: 'Two-factor authentication enabled.', recovery_codes: codes })
}

// ---------------------------------------------------------------------------
// DELETE /two-factor — disable 2FA
// ---------------------------------------------------------------------------

export async function disableTwoFactorHandler(ctx: Context): Promise<Response> {
  const user = ctx.get('user')
  const actions = JinaManager.actions

  await actions.setTwoFactorSecret!(user, null)
  await actions.setRecoveryCodes!(user, [])

  if (Emitter.listenerCount(JinaEvents.TWO_FACTOR_DISABLED) > 0) {
    Emitter.emit(JinaEvents.TWO_FACTOR_DISABLED, { user, ctx }).catch(() => {})
  }

  return ctx.json({ message: 'Two-factor authentication disabled.' })
}

// ---------------------------------------------------------------------------
// POST /two-factor/challenge — verify TOTP code during login
// ---------------------------------------------------------------------------

export async function twoFactorChallengeHandler(ctx: Context): Promise<Response> {
  const body = await ctx.body<{ code?: string; recovery_code?: string }>()
  const session = ctx.get<Session>('session')
  const actions = JinaManager.actions
  const config = JinaManager.config.twoFactor

  // Retrieve the pending login email from the session
  const pendingEmail = session.get<string>('_jina_2fa_email')
  if (!pendingEmail) {
    return ctx.json({ message: 'No pending two-factor challenge.' }, 422)
  }

  const user = await actions.findByEmail(pendingEmail)
  if (!user) {
    return ctx.json({ message: 'Invalid challenge.' }, 422)
  }

  const secret = actions.twoFactorSecretOf!(user)
  if (!secret) {
    return ctx.json({ message: 'Two-factor authentication is not enabled.' }, 422)
  }

  // Try TOTP code first
  if (body.code) {
    const secretBytes = base32Decode(secret)
    const valid = await verifyTotp(secretBytes, body.code, {
      digits: config.digits,
      period: config.period,
    })

    if (!valid) {
      return ctx.json({ message: 'Invalid two-factor code.' }, 422)
    }
  }
  // Try recovery code
  else if (body.recovery_code) {
    const codes = actions.recoveryCodesOf!(user)
    const index = codes.indexOf(body.recovery_code)
    if (index === -1) {
      return ctx.json({ message: 'Invalid recovery code.' }, 422)
    }

    // Remove the used recovery code
    codes.splice(index, 1)
    await actions.setRecoveryCodes!(user, codes)
  } else {
    return ctx.json({ message: 'A two-factor code or recovery code is required.' }, 422)
  }

  // Clean up pending state
  session.forget('_jina_2fa_email')

  // Complete the login
  return completeLogin(ctx, user)
}

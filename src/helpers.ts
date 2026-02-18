import JinaManager from './jina_manager.ts'
import { createSignedToken, verifySignedToken } from './tokens.ts'
import { generateSecret, totpUri, verifyTotp, base32Decode, generateRecoveryCodes } from './totp.ts'

/**
 * Jina helper — convenience API for auth flow utilities.
 *
 * @example
 * import { jina } from '@stravigor/jina'
 *
 * const token = jina.signedToken({ sub: user.id, typ: 'custom' }, 60)
 * const payload = jina.verifyToken(token)
 *
 * const { secret, qrUri } = jina.generateTwoFactorSecret(user)
 * const valid = await jina.verifyTwoFactorCode(secret, code)
 */
export const jina = {
  /** Check if a feature is enabled. */
  hasFeature(feature: string): boolean {
    return JinaManager.hasFeature(feature as any)
  },

  /** Create a signed, encrypted token with an expiration. */
  signedToken(
    data: { sub: string | number; typ: string; [key: string]: unknown },
    expiresInMinutes: number
  ): string {
    return createSignedToken(data, expiresInMinutes)
  },

  /** Verify and decode a signed token. Throws if expired or tampered. */
  verifyToken<T extends Record<string, unknown> = Record<string, unknown>>(token: string): T {
    return verifySignedToken<T>(token)
  },

  /** Generate a TOTP secret and QR URI for the given user. */
  generateTwoFactorSecret(user: unknown): { secret: string; qrUri: string } {
    const config = JinaManager.config.twoFactor
    const { base32 } = generateSecret()
    const email = JinaManager.actions.emailOf(user)

    const uri = totpUri({
      secret: base32,
      issuer: config.issuer,
      account: email,
      digits: config.digits,
      period: config.period,
    })

    return { secret: base32, qrUri: uri }
  },

  /** Verify a TOTP code against a base32 secret. */
  async verifyTwoFactorCode(base32Secret: string, code: string): Promise<boolean> {
    const config = JinaManager.config.twoFactor
    const secretBytes = base32Decode(base32Secret)
    return verifyTotp(secretBytes, code, {
      digits: config.digits,
      period: config.period,
    })
  },

  /** Generate a set of single-use recovery codes. */
  generateRecoveryCodes(count?: number): string[] {
    return generateRecoveryCodes(count ?? JinaManager.config.twoFactor.recoveryCodes)
  },
}

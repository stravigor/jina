import { defineActions } from '@stravigor/jina'
import { encrypt } from '@stravigor/kernel'
// import { User } from '../models/user'

/**
 * Jina actions — tell Jina how your User model works.
 *
 * These are the only functions you need to implement. Jina handles
 * the routing, token generation, rate limiting, and event emission.
 */
export default defineActions({
  // ── Core (required) ──────────────────────────────────────────────────

  async createUser(data) {
    // return await User.create({
    //   name: data.name,
    //   email: data.email,
    //   password: await encrypt.hash(data.password),
    // })
    throw new Error('Implement createUser in actions/jina.ts')
  },

  async findByEmail(email) {
    // return await User.query().where('email', email).first()
    throw new Error('Implement findByEmail in actions/jina.ts')
  },

  async findById(id) {
    // return await User.find(id)
    throw new Error('Implement findById in actions/jina.ts')
  },

  passwordHashOf(user: any) {
    return user.password
  },

  emailOf(user: any) {
    return user.email
  },

  async updatePassword(user: any, newPassword) {
    user.password = await encrypt.hash(newPassword)
    await user.save()
  },

  // ── Email verification (uncomment when feature is enabled) ───────────

  // isEmailVerified(user: any) {
  //   return user.emailVerifiedAt !== null
  // },

  // async markEmailVerified(user: any) {
  //   user.emailVerifiedAt = new Date()
  //   await user.save()
  // },

  // ── Two-factor authentication (uncomment when feature is enabled) ────

  // twoFactorSecretOf(user: any) {
  //   return user.twoFactorSecret ?? null
  // },

  // async setTwoFactorSecret(user: any, secret) {
  //   user.twoFactorSecret = secret
  //   await user.save()
  // },

  // recoveryCodesOf(user: any) {
  //   return user.recoveryCodes ?? []
  // },

  // async setRecoveryCodes(user: any, codes) {
  //   user.recoveryCodes = codes
  //   await user.save()
  // },

  // ── Profile update (uncomment when feature is enabled) ───────────────

  // async updateProfile(user: any, data) {
  //   Object.assign(user, data)
  //   await user.save()
  // },
})

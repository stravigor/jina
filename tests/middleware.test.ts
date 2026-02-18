import { test, expect, describe, beforeEach } from 'bun:test'
import { verified } from '../src/middleware/verified.ts'
import { confirmed } from '../src/middleware/confirmed.ts'
import { twoFactorChallenge } from '../src/middleware/two_factor_challenge.ts'
import { bootJina, mockContextWithSession, createMockUser, resetUserStore } from './helpers.ts'

describe('verified() middleware', () => {
  beforeEach(() => {
    resetUserStore()
    bootJina()
  })

  test('passes when email is verified', async () => {
    const user = createMockUser({ emailVerifiedAt: new Date() })
    const { ctx } = mockContextWithSession()
    ctx.set('user', user)

    let called = false
    const mw = verified()
    const response = await mw(ctx, async () => {
      called = true
      return ctx.json({ ok: true })
    })

    expect(called).toBe(true)
    expect(response.status).toBe(200)
  })

  test('returns 403 when email is not verified', async () => {
    const user = createMockUser({ emailVerifiedAt: null })
    const { ctx } = mockContextWithSession()
    ctx.set('user', user)

    let called = false
    const mw = verified()
    const response = await mw(ctx, async () => {
      called = true
      return ctx.json({ ok: true })
    })

    expect(called).toBe(false)
    expect(response.status).toBe(403)
    const body = await response.json()
    expect(body.message).toContain('not verified')
  })
})

describe('confirmed() middleware', () => {
  beforeEach(() => {
    resetUserStore()
    bootJina()
  })

  test('passes when password was recently confirmed', async () => {
    const { ctx, session } = mockContextWithSession()
    session.set('_jina_confirmed_at', Date.now())

    let called = false
    const mw = confirmed()
    const response = await mw(ctx, async () => {
      called = true
      return ctx.json({ ok: true })
    })

    expect(called).toBe(true)
    expect(response.status).toBe(200)
  })

  test('returns 423 when no confirmation exists', async () => {
    const { ctx } = mockContextWithSession()

    let called = false
    const mw = confirmed()
    const response = await mw(ctx, async () => {
      called = true
      return ctx.json({ ok: true })
    })

    expect(called).toBe(false)
    expect(response.status).toBe(423)
  })

  test('returns 423 when confirmation has expired', async () => {
    const { ctx, session } = mockContextWithSession()
    // Set confirmation to 4 hours ago (timeout is 3 hours = 10800s)
    session.set('_jina_confirmed_at', Date.now() - 4 * 60 * 60 * 1000)

    let called = false
    const mw = confirmed()
    const response = await mw(ctx, async () => {
      called = true
      return ctx.json({ ok: true })
    })

    expect(called).toBe(false)
    expect(response.status).toBe(423)
    const body = await response.json()
    expect(body.message).toContain('expired')
  })
})

describe('twoFactorChallenge() middleware', () => {
  beforeEach(() => {
    resetUserStore()
    bootJina()
  })

  test('passes when user has no 2FA enabled', async () => {
    const user = createMockUser({ twoFactorSecret: null })
    const { ctx } = mockContextWithSession()
    ctx.set('user', user)

    let called = false
    const mw = twoFactorChallenge()
    const response = await mw(ctx, async () => {
      called = true
      return ctx.json({ ok: true })
    })

    expect(called).toBe(true)
  })

  test('passes when user has 2FA and no pending challenge', async () => {
    const user = createMockUser({ twoFactorSecret: 'SOME_SECRET' })
    const { ctx } = mockContextWithSession()
    ctx.set('user', user)

    let called = false
    const mw = twoFactorChallenge()
    const response = await mw(ctx, async () => {
      called = true
      return ctx.json({ ok: true })
    })

    expect(called).toBe(true)
  })

  test('returns 403 when a 2FA challenge is pending', async () => {
    const user = createMockUser({ twoFactorSecret: 'SOME_SECRET' })
    const { ctx, session } = mockContextWithSession()
    ctx.set('user', user)
    session.set('_jina_2fa_email', user.email)

    let called = false
    const mw = twoFactorChallenge()
    const response = await mw(ctx, async () => {
      called = true
      return ctx.json({ ok: true })
    })

    expect(called).toBe(false)
    expect(response.status).toBe(403)
  })
})

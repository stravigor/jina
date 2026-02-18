import { test, expect, describe, beforeEach } from 'bun:test'
import {
  bootJina,
  bootEncryption,
  mockConfig,
  mockContext,
  mockContextWithSession,
  mockActions,
  createMockUser,
  resetUserStore,
  MockSession,
} from './helpers.ts'
import { registerHandler } from '../src/handlers/register.ts'
import { loginHandler } from '../src/handlers/login.ts'
import { logoutHandler } from '../src/handlers/logout.ts'
import { resetPasswordHandler } from '../src/handlers/reset_password.ts'
import { confirmPasswordHandler } from '../src/handlers/confirm_password.ts'
import { updatePasswordHandler } from '../src/handlers/update_password.ts'
import { updateProfileHandler } from '../src/handlers/update_profile.ts'
import { enableTwoFactorHandler, confirmTwoFactorHandler } from '../src/handlers/two_factor.ts'
import { createSignedToken } from '../src/tokens.ts'
import JinaManager from '../src/jina_manager.ts'

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  resetUserStore()
  bootEncryption()
  bootJina()
})

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

describe('registerHandler', () => {
  test('creates a user and returns 201', async () => {
    const { ctx, session } = mockContextWithSession({
      method: 'POST',
      path: '/register',
      body: {
        name: 'Alice',
        email: 'alice@example.com',
        password: 'password123',
        password_confirmation: 'password123',
      },
    })

    const response = await registerHandler(ctx)
    expect(response.status).toBe(201)

    const body = await response.json()
    expect(body.user).toBeDefined()
    expect(body.user.email).toBe('alice@example.com')
  })

  test('authenticates the session after registration', async () => {
    const { ctx, session } = mockContextWithSession({
      method: 'POST',
      path: '/register',
      body: {
        name: 'Bob',
        email: 'bob@example.com',
        password: 'password123',
        password_confirmation: 'password123',
      },
    })

    await registerHandler(ctx)
    expect(session.isAuthenticated).toBe(true)
    expect(session.regenerated).toBe(true)
  })

  test('rejects when email is missing', async () => {
    const { ctx } = mockContextWithSession({
      method: 'POST',
      path: '/register',
      body: { name: 'Test', password: 'password123', password_confirmation: 'password123' },
    })

    const response = await registerHandler(ctx)
    expect(response.status).toBe(422)
    const body = await response.json()
    expect(body.errors.email).toBeDefined()
  })

  test('rejects when password is too short', async () => {
    const { ctx } = mockContextWithSession({
      method: 'POST',
      path: '/register',
      body: {
        name: 'Test',
        email: 'test@test.com',
        password: 'short',
        password_confirmation: 'short',
      },
    })

    const response = await registerHandler(ctx)
    expect(response.status).toBe(422)
    const body = await response.json()
    expect(body.errors.password).toContain('8 characters')
  })

  test('rejects when passwords do not match', async () => {
    const { ctx } = mockContextWithSession({
      method: 'POST',
      path: '/register',
      body: {
        name: 'Test',
        email: 'test@test.com',
        password: 'password123',
        password_confirmation: 'different',
      },
    })

    const response = await registerHandler(ctx)
    expect(response.status).toBe(422)
    const body = await response.json()
    expect(body.errors.password_confirmation).toContain('do not match')
  })

  test('rejects duplicate email', async () => {
    createMockUser({ email: 'taken@example.com' })

    const { ctx } = mockContextWithSession({
      method: 'POST',
      path: '/register',
      body: {
        name: 'Test',
        email: 'taken@example.com',
        password: 'password123',
        password_confirmation: 'password123',
      },
    })

    const response = await registerHandler(ctx)
    expect(response.status).toBe(422)
    const body = await response.json()
    expect(body.errors.email).toContain('already taken')
  })
})

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

describe('loginHandler', () => {
  test('authenticates with valid credentials', async () => {
    // encrypt.verify will be called with the raw password and the hash
    // Our mock stores "hashed:password123", so we need encrypt.verify to work
    // For this test we use the real Bun.password hashing
    const hash = await Bun.password.hash('password123')
    createMockUser({ email: 'alice@example.com', password: hash })

    const { ctx, session } = mockContextWithSession({
      method: 'POST',
      path: '/login',
      body: { email: 'alice@example.com', password: 'password123' },
    })

    const response = await loginHandler(ctx)
    expect(response.status).toBe(200)
    expect(session.isAuthenticated).toBe(true)
  })

  test('rejects invalid email', async () => {
    const { ctx } = mockContextWithSession({
      method: 'POST',
      path: '/login',
      body: { email: 'nobody@example.com', password: 'password123' },
    })

    const response = await loginHandler(ctx)
    expect(response.status).toBe(401)
    const body = await response.json()
    expect(body.message).toContain('Invalid credentials')
  })

  test('rejects wrong password', async () => {
    const hash = await Bun.password.hash('correct')
    createMockUser({ email: 'alice@example.com', password: hash })

    const { ctx } = mockContextWithSession({
      method: 'POST',
      path: '/login',
      body: { email: 'alice@example.com', password: 'wrong' },
    })

    const response = await loginHandler(ctx)
    expect(response.status).toBe(401)
  })

  test('rejects when email or password missing', async () => {
    const { ctx } = mockContextWithSession({
      method: 'POST',
      path: '/login',
      body: { email: 'test@test.com' },
    })

    const response = await loginHandler(ctx)
    expect(response.status).toBe(422)
  })

  test('triggers 2FA challenge when user has 2FA enabled', async () => {
    const hash = await Bun.password.hash('password123')
    createMockUser({ email: 'alice@example.com', password: hash, twoFactorSecret: 'SOME_SECRET' })

    const { ctx, session } = mockContextWithSession({
      method: 'POST',
      path: '/login',
      body: { email: 'alice@example.com', password: 'password123' },
    })

    const response = await loginHandler(ctx)
    expect(response.status).toBe(200)

    const body = await response.json()
    expect(body.two_factor).toBe(true)
    // Should NOT be authenticated yet
    expect(session.isAuthenticated).toBe(false)
    // Should store email in session for challenge
    expect(session.get('_jina_2fa_email')).toBe('alice@example.com')
  })
})

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

describe('logoutHandler', () => {
  test('returns success message (token mode)', async () => {
    // Use token mode to avoid Session.destroy needing SessionManager
    JinaManager.reset()
    bootEncryption()
    new JinaManager(mockConfig({ mode: 'token' } as any))
    JinaManager.useActions(mockActions())

    const user = createMockUser()
    const { ctx } = mockContextWithSession({ method: 'POST', path: '/logout' })
    ctx.set('user', user)

    const response = await logoutHandler(ctx)
    expect(response.status).toBe(200)
    const body = await response.json()
    expect(body.message).toContain('Logged out')
  })
})

// ---------------------------------------------------------------------------
// Reset password
// ---------------------------------------------------------------------------

describe('resetPasswordHandler', () => {
  test('resets password with valid token', async () => {
    const user = createMockUser({ email: 'alice@example.com' })

    const token = createSignedToken(
      { sub: user.id, typ: 'password-reset', email: 'alice@example.com' },
      60
    )

    const { ctx } = mockContextWithSession({
      method: 'POST',
      path: '/reset-password',
      body: { token, password: 'newpassword123', password_confirmation: 'newpassword123' },
    })

    const response = await resetPasswordHandler(ctx)
    expect(response.status).toBe(200)

    const body = await response.json()
    expect(body.message).toContain('reset')
    // Password should have been updated
    expect(user.password).toBe('hashed:newpassword123')
  })

  test('rejects expired token', async () => {
    const user = createMockUser({ email: 'alice@example.com' })

    const token = createSignedToken(
      { sub: user.id, typ: 'password-reset', email: 'alice@example.com' },
      -1 // expired
    )

    const { ctx } = mockContextWithSession({
      method: 'POST',
      path: '/reset-password',
      body: { token, password: 'newpassword123', password_confirmation: 'newpassword123' },
    })

    const response = await resetPasswordHandler(ctx)
    expect(response.status).toBe(422)
  })

  test('rejects wrong token type', async () => {
    const user = createMockUser({ email: 'alice@example.com' })
    const token = createSignedToken(
      { sub: user.id, typ: 'email-verify', email: 'alice@example.com' },
      60
    )

    const { ctx } = mockContextWithSession({
      method: 'POST',
      path: '/reset-password',
      body: { token, password: 'newpassword123', password_confirmation: 'newpassword123' },
    })

    const response = await resetPasswordHandler(ctx)
    expect(response.status).toBe(422)
    const body = await response.json()
    expect(body.message).toContain('Invalid token type')
  })

  test('rejects mismatched passwords', async () => {
    const { ctx } = mockContextWithSession({
      method: 'POST',
      path: '/reset-password',
      body: { token: 'x', password: 'newpassword123', password_confirmation: 'different' },
    })

    const response = await resetPasswordHandler(ctx)
    expect(response.status).toBe(422)
  })
})

// ---------------------------------------------------------------------------
// Confirm password
// ---------------------------------------------------------------------------

describe('confirmPasswordHandler', () => {
  test('confirms with correct password', async () => {
    const hash = await Bun.password.hash('password123')
    const user = createMockUser({ password: hash })
    const { ctx, session } = mockContextWithSession({
      method: 'POST',
      path: '/confirm-password',
      body: { password: 'password123' },
    })
    ctx.set('user', user)

    const response = await confirmPasswordHandler(ctx)
    expect(response.status).toBe(200)
    expect(session.get('_jina_confirmed_at')).toBeGreaterThan(0)
  })

  test('rejects incorrect password', async () => {
    const hash = await Bun.password.hash('correct')
    const user = createMockUser({ password: hash })
    const { ctx, session } = mockContextWithSession({
      method: 'POST',
      path: '/confirm-password',
      body: { password: 'wrong' },
    })
    ctx.set('user', user)

    const response = await confirmPasswordHandler(ctx)
    expect(response.status).toBe(422)
  })
})

// ---------------------------------------------------------------------------
// Update password
// ---------------------------------------------------------------------------

describe('updatePasswordHandler', () => {
  test('updates password with valid current password', async () => {
    const hash = await Bun.password.hash('oldpass123')
    const user = createMockUser({ password: hash })
    const { ctx } = mockContextWithSession({
      method: 'PUT',
      path: '/password',
      body: {
        current_password: 'oldpass123',
        password: 'newpass1234',
        password_confirmation: 'newpass1234',
      },
    })
    ctx.set('user', user)

    const response = await updatePasswordHandler(ctx)
    expect(response.status).toBe(200)
    expect(user.password).toBe('hashed:newpass1234')
  })

  test('rejects wrong current password', async () => {
    const hash = await Bun.password.hash('correct')
    const user = createMockUser({ password: hash })
    const { ctx } = mockContextWithSession({
      method: 'PUT',
      path: '/password',
      body: {
        current_password: 'wrong',
        password: 'newpass1234',
        password_confirmation: 'newpass1234',
      },
    })
    ctx.set('user', user)

    const response = await updatePasswordHandler(ctx)
    expect(response.status).toBe(422)
    const body = await response.json()
    expect(body.message).toContain('incorrect')
  })
})

// ---------------------------------------------------------------------------
// Update profile
// ---------------------------------------------------------------------------

describe('updateProfileHandler', () => {
  test('updates profile fields', async () => {
    const user = createMockUser({ name: 'Old Name' })
    const { ctx } = mockContextWithSession({
      method: 'PUT',
      path: '/profile',
      body: { name: 'New Name' },
    })
    ctx.set('user', user)

    const response = await updateProfileHandler(ctx)
    expect(response.status).toBe(200)
    expect(user.name).toBe('New Name')
  })
})

// ---------------------------------------------------------------------------
// Two-factor enable
// ---------------------------------------------------------------------------

describe('enableTwoFactorHandler', () => {
  test('returns a secret and QR URI', async () => {
    const user = createMockUser({ twoFactorSecret: null })
    const { ctx, session } = mockContextWithSession({
      method: 'POST',
      path: '/two-factor/enable',
    })
    ctx.set('user', user)

    const response = await enableTwoFactorHandler(ctx)
    expect(response.status).toBe(200)

    const body = await response.json()
    expect(body.secret).toMatch(/^[A-Z2-7]+$/)
    expect(body.qr_uri).toStartWith('otpauth://totp/')
    // Secret should be stored in session, not on user yet
    expect(user.twoFactorSecret).toBeNull()
    expect(session.get('_jina_2fa_secret')).toBe(body.secret)
  })

  test('rejects if 2FA is already enabled', async () => {
    const user = createMockUser({ twoFactorSecret: 'EXISTING_SECRET' })
    const { ctx } = mockContextWithSession({ method: 'POST', path: '/two-factor/enable' })
    ctx.set('user', user)

    const response = await enableTwoFactorHandler(ctx)
    expect(response.status).toBe(409)
  })
})

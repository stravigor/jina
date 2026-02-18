import { test, expect, describe, beforeEach } from 'bun:test'
import { createSignedToken, verifySignedToken } from '../src/tokens.ts'
import { bootEncryption } from './helpers.ts'

describe('signed tokens', () => {
  beforeEach(() => bootEncryption())

  test('creates and verifies a token', () => {
    const token = createSignedToken({ sub: 42, typ: 'test' }, 60)
    expect(typeof token).toBe('string')
    expect(token.length).toBeGreaterThan(0)

    const payload = verifySignedToken(token)
    expect(payload.sub).toBe(42)
    expect(payload.typ).toBe('test')
    expect(payload.iat).toBeGreaterThan(0)
  })

  test('preserves extra fields', () => {
    const token = createSignedToken({ sub: 1, typ: 'email', email: 'a@b.com' }, 60)
    const payload = verifySignedToken(token)
    expect(payload.email).toBe('a@b.com')
  })

  test('produces different tokens for same payload (random IV)', () => {
    const a = createSignedToken({ sub: 1, typ: 'test' }, 60)
    const b = createSignedToken({ sub: 1, typ: 'test' }, 60)
    expect(a).not.toBe(b)
  })

  test('rejects expired tokens', () => {
    // Create a token that expired 1 minute ago
    const token = createSignedToken({ sub: 1, typ: 'test' }, -1)
    expect(() => verifySignedToken(token)).toThrow('expired')
  })

  test('rejects truncated tokens', () => {
    const token = createSignedToken({ sub: 1, typ: 'test' }, 60)
    // Truncate to break the iv+ciphertext+tag structure
    const truncated = token.slice(0, 10)
    expect(() => verifySignedToken(truncated)).toThrow()
  })

  test('rejects garbage tokens', () => {
    expect(() => verifySignedToken('not-a-real-token')).toThrow()
  })

  test('rejects empty string', () => {
    expect(() => verifySignedToken('')).toThrow()
  })

  test('works with string subject', () => {
    const token = createSignedToken({ sub: 'user-uuid-123', typ: 'reset' }, 30)
    const payload = verifySignedToken(token)
    expect(payload.sub).toBe('user-uuid-123')
  })
})

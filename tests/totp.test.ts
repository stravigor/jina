import { test, expect, describe } from 'bun:test'
import {
  base32Encode,
  base32Decode,
  generateTotp,
  verifyTotp,
  generateSecret,
  totpUri,
  generateRecoveryCodes,
} from '../src/totp.ts'

// ---------------------------------------------------------------------------
// Base32
// ---------------------------------------------------------------------------

describe('base32Encode / base32Decode', () => {
  test('round-trips arbitrary bytes', () => {
    const input = new Uint8Array([72, 101, 108, 108, 111]) // "Hello"
    const encoded = base32Encode(input)
    const decoded = base32Decode(encoded)
    expect(decoded).toEqual(input)
  })

  test('encodes known value', () => {
    // "Hello" → JBSWY3DP (standard base32)
    const input = new TextEncoder().encode('Hello')
    expect(base32Encode(input)).toBe('JBSWY3DP')
  })

  test('decodes with trailing padding stripped', () => {
    const decoded = base32Decode('JBSWY3DP====')
    expect(new TextDecoder().decode(decoded)).toBe('Hello')
  })

  test('handles empty buffer', () => {
    expect(base32Encode(new Uint8Array([]))).toBe('')
    expect(base32Decode('')).toEqual(new Uint8Array([]))
  })

  test('is case-insensitive on decode', () => {
    const upper = base32Decode('JBSWY3DP')
    const lower = base32Decode('jbswy3dp')
    expect(upper).toEqual(lower)
  })

  test('round-trips random 20-byte secrets', () => {
    const raw = crypto.getRandomValues(new Uint8Array(20))
    const encoded = base32Encode(raw)
    const decoded = base32Decode(encoded)
    expect(decoded).toEqual(raw)
  })
})

// ---------------------------------------------------------------------------
// TOTP generation & verification
// ---------------------------------------------------------------------------

describe('generateTotp / verifyTotp', () => {
  // Known secret for deterministic testing
  const secret = new TextEncoder().encode('12345678901234567890')

  test('generates a 6-digit code by default', async () => {
    const code = await generateTotp(secret)
    expect(code).toHaveLength(6)
    expect(code).toMatch(/^\d{6}$/)
  })

  test('generates an 8-digit code when requested', async () => {
    const code = await generateTotp(secret, { digits: 8 })
    expect(code).toHaveLength(8)
    expect(code).toMatch(/^\d{8}$/)
  })

  test('verifies a freshly generated code', async () => {
    const code = await generateTotp(secret)
    const valid = await verifyTotp(secret, code)
    expect(valid).toBe(true)
  })

  test('rejects a wrong code', async () => {
    const valid = await verifyTotp(secret, '000000')
    // Might be valid if the current TOTP happens to be 000000 (unlikely)
    // So we test with a clearly wrong code
    const wrong = await verifyTotp(secret, 'abcdef')
    expect(wrong).toBe(false)
  })

  test('accepts codes within the drift window', async () => {
    const code = await generateTotp(secret)
    // With window=1, the code from the current time step should be accepted
    const valid = await verifyTotp(secret, code, { window: 1 })
    expect(valid).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// Secret generation
// ---------------------------------------------------------------------------

describe('generateSecret', () => {
  test('returns 20 raw bytes', () => {
    const { raw } = generateSecret()
    expect(raw).toBeInstanceOf(Uint8Array)
    expect(raw.length).toBe(20)
  })

  test('returns a base32-encoded string', () => {
    const { base32 } = generateSecret()
    expect(base32).toMatch(/^[A-Z2-7]+$/)
    // 20 bytes → 32 base32 chars
    expect(base32.length).toBe(32)
  })

  test('produces different secrets each call', () => {
    const a = generateSecret()
    const b = generateSecret()
    expect(a.base32).not.toBe(b.base32)
  })

  test('round-trips through base32', () => {
    const { raw, base32 } = generateSecret()
    expect(base32Decode(base32)).toEqual(raw)
  })
})

// ---------------------------------------------------------------------------
// TOTP URI
// ---------------------------------------------------------------------------

describe('totpUri', () => {
  test('generates a valid otpauth:// URI', () => {
    const uri = totpUri({
      secret: 'JBSWY3DPEHPK3PXP',
      issuer: 'TestApp',
      account: 'user@example.com',
    })

    expect(uri).toStartWith('otpauth://totp/')
    expect(uri).toContain('secret=JBSWY3DPEHPK3PXP')
    expect(uri).toContain('issuer=TestApp')
    expect(uri).toContain('user%40example.com')
    expect(uri).toContain('algorithm=SHA1')
    expect(uri).toContain('digits=6')
    expect(uri).toContain('period=30')
  })

  test('respects custom digits and period', () => {
    const uri = totpUri({
      secret: 'JBSWY3DP',
      issuer: 'App',
      account: 'test',
      digits: 8,
      period: 60,
    })
    expect(uri).toContain('digits=8')
    expect(uri).toContain('period=60')
  })

  test('URL-encodes issuer and account', () => {
    const uri = totpUri({
      secret: 'JBSWY3DP',
      issuer: 'My App',
      account: 'user@test.com',
    })
    expect(uri).toContain('My%20App')
    expect(uri).toContain('user%40test.com')
  })
})

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

describe('generateRecoveryCodes', () => {
  test('generates the requested number of codes', () => {
    const codes = generateRecoveryCodes(8)
    expect(codes).toHaveLength(8)
  })

  test('each code is 8 hex characters', () => {
    const codes = generateRecoveryCodes(5)
    for (const code of codes) {
      expect(code).toMatch(/^[0-9a-f]{8}$/)
    }
  })

  test('generates unique codes', () => {
    const codes = generateRecoveryCodes(100)
    const unique = new Set(codes)
    // Very high probability all 100 are unique (4 bytes = 4 billion possibilities)
    expect(unique.size).toBe(100)
  })
})

import { EncryptionManager } from '@stravigor/kernel'
import { Context } from '@stravigor/http'
import JinaManager from '../src/jina_manager.ts'
import type { JinaActions, JinaConfig } from '../src/types.ts'

// ---------------------------------------------------------------------------
// Encryption bootstrap (needed for seal/unseal in token tests)
// ---------------------------------------------------------------------------

const TEST_KEY = 'test-app-key-for-jina-tests'

export function bootEncryption() {
  ;(EncryptionManager as any)._config = { key: TEST_KEY, previousKeys: [] }
  EncryptionManager.useKey(TEST_KEY)
  const { hkdfSync } = require('node:crypto')
  ;(EncryptionManager as any)._previousEncryptionKeys = []
  ;(EncryptionManager as any)._previousHmacKeys = []
}

// ---------------------------------------------------------------------------
// Mock configuration
// ---------------------------------------------------------------------------

export function mockConfig(overrides: Partial<JinaConfig> = {}): any {
  const data: Record<string, unknown> = {
    jina: {
      features: [
        'registration',
        'login',
        'logout',
        'password-reset',
        'email-verification',
        'two-factor',
        'password-confirmation',
        'update-password',
        'update-profile',
      ],
      prefix: '',
      mode: 'session',
      rateLimit: {
        login: { max: 5, window: 60 },
        register: { max: 3, window: 60 },
        forgotPassword: { max: 3, window: 60 },
        verifyEmail: { max: 3, window: 60 },
        twoFactor: { max: 5, window: 60 },
      },
      passwords: { expiration: 60 },
      verification: { expiration: 60 },
      confirmation: { timeout: 10_800 },
      twoFactor: { issuer: 'TestApp', digits: 6, period: 30, recoveryCodes: 8 },
      ...overrides,
    },
  }

  return {
    get(key: string, defaultValue?: unknown): unknown {
      const parts = key.split('.')
      let current: any = data
      for (const part of parts) {
        if (current === undefined || current === null) return defaultValue
        current = current[part]
      }
      return current !== undefined ? current : defaultValue
    },
    has(key: string): boolean {
      return this.get(key) !== undefined
    },
  }
}

// ---------------------------------------------------------------------------
// Mock user
// ---------------------------------------------------------------------------

export interface MockUser {
  id: number
  name: string
  email: string
  password: string
  emailVerifiedAt: Date | null
  twoFactorSecret: string | null
  recoveryCodes: string[]
}

let userStore: MockUser[] = []
let nextId = 1

export function resetUserStore() {
  userStore = []
  nextId = 1
}

export function createMockUser(overrides: Partial<MockUser> = {}): MockUser {
  const user: MockUser = {
    id: nextId++,
    name: 'Test User',
    email: 'test@example.com',
    password: 'hashed_password',
    emailVerifiedAt: null,
    twoFactorSecret: null,
    recoveryCodes: [],
    ...overrides,
  }
  userStore.push(user)
  return user
}

// ---------------------------------------------------------------------------
// Mock actions
// ---------------------------------------------------------------------------

export function mockActions(): JinaActions<MockUser> {
  return {
    createUser: async data => {
      return createMockUser({
        name: data.name,
        email: data.email,
        password: `hashed:${data.password}`,
      })
    },
    findByEmail: async email => userStore.find(u => u.email === email) ?? null,
    findById: async id => userStore.find(u => u.id === Number(id)) ?? null,
    passwordHashOf: user => user.password,
    emailOf: user => user.email,
    updatePassword: async (user, pw) => {
      user.password = `hashed:${pw}`
    },
    isEmailVerified: user => user.emailVerifiedAt !== null,
    markEmailVerified: async user => {
      user.emailVerifiedAt = new Date()
    },
    twoFactorSecretOf: user => user.twoFactorSecret,
    setTwoFactorSecret: async (user, secret) => {
      user.twoFactorSecret = secret
    },
    recoveryCodesOf: user => user.recoveryCodes,
    setRecoveryCodes: async (user, codes) => {
      user.recoveryCodes = codes
    },
    updateProfile: async (user, data) => {
      Object.assign(user, data)
    },
  }
}

// ---------------------------------------------------------------------------
// Boot jina manager with mocks
// ---------------------------------------------------------------------------

export function bootJina(overrides: Partial<JinaConfig> = {}) {
  const config = mockConfig(overrides)
  JinaManager.reset()
  new JinaManager(config)
  JinaManager.useActions(mockActions())
}

// ---------------------------------------------------------------------------
// Mock Context
// ---------------------------------------------------------------------------

export function mockContext(
  options: {
    method?: string
    path?: string
    body?: unknown
    params?: Record<string, string>
    headers?: Record<string, string>
  } = {}
): Context {
  const { method = 'GET', path = '/', body, params = {}, headers = {} } = options

  const requestInit: RequestInit = { method, headers }

  if (body && method !== 'GET') {
    requestInit.body = JSON.stringify(body)
    ;(requestInit.headers as Record<string, string>)['content-type'] = 'application/json'
  }

  const request = new Request(`http://localhost${path}`, requestInit)
  return new Context(request, params)
}

// ---------------------------------------------------------------------------
// Mock Session
// ---------------------------------------------------------------------------

export class MockSession {
  private _data = new Map<string, unknown>()
  private _userId: string | null = null
  private _regenerated = false

  get isAuthenticated() {
    return this._userId !== null
  }
  get userId() {
    return this._userId
  }
  get regenerated() {
    return this._regenerated
  }

  authenticate(user: unknown): void {
    this._userId = String((user as any).id)
  }

  clearUser(): void {
    this._userId = null
  }

  async regenerate(): Promise<void> {
    this._regenerated = true
  }

  get<T = unknown>(key: string, defaultValue?: T): T {
    return (this._data.get(key) as T) ?? (defaultValue as T)
  }

  set(key: string, value: unknown): void {
    this._data.set(key, value)
  }

  has(key: string): boolean {
    return this._data.has(key)
  }

  forget(key: string): void {
    this._data.delete(key)
  }

  static async destroy(ctx: Context, response: Response): Promise<Response> {
    return response
  }
}

/** Create a context with a mock session attached. */
export function mockContextWithSession(options: Parameters<typeof mockContext>[0] = {}) {
  const ctx = mockContext(options)
  const session = new MockSession()
  ctx.set('session', session)
  return { ctx, session }
}

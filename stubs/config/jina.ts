import { env } from '@stravigor/kernel'

export default {
  // Toggle features on/off. Uncomment to enable.
  features: [
    'registration',
    'login',
    'logout',
    'password-reset',
    // 'email-verification',
    // 'two-factor',
    // 'password-confirmation',
    // 'update-password',
    // 'update-profile',
  ],

  // Route prefix — '' means routes live at /login, /register, etc.
  prefix: '',

  // Auth mode: 'session' (cookie-based) or 'token' (access tokens)
  mode: 'session',

  // Rate limiting per flow (max attempts per window in seconds)
  rateLimit: {
    login: { max: 5, window: 60 },
    register: { max: 3, window: 60 },
    forgotPassword: { max: 3, window: 60 },
    verifyEmail: { max: 3, window: 60 },
    twoFactor: { max: 5, window: 60 },
  },

  // Password reset link lifetime (minutes)
  passwords: {
    expiration: 60,
  },

  // Email verification link lifetime (minutes)
  verification: {
    expiration: 60,
  },

  // Password confirmation timeout (seconds) — how long before the user
  // must re-enter their password for sensitive operations
  confirmation: {
    timeout: 10_800, // 3 hours
  },

  // Two-factor authentication (TOTP)
  twoFactor: {
    issuer: env('APP_NAME', 'Strav'),
    digits: 6,
    period: 30,
    recoveryCodes: 8,
  },
}

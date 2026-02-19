import { inject, Configuration, ConfigurationError } from '@stravigor/kernel'
import { Router, compose, rateLimit, auth, guest, session } from '@stravigor/http'
import type { Handler, Middleware } from '@stravigor/http'
import { MissingActionError } from './errors.ts'
import type { JinaActions, JinaConfig, Feature } from './types.ts'
import { registerHandler } from './handlers/register.ts'
import { loginHandler } from './handlers/login.ts'
import { logoutHandler } from './handlers/logout.ts'
import { forgotPasswordHandler } from './handlers/forgot_password.ts'
import { resetPasswordHandler } from './handlers/reset_password.ts'
import { sendVerificationHandler, verifyEmailHandler } from './handlers/verify_email.ts'
import {
  enableTwoFactorHandler,
  confirmTwoFactorHandler,
  disableTwoFactorHandler,
  twoFactorChallengeHandler,
} from './handlers/two_factor.ts'
import { confirmPasswordHandler } from './handlers/confirm_password.ts'
import { updatePasswordHandler } from './handlers/update_password.ts'
import { updateProfileHandler } from './handlers/update_profile.ts'
import { confirmed } from './middleware/confirmed.ts'

// ---------------------------------------------------------------------------
// Default config
// ---------------------------------------------------------------------------

const DEFAULTS: JinaConfig = {
  features: ['registration', 'login', 'logout', 'password-reset'],
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
  twoFactor: { issuer: 'Strav', digits: 6, period: 30, recoveryCodes: 8 },
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

/** Wrap a handler with middleware via compose. */
function withMiddleware(mw: Middleware[], handler: Handler): Handler {
  return mw.length > 0 ? compose(mw, handler) : handler
}

@inject
export default class JinaManager {
  private static _config: JinaConfig
  private static _actions: JinaActions

  constructor(config: Configuration) {
    const raw = config.get('jina', {}) as Partial<JinaConfig>
    JinaManager._config = { ...DEFAULTS, ...raw } as JinaConfig
  }

  // ── Accessors ────────────────────────────────────────────────────────

  static get config(): JinaConfig {
    if (!JinaManager._config) {
      throw new ConfigurationError(
        'JinaManager not configured. Resolve it through the container first.'
      )
    }
    return JinaManager._config
  }

  static get actions(): JinaActions {
    if (!JinaManager._actions) {
      throw new ConfigurationError('Jina actions not set. Pass actions to JinaProvider.')
    }
    return JinaManager._actions
  }

  /** Set the user-defined actions contract. */
  static useActions(actions: JinaActions): void {
    JinaManager._actions = actions
  }

  /** Check whether a feature is enabled. */
  static hasFeature(feature: Feature): boolean {
    return JinaManager._config.features.includes(feature)
  }

  // ── Validation ───────────────────────────────────────────────────────

  /** Verify that all required actions are provided for enabled features. */
  static validateActions(): void {
    const a = JinaManager._actions
    const has = (f: Feature) => JinaManager.hasFeature(f)

    if (has('email-verification')) {
      if (!a.isEmailVerified) throw new MissingActionError('isEmailVerified', 'email-verification')
      if (!a.markEmailVerified)
        throw new MissingActionError('markEmailVerified', 'email-verification')
    }

    if (has('two-factor')) {
      if (!a.twoFactorSecretOf) throw new MissingActionError('twoFactorSecretOf', 'two-factor')
      if (!a.setTwoFactorSecret) throw new MissingActionError('setTwoFactorSecret', 'two-factor')
      if (!a.recoveryCodesOf) throw new MissingActionError('recoveryCodesOf', 'two-factor')
      if (!a.setRecoveryCodes) throw new MissingActionError('setRecoveryCodes', 'two-factor')
    }

    if (has('update-profile')) {
      if (!a.updateProfile) throw new MissingActionError('updateProfile', 'update-profile')
    }
  }

  // ── Route registration ───────────────────────────────────────────────

  /** Build a rate limit middleware from a config key. */
  private static rl(key: keyof JinaConfig['rateLimit']): Middleware {
    const cfg = JinaManager._config.rateLimit[key]
    return rateLimit({ max: cfg.max, window: cfg.window * 1000 })
  }

  /**
   * Register all Jina routes on the given router.
   *
   * @param router  - The router instance.
   * @param options - `only` or `except` to selectively register routes.
   */
  static routes(router: Router, options?: { only?: Feature[]; except?: Feature[] }): void {
    const enabled = (f: Feature): boolean => {
      if (!JinaManager.hasFeature(f)) return false
      if (options?.only) return options.only.includes(f)
      if (options?.except) return !options.except.includes(f)
      return true
    }

    const prefix = JinaManager._config.prefix

    const middleware = JinaManager._config.mode === 'session' ? [session()] : []

    router.group({ prefix, middleware }, r => {
      if (enabled('registration')) {
        r.post('/register', withMiddleware([guest(), JinaManager.rl('register')], registerHandler))
      }

      if (enabled('login')) {
        r.post('/login', withMiddleware([guest(), JinaManager.rl('login')], loginHandler))
      }

      if (enabled('logout')) {
        r.post('/logout', withMiddleware([auth()], logoutHandler))
      }

      if (enabled('password-reset')) {
        r.post(
          '/forgot-password',
          withMiddleware([guest(), JinaManager.rl('forgotPassword')], forgotPasswordHandler)
        )
        r.post('/reset-password', withMiddleware([guest()], resetPasswordHandler))
      }

      if (enabled('email-verification')) {
        r.post(
          '/email/send',
          withMiddleware([auth(), JinaManager.rl('verifyEmail')], sendVerificationHandler)
        )
        r.get('/email/verify/:token', verifyEmailHandler)
      }

      if (enabled('two-factor')) {
        r.post('/two-factor/enable', withMiddleware([auth(), confirmed()], enableTwoFactorHandler))
        r.post('/two-factor/confirm', withMiddleware([auth()], confirmTwoFactorHandler))
        r.delete('/two-factor', withMiddleware([auth(), confirmed()], disableTwoFactorHandler))
        r.post(
          '/two-factor/challenge',
          withMiddleware([JinaManager.rl('twoFactor')], twoFactorChallengeHandler)
        )
      }

      if (enabled('password-confirmation')) {
        r.post('/confirm-password', withMiddleware([auth()], confirmPasswordHandler))
      }

      if (enabled('update-password')) {
        r.put('/password', withMiddleware([auth()], updatePasswordHandler))
      }

      if (enabled('update-profile')) {
        r.put('/profile', withMiddleware([auth()], updateProfileHandler))
      }
    })
  }

  /** Clear all state. For testing. */
  static reset(): void {
    JinaManager._config = undefined as any
    JinaManager._actions = undefined as any
  }
}

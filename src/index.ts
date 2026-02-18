// Manager & provider
export { default, default as JinaManager } from './jina_manager.ts'
export { default as JinaProvider } from './jina_provider.ts'

// Helper
export { jina } from './helpers.ts'

// Actions
export { defineActions } from './actions.ts'

// Middleware
export { verified } from './middleware/verified.ts'
export { confirmed } from './middleware/confirmed.ts'
export { twoFactorChallenge } from './middleware/two_factor_challenge.ts'

// Handlers (for manual route registration)
export { registerHandler } from './handlers/register.ts'
export { loginHandler } from './handlers/login.ts'
export { logoutHandler } from './handlers/logout.ts'
export { forgotPasswordHandler } from './handlers/forgot_password.ts'
export { resetPasswordHandler } from './handlers/reset_password.ts'
export { sendVerificationHandler, verifyEmailHandler } from './handlers/verify_email.ts'
export {
  enableTwoFactorHandler,
  confirmTwoFactorHandler,
  disableTwoFactorHandler,
  twoFactorChallengeHandler,
} from './handlers/two_factor.ts'
export { confirmPasswordHandler } from './handlers/confirm_password.ts'
export { updatePasswordHandler } from './handlers/update_password.ts'
export { updateProfileHandler } from './handlers/update_profile.ts'

// Errors
export { JinaError, MissingActionError, ValidationError } from './errors.ts'

// Types
export type {
  Feature,
  JinaActions,
  JinaConfig,
  JinaEvent,
  RegistrationData,
  RateLimitConfig,
} from './types.ts'
export { JinaEvents } from './types.ts'

// TOTP utilities
export {
  generateSecret,
  totpUri,
  verifyTotp,
  generateRecoveryCodes,
  base32Encode,
  base32Decode,
} from './totp.ts'

// Token utilities
export { createSignedToken, verifySignedToken } from './tokens.ts'

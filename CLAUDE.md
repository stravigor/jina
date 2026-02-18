# @stravigor/jina

Headless authentication flows — registration, login, logout, password reset, email verification, two-factor authentication (TOTP), password confirmation, and profile updates. Supports both session-based and token-based authentication via a headless JSON API.

## Dependencies
- @stravigor/kernel (peer)
- @stravigor/http (peer)
- @stravigor/signal (peer)
- @stravigor/database (peer)

## Commands
- bun test
- bun run build

## Architecture
- src/jina_manager.ts — main manager class
- src/jina_provider.ts — service provider registration
- src/handlers/ — request handlers for each auth flow
- src/middleware/ — auth middleware
- src/actions.ts — reusable auth actions
- src/tokens.ts — token management
- src/totp.ts — TOTP two-factor authentication
- src/types.ts — type definitions
- src/errors.ts — package-specific errors

## Conventions
- Auth flows are implemented as handlers, not controllers
- Token logic is centralized in tokens.ts
- TOTP is optional and handled separately from primary auth

# @stravigor/jina

Headless authentication flows for the [Strav](https://www.npmjs.com/package/@stravigor/core) framework. Registration, login, logout, password reset, email verification, two-factor authentication (TOTP), password confirmation, and profile updates — all as JSON API endpoints.

## Install

```bash
bun add @stravigor/jina
bun strav install jina
```

Requires `@stravigor/core` as a peer dependency.

## Setup

```ts
import { defineActions } from '@stravigor/jina'
import User from './models/user'

const actions = defineActions<User>({
  async createUser(data) { return User.create(data) },
  async findByEmail(email) { return User.query().where('email', email).first() },
  async findById(id) { return User.find(id) },
  passwordHashOf(user) { return user.password },
  emailOf(user) { return user.email },
  async updatePassword(user, pw) { user.password = pw; await user.save() },
})
```

```ts
import { JinaProvider } from '@stravigor/jina'

app.use(new JinaProvider(actions))
```

## Routes

Routes are registered automatically:

| Method | Path | Feature |
|--------|------|---------|
| POST | `/register` | registration |
| POST | `/login` | login |
| POST | `/logout` | logout |
| POST | `/forgot-password` | password-reset |
| POST | `/reset-password` | password-reset |
| POST | `/email/send` | email-verification |
| GET | `/email/verify/:token` | email-verification |
| POST | `/two-factor/enable` | two-factor |
| POST | `/two-factor/confirm` | two-factor |
| DELETE | `/two-factor` | two-factor |
| POST | `/two-factor/challenge` | two-factor |
| POST | `/confirm-password` | password-confirmation |
| PUT | `/password` | update-password |
| PUT | `/profile` | update-profile |

## Middleware

```ts
import { verified, confirmed, twoFactorChallenge } from '@stravigor/jina'

router.group({ middleware: [auth(), verified()] }, r => {
  r.delete('/account', compose([confirmed()], deleteAccountHandler))
})
```

## Documentation

See the full [Jina guide](../../guides/jina.md).

## License

MIT

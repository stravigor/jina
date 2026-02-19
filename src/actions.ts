import type { JinaActions } from './types.ts'

/**
 * Type-safe identity function for defining Jina actions.
 * Zero runtime cost — just provides autocompletion and type checking.
 *
 * @example
 * import { defineActions } from '@stravigor/jina'
 * import { User } from '../models/user'
 *
 * export default defineActions<User>({
 *   createUser: async (data) => User.create({ ... }),
 *   findByEmail: (email) => User.query().where('email', email).first(),
 *   findById: (id) => User.find(id),
 *   passwordHashOf: (user) => user.password,
 *   emailOf: (user) => user.email,
 *   updatePassword: async (user, pw) => { user.password = await encrypt.hash(pw); await user.save() },
 * })
 */
export function defineActions<TUser = unknown>(actions: JinaActions<TUser>): JinaActions<TUser> {
  return actions
}

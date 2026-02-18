import { ServiceProvider } from '@stravigor/kernel'
import type { Application } from '@stravigor/kernel'
import { Router } from '@stravigor/http'
import JinaManager from './jina_manager.ts'
import type { JinaActions } from './types.ts'

export default class JinaProvider extends ServiceProvider {
  readonly name = 'jina'
  override readonly dependencies = ['auth', 'session', 'encryption', 'mail']

  constructor(private actions: JinaActions) {
    super()
  }

  override register(app: Application): void {
    app.singleton(JinaManager)
  }

  override boot(app: Application): void {
    app.resolve(JinaManager)
    JinaManager.useActions(this.actions)
    JinaManager.validateActions()
    JinaManager.routes(app.resolve(Router))
  }
}

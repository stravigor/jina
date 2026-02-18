import { StravError } from '@stravigor/kernel'

/** Base error for all Jina errors. */
export class JinaError extends StravError {}

/** Thrown when a required action is missing for an enabled feature. */
export class MissingActionError extends JinaError {
  constructor(action: string, feature: string) {
    super(`Jina action "${action}" is required when the "${feature}" feature is enabled.`)
  }
}

/** Thrown when input validation fails. */
export class ValidationError extends JinaError {
  constructor(
    message: string,
    public readonly errors: Record<string, string> = {}
  ) {
    super(message)
  }
}

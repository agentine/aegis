import { Strategy } from '../strategy.js';
import type { AegisRequest, VerifyFn, DoneCallback } from '../types.js';

export interface LocalStrategyOptions {
  usernameField?: string;
  passwordField?: string;
  passReqToCallback?: boolean;
}

/**
 * Local strategy — authenticate with username and password.
 */
export class LocalStrategy<User = unknown> extends Strategy {
  name = 'local';
  private _usernameField: string;
  private _passwordField: string;
  private _verify: VerifyFn<User>;

  constructor(verify: VerifyFn<User>);
  constructor(options: LocalStrategyOptions, verify: VerifyFn<User>);
  constructor(
    optionsOrVerify: LocalStrategyOptions | VerifyFn<User>,
    maybeVerify?: VerifyFn<User>,
  ) {
    super();
    let options: LocalStrategyOptions;
    if (typeof optionsOrVerify === 'function') {
      options = {};
      this._verify = optionsOrVerify;
    } else {
      options = optionsOrVerify;
      this._verify = maybeVerify!;
    }
    this._usernameField = options.usernameField || 'username';
    this._passwordField = options.passwordField || 'password';
  }

  async authenticate(req: AegisRequest): Promise<void> {
    // Extract username/password from body
    const body = (req as unknown as { body?: Record<string, string> }).body;
    if (!body) {
      return this.fail({ message: 'Missing credentials' }, 400);
    }

    const username = body[this._usernameField];
    const password = body[this._passwordField];

    if (!username || !password) {
      return this.fail({ message: 'Missing credentials' }, 400);
    }

    try {
      const verify = this._verify;
      let user: User | false | null | undefined;

      if (verify.length <= 2) {
        // Async verify(username, password) => User | false
        user = await (verify as (u: string, p: string) => Promise<User | false | null | undefined>)(username, password);
      } else {
        // Callback verify(username, password, done)
        user = await new Promise<User | false | null | undefined>((resolve, reject) => {
          (verify as (u: string, p: string, done: DoneCallback<User>) => void)(
            username,
            password,
            (err, result, info) => {
              if (err) return reject(err);
              if (result === false) {
                this.fail(info || { message: 'Invalid credentials' });
                return resolve(undefined);
              }
              resolve(result);
            },
          );
        });
        // If fail was already called via callback, user is undefined
        if (user === undefined) return;
      }

      if (!user) {
        return this.fail({ message: 'Invalid credentials' }, 401);
      }

      this.success(user);
    } catch (err) {
      this.error(err as Error);
    }
  }
}

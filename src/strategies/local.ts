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
  private _passReqToCallback: boolean;
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
    this._passReqToCallback = options.passReqToCallback || false;
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
      const verify = this._verify as Function;
      let user: User | false | null | undefined;

      // Determine arity threshold: passReqToCallback adds 1 extra param.
      const arityThreshold = this._passReqToCallback ? 3 : 2;

      if (verify.length <= arityThreshold) {
        // Async verify — returns Promise
        const args = this._passReqToCallback
          ? [req, username, password]
          : [username, password];
        user = await verify(...args);
      } else {
        // Callback verify — last arg is done(err, user, info)
        user = await new Promise<User | false | null | undefined>((resolve, reject) => {
          const done: DoneCallback<User> = (err, result, info) => {
            if (err) return reject(err);
            if (result === false) {
              this.fail(info || { message: 'Invalid credentials' });
              return resolve(undefined);
            }
            resolve(result);
          };
          const args = this._passReqToCallback
            ? [req, username, password, done]
            : [username, password, done];
          verify(...args);
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

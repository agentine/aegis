import { Strategy } from './strategy.js';
import { runSerialize, runDeserialize } from './session/serializer.js';
import type {
  SerializeFn,
  DeserializeFn,
  AuthenticateOptions,
  Middleware,
} from './types.js';
import { createInitializeMiddleware } from './middleware/initialize.js';
import { createAuthenticateMiddleware } from './middleware/authenticate.js';
import { SessionStrategy } from './session/session-strategy.js';

export class Authenticator<User = unknown> {
  private _strategies: Map<string, Strategy> = new Map();
  private _serializers: SerializeFn<User>[] = [];
  private _deserializers: DeserializeFn<User>[] = [];
  private _userProperty: string = 'user';
  private _infoProperty: string = 'authInfo';

  /**
   * Register a strategy.
   */
  use(strategy: Strategy): this;
  use(name: string, strategy: Strategy): this;
  use(nameOrStrategy: string | Strategy, maybeStrategy?: Strategy): this {
    let name: string;
    let strategy: Strategy;
    if (typeof nameOrStrategy === 'string') {
      name = nameOrStrategy;
      strategy = maybeStrategy!;
    } else {
      strategy = nameOrStrategy;
      name = strategy.name || '';
      if (!name) {
        throw new Error('Strategy must have a name, or a name must be provided');
      }
    }
    this._strategies.set(name, strategy);
    return this;
  }

  /**
   * Unregister a strategy.
   */
  unuse(name: string): this {
    this._strategies.delete(name);
    return this;
  }

  /**
   * Get a strategy by name.
   */
  _strategy(name: string): Strategy | undefined {
    return this._strategies.get(name);
  }

  /**
   * Register a user serializer.
   */
  serializeUser(fn: SerializeFn<User>): void {
    this._serializers.push(fn);
  }

  /**
   * Register a user deserializer.
   */
  deserializeUser(fn: DeserializeFn<User>): void {
    this._deserializers.push(fn);
  }

  /**
   * Serialize a user to session identifier.
   */
  async _serializeUser(user: User): Promise<string | number> {
    for (const fn of this._serializers) {
      try {
        const id = await runSerialize(fn, user);
        if (id !== undefined && id !== null) return id;
      } catch {
        continue;
      }
    }
    throw new Error('Failed to serialize user into session');
  }

  /**
   * Deserialize a user from session identifier.
   */
  async _deserializeUser(id: string | number): Promise<User | false | null | undefined> {
    for (const fn of this._deserializers) {
      try {
        const user = await runDeserialize(fn, id);
        if (user !== undefined) return user;
      } catch {
        continue;
      }
    }
    throw new Error('Failed to deserialize user out of session');
  }

  get userProperty(): string {
    return this._userProperty;
  }

  get infoProperty(): string {
    return this._infoProperty;
  }

  /**
   * Return middleware that initializes the request with login/logout/isAuthenticated.
   */
  initialize(options?: { userProperty?: string }): Middleware {
    if (options?.userProperty) {
      this._userProperty = options.userProperty;
    }
    return createInitializeMiddleware(this);
  }

  /**
   * Return middleware that restores session-based authentication.
   */
  session(options?: { optional?: boolean }): Middleware {
    // Register the built-in session strategy if not already registered
    if (!this._strategies.has('session')) {
      this.use('session', new SessionStrategy(this));
    }
    return this.authenticate('session', {
      session: false,
      ...(options?.optional ? {} : {}),
    });
  }

  /**
   * Return middleware that authenticates with the given strategy.
   */
  authenticate(
    strategy: string | string[],
    options?: AuthenticateOptions,
  ): Middleware;
  authenticate(
    strategy: string | string[],
    options: AuthenticateOptions,
    callback: (...args: unknown[]) => void,
  ): Middleware;
  authenticate(
    strategy: string | string[],
    optionsOrCallback?: AuthenticateOptions | ((...args: unknown[]) => void),
    maybeCallback?: (...args: unknown[]) => void,
  ): Middleware {
    let options: AuthenticateOptions;
    let callback: ((...args: unknown[]) => void) | undefined;

    if (typeof optionsOrCallback === 'function') {
      options = {};
      callback = optionsOrCallback;
    } else {
      options = optionsOrCallback || {};
      callback = maybeCallback;
    }

    return createAuthenticateMiddleware(this, strategy, options, callback);
  }
}

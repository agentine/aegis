import type { AegisRequest, AuthInfo } from './types.js';

/**
 * Abstract base class for authentication strategies.
 *
 * Subclasses must implement `authenticate(req)` and call one of:
 *   this.success(user, info?)
 *   this.fail(challenge?, status?)
 *   this.redirect(url, status?)
 *   this.pass()
 *   this.error(err)
 */
export abstract class Strategy {
  public name?: string;

  // These are set by the authenticate middleware before calling authenticate()
  private _successCb?: (user: unknown, info?: AuthInfo) => void;
  private _failCb?: (challenge?: string | AuthInfo, status?: number) => void;
  private _redirectCb?: (url: string, status?: number) => void;
  private _passCb?: () => void;
  private _errorCb?: (err: Error) => void;

  /** Called by the middleware to wire up result handlers */
  _setup(handlers: {
    success: (user: unknown, info?: AuthInfo) => void;
    fail: (challenge?: string | AuthInfo, status?: number) => void;
    redirect: (url: string, status?: number) => void;
    pass: () => void;
    error: (err: Error) => void;
  }): void {
    this._successCb = handlers.success;
    this._failCb = handlers.fail;
    this._redirectCb = handlers.redirect;
    this._passCb = handlers.pass;
    this._errorCb = handlers.error;
  }

  abstract authenticate(req: AegisRequest): void | Promise<void>;

  protected success(user: unknown, info?: AuthInfo): void {
    this._successCb!(user, info);
  }

  protected fail(challenge?: string | AuthInfo, status?: number): void {
    this._failCb!(challenge, status);
  }

  protected redirect(url: string, status?: number): void {
    this._redirectCb!(url, status);
  }

  protected pass(): void {
    this._passCb!();
  }

  protected error(err: Error): void {
    this._errorCb!(err);
  }
}

/**
 * authorize() middleware — for account linking.
 *
 * Unlike authenticate(), authorize() does NOT establish a login session.
 * Instead, it stores the authenticated third-party account on the request
 * (default: req.account) for the route handler to link to the existing user.
 */
import type { Authenticator } from '../authenticator.js';
import type {
  AegisRequest,
  AegisResponse,
  NextFunction,
  AuthInfo,
  Middleware,
} from '../types.js';

export interface AuthorizeOptions {
  /** Property name on req where the authorized account is stored (default: 'account') */
  assignProperty?: string;
  failureRedirect?: string;
}

export function createAuthorizeMiddleware(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  authenticator: Authenticator<any>,
  strategyName: string,
  options: AuthorizeOptions = {},
): Middleware {
  const property = options.assignProperty || 'account';

  return function authorizeMiddleware(
    req: AegisRequest,
    res: AegisResponse,
    next: NextFunction,
  ): void {
    const strategy = authenticator._strategy(strategyName);
    if (!strategy) {
      return next(new Error(`Unknown authentication strategy "${strategyName}"`));
    }

    strategy._setup({
      success(user: unknown, info?: AuthInfo) {
        // Store the authorized account — do NOT call req.login().
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (req as any)[property] = user;
        if (info) {
          req.authInfo = info;
        }
        next();
      },

      fail(challenge?: string | AuthInfo, _status?: number) {
        if (options.failureRedirect) {
          res.writeHead(302, { Location: options.failureRedirect });
          res.end();
          return;
        }
        const status = _status || 403;
        const msg = typeof challenge === 'string' ? challenge : 'Authorization failed';
        res.writeHead(status, { 'Content-Type': 'text/plain' });
        res.end(msg);
      },

      redirect(url: string, status?: number) {
        const isRelative = url.startsWith('/') && !url.startsWith('//');
        const isHttps = url.startsWith('https://');
        const isLocalhost = url.startsWith('http://localhost');
        if (isRelative || isHttps || isLocalhost) {
          res.writeHead(status || 302, { Location: url });
          res.end();
        } else {
          res.writeHead(400, { 'Content-Type': 'text/plain' });
          res.end('Invalid redirect URL');
        }
      },

      pass() {
        next();
      },

      error(err: Error) {
        next(err);
      },
    });

    try {
      const result = strategy.authenticate(req);
      if (result && typeof (result as Promise<void>).catch === 'function') {
        (result as Promise<void>).catch((err: Error) => next(err));
      }
    } catch (err) {
      next(err as Error);
    }
  };
}

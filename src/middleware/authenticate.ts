import type { Authenticator } from '../authenticator.js';
import type {
  AegisRequest,
  AegisResponse,
  NextFunction,
  AuthenticateOptions,
  AuthInfo,
  Middleware,
} from '../types.js';
import { AuthenticationError } from '../errors.js';

export function createAuthenticateMiddleware(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  authenticator: Authenticator<any>,
  strategyNames: string | string[],
  options: AuthenticateOptions,
  customCallback?: (...args: unknown[]) => void,
): Middleware {
  const names = Array.isArray(strategyNames) ? strategyNames : [strategyNames];

  return function authenticateMiddleware(
    req: AegisRequest,
    res: AegisResponse,
    next: NextFunction,
  ): void {
    let strategyIdx = 0;

    function attemptStrategy(): void {
      if (strategyIdx >= names.length) {
        // All strategies failed
        if (customCallback) {
          customCallback(null, false, { message: 'Authentication failed' });
          return;
        }
        if (options.failureRedirect) {
          res.writeHead(302, { Location: options.failureRedirect });
          res.end();
          return;
        }
        next(new AuthenticationError('Unauthorized'));
        return;
      }

      const name = names[strategyIdx++];
      const strategy = authenticator._strategy(name);
      if (!strategy) {
        return next(new Error(`Unknown authentication strategy "${name}"`));
      }

      strategy._setup({
        success(user: unknown, info?: AuthInfo) {
          if (customCallback) {
            customCallback(null, user, info);
            return;
          }

          if (options.assignProperty) {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (req as any)[options.assignProperty] = user;
            return next();
          }

          const shouldSession = options.session !== false;
          req.login(user, { session: shouldSession }, (err) => {
            if (err) return next(err as Error);

            if (info) {
              req.authInfo = info;
            }

            if (options.successRedirect) {
              res.writeHead(302, { Location: options.successRedirect });
              res.end();
              return;
            }

            next();
          });
        },

        fail(challenge?: string | AuthInfo, _status?: number) {
          // If there are more strategies, try the next one
          if (strategyIdx < names.length) {
            return attemptStrategy();
          }

          if (customCallback) {
            const info = typeof challenge === 'string' ? { message: challenge } : challenge;
            customCallback(null, false, info);
            return;
          }

          if (options.failureRedirect) {
            res.writeHead(302, { Location: options.failureRedirect });
            res.end();
            return;
          }

          const status = _status || 401;
          const msg = typeof challenge === 'string' ? challenge : 'Unauthorized';
          res.writeHead(status, { 'Content-Type': 'text/plain' });
          res.end(msg);
        },

        redirect(url: string, status?: number) {
          res.writeHead(status || 302, { Location: url });
          res.end();
        },

        pass() {
          next();
        },

        error(err: Error) {
          if (customCallback) {
            customCallback(err);
            return;
          }
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
    }

    attemptStrategy();
  };
}

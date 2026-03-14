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

            // Flash message support (requires connect-flash or compatible middleware).
            if (options.successFlash) {
              const flash = (req as unknown as { flash?: (type: string, msg: string) => void }).flash;
              if (flash) {
                const msg = typeof options.successFlash === 'string'
                  ? options.successFlash
                  : (info?.message || 'Logged in');
                flash('success', msg);
              }
            }

            // Session message support (no flash middleware required).
            if (options.successMessage) {
              const messages = (req.session as Record<string, unknown>).messages as string[] | undefined;
              const msg = typeof options.successMessage === 'string'
                ? options.successMessage
                : (info?.message || 'Logged in');
              if (messages) {
                messages.push(msg);
              } else {
                (req.session as Record<string, unknown>).messages = [msg];
              }
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

          // Flash message support (requires connect-flash or compatible middleware).
          if (options.failureFlash) {
            const flash = (req as unknown as { flash?: (type: string, msg: string) => void }).flash;
            if (flash) {
              const info = typeof challenge === 'string' ? challenge : challenge?.message;
              const msg = typeof options.failureFlash === 'string'
                ? options.failureFlash
                : (info || 'Authentication failed');
              flash('error', msg);
            }
          }

          // Session message support (no flash middleware required).
          if (options.failureMessage) {
            const info = typeof challenge === 'string' ? challenge : challenge?.message;
            const msg = typeof options.failureMessage === 'string'
              ? options.failureMessage
              : (info || 'Authentication failed');
            if (req.session) {
              const messages = (req.session as Record<string, unknown>).messages as string[] | undefined;
              if (messages) {
                messages.push(msg);
              } else {
                (req.session as Record<string, unknown>).messages = [msg];
              }
            }
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
          // Validate redirect URL to prevent open redirect attacks.
          // Allow: relative paths, https:// URLs (strategy-initiated provider
          // redirects), and http://localhost for development.
          // Block: protocol-relative URLs (//evil.com), javascript:, data:, etc.
          const isRelative = url.startsWith('/') && !url.startsWith('//');
          const isHttps = url.startsWith('https://');
          const isLocalhost = url.startsWith('http://localhost');
          if (isRelative || isHttps || isLocalhost) {
            res.writeHead(status || 302, { Location: url });
            res.end();
          } else {
            // Reject protocol-relative URLs and non-https schemes.
            res.writeHead(400, { 'Content-Type': 'text/plain' });
            res.end('Invalid redirect URL');
          }
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

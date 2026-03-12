import type { Authenticator } from '../authenticator.js';
import type {
  AegisRequest,
  AegisResponse,
  NextFunction,
  Middleware,
  LoginOptions,
  LogoutOptions,
  DoneCallback,
} from '../types.js';

export function createInitializeMiddleware(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  authenticator: Authenticator<any>,
): Middleware {
  return function initializeMiddleware(
    req: AegisRequest,
    _res: AegisResponse,
    next: NextFunction,
  ): void {
    const userProp = authenticator.userProperty;

    // req.login / req.logIn
    function login(
      user: unknown,
      optionsOrDone?: LoginOptions | DoneCallback<void>,
      done?: DoneCallback<void>,
    ): void {
      let options: LoginOptions;
      let cb: DoneCallback<void>;

      if (typeof optionsOrDone === 'function') {
        options = {};
        cb = optionsOrDone;
      } else {
        options = optionsOrDone || {};
        cb = done || (() => {});
      }

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (req as any)[userProp] = user;

      const shouldSession = options.session !== false;
      if (shouldSession && req.session) {
        const storeUser = () => {
          authenticator
            ._serializeUser(user as never)
            .then((serialized: string | number) => {
              if (!req.session) {
                return cb(new Error('No session available'));
              }
              if (!req.session.passport) {
                req.session.passport = {};
              }
              req.session.passport.user = serialized;

              if (typeof req.session.save === 'function') {
                req.session.save((err) => {
                  cb(err || null);
                });
              } else {
                cb(null);
              }
            })
            .catch((err: Error) => cb(err));
        };

        // Regenerate session to prevent session fixation attacks.
        if (typeof req.session.regenerate === 'function') {
          req.session.regenerate((err) => {
            if (err) {
              return cb(err);
            }
            storeUser();
          });
        } else {
          storeUser();
        }
      } else {
        cb(null);
      }
    }

    // req.logout / req.logOut
    function logout(
      optionsOrDone?: LogoutOptions | DoneCallback<void>,
      done?: DoneCallback<void>,
    ): void {
      let cb: DoneCallback<void>;

      if (typeof optionsOrDone === 'function') {
        cb = optionsOrDone;
      } else {
        cb = done || (() => {});
      }

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (req as any)[userProp] = undefined;

      if (req.session?.passport) {
        delete req.session.passport.user;
      }

      if (req.session && typeof req.session.save === 'function') {
        req.session.save((err) => {
          cb(err || null);
        });
      } else {
        cb(null);
      }
    }

    function isAuthenticated(): boolean {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return (req as any)[userProp] != null;
    }

    function isUnauthenticated(): boolean {
      return !isAuthenticated();
    }

    req.login = login;
    req.logIn = login;
    req.logout = logout;
    req.logOut = logout;
    req.isAuthenticated = isAuthenticated;
    req.isUnauthenticated = isUnauthenticated;

    next();
  };
}

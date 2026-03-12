import { Strategy } from '../strategy.js';
import type { Authenticator } from '../authenticator.js';
import type { AegisRequest } from '../types.js';

/**
 * Session strategy — restores user from session on each request.
 */
export class SessionStrategy extends Strategy {
  name = 'session';
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private _authenticator: Authenticator<any>;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  constructor(authenticator: Authenticator<any>) {
    super();
    this._authenticator = authenticator;
  }

  async authenticate(req: AegisRequest): Promise<void> {
    const sessionUser = req.session?.passport?.user;

    if (sessionUser === undefined || sessionUser === null) {
      return this.pass();
    }

    try {
      const user = await this._authenticator._deserializeUser(
        sessionUser as string | number,
      );

      if (!user) {
        // User no longer valid — clear session and pass
        if (req.session?.passport) {
          delete req.session.passport.user;
        }
        return this.pass();
      }

      this.success(user);
    } catch (err) {
      this.error(err as Error);
    }
  }
}

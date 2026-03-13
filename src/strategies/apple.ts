import {
  OAuth2Strategy,
  type OAuth2Profile,
  type OAuth2VerifyFn,
} from './oauth2.js';
import type { AegisRequest } from '../types.js';

export interface AppleStrategyOptions {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope?: string | string[];
}

/**
 * Apple "Sign in with Apple" strategy.
 *
 * Apple returns user info via a JWT id_token in the token response rather than
 * a profile endpoint. On the very first login Apple may also POST a `user`
 * JSON blob with name fields; subsequent logins omit it.
 */
export class AppleStrategy<User = unknown> extends OAuth2Strategy<User> {
  name = 'apple';

  private _appleClientID: string;
  private _pendingProfile: OAuth2Profile | null = null;

  constructor(options: AppleStrategyOptions, verify: OAuth2VerifyFn<User>) {
    super(
      {
        authorizationURL: 'https://appleid.apple.com/auth/authorize',
        tokenURL: 'https://appleid.apple.com/auth/token',
        clientID: options.clientID,
        clientSecret: options.clientSecret,
        callbackURL: options.callbackURL,
        scope: options.scope || ['name', 'email'],
      },
      verify,
    );
    this._appleClientID = options.clientID;
  }

  /**
   * Override to handle Apple's POST-based callback and id_token.
   */
  async authenticate(req: AegisRequest): Promise<void> {
    // Apple POSTs the callback with code + id_token in the body.
    const body = (req as unknown as { body?: Record<string, string> }).body;

    if (body?.code) {
      // Synthesise query params so the base class can handle the callback.
      const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
      if (!url.searchParams.has('code')) {
        url.searchParams.set('code', body.code);
        if (body.state) url.searchParams.set('state', body.state);
        req.url = url.pathname + url.search;
      }

      // Stash the user blob (Apple only sends it on first login).
      if (body.user) {
        try {
          (req as unknown as Record<string, unknown>)._appleUser = JSON.parse(body.user);
        } catch {
          // Ignore parse errors
        }
      }
    }

    return super.authenticate(req);
  }

  /**
   * Build profile from the JWT id_token decoded during token exchange.
   * Apple does not provide a userinfo endpoint — user data lives in the token.
   */
  async userProfile(_accessToken: string): Promise<OAuth2Profile> {
    // Return the profile built during _exchangeCode. The base class calls
    // userProfile(accessToken) after _exchangeCode, so _pendingProfile is set.
    if (this._pendingProfile) {
      const profile = this._pendingProfile;
      this._pendingProfile = null;
      return profile;
    }

    return {
      provider: 'apple',
      id: '',
      displayName: '',
    };
  }

  /**
   * Override token exchange to capture the id_token and build a profile.
   */
  protected async _exchangeCode(
    req: AegisRequest,
    code: string,
  ): Promise<Record<string, string>> {
    const tokenData = await super._exchangeCode(req, code);

    let sub = '';
    let email = '';

    // Decode and validate id_token JWT payload.
    if (tokenData.id_token) {
      const parts = tokenData.id_token.split('.');
      if (parts.length === 3) {
        try {
          const payload = JSON.parse(
            Buffer.from(parts[1], 'base64url').toString('utf8'),
          ) as Record<string, unknown>;

          // Validate issuer and audience claims.
          if (payload.iss !== 'https://appleid.apple.com') {
            throw new Error(
              `Apple id_token issuer mismatch: expected https://appleid.apple.com, got ${String(payload.iss)}`,
            );
          }
          if (payload.aud !== this._appleClientID) {
            throw new Error(
              `Apple id_token audience mismatch: expected ${this._appleClientID}, got ${String(payload.aud)}`,
            );
          }

          // Validate expiry.
          if (typeof payload.exp === 'number' && payload.exp * 1000 < Date.now()) {
            throw new Error('Apple id_token has expired');
          }

          sub = String(payload.sub || '');
          email = String(payload.email || '');

          tokenData._apple_sub = sub;
          tokenData._apple_email = email;
          tokenData._apple_email_verified = String(payload.email_verified || '');
        } catch (err) {
          if (err instanceof Error && err.message.startsWith('Apple id_token')) {
            throw err; // Re-throw validation errors
          }
          // If JWT decode fails, continue without profile data
        }
      }
    }

    // Capture first-login user data from request body.
    const appleUser = (req as unknown as Record<string, unknown>)._appleUser as
      | { name?: { firstName?: string; lastName?: string } }
      | undefined;

    let firstName = '';
    let lastName = '';
    if (appleUser?.name) {
      firstName = appleUser.name.firstName || '';
      lastName = appleUser.name.lastName || '';
      tokenData._apple_firstName = firstName;
      tokenData._apple_lastName = lastName;
    }

    // Build the profile and store for userProfile() to return.
    const displayName = [firstName, lastName].filter(Boolean).join(' ') || email || sub;
    this._pendingProfile = {
      provider: 'apple',
      id: sub,
      displayName,
      name: firstName || lastName ? { givenName: firstName || undefined, familyName: lastName || undefined } : undefined,
      emails: email ? [{ value: email }] : [],
    };

    return tokenData;
  }
}

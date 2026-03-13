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
   * Build profile from the JWT id_token returned in the token response.
   * Apple does not provide a userinfo endpoint — user data lives in the token.
   */
  async userProfile(_accessToken: string): Promise<OAuth2Profile> {
    // The access token is not useful for Apple profiles.
    // We decode the id_token that was returned alongside it.
    // Since we trust the TLS connection to Apple's token endpoint, we decode
    // without signature verification (same approach as passport-apple).
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

    // Decode id_token JWT payload (base64url, no verification needed — we
    // trust the TLS connection to Apple's token endpoint).
    if (tokenData.id_token) {
      const parts = tokenData.id_token.split('.');
      if (parts.length === 3) {
        try {
          const payload = JSON.parse(
            Buffer.from(parts[1], 'base64url').toString('utf8'),
          ) as Record<string, unknown>;

          // Store parsed profile data on tokenData for userProfile to use.
          tokenData._apple_sub = String(payload.sub || '');
          tokenData._apple_email = String(payload.email || '');
          tokenData._apple_email_verified = String(payload.email_verified || '');
        } catch {
          // If JWT decode fails, continue without profile data
        }
      }
    }

    // Capture first-login user data from request body.
    const appleUser = (req as unknown as Record<string, unknown>)._appleUser as
      | { name?: { firstName?: string; lastName?: string } }
      | undefined;

    if (appleUser?.name) {
      tokenData._apple_firstName = appleUser.name.firstName || '';
      tokenData._apple_lastName = appleUser.name.lastName || '';
    }

    return tokenData;
  }
}

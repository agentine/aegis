import { randomBytes, createHash } from 'node:crypto';
import { Strategy } from '../strategy.js';
import type { AegisRequest, DoneCallback, AuthInfo } from '../types.js';

export interface OAuth2Profile {
  provider: string;
  id: string;
  displayName?: string;
  name?: { familyName?: string; givenName?: string; middleName?: string };
  emails?: Array<{ value: string; type?: string }>;
  photos?: Array<{ value: string }>;
  _raw?: string;
  _json?: Record<string, unknown>;
}

export type OAuth2VerifyCallback<User> = (
  accessToken: string,
  refreshToken: string | undefined,
  profile: OAuth2Profile,
  done: DoneCallback<User>,
) => void;

export type OAuth2VerifyAsync<User> = (
  accessToken: string,
  refreshToken: string | undefined,
  profile: OAuth2Profile,
) => Promise<User | false | null | undefined>;

export type OAuth2VerifyFn<User> = OAuth2VerifyCallback<User> | OAuth2VerifyAsync<User>;

export interface OAuth2StrategyOptions {
  authorizationURL: string;
  tokenURL: string;
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope?: string | string[];
  state?: boolean;
  pkce?: boolean;
  passReqToCallback?: boolean;
}

/**
 * Base OAuth 2.0 strategy.
 *
 * Handles:
 * - Authorization URL construction with PKCE (S256) and state parameter
 * - Authorization code → token exchange via native fetch()
 * - User profile fetching (delegated to subclasses)
 * - Token refresh
 */
export class OAuth2Strategy<User = unknown> extends Strategy {
  name = 'oauth2';

  protected _authorizationURL: string;
  protected _tokenURL: string;
  protected _clientID: string;
  protected _clientSecret: string;
  protected _callbackURL: string;
  protected _scope: string;
  protected _usePKCE: boolean;
  protected _useState: boolean;
  protected _verify: OAuth2VerifyFn<User>;

  constructor(options: OAuth2StrategyOptions, verify: OAuth2VerifyFn<User>) {
    super();
    this._authorizationURL = options.authorizationURL;
    this._tokenURL = options.tokenURL;
    this._clientID = options.clientID;
    this._clientSecret = options.clientSecret;
    this._callbackURL = options.callbackURL;
    this._scope = Array.isArray(options.scope)
      ? options.scope.join(' ')
      : options.scope || '';
    this._usePKCE = options.pkce !== false; // default: true
    this._useState = options.state !== false; // default: true
    this._verify = verify;
  }

  async authenticate(req: AegisRequest): Promise<void> {
    // Check if this is the callback (has 'code' query param).
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const code = url.searchParams.get('code');
    const errorParam = url.searchParams.get('error');

    if (errorParam) {
      // Clean up stored state and PKCE verifier on error to avoid stale session data.
      this._removeFromSession(req, 'oauth2:state');
      this._removeFromSession(req, 'oauth2:code_verifier');
      return this.fail({ message: url.searchParams.get('error_description') || errorParam });
    }

    if (code) {
      return this._handleCallback(req, code, url);
    }

    // Initiate OAuth flow: redirect to authorization URL.
    return this._redirectToProvider(req);
  }

  /**
   * Redirect the user to the OAuth provider's authorization page.
   */
  private async _redirectToProvider(req: AegisRequest): Promise<void> {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this._clientID,
      redirect_uri: this._callbackURL,
    });

    if (this._scope) {
      params.set('scope', this._scope);
    }

    // State parameter (CSRF protection).
    if (this._useState) {
      const state = randomBytes(24).toString('hex');
      this._storeInSession(req, 'oauth2:state', state);
      params.set('state', state);
    }

    // PKCE (S256).
    if (this._usePKCE) {
      const verifier = randomBytes(32).toString('base64url');
      const challenge = createHash('sha256').update(verifier).digest('base64url');
      this._storeInSession(req, 'oauth2:code_verifier', verifier);
      params.set('code_challenge', challenge);
      params.set('code_challenge_method', 'S256');
    }

    const authUrl = `${this._authorizationURL}?${params.toString()}`;
    this.redirect(authUrl);
  }

  /**
   * Handle the OAuth callback: validate state, exchange code for tokens, fetch profile.
   */
  private async _handleCallback(req: AegisRequest, code: string, url: URL): Promise<void> {
    // Validate state.
    if (this._useState) {
      const returnedState = url.searchParams.get('state');
      const storedState = this._loadFromSession(req, 'oauth2:state');
      this._removeFromSession(req, 'oauth2:state');

      if (!returnedState || returnedState !== storedState) {
        return this.fail({ message: 'OAuth2 state mismatch (possible CSRF)' }, 403);
      }
    }

    try {
      // Exchange authorization code for tokens.
      const tokenData = await this._exchangeCode(req, code);
      const accessToken = tokenData.access_token;
      const refreshToken = tokenData.refresh_token;

      if (!accessToken) {
        return this.fail({ message: 'No access token in response' });
      }

      // Fetch user profile.
      const profile = await this.userProfile(accessToken);

      // Call verify.
      await this._callVerify(accessToken, refreshToken, profile);
    } catch (err) {
      this.error(err as Error);
    }
  }

  /**
   * Exchange an authorization code for access/refresh tokens.
   */
  protected async _exchangeCode(
    req: AegisRequest,
    code: string,
  ): Promise<Record<string, string>> {
    const body: Record<string, string> = {
      grant_type: 'authorization_code',
      code,
      redirect_uri: this._callbackURL,
      client_id: this._clientID,
      client_secret: this._clientSecret,
    };

    // Include PKCE verifier if used.
    if (this._usePKCE) {
      const verifier = this._loadFromSession(req, 'oauth2:code_verifier');
      this._removeFromSession(req, 'oauth2:code_verifier');
      if (!verifier) {
        throw new Error(
          'PKCE code_verifier not found in session. The session may have expired or session middleware may be misconfigured.',
        );
      }
      body.code_verifier = verifier;
    }

    const res = await fetch(this._tokenURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: new URLSearchParams(body).toString(),
    });

    if (!res.ok) {
      throw new Error(`Token exchange failed (${res.status})`);
    }

    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      return await res.json() as Record<string, string>;
    }

    // Some providers return form-encoded.
    const text = await res.text();
    return Object.fromEntries(new URLSearchParams(text));
  }

  /**
   * Fetch the user profile from the provider.
   * Subclasses must override this.
   */
  async userProfile(accessToken: string): Promise<OAuth2Profile> {
    return {
      provider: this.name || 'oauth2',
      id: '',
      displayName: '',
    };
  }

  /**
   * Refresh an access token using a refresh token.
   */
  async refreshAccessToken(refreshToken: string): Promise<Record<string, string>> {
    const body: Record<string, string> = {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: this._clientID,
      client_secret: this._clientSecret,
    };

    const res = await fetch(this._tokenURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: new URLSearchParams(body).toString(),
    });

    if (!res.ok) {
      throw new Error(`Token refresh failed (${res.status})`);
    }

    return await res.json() as Record<string, string>;
  }

  /**
   * Call the verify function (supports both callback and async styles).
   */
  private async _callVerify(
    accessToken: string,
    refreshToken: string | undefined,
    profile: OAuth2Profile,
  ): Promise<void> {
    const verify = this._verify;

    if (verify.length <= 3) {
      // Async verify(accessToken, refreshToken, profile) => User
      const user = await (verify as OAuth2VerifyAsync<User>)(accessToken, refreshToken, profile);
      if (!user) {
        return this.fail({ message: 'Authentication failed' });
      }
      this.success(user);
    } else {
      // Callback verify(accessToken, refreshToken, profile, done)
      await new Promise<void>((resolve, reject) => {
        (verify as OAuth2VerifyCallback<User>)(
          accessToken,
          refreshToken,
          profile,
          (err, result, info) => {
            if (err) return reject(err);
            if (result === false || !result) {
              this.fail(info || { message: 'Authentication failed' });
              return resolve();
            }
            this.success(result, info);
            resolve();
          },
        );
      });
    }
  }

  // --- Session helpers ---

  private _storeInSession(req: AegisRequest, key: string, value: string): void {
    if (!req.session) {
      throw new Error(
        'OAuth2 requires session support. Ensure session middleware is configured before authentication.',
      );
    }
    (req.session as Record<string, unknown>)[key] = value;
  }

  private _loadFromSession(req: AegisRequest, key: string): string | undefined {
    if (req.session) {
      return (req.session as Record<string, unknown>)[key] as string | undefined;
    }
    return undefined;
  }

  private _removeFromSession(req: AegisRequest, key: string): void {
    if (req.session) {
      delete (req.session as Record<string, unknown>)[key];
    }
  }
}

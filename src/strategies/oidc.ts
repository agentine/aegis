import {
  OAuth2Strategy,
  type OAuth2Profile,
  type OAuth2VerifyFn,
} from './oauth2.js';

export interface OIDCStrategyOptions {
  issuer: string;
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope?: string | string[];
}

interface OIDCConfiguration {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  issuer: string;
}

/**
 * Generic OpenID Connect strategy with Discovery.
 *
 * Fetches the provider's `.well-known/openid-configuration` to discover
 * endpoints dynamically. Supports any OIDC-compliant identity provider.
 */
export class OIDCStrategy<User = unknown> extends OAuth2Strategy<User> {
  name = 'oidc';

  private _issuer: string;
  private _userinfoEndpoint?: string;
  private _discovered = false;

  constructor(options: OIDCStrategyOptions, verify: OAuth2VerifyFn<User>) {
    // Use placeholder URLs — they'll be replaced after discovery.
    super(
      {
        authorizationURL: 'https://placeholder/authorize',
        tokenURL: 'https://placeholder/token',
        clientID: options.clientID,
        clientSecret: options.clientSecret,
        callbackURL: options.callbackURL,
        scope: options.scope || ['openid', 'profile', 'email'],
      },
      verify,
    );
    this._issuer = options.issuer.replace(/\/+$/, '');
  }

  /**
   * Discover OIDC endpoints before first authentication attempt.
   */
  private async _discover(): Promise<void> {
    if (this._discovered) return;

    const url = `${this._issuer}/.well-known/openid-configuration`;
    const res = await fetch(url);
    if (!res.ok) {
      throw new Error(`OIDC discovery failed for ${this._issuer} (${res.status})`);
    }

    const config = (await res.json()) as OIDCConfiguration;

    this._authorizationURL = config.authorization_endpoint;
    this._tokenURL = config.token_endpoint;
    this._userinfoEndpoint = config.userinfo_endpoint;
    this._discovered = true;
  }

  async authenticate(req: import('../types.js').AegisRequest): Promise<void> {
    try {
      await this._discover();
    } catch (err) {
      return this.error(err as Error);
    }
    return super.authenticate(req);
  }

  async userProfile(accessToken: string): Promise<OAuth2Profile> {
    const endpoint = this._userinfoEndpoint;
    if (!endpoint) {
      return { provider: 'oidc', id: '', displayName: '' };
    }

    const res = await fetch(endpoint, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!res.ok) {
      throw new Error(`OIDC userinfo request failed (${res.status})`);
    }

    const json = (await res.json()) as Record<string, unknown>;

    return {
      provider: 'oidc',
      id: String(json.sub || ''),
      displayName: String(json.name || ''),
      name: {
        givenName: json.given_name as string | undefined,
        familyName: json.family_name as string | undefined,
      },
      emails: json.email ? [{ value: String(json.email) }] : [],
      photos: json.picture ? [{ value: String(json.picture) }] : [],
      _raw: JSON.stringify(json),
      _json: json,
    };
  }
}

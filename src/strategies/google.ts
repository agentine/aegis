import {
  OAuth2Strategy,
  type OAuth2Profile,
  type OAuth2StrategyOptions,
  type OAuth2VerifyFn,
} from './oauth2.js';

export interface GoogleStrategyOptions {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope?: string | string[];
}

/**
 * Google OAuth 2.0 strategy.
 */
export class GoogleStrategy<User = unknown> extends OAuth2Strategy<User> {
  name = 'google';

  constructor(options: GoogleStrategyOptions, verify: OAuth2VerifyFn<User>) {
    super(
      {
        authorizationURL: 'https://accounts.google.com/o/oauth2/v2/auth',
        tokenURL: 'https://oauth2.googleapis.com/token',
        clientID: options.clientID,
        clientSecret: options.clientSecret,
        callbackURL: options.callbackURL,
        scope: options.scope || ['openid', 'profile', 'email'],
      },
      verify,
    );
  }

  async userProfile(accessToken: string): Promise<OAuth2Profile> {
    const res = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!res.ok) {
      throw new Error(`Google userinfo request failed (${res.status})`);
    }

    const json = (await res.json()) as Record<string, unknown>;

    return {
      provider: 'google',
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

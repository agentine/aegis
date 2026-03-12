import {
  OAuth2Strategy,
  type OAuth2Profile,
  type OAuth2StrategyOptions,
  type OAuth2VerifyFn,
} from './oauth2.js';

export interface TwitterStrategyOptions {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope?: string | string[];
}

/**
 * Twitter/X OAuth 2.0 strategy (NOT OAuth 1.0a).
 *
 * Uses the Twitter API v2 OAuth 2.0 with PKCE.
 */
export class TwitterStrategy<User = unknown> extends OAuth2Strategy<User> {
  name = 'twitter';

  constructor(options: TwitterStrategyOptions, verify: OAuth2VerifyFn<User>) {
    super(
      {
        authorizationURL: 'https://twitter.com/i/oauth2/authorize',
        tokenURL: 'https://api.twitter.com/2/oauth2/token',
        clientID: options.clientID,
        clientSecret: options.clientSecret,
        callbackURL: options.callbackURL,
        scope: options.scope || ['tweet.read', 'users.read', 'offline.access'],
        pkce: true, // Twitter requires PKCE
      },
      verify,
    );
  }

  async userProfile(accessToken: string): Promise<OAuth2Profile> {
    const res = await fetch(
      'https://api.twitter.com/2/users/me?user.fields=id,name,username,profile_image_url,description',
      {
        headers: { Authorization: `Bearer ${accessToken}` },
      },
    );

    if (!res.ok) {
      throw new Error(`Twitter user request failed (${res.status})`);
    }

    const json = (await res.json()) as { data?: Record<string, unknown> };
    const data = json.data || {};

    return {
      provider: 'twitter',
      id: String(data.id || ''),
      displayName: String(data.name || ''),
      name: {
        givenName: undefined,
        familyName: undefined,
      },
      emails: [], // Twitter API v2 doesn't return emails
      photos: data.profile_image_url
        ? [{ value: String(data.profile_image_url) }]
        : [],
      _raw: JSON.stringify(json),
      _json: data,
    };
  }
}

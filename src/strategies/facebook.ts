import {
  OAuth2Strategy,
  type OAuth2Profile,
  type OAuth2StrategyOptions,
  type OAuth2VerifyFn,
} from './oauth2.js';

export interface FacebookStrategyOptions {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope?: string | string[];
  profileFields?: string[];
}

/**
 * Facebook OAuth 2.0 strategy.
 */
export class FacebookStrategy<User = unknown> extends OAuth2Strategy<User> {
  name = 'facebook';
  private _profileFields: string[];

  constructor(options: FacebookStrategyOptions, verify: OAuth2VerifyFn<User>) {
    super(
      {
        authorizationURL: 'https://www.facebook.com/v18.0/dialog/oauth',
        tokenURL: 'https://graph.facebook.com/v18.0/oauth/access_token',
        clientID: options.clientID,
        clientSecret: options.clientSecret,
        callbackURL: options.callbackURL,
        scope: options.scope || ['email', 'public_profile'],
      },
      verify,
    );
    this._profileFields = options.profileFields || ['id', 'name', 'email', 'picture'];
  }

  async userProfile(accessToken: string): Promise<OAuth2Profile> {
    const fields = this._profileFields.join(',');
    const url = `https://graph.facebook.com/v18.0/me?fields=${fields}&access_token=${accessToken}`;

    const res = await fetch(url);

    if (!res.ok) {
      throw new Error(`Facebook graph request failed (${res.status})`);
    }

    const json = (await res.json()) as Record<string, unknown>;

    const nameParts = String(json.name || '').split(' ');
    const picture = json.picture as { data?: { url?: string } } | undefined;

    return {
      provider: 'facebook',
      id: String(json.id || ''),
      displayName: String(json.name || ''),
      name: {
        givenName: nameParts[0],
        familyName: nameParts.length > 1 ? nameParts.slice(1).join(' ') : undefined,
      },
      emails: json.email ? [{ value: String(json.email) }] : [],
      photos: picture?.data?.url ? [{ value: picture.data.url }] : [],
      _raw: JSON.stringify(json),
      _json: json,
    };
  }
}

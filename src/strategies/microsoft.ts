import {
  OAuth2Strategy,
  type OAuth2Profile,
  type OAuth2VerifyFn,
} from './oauth2.js';

export interface MicrosoftStrategyOptions {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  tenant?: string;
  scope?: string | string[];
}

/**
 * Microsoft (Azure AD) OAuth 2.0 strategy.
 *
 * Uses Microsoft identity platform v2.0 endpoints and Microsoft Graph
 * for user profile data.
 */
export class MicrosoftStrategy<User = unknown> extends OAuth2Strategy<User> {
  name = 'microsoft';

  constructor(options: MicrosoftStrategyOptions, verify: OAuth2VerifyFn<User>) {
    const tenant = options.tenant || 'common';
    super(
      {
        authorizationURL: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
        tokenURL: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
        clientID: options.clientID,
        clientSecret: options.clientSecret,
        callbackURL: options.callbackURL,
        scope: options.scope || ['openid', 'profile', 'email', 'User.Read'],
      },
      verify,
    );
  }

  async userProfile(accessToken: string): Promise<OAuth2Profile> {
    const res = await fetch('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!res.ok) {
      throw new Error(`Microsoft Graph /me request failed (${res.status})`);
    }

    const json = (await res.json()) as Record<string, unknown>;

    return {
      provider: 'microsoft',
      id: String(json.id || ''),
      displayName: String(json.displayName || ''),
      name: {
        givenName: json.givenName as string | undefined,
        familyName: json.surname as string | undefined,
      },
      emails: json.mail
        ? [{ value: String(json.mail) }]
        : json.userPrincipalName
          ? [{ value: String(json.userPrincipalName) }]
          : [],
      _raw: JSON.stringify(json),
      _json: json,
    };
  }
}

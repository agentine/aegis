import {
  OAuth2Strategy,
  type OAuth2Profile,
  type OAuth2StrategyOptions,
  type OAuth2VerifyFn,
} from './oauth2.js';

export interface GitHubStrategyOptions {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  scope?: string | string[];
}

/**
 * GitHub OAuth 2.0 strategy.
 */
export class GitHubStrategy<User = unknown> extends OAuth2Strategy<User> {
  name = 'github';

  constructor(options: GitHubStrategyOptions, verify: OAuth2VerifyFn<User>) {
    super(
      {
        authorizationURL: 'https://github.com/login/oauth/authorize',
        tokenURL: 'https://github.com/login/oauth/access_token',
        clientID: options.clientID,
        clientSecret: options.clientSecret,
        callbackURL: options.callbackURL,
        scope: options.scope || ['read:user', 'user:email'],
      },
      verify,
    );
  }

  async userProfile(accessToken: string): Promise<OAuth2Profile> {
    const res = await fetch('https://api.github.com/user', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'aegis-oauth',
      },
    });

    if (!res.ok) {
      throw new Error(`GitHub user request failed (${res.status})`);
    }

    const json = (await res.json()) as Record<string, unknown>;

    // Fetch emails separately (may not be in public profile).
    let emails: Array<{ value: string; type?: string }> = [];
    if (json.email) {
      emails = [{ value: String(json.email) }];
    } else {
      try {
        const emailRes = await fetch('https://api.github.com/user/emails', {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'aegis-oauth',
          },
        });
        if (emailRes.ok) {
          const emailData = (await emailRes.json()) as Array<{
            email: string;
            primary: boolean;
            verified: boolean;
          }>;
          emails = emailData
            .filter((e) => e.verified)
            .map((e) => ({ value: e.email, type: e.primary ? 'primary' : 'secondary' }));
        }
      } catch {
        // Ignore email fetch errors.
      }
    }

    return {
      provider: 'github',
      id: String(json.id || ''),
      displayName: String(json.name || json.login || ''),
      name: {
        givenName: undefined,
        familyName: undefined,
      },
      emails,
      photos: json.avatar_url ? [{ value: String(json.avatar_url) }] : [],
      _raw: JSON.stringify(json),
      _json: json,
    };
  }
}

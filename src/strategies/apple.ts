import { createHash, createPublicKey, createVerify, randomBytes } from 'node:crypto';
import {
  OAuth2Strategy,
  type OAuth2Profile,
  type OAuth2VerifyFn,
} from './oauth2.js';
import type { AegisRequest } from '../types.js';

// ---- Apple JWKS helpers (zero-dependency JWT signature verification) ----

interface AppleJWK {
  kty: string;
  kid: string;
  use: string;
  alg: string;
  n: string;
  e: string;
}

interface AppleJWKS {
  keys: AppleJWK[];
}

const APPLE_JWKS_URL = 'https://appleid.apple.com/auth/keys';
const JWKS_CACHE_TTL_MS = 3600_000; // 1 hour

let _jwksCache: { keys: AppleJWK[]; fetchedAt: number } | null = null;

async function fetchAppleJWKS(): Promise<AppleJWK[]> {
  if (_jwksCache && Date.now() - _jwksCache.fetchedAt < JWKS_CACHE_TTL_MS) {
    return _jwksCache.keys;
  }
  const res = await fetch(APPLE_JWKS_URL);
  if (!res.ok) {
    throw new Error(`Failed to fetch Apple JWKS (${res.status})`);
  }
  const jwks = (await res.json()) as AppleJWKS;
  _jwksCache = { keys: jwks.keys, fetchedAt: Date.now() };
  return jwks.keys;
}

function verifyAppleJWT(idToken: string, keys: AppleJWK[]): Record<string, unknown> {
  const parts = idToken.split('.');
  if (parts.length !== 3) {
    throw new Error('Apple id_token is not a valid JWT');
  }

  // Decode header to find kid and alg.
  const header = JSON.parse(
    Buffer.from(parts[0], 'base64url').toString('utf8'),
  ) as { kid?: string; alg?: string };

  if (!header.kid || !header.alg) {
    throw new Error('Apple id_token header missing kid or alg');
  }

  // Only RS256 is expected from Apple.
  if (header.alg !== 'RS256') {
    throw new Error(`Unsupported Apple id_token algorithm: ${header.alg}`);
  }

  // Find matching key.
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) {
    throw new Error(`No Apple JWKS key found for kid: ${header.kid}`);
  }

  // Import JWK as a Node.js public key.
  const publicKey = createPublicKey({
    key: { kty: jwk.kty, n: jwk.n, e: jwk.e },
    format: 'jwk',
  });

  // Verify RS256 signature.
  const signatureInput = `${parts[0]}.${parts[1]}`;
  const signature = Buffer.from(parts[2], 'base64url');
  const verifier = createVerify('RSA-SHA256');
  verifier.update(signatureInput);
  if (!verifier.verify(publicKey, signature)) {
    throw new Error('Apple id_token signature verification failed');
  }

  // Signature valid — decode payload.
  return JSON.parse(
    Buffer.from(parts[1], 'base64url').toString('utf8'),
  ) as Record<string, unknown>;
}

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
   * Generates and stores a nonce for id_token replay protection.
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

      return super.authenticate(req);
    }

    // Initiating flow — generate nonce and store in session for replay protection.
    // Apple expects the SHA-256 hash of the nonce in the authorization URL.
    if (req.session) {
      const nonce = randomBytes(16).toString('hex');
      (req.session as Record<string, unknown>)['apple:nonce'] = nonce;
    }

    return super.authenticate(req);
  }

  /**
   * Include the nonce hash in the authorization URL for Apple.
   * Apple requires the SHA-256 hash of the nonce in the auth request.
   */
  protected _extraAuthorizationParams(req: AegisRequest): Record<string, string> {
    if (req.session) {
      const nonce = (req.session as Record<string, unknown>)['apple:nonce'] as string | undefined;
      if (nonce) {
        const nonceHash = createHash('sha256').update(nonce).digest('hex');
        return { nonce: nonceHash, response_mode: 'form_post' };
      }
    }
    return { response_mode: 'form_post' };
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

    // Verify and decode id_token JWT with cryptographic signature check.
    if (tokenData.id_token) {
      // Fetch Apple's public keys and verify the JWT signature.
      const appleKeys = await fetchAppleJWKS();
      const payload = verifyAppleJWT(tokenData.id_token, appleKeys);

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

      // Validate nonce (replay protection).
      if (req.session) {
        const storedNonce = (req.session as Record<string, unknown>)['apple:nonce'] as string | undefined;
        delete (req.session as Record<string, unknown>)['apple:nonce'];
        if (storedNonce) {
          if (!payload.nonce) {
            throw new Error('Apple id_token missing nonce claim (possible replay attack)');
          }
          // Apple includes the SHA-256 hash of the nonce in the id_token.
          const expectedNonceHash = createHash('sha256').update(storedNonce).digest('hex');
          if (String(payload.nonce) !== expectedNonceHash && String(payload.nonce) !== storedNonce) {
            throw new Error('Apple id_token nonce mismatch (possible replay attack)');
          }
        }
      }

      sub = String(payload.sub || '');
      email = String(payload.email || '');

      tokenData._apple_sub = sub;
      tokenData._apple_email = email;
      tokenData._apple_email_verified = String(payload.email_verified || '');
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

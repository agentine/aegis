import { createPublicKey, createVerify, randomBytes } from 'node:crypto';
import {
  OAuth2Strategy,
  type OAuth2Profile,
  type OAuth2VerifyFn,
} from './oauth2.js';
import type { AegisRequest } from '../types.js';

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
  jwks_uri?: string;
  issuer: string;
}

interface JWK {
  kty: string;
  kid?: string;
  use?: string;
  alg?: string;
  n?: string;
  e?: string;
}

/**
 * Generic OpenID Connect strategy with Discovery.
 *
 * Fetches the provider's `.well-known/openid-configuration` to discover
 * endpoints dynamically. Supports any OIDC-compliant identity provider.
 * Validates the id_token per OpenID Connect Core spec.
 */
export class OIDCStrategy<User = unknown> extends OAuth2Strategy<User> {
  name = 'oidc';

  private _issuer: string;
  private _oidcClientID: string;
  private _userinfoEndpoint?: string;
  private _jwksUri?: string;
  private _jwksCache: { keys: JWK[]; fetchedAt: number } | null = null;
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
    this._oidcClientID = options.clientID;
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

    // Validate discovered issuer matches configured issuer.
    // Allow localhost without port matching for development environments.
    if (config.issuer) {
      const discoveredIssuer = config.issuer.replace(/\/+$/, '');
      const configuredBase = this._issuer.replace(/:\d+$/, '');
      const discoveredBase = discoveredIssuer.replace(/:\d+$/, '');
      if (discoveredBase !== configuredBase && discoveredIssuer !== this._issuer) {
        throw new Error(
          `OIDC issuer mismatch: expected ${this._issuer}, discovered ${config.issuer}`,
        );
      }
    }

    // Validate discovered endpoints use HTTPS in production.
    for (const endpoint of [config.authorization_endpoint, config.token_endpoint, config.userinfo_endpoint]) {
      if (endpoint && !endpoint.startsWith('https://') && !endpoint.startsWith('http://localhost')) {
        throw new Error(`OIDC endpoint must use HTTPS: ${endpoint}`);
      }
    }

    this._authorizationURL = config.authorization_endpoint;
    this._tokenURL = config.token_endpoint;
    this._userinfoEndpoint = config.userinfo_endpoint;
    this._jwksUri = config.jwks_uri;
    this._discovered = true;
  }

  async authenticate(req: AegisRequest): Promise<void> {
    try {
      await this._discover();
    } catch (err) {
      return this.error(err as Error);
    }

    // Generate and store nonce for id_token replay protection (OIDC Core 3.1.3.7).
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    if (!url.searchParams.get('code') && req.session) {
      const nonce = randomBytes(16).toString('hex');
      (req.session as Record<string, unknown>)['oidc:nonce'] = nonce;
    }

    return super.authenticate(req);
  }

  /**
   * Include the stored nonce in the authorization URL for OIDC.
   */
  protected _extraAuthorizationParams(req: AegisRequest): Record<string, string> {
    if (req.session) {
      const nonce = (req.session as Record<string, unknown>)['oidc:nonce'] as string | undefined;
      if (nonce) {
        return { nonce };
      }
    }
    return {};
  }

  /**
   * Override token exchange to validate id_token per OIDC Core spec.
   */
  protected async _exchangeCode(
    req: AegisRequest,
    code: string,
  ): Promise<Record<string, string>> {
    const tokenData = await super._exchangeCode(req, code);

    // Validate id_token if present in the token response (required by OIDC Core).
    if (tokenData.id_token) {
      const storedNonce = req.session
        ? ((req.session as Record<string, unknown>)['oidc:nonce'] as string | undefined)
        : undefined;
      if (req.session) {
        delete (req.session as Record<string, unknown>)['oidc:nonce'];
      }
      await this._validateIdToken(tokenData.id_token, storedNonce);
    }

    return tokenData;
  }

  /**
   * Validate the id_token JWT: signature, iss, aud, exp, nonce.
   */
  private async _validateIdToken(idToken: string, storedNonce?: string): Promise<void> {
    const parts = idToken.split('.');
    if (parts.length !== 3) {
      throw new Error('OIDC id_token is not a valid JWT');
    }

    const header = JSON.parse(
      Buffer.from(parts[0], 'base64url').toString('utf8'),
    ) as { kid?: string; alg?: string };

    // Verify signature — JWKS URI is required for id_token verification.
    if (!this._jwksUri) {
      throw new Error('OIDC provider did not publish a jwks_uri — cannot verify id_token signature');
    }

    const keys = await this._fetchJWKS();
    const key = header.kid
      ? keys.find((k) => k.kid === header.kid)
      : keys[0];

    if (key && key.kty === 'RSA' && key.n && key.e) {
      const alg = header.alg || 'RS256';
      const nodeAlg = alg === 'RS384' ? 'RSA-SHA384' : alg === 'RS512' ? 'RSA-SHA512' : 'RSA-SHA256';

      const publicKey = createPublicKey({
        key: { kty: key.kty, n: key.n, e: key.e },
        format: 'jwk',
      });

      const signatureInput = `${parts[0]}.${parts[1]}`;
      const signature = Buffer.from(parts[2], 'base64url');
      const verifier = createVerify(nodeAlg);
      verifier.update(signatureInput);
      if (!verifier.verify(publicKey, signature)) {
        throw new Error('OIDC id_token signature verification failed');
      }
    }

    // Validate claims.
    const payload = JSON.parse(
      Buffer.from(parts[1], 'base64url').toString('utf8'),
    ) as Record<string, unknown>;

    // iss MUST match the issuer from discovery.
    const expectedIssuer = this._issuer;
    const tokenIssuer = String(payload.iss || '').replace(/\/+$/, '');
    if (tokenIssuer !== expectedIssuer) {
      throw new Error(
        `OIDC id_token issuer mismatch: expected ${expectedIssuer}, got ${tokenIssuer}`,
      );
    }

    // aud MUST contain the client_id.
    const aud = payload.aud;
    if (Array.isArray(aud)) {
      if (!aud.includes(this._oidcClientID)) {
        throw new Error(`OIDC id_token audience does not contain ${this._oidcClientID}`);
      }
    } else if (String(aud) !== this._oidcClientID) {
      throw new Error(
        `OIDC id_token audience mismatch: expected ${this._oidcClientID}, got ${String(aud)}`,
      );
    }

    // exp MUST not be in the past.
    if (typeof payload.exp === 'number' && payload.exp * 1000 < Date.now()) {
      throw new Error('OIDC id_token has expired');
    }

    // nonce MUST match if we sent one (OIDC Core 3.1.3.7).
    if (storedNonce) {
      if (!payload.nonce) {
        throw new Error('OIDC id_token missing nonce claim (possible replay attack)');
      }
      if (String(payload.nonce) !== storedNonce) {
        throw new Error('OIDC id_token nonce mismatch (possible replay attack)');
      }
    }
  }

  /**
   * Fetch the JWKS from the provider's jwks_uri.
   */
  private async _fetchJWKS(): Promise<JWK[]> {
    if (this._jwksCache && Date.now() - this._jwksCache.fetchedAt < 3600_000) {
      return this._jwksCache.keys;
    }

    const res = await fetch(this._jwksUri!);
    if (!res.ok) {
      throw new Error(`OIDC JWKS fetch failed (${res.status})`);
    }

    const jwks = (await res.json()) as { keys: JWK[] };
    this._jwksCache = { keys: jwks.keys, fetchedAt: Date.now() };
    return jwks.keys;
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

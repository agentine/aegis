import { Authenticator } from './authenticator.js';

// Core
export { Authenticator } from './authenticator.js';
export { Strategy } from './strategy.js';

// Errors
export { AuthenticationError } from './errors.js';

// Types
export type {
  AegisRequest,
  AegisResponse,
  NextFunction,
  Middleware,
  AuthenticateOptions,
  AuthInfo,
  DoneCallback,
  SerializeFn,
  DeserializeFn,
  VerifyFn,
  LoginOptions,
  LogoutOptions,
} from './types.js';

// Session
export { SessionStrategy } from './session/session-strategy.js';
export { runSerialize, runDeserialize } from './session/serializer.js';

// Strategies
export { LocalStrategy } from './strategies/local.js';
export type { LocalStrategyOptions } from './strategies/local.js';

export { OAuth2Strategy } from './strategies/oauth2.js';
export type { OAuth2StrategyOptions, OAuth2Profile, OAuth2VerifyFn } from './strategies/oauth2.js';

export { GoogleStrategy } from './strategies/google.js';
export type { GoogleStrategyOptions } from './strategies/google.js';

export { GitHubStrategy } from './strategies/github.js';
export type { GitHubStrategyOptions } from './strategies/github.js';

export { FacebookStrategy } from './strategies/facebook.js';
export type { FacebookStrategyOptions } from './strategies/facebook.js';

export { TwitterStrategy } from './strategies/twitter.js';
export type { TwitterStrategyOptions } from './strategies/twitter.js';

// Passport-compatible default export
const defaultAuthenticator = new Authenticator();
export default defaultAuthenticator;

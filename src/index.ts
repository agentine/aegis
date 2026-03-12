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

// Passport-compatible default export
const defaultAuthenticator = new Authenticator();
export default defaultAuthenticator;

import type { IncomingMessage, ServerResponse } from 'node:http';

// ---- User generics ----

export type DoneCallback<T = unknown> = (err: Error | null, result?: T | false, info?: AuthInfo) => void;
export type AuthInfo = { message?: string; [key: string]: unknown };

// ---- Serialize / Deserialize ----

/** Callback-style serializer */
export type SerializeCallback<User> = (user: User, done: DoneCallback<string | number>) => void;
/** Async serializer */
export type SerializeAsync<User> = (user: User) => Promise<string | number>;
export type SerializeFn<User> = SerializeCallback<User> | SerializeAsync<User>;

/** Callback-style deserializer */
export type DeserializeCallback<User> = (id: string | number, done: DoneCallback<User>) => void;
/** Async deserializer */
export type DeserializeAsync<User> = (id: string | number) => Promise<User | false | null | undefined>;
export type DeserializeFn<User> = DeserializeCallback<User> | DeserializeAsync<User>;

// ---- Verify functions ----

/** Callback-style verify for LocalStrategy */
export type VerifyCallback<User> = (
  username: string,
  password: string,
  done: DoneCallback<User>,
) => void;

/** Async verify for LocalStrategy */
export type VerifyAsync<User> = (
  username: string,
  password: string,
) => Promise<User | false | null | undefined>;

export type VerifyFn<User> = VerifyCallback<User> | VerifyAsync<User>;

// ---- Authenticate options ----

export interface AuthenticateOptions {
  session?: boolean;
  optional?: boolean;
  successRedirect?: string;
  failureRedirect?: string;
  failureMessage?: string | boolean;
  successMessage?: string | boolean;
  failureFlash?: string | boolean;
  successFlash?: string | boolean;
  assignProperty?: string;
  passReqToCallback?: boolean;
}

// ---- Request augmentation ----

export interface AegisRequest extends IncomingMessage {
  user?: unknown;
  authInfo?: AuthInfo;
  session?: Record<string, unknown> & {
    passport?: { user?: unknown };
    regenerate?: (cb: (err?: Error) => void) => void;
    save?: (cb: (err?: Error) => void) => void;
  };
  login: (user: unknown, optionsOrDone?: LoginOptions | DoneCallback<void>, done?: DoneCallback<void>) => void;
  logIn: (user: unknown, optionsOrDone?: LoginOptions | DoneCallback<void>, done?: DoneCallback<void>) => void;
  logout: (optionsOrDone?: LogoutOptions | DoneCallback<void>, done?: DoneCallback<void>) => void;
  logOut: (optionsOrDone?: LogoutOptions | DoneCallback<void>, done?: DoneCallback<void>) => void;
  isAuthenticated: () => boolean;
  isUnauthenticated: () => boolean;
}

export interface LoginOptions {
  session?: boolean;
}

export interface LogoutOptions {
  keepSessionInfo?: boolean;
}

export type AegisResponse = ServerResponse;

export type NextFunction = (err?: Error | 'route') => void;
export type Middleware = (req: AegisRequest, res: AegisResponse, next: NextFunction) => void;

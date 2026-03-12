import type { SerializeFn, DeserializeFn, DoneCallback } from '../types.js';

/**
 * Wraps both callback-style and async serialize/deserialize functions
 * into a consistent async interface.
 */
export function runSerialize<User>(
  fn: SerializeFn<User>,
  user: User,
): Promise<string | number> {
  // Async function (1 arg)
  if (fn.length <= 1) {
    return (fn as (user: User) => Promise<string | number>)(user);
  }
  // Callback function (2 args)
  return new Promise<string | number>((resolve, reject) => {
    (fn as (user: User, done: DoneCallback<string | number>) => void)(
      user,
      (err, id) => {
        if (err) return reject(err);
        resolve(id as string | number);
      },
    );
  });
}

export function runDeserialize<User>(
  fn: DeserializeFn<User>,
  id: string | number,
): Promise<User | false | null | undefined> {
  // Async function (1 arg)
  if (fn.length <= 1) {
    return (fn as (id: string | number) => Promise<User | false | null | undefined>)(id);
  }
  // Callback function (2 args)
  return new Promise<User | false | null | undefined>((resolve, reject) => {
    (fn as (id: string | number, done: DoneCallback<User>) => void)(
      id,
      (err, user) => {
        if (err) return reject(err);
        resolve(user as User | false | null | undefined);
      },
    );
  });
}

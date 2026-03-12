/**
 * Base authentication error.
 */
export class AuthenticationError extends Error {
  public status: number;

  constructor(message: string, status: number = 401) {
    super(message);
    this.name = 'AuthenticationError';
    this.status = status;
  }
}

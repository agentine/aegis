/**
 * Express adapter — aegis middleware works natively with Express.
 * This module re-exports the Authenticator for use with Express apps.
 * No wrapping needed since aegis uses the same (req, res, next) signature.
 */

export { Authenticator } from '../authenticator.js';

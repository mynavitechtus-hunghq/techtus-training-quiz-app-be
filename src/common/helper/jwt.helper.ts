import { join } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';

export function convertExpiry(expiry: string): number {
  const timeValue = parseInt(expiry.slice(0, -1), 10);
  const timeUnit = expiry.slice(-1);

  switch (timeUnit) {
    case 's':
      return timeValue;
    case 'm':
      return timeValue * 60;
    case 'h':
      return timeValue * 3600;
    case 'd':
      return timeValue * 86400;
    default:
      throw new Error('Invalid expiry format');
  }
}

/**
 * Get the private key for JWT signing from environment or file system.
 * @returns Private key string in PEM format
 * @throws Error if private key is not configured
 */
export function getPrivateKey(): string {
  if (process.env.JWT_PRIVATE_KEY) {
    return process.env.JWT_PRIVATE_KEY;
  }

  const keyPath = join(__dirname, '../../../keys/private.pem');
  if (existsSync(keyPath)) {
    return readFileSync(keyPath, 'utf-8');
  }

  throw new Error('JWT_PRIVATE_KEY not configured');
}

/**
 * Get the public key for JWT verification from environment or file system.
 * @returns Public key string in PEM format
 * @throws Error if public key is not configured
 */
export function getPublicKey(): string {
  if (process.env.JWT_PUBLIC_KEY) {
    return process.env.JWT_PUBLIC_KEY;
  }

  const keyPath = join(__dirname, '../../../keys/public.pem');
  if (existsSync(keyPath)) {
    return readFileSync(keyPath, 'utf-8');
  }

  throw new Error('JWT_PUBLIC_KEY not configured');
}

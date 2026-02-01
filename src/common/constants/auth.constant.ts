export const MIN_PASSWORD_LENGTH = 8;
export const MAX_PASSWORD_LENGTH = 32;
export const TOKEN_CONFIG = {
  ACCESS_TOKEN_EXPIRY: process.env.JWT_ACCESS_EXPIRES_IN || '15m',
  REFRESH_TOKEN_EXPIRY: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
} as const;

export const REFRESH_TOKEN_EXPIRY_DAYS = 7;

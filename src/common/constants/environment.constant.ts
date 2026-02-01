/**
 * Environment constants for the application
 */
export const ENVIRONMENT = {
  DEVELOPMENT: 'development',
  PRODUCTION: 'production',
  TEST: 'test',
} as const;

/**
 * Environment variable keys
 */
export const ENV_KEYS = {
  NODE_ENV: 'NODE_ENV',
} as const;

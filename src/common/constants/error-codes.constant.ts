/**
 * Authentication error codes for the application.
 * All codes follow the AUTH-XXX format where XXX is a 3-digit number.
 */
export const AUTH_ERROR_CODES = {
  /** Password and confirmation password do not match */
  PASSWORD_MISMATCH: 'AUTH-001',
  /** Email address is already registered */
  EMAIL_ALREADY_EXISTS: 'AUTH-002',
  /** User account not found */
  USER_NOT_FOUND: 'AUTH-003',
  /** Invalid email or password */
  INVALID_CREDENTIALS: 'AUTH-004',
  /** Session does not exist in database */
  SESSION_NOT_FOUND: 'AUTH-005',
  /** Session has been revoked/invalidated */
  SESSION_REVOKED: 'AUTH-006',
  /** Session has expired */
  SESSION_EXPIRED: 'AUTH-007',
  /** Refresh token is invalid or malformed */
  INVALID_REFRESH_TOKEN: 'AUTH-008',
  /** User has exceeded maximum allowed sessions */
  MAX_SESSIONS_EXCEEDED: 'AUTH-009',
  /** Access token has expired */
  TOKEN_EXPIRED: 'AUTH-010',
  /** Access token is invalid or malformed */
  INVALID_ACCESS_TOKEN: 'AUTH-011',
} as const;

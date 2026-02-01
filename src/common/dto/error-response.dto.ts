import { ApiProperty } from '@nestjs/swagger';

/**
 * Standard error response DTO for API documentation
 */
export class ErrorResponseDto {
  @ApiProperty({
    description: 'HTTP status code',
    example: 400,
  })
  statusCode: number;

  @ApiProperty({
    description: 'Error code for client handling',
    example: 'AUTH-001',
  })
  message: string;

  @ApiProperty({
    description: 'Error type/reason',
    example: 'Bad Request',
  })
  error: string;
}

/**
 * Authentication error responses for Swagger documentation
 *
 * Error Code Reference:
 * - AUTH-001: Password mismatch during sign-up
 * - AUTH-002: Email already exists during sign-up
 * - AUTH-003: User not found during sign-in
 * - AUTH-004: Invalid credentials (wrong password)
 * - AUTH-005: Session not found in database
 * - AUTH-006: Session has been revoked/logged out
 * - AUTH-007: Session has expired (beyond expiry time)
 * - AUTH-008: Refresh token format is invalid
 * - AUTH-009: Maximum sessions limit exceeded
 * - AUTH-010: Access token has expired (trigger refresh)
 * - AUTH-011: Access token is invalid or malformed
 */
export const AUTH_ERROR_RESPONSES = {
  PASSWORD_MISMATCH: {
    status: 400,
    description:
      '**[AUTH-001]** Password and confirmation password do not match. Frontend should validate passwords match before submission.',
    schema: {
      example: {
        statusCode: 400,
        message: 'AUTH-001',
        error: 'Bad Request',
      },
    },
  },
  EMAIL_ALREADY_EXISTS: {
    status: 409,
    description:
      '**[AUTH-002]** Email address is already registered. Frontend should prompt user to sign in instead or use a different email.',
    schema: {
      example: {
        statusCode: 409,
        message: 'AUTH-002',
        error: 'Conflict',
      },
    },
  },
  USER_NOT_FOUND: {
    status: 404,
    description:
      '**[AUTH-003]** User account not found. The email address is not registered in the system.',
    schema: {
      example: {
        statusCode: 404,
        message: 'AUTH-003',
        error: 'Not Found',
      },
    },
  },
  INVALID_CREDENTIALS: {
    status: 401,
    description:
      "**[AUTH-004]** Invalid email or password. Frontend should display a generic error message for security (don't reveal which field is wrong).",
    schema: {
      example: {
        statusCode: 401,
        message: 'AUTH-004',
        error: 'Unauthorized',
      },
    },
  },
  SESSION_NOT_FOUND: {
    status: 404,
    description:
      '**[AUTH-005]** Session does not exist in database. The session may have been deleted. Frontend should redirect to login.',
    schema: {
      example: {
        statusCode: 404,
        message: 'AUTH-005',
        error: 'Not Found',
      },
    },
  },
  SESSION_REVOKED: {
    status: 401,
    description:
      '**[AUTH-006]** Session has been revoked/invalidated (user logged out). Frontend should clear tokens and redirect to login.',
    schema: {
      example: {
        statusCode: 401,
        message: 'AUTH-006',
        error: 'Unauthorized',
      },
    },
  },
  SESSION_EXPIRED: {
    status: 401,
    description:
      '**[AUTH-007]** Session has expired beyond its expiration time. Frontend should clear tokens and redirect to login (cannot be refreshed).',
    schema: {
      example: {
        statusCode: 401,
        message: 'AUTH-007',
        error: 'Unauthorized',
      },
    },
  },
  INVALID_REFRESH_TOKEN: {
    status: 401,
    description:
      '**[AUTH-008]** Refresh token is invalid or malformed (JWT format error). Frontend should clear tokens and redirect to login.',
    schema: {
      example: {
        statusCode: 401,
        message: 'AUTH-008',
        error: 'Unauthorized',
      },
    },
  },
  MAX_SESSIONS_EXCEEDED: {
    status: 403,
    description:
      '**[AUTH-009]** User has exceeded maximum allowed sessions. Frontend should prompt user to log out from other devices or try again later.',
    schema: {
      example: {
        statusCode: 403,
        message: 'AUTH-009',
        error: 'Forbidden',
      },
    },
  },
  TOKEN_EXPIRED: {
    status: 401,
    description:
      '**[AUTH-010]** Access token has expired. **Frontend should automatically call /auth/refresh-token endpoint** with the refresh token to get new tokens.',
    schema: {
      example: {
        statusCode: 401,
        message: 'AUTH-010',
        error: 'Unauthorized',
      },
    },
  },
  INVALID_ACCESS_TOKEN: {
    status: 401,
    description:
      '**[AUTH-011]** Access token is invalid or malformed. Frontend should clear tokens and redirect to login.',
    schema: {
      example: {
        statusCode: 401,
        message: 'AUTH-011',
        error: 'Unauthorized',
      },
    },
  },
} as const;

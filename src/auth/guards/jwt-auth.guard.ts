import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AUTH_ERROR_CODES } from '@/common/constants/error-codes.constant';

/**
 * JWT Authentication Guard that validates access tokens.
 * Extends Passport's AuthGuard to provide custom error handling.
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  /**
   * Handles the authentication request and provides custom error messages.
   * @param err - Error from the authentication process
   * @param user - Authenticated user object
   * @param info - Additional information about the authentication failure
   * @returns Authenticated user object
   * @throws UnauthorizedException with appropriate error code
   */
  handleRequest<TUser = { userId: string; email: string }>(
    err: Error | null,
    user: TUser | false,
    info: { name?: string } | undefined,
  ): TUser {
    // Handle expired token
    if (info?.name === 'TokenExpiredError') {
      throw new UnauthorizedException({
        errorCode: AUTH_ERROR_CODES.TOKEN_EXPIRED,
        message: 'Access token has expired',
      });
    }

    // Handle invalid token or missing user
    if (err || !user) {
      throw new UnauthorizedException({
        errorCode: AUTH_ERROR_CODES.INVALID_ACCESS_TOKEN,
        message: 'Invalid or missing access token',
      });
    }

    return user;
  }
}

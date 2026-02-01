import { UnauthorizedException } from '@nestjs/common';

/* eslint-disable @typescript-eslint/no-unsafe-member-access */
import { JwtAuthGuard } from './jwt-auth.guard';
import { AUTH_ERROR_CODES } from '@/common/constants/error-codes.constant';

describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard;

  beforeEach(() => {
    guard = new JwtAuthGuard();
  });

  describe('handleRequest', () => {
    it('should return user when valid', () => {
      const user = { userId: 'user-123', email: 'test@example.com' };

      const result = guard.handleRequest(null, user, undefined);

      expect(result).toEqual(user);
    });

    it('should throw UnauthorizedException with TOKEN_EXPIRED for expired token', () => {
      const info = { name: 'TokenExpiredError', message: 'jwt expired' };

      expect(() => guard.handleRequest(null, null, info)).toThrow(
        UnauthorizedException,
      );

      try {
        guard.handleRequest(null, null, info);
      } catch (error) {
        expect(error).toBeInstanceOf(UnauthorizedException);
        expect(error.response.errorCode).toBe(AUTH_ERROR_CODES.TOKEN_EXPIRED);
      }
    });

    it('should throw UnauthorizedException with INVALID_ACCESS_TOKEN for invalid token', () => {
      const info = { name: 'JsonWebTokenError', message: 'invalid signature' };

      expect(() => guard.handleRequest(null, null, info)).toThrow(
        UnauthorizedException,
      );

      try {
        guard.handleRequest(null, null, info);
      } catch (error) {
        expect(error).toBeInstanceOf(UnauthorizedException);
        expect(error.response.errorCode).toBe(
          AUTH_ERROR_CODES.INVALID_ACCESS_TOKEN,
        );
      }
    });

    it('should throw UnauthorizedException when user is null', () => {
      expect(() => guard.handleRequest(null, null, undefined)).toThrow(
        UnauthorizedException,
      );

      try {
        guard.handleRequest(null, null, undefined);
      } catch (error) {
        expect(error).toBeInstanceOf(UnauthorizedException);
        expect(error.response.errorCode).toBe(
          AUTH_ERROR_CODES.INVALID_ACCESS_TOKEN,
        );
      }
    });

    it('should throw UnauthorizedException when error exists', () => {
      const error = new Error('Authentication failed');
      const user = { userId: 'user-123', email: 'test@example.com' };

      expect(() => guard.handleRequest(error, user, undefined)).toThrow(
        UnauthorizedException,
      );

      try {
        guard.handleRequest(error, user, undefined);
      } catch (err) {
        expect(err).toBeInstanceOf(UnauthorizedException);
        expect(err.response.errorCode).toBe(
          AUTH_ERROR_CODES.INVALID_ACCESS_TOKEN,
        );
      }
    });

    it('should throw UnauthorizedException for malformed token', () => {
      const info = { name: 'JsonWebTokenError', message: 'jwt malformed' };

      expect(() => guard.handleRequest(null, null, info)).toThrow(
        UnauthorizedException,
      );

      try {
        guard.handleRequest(null, null, info);
      } catch (error) {
        expect(error).toBeInstanceOf(UnauthorizedException);
        expect(error.response.errorCode).toBe(
          AUTH_ERROR_CODES.INVALID_ACCESS_TOKEN,
        );
      }
    });

    it('should throw UnauthorizedException for NotBeforeError', () => {
      const info = { name: 'NotBeforeError', message: 'jwt not active' };

      expect(() => guard.handleRequest(null, null, info)).toThrow(
        UnauthorizedException,
      );

      try {
        guard.handleRequest(null, null, info);
      } catch (error) {
        expect(error).toBeInstanceOf(UnauthorizedException);
        expect(error.response.errorCode).toBe(
          AUTH_ERROR_CODES.INVALID_ACCESS_TOKEN,
        );
      }
    });
  });
});

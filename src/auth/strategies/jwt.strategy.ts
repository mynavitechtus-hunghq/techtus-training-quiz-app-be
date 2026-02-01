import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

import { getPublicKey } from '@/common/helper/jwt.helper';

/**
 * JWT authentication strategy for validating access tokens.
 * Uses RS256 algorithm with public key verification.
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: getPublicKey(),
      algorithms: ['RS256'],
    });
  }

  /**
   * Validates the JWT payload and extracts user information.
   * @param payload - Decoded JWT payload
   * @returns User object with userId and email
   * @throws UnauthorizedException if payload is invalid
   */
  validate(payload: { sub?: unknown; email?: unknown }) {
    if (!payload.sub || !payload.email) {
      throw new UnauthorizedException({
        message: 'Invalid token payload',
      });
    }

    if (typeof payload.sub !== 'string' || payload.sub.trim() === '') {
      throw new UnauthorizedException({
        message: 'Invalid user ID in token',
      });
    }

    if (typeof payload.email !== 'string' || payload.email.trim() === '') {
      throw new UnauthorizedException({
        message: 'Invalid email in token',
      });
    }

    return {
      userId: payload.sub,
      email: payload.email,
    };
  }
}

import { Test, TestingModule } from '@nestjs/testing';
import { JwtStrategy } from './jwt.strategy';
import { UnauthorizedException } from '@nestjs/common';

// Mock the helper functions
jest.mock('@/common/helper/jwt.helper', () => ({
  getPublicKey: jest.fn(() => 'mock-public-key'),
}));

describe('JwtStrategy', () => {
  let strategy: JwtStrategy;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [JwtStrategy],
    }).compile();

    strategy = module.get<JwtStrategy>(JwtStrategy);
  });

  describe('validate', () => {
    it('should extract user from valid token payload', () => {
      const payload = {
        sub: 'user-id-123',
        email: 'test@example.com',
      };

      const result = strategy.validate(payload);

      expect(result).toBeDefined();
      expect(result.userId).toBe('user-id-123');
      expect(result.email).toBe('test@example.com');
    });

    it('should return user object with id and email', () => {
      const payload = {
        sub: 'user-id-456',
        email: 'user@test.com',
      };

      const result = strategy.validate(payload);

      expect(result).toHaveProperty('userId');
      expect(result).toHaveProperty('email');
      expect(Object.keys(result).sort()).toEqual(['email', 'userId'].sort());
    });

    it('should handle token with sub claim', () => {
      const payload = {
        sub: 'unique-user-id',
        email: 'valid@example.com',
        iat: 1234567890,
      };

      const result = strategy.validate(payload);

      expect(result.userId).toBe('unique-user-id');
    });

    it('should reject payload without sub', () => {
      const payload = {
        email: 'test@example.com',
      };

      expect(() => strategy.validate(payload)).toThrow(UnauthorizedException);
    });

    it('should reject payload without email', () => {
      const payload = {
        sub: 'user-id-123',
      };

      expect(() => strategy.validate(payload)).toThrow(UnauthorizedException);
    });

    it('should reject empty sub', () => {
      const payload = {
        sub: '',
        email: 'test@example.com',
      };

      expect(() => strategy.validate(payload)).toThrow(UnauthorizedException);
    });

    it('should reject empty email', () => {
      const payload = {
        sub: 'user-id-123',
        email: '',
      };

      expect(() => strategy.validate(payload)).toThrow(UnauthorizedException);
    });
  });
});

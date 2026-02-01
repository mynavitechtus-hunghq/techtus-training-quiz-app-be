/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { Test, TestingModule } from '@nestjs/testing';
import {
  BadRequestException,
  ConflictException,
  UnauthorizedException,
  ValidationPipe,
} from '@nestjs/common';
import type { Request } from 'express';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { SignUpResponseDto } from './dto/sign-up-response.dto';
import { SignInResponseDto } from './dto/sign-in-response.dto';
import { RefreshTokenResponseDto } from './dto/refresh-token-response.dto';
import { AUTH_ERROR_CODES } from '@/common/constants/error-codes.constant';
import { expectExceptionWithCode } from '@test/helpers/exception.helper';
import {
  MAX_PASSWORD_LENGTH,
  MIN_PASSWORD_LENGTH,
} from '@/common/constants/auth.constant';

const mockAuthService = {
  signUp: jest.fn(),
  signIn: jest.fn(),
  refreshToken: jest.fn(),
};

const validSignUpDto: SignUpDto = {
  email: 'test@example.com',
  password: 'StrongPassword123!',
  confirmPassword: 'StrongPassword123!',
};

const validSignInDto: SignInDto = {
  email: 'test@example.com',
  password: 'StrongPassword123!',
};

const mockSignUpResponse: SignUpResponseDto = {
  id: 'uuid-123',
  email: validSignUpDto.email,
  createdAt: new Date(),
  updatedAt: new Date(),
};

const mockSignInResponse: SignInResponseDto = {
  accessToken: 'mock-access-token',
  refreshToken: 'mock-refresh-token',
};

const mockRequest = {
  ip: '127.0.0.1',
  headers: {
    'user-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)',
  },
} as unknown as Request;

describe('auth.controller', () => {
  let controller: AuthController;
  let validationPipe: ValidationPipe;

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
      ],
      controllers: [AuthController],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    validationPipe = new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    });
  });

  describe('POST /auth/sign-up', () => {
    it('should return 201 with user data', async () => {
      mockAuthService.signUp.mockResolvedValue(mockSignUpResponse);

      const result = await controller.signUp(validSignUpDto);

      expect(mockAuthService.signUp).toHaveBeenCalledWith(validSignUpDto);
      expect(result).toEqual(mockSignUpResponse);
      expect(result).not.toHaveProperty('password');
    });

    describe('validation', () => {
      it('should reject password shorter than MIN_PASSWORD_LENGTH', async () => {
        const dto: SignUpDto = {
          email: 'test@example.com',
          password: 'Test1!',
          confirmPassword: 'Test1!',
        };

        await expect(
          validationPipe.transform(dto, {
            type: 'body',
            metatype: SignUpDto,
          }),
        ).rejects.toThrow();
      });

      it('should reject password longer than MAX_PASSWORD_LENGTH', async () => {
        const longPassword = 'A'.repeat(MAX_PASSWORD_LENGTH + 1) + '1!';
        const dto: SignUpDto = {
          email: 'test@example.com',
          password: longPassword,
          confirmPassword: longPassword,
        };

        await expect(
          validationPipe.transform(dto, {
            type: 'body',
            metatype: SignUpDto,
          }),
        ).rejects.toThrow();
      });

      it('should reject invalid email format', async () => {
        const dto: SignUpDto = {
          email: 'invalid-email',
          password: 'StrongPassword123!',
          confirmPassword: 'StrongPassword123!',
        };

        await expect(
          validationPipe.transform(dto, {
            type: 'body',
            metatype: SignUpDto,
          }),
        ).rejects.toThrow();
      });

      it('should reject empty email', async () => {
        const dto = {
          email: '',
          password: 'StrongPassword123!',
          confirmPassword: 'StrongPassword123!',
        };

        await expect(
          validationPipe.transform(dto, {
            type: 'body',
            metatype: SignUpDto,
          }),
        ).rejects.toThrow();
      });

      it('should reject empty password', async () => {
        const dto = {
          email: 'test@example.com',
          password: '',
          confirmPassword: '',
        };

        await expect(
          validationPipe.transform(dto, {
            type: 'body',
            metatype: SignUpDto,
          }),
        ).rejects.toThrow();
      });

      it('should reject when password is exactly MIN_PASSWORD_LENGTH - 1', async () => {
        const shortPassword = 'A'.repeat(MIN_PASSWORD_LENGTH - 1);
        const dto: SignUpDto = {
          email: 'test@example.com',
          password: shortPassword,
          confirmPassword: shortPassword,
        };

        await expect(
          validationPipe.transform(dto, {
            type: 'body',
            metatype: SignUpDto,
          }),
        ).rejects.toThrow();
      });

      it('should accept password at exactly MIN_PASSWORD_LENGTH', async () => {
        const minPassword = 'A'.repeat(MIN_PASSWORD_LENGTH);
        const dto: SignUpDto = {
          email: 'test@example.com',
          password: minPassword,
          confirmPassword: minPassword,
        };

        const result = await validationPipe.transform(dto, {
          type: 'body',
          metatype: SignUpDto,
        });

        expect(result).toEqual(dto);
      });

      it('should accept password at exactly MAX_PASSWORD_LENGTH', async () => {
        const maxPassword = 'A'.repeat(MAX_PASSWORD_LENGTH);
        const dto: SignUpDto = {
          email: 'test@example.com',
          password: maxPassword,
          confirmPassword: maxPassword,
        };

        const result = await validationPipe.transform(dto, {
          type: 'body',
          metatype: SignUpDto,
        });

        expect(result).toEqual(dto);
      });

      it('should reject unknown properties when forbidNonWhitelisted is true', async () => {
        const dto = {
          email: 'test@example.com',
          password: 'StrongPassword123!',
          confirmPassword: 'StrongPassword123!',
          unknownField: 'should cause error',
        };

        await expect(
          validationPipe.transform(dto, {
            type: 'body',
            metatype: SignUpDto,
          }),
        ).rejects.toThrow();
      });
    });

    it('should return 400 when validation fails', async () => {
      const dto: SignUpDto = {
        ...validSignUpDto,
        confirmPassword: 'DifferentPassword!',
      };

      mockAuthService.signUp.mockRejectedValue(
        new BadRequestException({
          errorCode: AUTH_ERROR_CODES.PASSWORD_MISMATCH,
        }),
      );

      await expectExceptionWithCode(
        controller.signUp(dto),
        BadRequestException,
        AUTH_ERROR_CODES.PASSWORD_MISMATCH,
      );
      expect(mockAuthService.signUp).toHaveBeenCalledWith(dto);
    });

    it('should return 409 when email already exists', async () => {
      const dto: SignUpDto = {
        ...validSignUpDto,
      };

      mockAuthService.signUp.mockRejectedValue(
        new ConflictException({
          errorCode: AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS,
        }),
      );

      await expectExceptionWithCode(
        controller.signUp(dto),
        ConflictException,
        AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS,
      );
      expect(mockAuthService.signUp).toHaveBeenCalledWith(dto);
    });
  });

  describe('POST /auth/sign-in', () => {
    describe('when successful', () => {
      it('should return 200 with accessToken and refreshToken', async () => {
        mockAuthService.signIn.mockResolvedValue(mockSignInResponse);

        const result = await controller.signIn(validSignInDto, mockRequest);

        expect(mockAuthService.signIn).toHaveBeenCalledWith(validSignInDto, {
          ip: '127.0.0.1',
          userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)',
        });
        expect(result).toEqual(mockSignInResponse);
        expect(result).toHaveProperty('accessToken');
        expect(result).toHaveProperty('refreshToken');
      });

      it('should pass request IP to service', async () => {
        mockAuthService.signIn.mockResolvedValue(mockSignInResponse);

        await controller.signIn(validSignInDto, mockRequest);

        expect(mockAuthService.signIn).toHaveBeenCalledWith(
          validSignInDto,
          expect.objectContaining({ ip: '127.0.0.1' }),
        );
      });

      it('should pass request user-agent to service', async () => {
        mockAuthService.signIn.mockResolvedValue(mockSignInResponse);

        await controller.signIn(validSignInDto, mockRequest);

        expect(mockAuthService.signIn).toHaveBeenCalledWith(
          validSignInDto,
          expect.objectContaining({
            userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)',
          }),
        );
      });

      it('should handle missing IP address', async () => {
        mockAuthService.signIn.mockResolvedValue(mockSignInResponse);
        const reqWithoutIp = {
          headers: mockRequest.headers,
        } as unknown as Request;

        await controller.signIn(validSignInDto, reqWithoutIp);

        expect(mockAuthService.signIn).toHaveBeenCalledWith(
          validSignInDto,
          expect.objectContaining({ ip: 'unknown' }),
        );
      });

      it('should handle missing user-agent', async () => {
        mockAuthService.signIn.mockResolvedValue(mockSignInResponse);
        const reqWithoutUA = {
          ip: '127.0.0.1',
          headers: {},
        } as unknown as Request;

        await controller.signIn(validSignInDto, reqWithoutUA);

        expect(mockAuthService.signIn).toHaveBeenCalledWith(
          validSignInDto,
          expect.objectContaining({ userAgent: undefined }),
        );
      });
    });

    describe('when user not found', () => {
      it('should return 401 with INVALID_CREDENTIALS error code', async () => {
        mockAuthService.signIn.mockRejectedValue(
          new UnauthorizedException({
            errorCode: AUTH_ERROR_CODES.INVALID_CREDENTIALS,
          }),
        );

        await expectExceptionWithCode(
          controller.signIn(validSignInDto, mockRequest),
          UnauthorizedException,
          AUTH_ERROR_CODES.INVALID_CREDENTIALS,
        );
      });
    });

    describe('when password is invalid', () => {
      it('should return 401 with INVALID_CREDENTIALS error code', async () => {
        const dtoWithWrongPassword: SignInDto = {
          ...validSignInDto,
          password: 'WrongPassword123!',
        };

        mockAuthService.signIn.mockRejectedValue(
          new UnauthorizedException({
            errorCode: AUTH_ERROR_CODES.INVALID_CREDENTIALS,
          }),
        );

        await expectExceptionWithCode(
          controller.signIn(dtoWithWrongPassword, mockRequest),
          UnauthorizedException,
          AUTH_ERROR_CODES.INVALID_CREDENTIALS,
        );
      });
    });

    describe('input validation', () => {
      it('should accept valid email and password', async () => {
        mockAuthService.signIn.mockResolvedValue(mockSignInResponse);

        await controller.signIn(validSignInDto, mockRequest);

        expect(mockAuthService.signIn).toHaveBeenCalledWith(
          validSignInDto,
          expect.any(Object),
        );
      });

      it('should call service with exact DTO values', async () => {
        mockAuthService.signIn.mockResolvedValue(mockSignInResponse);

        await controller.signIn(validSignInDto, mockRequest);

        expect(mockAuthService.signIn).toHaveBeenCalledWith(
          expect.objectContaining({
            email: 'test@example.com',
            password: 'StrongPassword123!',
          }),
          expect.any(Object),
        );
      });

      it('should reject password shorter than MIN_PASSWORD_LENGTH', async () => {
        const dto: SignInDto = {
          email: 'test@example.com',
          password: 'test1',
        };

        await expect(
          validationPipe.transform(dto, {
            type: 'body',
            metatype: SignInDto,
          }),
        ).rejects.toThrow();
      });

      it('should reject password longer than MAX_PASSWORD_LENGTH', async () => {
        const longPassword = 'A'.repeat(MAX_PASSWORD_LENGTH + 1) + '1!';
        const dto: SignInDto = {
          email: 'test@example.com',
          password: longPassword,
        };

        await expect(
          validationPipe.transform(dto, {
            type: 'body',
            metatype: SignInDto,
          }),
        ).rejects.toThrow();
      });

      it('should reject invalid email format', async () => {
        const dto: SignInDto = {
          email: 'invalid-email',
          password: 'StrongPassword123!',
        };

        await expect(
          validationPipe.transform(dto, {
            type: 'body',
            metatype: SignInDto,
          }),
        ).rejects.toThrow();
      });

      it('should reject empty email', async () => {
        const dto = {
          email: '',
          password: 'StrongPassword123!',
        };

        await expect(
          validationPipe.transform(dto, {
            type: 'body',
            metatype: SignInDto,
          }),
        ).rejects.toThrow();
      });

      it('should reject empty password', async () => {
        const dto = {
          email: 'test@example.com',
          password: '',
        };

        await expect(
          validationPipe.transform(dto, {
            type: 'body',
            metatype: SignInDto,
          }),
        ).rejects.toThrow();
      });
    });
  });

  describe('POST /auth/refresh-token', () => {
    const validRefreshTokenDto: RefreshTokenDto = {
      refreshToken:
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA',
    };

    const mockRefreshResponse: RefreshTokenResponseDto = {
      accessToken: 'new-access-token',
      refreshToken: 'new-refresh-token',
    };

    describe('when successful', () => {
      it('should return 200 with new tokens', async () => {
        mockAuthService.refreshToken.mockResolvedValue(mockRefreshResponse);

        const result = await controller.refreshToken(
          validRefreshTokenDto,
          mockRequest,
        );

        expect(result).toEqual(mockRefreshResponse);
        expect(result).toHaveProperty('accessToken');
        expect(result).toHaveProperty('refreshToken');
      });

      it('should call authService.refreshToken with correct params', async () => {
        mockAuthService.refreshToken.mockResolvedValue(mockRefreshResponse);

        await controller.refreshToken(validRefreshTokenDto, mockRequest);

        expect(mockAuthService.refreshToken).toHaveBeenCalledWith(
          validRefreshTokenDto.refreshToken,
          {
            ip: '127.0.0.1',
            userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)',
          },
        );
      });

      it('should pass client IP to service', async () => {
        mockAuthService.refreshToken.mockResolvedValue(mockRefreshResponse);

        await controller.refreshToken(validRefreshTokenDto, mockRequest);

        expect(mockAuthService.refreshToken).toHaveBeenCalledWith(
          validRefreshTokenDto.refreshToken,
          expect.objectContaining({ ip: '127.0.0.1' }),
        );
      });

      it('should pass user-agent to service', async () => {
        mockAuthService.refreshToken.mockResolvedValue(mockRefreshResponse);

        await controller.refreshToken(validRefreshTokenDto, mockRequest);

        expect(mockAuthService.refreshToken).toHaveBeenCalledWith(
          validRefreshTokenDto.refreshToken,
          expect.objectContaining({
            userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)',
          }),
        );
      });

      it('should return tokens matching expected structure', async () => {
        mockAuthService.refreshToken.mockResolvedValue(mockRefreshResponse);

        const result = await controller.refreshToken(
          validRefreshTokenDto,
          mockRequest,
        );

        expect(typeof result.accessToken).toBe('string');
        expect(typeof result.refreshToken).toBe('string');
        expect(Object.keys(result).sort()).toEqual(
          ['accessToken', 'refreshToken'].sort(),
        );
      });
    });

    describe('validation errors', () => {
      it('should return 400 when refreshToken is missing', async () => {
        const dto = {} as RefreshTokenDto;

        await expect(
          validationPipe.transform(dto, {
            type: 'body',
            metatype: RefreshTokenDto,
          }),
        ).rejects.toThrow();
      });

      it('should return 400 when refreshToken is empty', async () => {
        const dto: RefreshTokenDto = {
          refreshToken: '',
        };

        await expect(
          validationPipe.transform(dto, {
            type: 'body',
            metatype: RefreshTokenDto,
          }),
        ).rejects.toThrow();
      });

      it('should return 400 when refreshToken is not a string', async () => {
        const dto = {
          refreshToken: 123456,
        } as any;

        await expect(
          validationPipe.transform(dto, {
            type: 'body',
            metatype: RefreshTokenDto,
          }),
        ).rejects.toThrow();
      });

      it('should return 400 when refreshToken is not valid JWT', async () => {
        const dto: RefreshTokenDto = {
          refreshToken: 'not.a.valid.jwt',
        };

        await expect(
          validationPipe.transform(dto, {
            type: 'body',
            metatype: RefreshTokenDto,
          }),
        ).rejects.toThrow();
      });
    });

    describe('authentication errors', () => {
      it('should return 401 with AUTH-008 when token is invalid', async () => {
        mockAuthService.refreshToken.mockRejectedValue(
          new UnauthorizedException({
            errorCode: AUTH_ERROR_CODES.INVALID_REFRESH_TOKEN,
          }),
        );

        await expectExceptionWithCode(
          controller.refreshToken(validRefreshTokenDto, mockRequest),
          UnauthorizedException,
          AUTH_ERROR_CODES.INVALID_REFRESH_TOKEN,
        );
      });

      it('should return 401 with AUTH-005 when session not found', async () => {
        mockAuthService.refreshToken.mockRejectedValue(
          new UnauthorizedException({
            errorCode: AUTH_ERROR_CODES.SESSION_NOT_FOUND,
          }),
        );

        await expectExceptionWithCode(
          controller.refreshToken(validRefreshTokenDto, mockRequest),
          UnauthorizedException,
          AUTH_ERROR_CODES.SESSION_NOT_FOUND,
        );
      });

      it('should return 401 with AUTH-006 when session is revoked', async () => {
        mockAuthService.refreshToken.mockRejectedValue(
          new UnauthorizedException({
            errorCode: AUTH_ERROR_CODES.SESSION_REVOKED,
          }),
        );

        await expectExceptionWithCode(
          controller.refreshToken(validRefreshTokenDto, mockRequest),
          UnauthorizedException,
          AUTH_ERROR_CODES.SESSION_REVOKED,
        );
      });

      it('should return 401 with AUTH-007 when session is expired', async () => {
        mockAuthService.refreshToken.mockRejectedValue(
          new UnauthorizedException({
            errorCode: AUTH_ERROR_CODES.SESSION_EXPIRED,
          }),
        );

        await expectExceptionWithCode(
          controller.refreshToken(validRefreshTokenDto, mockRequest),
          UnauthorizedException,
          AUTH_ERROR_CODES.SESSION_EXPIRED,
        );
      });
    });

    describe('request context handling', () => {
      it('should extract IP from x-forwarded-for header', async () => {
        mockAuthService.refreshToken.mockResolvedValue(mockRefreshResponse);

        const requestWithForwardedIp = {
          ...mockRequest,
          headers: {
            ...mockRequest.headers,
            'x-forwarded-for': '203.0.113.5, 198.51.100.1',
          },
        } as unknown as Request;

        await controller.refreshToken(
          validRefreshTokenDto,
          requestWithForwardedIp,
        );

        expect(mockAuthService.refreshToken).toHaveBeenCalledWith(
          validRefreshTokenDto.refreshToken,
          expect.objectContaining({
            ip: '203.0.113.5',
          }),
        );
      });

      it('should normalize IPv6 localhost to 127.0.0.1', async () => {
        mockAuthService.refreshToken.mockResolvedValue(mockRefreshResponse);

        const requestWithIPv6 = {
          ...mockRequest,
          ip: '::1',
        } as unknown as Request;

        await controller.refreshToken(validRefreshTokenDto, requestWithIPv6);

        expect(mockAuthService.refreshToken).toHaveBeenCalledWith(
          validRefreshTokenDto.refreshToken,
          expect.objectContaining({
            ip: '127.0.0.1',
          }),
        );
      });

      it('should extract user-agent from headers', async () => {
        mockAuthService.refreshToken.mockResolvedValue(mockRefreshResponse);

        const customRequest = {
          ...mockRequest,
          headers: {
            'user-agent': 'Custom User Agent/1.0',
          },
        } as unknown as Request;

        await controller.refreshToken(validRefreshTokenDto, customRequest);

        expect(mockAuthService.refreshToken).toHaveBeenCalledWith(
          validRefreshTokenDto.refreshToken,
          expect.objectContaining({
            userAgent: 'Custom User Agent/1.0',
          }),
        );
      });
    });
  });
});

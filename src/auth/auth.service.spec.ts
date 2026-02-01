import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';

jest.mock('bcrypt');
jest.mock('uuid', () => ({ v4: jest.fn(() => 'mock-uuid-123') }));

import { AuthService } from './auth.service';
import { SignUpDto } from './dto/sign-up.dto';
import { SignUpResponseDto } from './dto/sign-up-response.dto';
import { SignInDto } from './dto/sign-in.dto';
import { SignInResponseDto } from './dto/sign-in-response.dto';
import { User } from '@/entities/User';
import { Session } from '@/entities/Session';
import {
  BadRequestException,
  ConflictException,
  UnauthorizedException,
} from '@nestjs/common';
import { AUTH_ERROR_CODES } from '@/common/constants/error-codes.constant';
import { expectExceptionWithCode } from '@test/helpers/exception.helper';

const mockUserRepository = {
  create: jest.fn(),
  save: jest.fn(),
  findOne: jest.fn(),
};

const mockSessionRepository = {
  create: jest.fn(),
  save: jest.fn(),
  findOne: jest.fn(),
  find: jest.fn(),
  count: jest.fn(),
  createQueryBuilder: jest.fn(),
};

const mockJwtService = {
  sign: jest.fn(),
  verify: jest.fn(),
};

const validSignUpDto: SignUpDto = {
  email: 'test@example.com',
  password: 'StrongPassword123!',
  confirmPassword: 'StrongPassword123!',
};

const mockHashedPassword = 'hashedPassword123';

const mockSavedUser = {
  id: 'uuid-123',
  email: validSignUpDto.email,
  password: mockHashedPassword,
  createdAt: new Date(),
  updatedAt: new Date(),
};

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    jest.clearAllMocks();

    (bcrypt.hash as jest.Mock).mockResolvedValue(mockHashedPassword as never);

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getRepositoryToken(User),
          useValue: mockUserRepository,
        },
        {
          provide: getRepositoryToken(Session),
          useValue: mockSessionRepository,
        },
        {
          provide: JwtService,
          useValue: mockJwtService,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  describe('signUp', () => {
    describe('when successful', () => {
      beforeEach(() => {
        mockUserRepository.findOne.mockResolvedValue(null);
        mockUserRepository.create.mockReturnValue(mockSavedUser);
        mockUserRepository.save.mockResolvedValue(mockSavedUser);
      });

      it('should create a new user with hashed password', async () => {
        const result: SignUpResponseDto = await service.signUp(validSignUpDto);

        expect(bcrypt.hash).toHaveBeenCalledWith(
          validSignUpDto.password,
          expect.any(Number),
        );
        expect(mockUserRepository.save).toHaveBeenCalled();
        expect(mockUserRepository.create).toHaveBeenCalledWith({
          email: validSignUpDto.email,
          password: mockHashedPassword,
        });
        expect(result).not.toHaveProperty('password');
        expect(result.email).toBe(validSignUpDto.email);
      });

      it('should call findOne with correct email', async () => {
        await service.signUp(validSignUpDto);

        expect(mockUserRepository.findOne).toHaveBeenCalledWith({
          where: { email: validSignUpDto.email },
        });
      });
    });

    describe('when passwords do not match', () => {
      it('should throw BadRequestException with PASSWORD_MISMATCH error code', async () => {
        const dto: SignUpDto = {
          ...validSignUpDto,
          confirmPassword: 'differentPassword!',
        };

        await expectExceptionWithCode(
          service.signUp(dto),
          BadRequestException,
          AUTH_ERROR_CODES.PASSWORD_MISMATCH,
        );

        expect(mockUserRepository.findOne).not.toHaveBeenCalled();
      });

      it('should not hash password when passwords do not match', async () => {
        const dto: SignUpDto = {
          ...validSignUpDto,
          confirmPassword: 'differentPassword!',
        };

        await expect(service.signUp(dto)).rejects.toThrow();

        expect(bcrypt.hash).not.toHaveBeenCalled();
      });
    });

    describe('when email already exists', () => {
      it('should throw ConflictException with AUTH-002 error code', async () => {
        mockUserRepository.findOne.mockResolvedValue({
          id: 'existing-user-id',
        });

        await expectExceptionWithCode(
          service.signUp(validSignUpDto),
          ConflictException,
          AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS,
        );

        expect(mockUserRepository.save).not.toHaveBeenCalled();
      });
    });
  });

  describe('signIn', () => {
    const validSignInDto: SignInDto = {
      email: 'test@example.com',
      password: 'StrongPassword123!',
    };

    const mockUserWithPassword = {
      id: 'uuid-123',
      email: validSignInDto.email,
      password: mockHashedPassword,
    };

    const mockSession = {
      id: 'session-uuid-123',
      userId: 'uuid-123',
      deviceName: 'Unknown Device',
      ipAddress: '127.0.0.1',
      userAgent: 'test-agent',
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      lastActivityAt: new Date(),
      isRevoked: false,
    };

    const mockRequest = {
      ip: '127.0.0.1',
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    };

    describe('when successful', () => {
      beforeEach(() => {
        mockUserRepository.findOne.mockResolvedValue(mockUserWithPassword);
        (bcrypt.compare as jest.Mock).mockResolvedValue(true);
        mockSessionRepository.create.mockReturnValue(mockSession);
        mockSessionRepository.save.mockResolvedValue(mockSession);
        mockJwtService.sign.mockReturnValue('mock-jwt-token');
      });

      it('should return accessToken and refreshToken when credentials are valid', async () => {
        const result: SignInResponseDto =
          await service.signIn(validSignInDto, mockRequest);

        expect(result).toEqual({
          accessToken: 'mock-jwt-token',
          refreshToken: 'mock-jwt-token',
        });
      });

      it('should select password field explicitly in findOne query', async () => {
        await service.signIn(validSignInDto, mockRequest);

        expect(mockUserRepository.findOne).toHaveBeenCalledWith({
          where: { email: validSignInDto.email },
          select: ['id', 'email', 'password'],
        });
      });

      it('should verify password with bcrypt.compare', async () => {
        await service.signIn(validSignInDto, mockRequest);

        expect(bcrypt.compare).toHaveBeenCalledWith(
          validSignInDto.password,
          mockUserWithPassword.password,
        );
      });

      it('should create session with correct data', async () => {
        await service.signIn(validSignInDto, mockRequest);

        expect(mockSessionRepository.create).toHaveBeenCalledWith(
          expect.objectContaining({
            id: expect.any(String),
            userId: mockUserWithPassword.id,
            deviceName: expect.any(String),
            ipAddress: mockRequest.ip,
            userAgent: mockRequest.userAgent,
            expiresAt: expect.any(Date),
            lastActivityAt: expect.any(Date),
            isRevoked: false,
          }),
        );
        expect(mockSessionRepository.save).toHaveBeenCalled();
      });

      it('should generate access token with correct payload', async () => {
        await service.signIn(validSignInDto, mockRequest);

        expect(mockJwtService.sign).toHaveBeenNthCalledWith(
          1,
          {
            sub: mockUserWithPassword.id,
            email: mockUserWithPassword.email,
          },
          { expiresIn: '15m' },
        );
      });

      it('should generate refresh token with sessionId (sid)', async () => {
        await service.signIn(validSignInDto, mockRequest);

        expect(mockJwtService.sign).toHaveBeenNthCalledWith(
          2,
          expect.objectContaining({
            sub: mockUserWithPassword.id,
            email: mockUserWithPassword.email,
            sid: expect.any(String),
          }),
          { expiresIn: '7d' },
        );
      });

      it('should call jwtService.sign twice (access + refresh)', async () => {
        await service.signIn(validSignInDto, mockRequest);

        expect(mockJwtService.sign).toHaveBeenCalledTimes(2);
      });

      it('should extract device name from user agent', async () => {
        const macRequest = {
          ip: '127.0.0.1',
          userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        };

        await service.signIn(validSignInDto, macRequest);

        expect(mockSessionRepository.create).toHaveBeenCalledWith(
          expect.objectContaining({
            deviceName: 'Mac',
          }),
        );
      });
    });

    describe('when user not found', () => {
      it('should throw UnauthorizedException with INVALID_CREDENTIALS error code', async () => {
        mockUserRepository.findOne.mockResolvedValue(null);
        (bcrypt.compare as jest.Mock).mockResolvedValue(false);

        await expectExceptionWithCode(
          service.signIn(validSignInDto, mockRequest),
          UnauthorizedException,
          AUTH_ERROR_CODES.INVALID_CREDENTIALS,
        );

        expect(bcrypt.compare).toHaveBeenCalled();
        expect(mockSessionRepository.create).not.toHaveBeenCalled();
        expect(mockJwtService.sign).not.toHaveBeenCalled();
      });
    });

    describe('when password is invalid', () => {
      it('should throw UnauthorizedException with INVALID_CREDENTIALS error code', async () => {
        mockUserRepository.findOne.mockResolvedValue(mockUserWithPassword);
        (bcrypt.compare as jest.Mock).mockResolvedValue(false);

        await expectExceptionWithCode(
          service.signIn(validSignInDto, mockRequest),
          UnauthorizedException,
          AUTH_ERROR_CODES.INVALID_CREDENTIALS,
        );

        expect(mockSessionRepository.create).not.toHaveBeenCalled();
        expect(mockJwtService.sign).not.toHaveBeenCalled();
      });
    });

    describe('device name extraction', () => {
      it('should extract iPhone from user agent', async () => {
        mockUserRepository.findOne.mockResolvedValue(mockUserWithPassword);
        (bcrypt.compare as jest.Mock).mockResolvedValue(true);
        mockSessionRepository.create.mockReturnValue(mockSession);
        mockSessionRepository.save.mockResolvedValue(mockSession);
        mockJwtService.sign.mockReturnValue('mock-token');

        const iPhoneRequest = {
          ip: '127.0.0.1',
          userAgent:
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
        };

        await service.signIn(validSignInDto, iPhoneRequest);

        expect(mockSessionRepository.create).toHaveBeenCalledWith(
          expect.objectContaining({
            deviceName: 'iPhone',
          }),
        );
      });

      it('should extract Android from user agent', async () => {
        mockUserRepository.findOne.mockResolvedValue(mockUserWithPassword);
        (bcrypt.compare as jest.Mock).mockResolvedValue(true);
        mockSessionRepository.create.mockReturnValue(mockSession);
        mockSessionRepository.save.mockResolvedValue(mockSession);
        mockJwtService.sign.mockReturnValue('mock-token');

        const androidRequest = {
          ip: '127.0.0.1',
          userAgent:
            'Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36',
        };

        await service.signIn(validSignInDto, androidRequest);

        expect(mockSessionRepository.create).toHaveBeenCalledWith(
          expect.objectContaining({
            deviceName: 'Android Device',
          }),
        );
      });

      it('should return Unknown Device for unrecognized user agent', async () => {
        mockUserRepository.findOne.mockResolvedValue(mockUserWithPassword);
        (bcrypt.compare as jest.Mock).mockResolvedValue(true);
        mockSessionRepository.create.mockReturnValue(mockSession);
        mockSessionRepository.save.mockResolvedValue(mockSession);
        mockJwtService.sign.mockReturnValue('mock-token');

        const unknownRequest = {
          ip: '127.0.0.1',
          userAgent: 'CustomBot/1.0',
        };

        await service.signIn(validSignInDto, unknownRequest);

        expect(mockSessionRepository.create).toHaveBeenCalledWith(
          expect.objectContaining({
            deviceName: 'Unknown Device',
          }),
        );
      });
    });

    describe('when request context is not provided', () => {
      it('should handle missing IP and user agent gracefully', async () => {
        mockUserRepository.findOne.mockResolvedValue(mockUserWithPassword);
        (bcrypt.compare as jest.Mock).mockResolvedValue(true);
        mockSessionRepository.create.mockReturnValue(mockSession);
        mockSessionRepository.save.mockResolvedValue(mockSession);
        mockJwtService.sign.mockReturnValue('mock-token');

        await service.signIn(validSignInDto);

        expect(mockSessionRepository.create).toHaveBeenCalledWith(
          expect.objectContaining({
            deviceName: 'Unknown Device',
            ipAddress: undefined,
            userAgent: undefined,
          }),
        );
      });
    });
  });
});

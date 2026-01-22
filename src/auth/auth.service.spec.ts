import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';

jest.mock('bcrypt');

import { AuthService } from './auth.service';
import { SignUpDto } from './dto/sign-up.dto';
import { SignUpResponseDto } from './dto/sign-up-response.dto';
import { User } from '@/entities/User';
import { BadRequestException, ConflictException } from '@nestjs/common';
import { AUTH_ERROR_CODES } from '@/common/constants/error-codes.constant';
import { expectExceptionWithCode } from '@test/helpers/exception.helper';

const mockUserRepository = {
  create: jest.fn(),
  save: jest.fn(),
  findOne: jest.fn(),
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
});

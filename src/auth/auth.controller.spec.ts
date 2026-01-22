import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException, ConflictException } from '@nestjs/common';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { SignUpDto } from './dto/sign-up.dto';
import { AUTH_ERROR_CODES } from '@/common/constants/error-codes.constant';
import { SignUpResponseDto } from './dto/sign-up-response.dto';
import { expectExceptionWithCode } from '@test/helpers/exception.helper';

const mockAuthService = {
  signUp: jest.fn(),
};

const validSignUpDto: SignUpDto = {
  email: 'test@example.com',
  password: 'StrongPassword123!',
  confirmPassword: 'StrongPassword123!',
};

const mockSignUpResponse: SignUpResponseDto = {
  id: 'uuid-123',
  email: validSignUpDto.email,
  createdAt: new Date(),
  updatedAt: new Date(),
};

describe('auth.controller', () => {
  let controller: AuthController;

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
  });

  describe('POST /auth/sign-up', () => {
    it('should return 201 with user data', async () => {
      mockAuthService.signUp.mockResolvedValue(mockSignUpResponse);

      const result = await controller.signUp(validSignUpDto);

      expect(mockAuthService.signUp).toHaveBeenCalledWith(validSignUpDto);
      expect(result).toEqual(mockSignUpResponse);
      expect(result).not.toHaveProperty('password');
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
});

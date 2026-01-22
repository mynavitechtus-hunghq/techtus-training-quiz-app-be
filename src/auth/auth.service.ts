import {
  BadRequestException,
  ConflictException,
  Injectable,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';

import { SignUpDto } from './dto/sign-up.dto';
import { User } from '@/entities/User';
import { SALT_ROUNDS } from '@/common/constants/bcrypt.constant';
import { AUTH_ERROR_CODES } from '@/common/constants/error-codes.constant';
import { SignUpResponseDto } from './dto/sign-up-response.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
  ) {}

  async signUp(signUpDto: SignUpDto): Promise<SignUpResponseDto> {
    const { email, password, confirmPassword } = signUpDto;

    if (password !== confirmPassword) {
      throw new BadRequestException({
        errorCode: AUTH_ERROR_CODES.PASSWORD_MISMATCH,
      });
    }

    const existedUser = await this.userRepository.findOne({ where: { email } });

    if (existedUser) {
      throw new ConflictException({
        errorCode: AUTH_ERROR_CODES.EMAIL_ALREADY_EXISTS,
      });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const newUser = this.userRepository.create({
      email,
      password: hashedPassword,
    });

    const savedUser = await this.userRepository.save(newUser);
    // Remove password from response
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password: _, ...userWithoutPassword } = savedUser;

    return userWithoutPassword;
  }
}

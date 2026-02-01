import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { v4 as uuidv4 } from 'uuid';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

import { SignUpDto } from './dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto';
import { SignUpResponseDto } from './dto/sign-up-response.dto';
import { SignInResponseDto } from './dto/sign-in-response.dto';
import { User } from '@/entities/User';
import { Session } from '@/entities/Session';
import { SALT_ROUNDS } from '@/common/constants/bcrypt.constant';
import { AUTH_ERROR_CODES } from '@/common/constants/error-codes.constant';
import {
  TOKEN_CONFIG,
  REFRESH_TOKEN_EXPIRY_DAYS,
} from '@/common/constants/auth.constant';
import { convertExpiry } from '@/common/helper/jwt.helper';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User) private readonly userRepository: Repository<User>,
    @InjectRepository(Session)
    private readonly sessionRepository: Repository<Session>,
    private readonly jwtService: JwtService,
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
    const { password: _, ...userWithoutPassword } = savedUser;

    return userWithoutPassword;
  }

  async signIn(
    signInDto: SignInDto,
    request?: { ip?: string; userAgent?: string },
  ): Promise<SignInResponseDto> {
    const { email, password } = signInDto;

    const user = await this.userRepository.findOne({
      where: { email },
      select: ['id', 'email', 'password'],
    });

    const passwordToCompare =
      user?.password ||
      '$2b$10$dummyHashToPreventTimingAttackXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
    const isPasswordValid = await bcrypt.compare(password, passwordToCompare);

    if (!user || !isPasswordValid) {
      throw new UnauthorizedException({
        errorCode: AUTH_ERROR_CODES.INVALID_CREDENTIALS,
      });
    }

    const sessionId = uuidv4();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + REFRESH_TOKEN_EXPIRY_DAYS);

    const session = this.sessionRepository.create({
      id: sessionId,
      userId: user.id,
      deviceName: this.extractDeviceName(request?.userAgent),
      ipAddress: request?.ip,
      userAgent: request?.userAgent,
      expiresAt,
      lastActivityAt: new Date(),
      isRevoked: false,
    });

    await this.sessionRepository.save(session);

    const accessToken = this.jwtService.sign(
      { sub: user.id, email: user.email },
      { expiresIn: convertExpiry(TOKEN_CONFIG.ACCESS_TOKEN_EXPIRY) },
    );

    const refreshToken = this.jwtService.sign(
      {
        sub: user.id,
        email: user.email,
        sid: sessionId,
      },
      { expiresIn: convertExpiry(TOKEN_CONFIG.REFRESH_TOKEN_EXPIRY) },
    );

    return { accessToken, refreshToken };
  }

  private extractDeviceName(userAgent?: string): string {
    if (!userAgent) return 'Unknown Device';

    if (userAgent.includes('iPhone')) return 'iPhone';
    if (userAgent.includes('iPad')) return 'iPad';
    if (userAgent.includes('Android')) return 'Android Device';
    if (userAgent.includes('Windows')) return 'Windows PC';
    if (userAgent.includes('Macintosh')) return 'Mac';
    if (userAgent.includes('Linux')) return 'Linux PC';

    return 'Unknown Device';
  }
}

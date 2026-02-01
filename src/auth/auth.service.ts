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
import { RefreshTokenResponseDto } from './dto/refresh-token-response.dto';
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
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password: _password, ...userWithoutPassword } = savedUser;

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

  /**
   * Refreshes access and refresh tokens using a valid refresh token.
   * Validates the refresh token, checks session status, and generates new tokens.
   * @param refreshToken - The refresh token to validate
   * @param request - Optional request context containing IP and user agent
   * @returns New access and refresh token pair
   * @throws UnauthorizedException if token or session is invalid
   */
  async refreshToken(
    refreshToken: string,
    request?: { ip?: string; userAgent?: string },
  ): Promise<RefreshTokenResponseDto> {
    // 1. Verify and decode refresh token
    let payload: { sub: string; email: string; sid: string };
    try {
      payload = this.jwtService.verify(refreshToken);
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
    } catch (error) {
      throw new UnauthorizedException({
        errorCode: AUTH_ERROR_CODES.INVALID_REFRESH_TOKEN,
        message: 'Invalid or expired refresh token',
      });
    }

    // 2. Extract and validate session ID
    const sessionId: string = payload.sid;
    if (!sessionId) {
      throw new UnauthorizedException({
        errorCode: AUTH_ERROR_CODES.INVALID_REFRESH_TOKEN,
        message: 'Refresh token missing session ID',
      });
    }

    // 3. Find and validate session
    const session: {
      id: string;
      isRevoked: boolean;
      expiresAt: Date;
      lastActivityAt: Date;
      ipAddress?: string;
      deviceName?: string;
    } | null = await this.sessionRepository.findOne({
      where: { id: sessionId },
    });

    if (!session) {
      throw new UnauthorizedException({
        errorCode: AUTH_ERROR_CODES.SESSION_NOT_FOUND,
        message: 'Session not found',
      });
    }

    if (session.isRevoked) {
      throw new UnauthorizedException({
        errorCode: AUTH_ERROR_CODES.SESSION_REVOKED,
        message: 'Session has been revoked',
      });
    }

    if (session.expiresAt < new Date()) {
      throw new UnauthorizedException({
        errorCode: AUTH_ERROR_CODES.SESSION_EXPIRED,
        message: 'Session has expired',
      });
    }

    // 4. Update session activity
    session.lastActivityAt = new Date();
    if (request?.ip) {
      session.ipAddress = request.ip;
    }
    if (request?.userAgent) {
      session.deviceName = this.extractDeviceName(request.userAgent);
    }
    await this.sessionRepository.save(session);

    // 5. Generate new tokens
    const accessToken = this.jwtService.sign(
      { sub: payload.sub, email: payload.email },
      { expiresIn: convertExpiry(TOKEN_CONFIG.ACCESS_TOKEN_EXPIRY) },
    );

    const newRefreshToken = this.jwtService.sign(
      { sub: payload.sub, email: payload.email, sid: sessionId },
      { expiresIn: convertExpiry(TOKEN_CONFIG.REFRESH_TOKEN_EXPIRY) },
    );

    return { accessToken, refreshToken: newRefreshToken };
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

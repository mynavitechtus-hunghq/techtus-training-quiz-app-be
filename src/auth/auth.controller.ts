import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import type { Request } from 'express';

import { AuthService } from './auth.service';
import { SignUpDto } from './dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { SignUpResponseDto } from './dto/sign-up-response.dto';
import { SignInResponseDto } from './dto/sign-in-response.dto';
import { RefreshTokenResponseDto } from './dto/refresh-token-response.dto';
import { AUTH_ERROR_RESPONSES } from '@/common/dto/error-response.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  private getClientIp(req: Request): string {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') {
      return forwarded.split(',')[0].trim();
    }

    if (req.ip === '::1' || req.ip === '::ffff:127.0.0.1') {
      return '127.0.0.1';
    }

    return req.ip || 'unknown';
  }

  @Post('sign-up')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Register a new user',
    description: 'Create a new user account with email and password',
  })
  @ApiResponse({
    status: 201,
    description: 'User successfully registered',
    type: SignUpResponseDto,
  })
  @ApiResponse({ ...AUTH_ERROR_RESPONSES.PASSWORD_MISMATCH })
  @ApiResponse({ ...AUTH_ERROR_RESPONSES.EMAIL_ALREADY_EXISTS })
  async signUp(@Body() signUpDto: SignUpDto): Promise<SignUpResponseDto> {
    return this.authService.signUp(signUpDto);
  }

  @Post('sign-in')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Sign in a user',
    description:
      'Authenticate user and create a new session with access and refresh tokens',
  })
  @ApiResponse({
    status: 200,
    description: 'User successfully authenticated',
    type: SignInResponseDto,
  })
  @ApiResponse({ ...AUTH_ERROR_RESPONSES.USER_NOT_FOUND })
  @ApiResponse({ ...AUTH_ERROR_RESPONSES.INVALID_CREDENTIALS })
  @ApiResponse({ ...AUTH_ERROR_RESPONSES.MAX_SESSIONS_EXCEEDED })
  async signIn(
    @Body() signInDto: SignInDto,
    @Req() req: Request,
  ): Promise<SignInResponseDto> {
    return this.authService.signIn(signInDto, {
      ip: this.getClientIp(req),
      userAgent: req.headers['user-agent'],
    });
  }

  @Post('refresh-token')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Refresh access token',
    description:
      'Generate new access and refresh tokens using a valid refresh token. Requires valid access token authentication. The old refresh token will be invalidated.',
  })
  @ApiResponse({
    status: 200,
    description: 'Tokens successfully refreshed',
    type: RefreshTokenResponseDto,
  })
  @ApiResponse({ ...AUTH_ERROR_RESPONSES.TOKEN_EXPIRED })
  @ApiResponse({ ...AUTH_ERROR_RESPONSES.INVALID_ACCESS_TOKEN })
  @ApiResponse({ ...AUTH_ERROR_RESPONSES.INVALID_REFRESH_TOKEN })
  @ApiResponse({ ...AUTH_ERROR_RESPONSES.SESSION_NOT_FOUND })
  @ApiResponse({ ...AUTH_ERROR_RESPONSES.SESSION_REVOKED })
  @ApiResponse({ ...AUTH_ERROR_RESPONSES.SESSION_EXPIRED })
  async refreshToken(
    @Body() refreshTokenDto: RefreshTokenDto,
    @Req() req: Request,
  ): Promise<RefreshTokenResponseDto> {
    return this.authService.refreshToken(refreshTokenDto.refreshToken, {
      ip: this.getClientIp(req),
      userAgent: req.headers['user-agent'],
    });
  }
}

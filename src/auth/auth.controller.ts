import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';

import { AuthService } from './auth.service';
import { SignUpDto } from './dto/sign-up.dto';
import { SignUpResponseDto } from './dto/sign-up-response.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('sign-up')
  @HttpCode(HttpStatus.CREATED)
  async signUp(@Body() signUpDto: SignUpDto): Promise<SignUpResponseDto> {
    return this.authService.signUp(signUpDto);
  }
}

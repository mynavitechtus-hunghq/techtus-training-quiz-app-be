import { IsNotEmpty, IsString, IsJWT } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RefreshTokenDto {
  @ApiProperty({
    description: 'JWT refresh token received from sign-in',
    example:
      'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0...',
  })
  @IsNotEmpty()
  @IsString()
  @IsJWT()
  refreshToken: string;
}

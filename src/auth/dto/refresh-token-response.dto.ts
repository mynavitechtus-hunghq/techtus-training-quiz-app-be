import { ApiProperty } from '@nestjs/swagger';

export class RefreshTokenResponseDto {
  @ApiProperty({
    description: 'New JWT access token',
    example:
      'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0...',
  })
  accessToken: string;

  @ApiProperty({
    description: 'New JWT refresh token',
    example:
      'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0...',
  })
  refreshToken: string;
}

import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { User } from '@/entities/User';
import { Session } from '@/entities/Session';
import { getPrivateKey, getPublicKey } from '@/common/helper/jwt.helper';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, Session]),
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.register({
      privateKey: getPrivateKey(),
      publicKey: getPublicKey(),
      signOptions: {
        algorithm: 'RS256',
      },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
  exports: [AuthService, JwtStrategy, PassportModule],
})
export class AuthModule {}

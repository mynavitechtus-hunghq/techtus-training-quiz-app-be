import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { join } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { User } from '@/entities/User';
import { Session } from '@/entities/Session';
import { convertExpiry } from '@/common/helper/jwt.helper';

const getPrivateKey = (): string => {
  if (process.env.JWT_PRIVATE_KEY) {
    return process.env.JWT_PRIVATE_KEY;
  }

  const keyPath = join(__dirname, '../../keys/private.pem');
  if (existsSync(keyPath)) {
    return readFileSync(keyPath, 'utf-8');
  }

  throw new Error('JWT_PRIVATE_KEY not configured');
};

const getPublicKey = (): string => {
  if (process.env.JWT_PUBLIC_KEY) {
    return process.env.JWT_PUBLIC_KEY;
  }

  const keyPath = join(__dirname, '../../keys/public.pem');
  if (existsSync(keyPath)) {
    return readFileSync(keyPath, 'utf-8');
  }

  throw new Error('JWT_PUBLIC_KEY not configured');
};
@Module({
  imports: [
    TypeOrmModule.forFeature([User, Session]),
    JwtModule.register({
      privateKey: getPrivateKey(),
      publicKey: getPublicKey(),
      signOptions: {
        algorithm: 'RS256',
        expiresIn: convertExpiry(process.env.JWT_ACCESS_EXPIRES_IN || '15m'),
      },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService],
  exports: [],
})
export class AuthModule {}

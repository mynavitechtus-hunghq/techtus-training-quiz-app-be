import { Controller, Get, Redirect } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ENVIRONMENT, ENV_KEYS } from '@/common/constants/environment.constant';

@Controller()
export class AppController {
  constructor(private readonly configService: ConfigService) {}

  @Get()
  @Redirect('/api/docs', 302)
  redirect() {
    // Only redirect in development mode
    const nodeEnv = this.configService.get<string>(ENV_KEYS.NODE_ENV);
    if (nodeEnv === ENVIRONMENT.DEVELOPMENT || !nodeEnv) {
      return { url: '/api/docs' };
    }
    return { url: '/api/docs' };
  }
}

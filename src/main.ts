import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';

import { AppModule } from '@/app.module';
import { setupSwagger } from '@core/swagger/swagger.setup';
import { setupHelmet } from '@core/security/helmet.setup';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const port = configService.get<number>('PORT', 3000);

  setupHelmet(app);
  setupSwagger(app);

  await app.listen(port);
}

void bootstrap();

import helmet from 'helmet';
import { INestApplication } from '@nestjs/common';

export function setupHelmet(app: INestApplication) {
  app.use(
    helmet({
      crossOriginResourcePolicy: { policy: 'same-origin' },
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          fontSrc: ["'self'", 'data:'],
          connectSrc: ["'self'", 'https:'],
        },
      },
    }),
  );
}

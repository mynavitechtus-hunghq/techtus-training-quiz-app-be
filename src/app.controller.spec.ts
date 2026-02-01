import { Test, TestingModule } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { AppController } from './app.controller';
import { ENVIRONMENT, ENV_KEYS } from '@/common/constants/environment.constant';

const mockConfigService = {
  get: jest.fn((key: string) => {
    if (key === ENV_KEYS.NODE_ENV) return ENVIRONMENT.DEVELOPMENT;
    return null;
  }),
};

describe('AppController', () => {
  let appController: AppController;

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      controllers: [AppController],
      providers: [
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    appController = app.get<AppController>(AppController);
  });

  describe('root', () => {
    it('should redirect to /api/docs', () => {
      const result = appController.redirect();
      expect(result).toEqual({ url: '/api/docs' });
    });
  });
});

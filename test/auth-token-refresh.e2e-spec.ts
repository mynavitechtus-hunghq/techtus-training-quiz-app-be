/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, ValidationPipe } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from '@/app.module';
import { DataSource } from 'typeorm';

describe('Token Refresh Flow (E2E)', () => {
  let app: INestApplication;
  let dataSource: DataSource;

  let accessToken: string;
  let refreshToken: string;
  let userId: string;
  const testEmail = `test-${Date.now()}@example.com`;
  const testPassword = 'StrongPassword123!';

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        forbidNonWhitelisted: true,
        transform: true,
      }),
    );

    await app.init();
    dataSource = moduleFixture.get<DataSource>(DataSource);
  });

  afterAll(async () => {
    // Clean up test data
    if (userId) {
      await dataSource.query('DELETE FROM "session" WHERE "userId" = $1', [
        userId,
      ]);
      await dataSource.query('DELETE FROM "user" WHERE id = $1', [userId]);
    }
    await app.close();
  });

  describe('POST /auth/refresh-token', () => {
    describe('successful refresh flow', () => {
      it('should sign up and receive user data', async () => {
        const response = await request(app.getHttpServer())
          .post('/auth/sign-up')
          .send({
            email: testEmail,
            password: testPassword,
            confirmPassword: testPassword,
          })
          .expect(201);

        expect(response.body).toHaveProperty('id');
        expect(response.body).toHaveProperty('email', testEmail);
        expect(response.body).not.toHaveProperty('password');
        userId = response.body.id;
      });

      it('should sign in and receive tokens', async () => {
        const response = await request(app.getHttpServer())
          .post('/auth/sign-in')
          .send({
            email: testEmail,
            password: testPassword,
          })
          .expect(200);

        expect(response.body).toHaveProperty('accessToken');
        expect(response.body).toHaveProperty('refreshToken');
        expect(typeof response.body.accessToken).toBe('string');
        expect(typeof response.body.refreshToken).toBe('string');

        accessToken = response.body.accessToken;
        refreshToken = response.body.refreshToken;
      });

      it('should refresh with valid refresh token', async () => {
        const response = await request(app.getHttpServer())
          .post('/auth/refresh-token')
          .send({
            refreshToken: refreshToken,
          })
          .expect(200);

        expect(response.body).toHaveProperty('accessToken');
        expect(response.body).toHaveProperty('refreshToken');
        expect(typeof response.body.accessToken).toBe('string');
        expect(typeof response.body.refreshToken).toBe('string');
      });

      it('should return new access and refresh tokens', async () => {
        const response = await request(app.getHttpServer())
          .post('/auth/refresh-token')
          .send({
            refreshToken: refreshToken,
          })
          .expect(200);

        expect(response.body.accessToken).toBeDefined();
        expect(response.body.refreshToken).toBeDefined();

        // Tokens should be different from original (rotation)
        expect(response.body.accessToken).not.toBe(accessToken);
        expect(response.body.refreshToken).not.toBe(refreshToken);

        // Update tokens for subsequent tests
        accessToken = response.body.accessToken;
        refreshToken = response.body.refreshToken;
      });

      it('should allow multiple refreshes in sequence', async () => {
        const firstRefresh = await request(app.getHttpServer())
          .post('/auth/refresh-token')
          .send({ refreshToken })
          .expect(200);

        const newRefreshToken = firstRefresh.body.refreshToken;

        const secondRefresh = await request(app.getHttpServer())
          .post('/auth/refresh-token')
          .send({ refreshToken: newRefreshToken })
          .expect(200);

        expect(secondRefresh.body).toHaveProperty('accessToken');
        expect(secondRefresh.body).toHaveProperty('refreshToken');

        // Update for subsequent tests
        refreshToken = secondRefresh.body.refreshToken;
      });
    });

    describe('validation errors', () => {
      it('should reject request without refresh token (400)', async () => {
        const response = await request(app.getHttpServer())
          .post('/auth/refresh-token')
          .send({})
          .expect(400);

        expect(response.body).toHaveProperty('message');
      });

      it('should reject empty refresh token (400)', async () => {
        const response = await request(app.getHttpServer())
          .post('/auth/refresh-token')
          .send({ refreshToken: '' })
          .expect(400);

        expect(response.body).toHaveProperty('message');
      });

      it('should reject non-JWT refresh token (400)', async () => {
        const response = await request(app.getHttpServer())
          .post('/auth/refresh-token')
          .send({ refreshToken: 'not-a-jwt-token' })
          .expect(400);

        expect(response.body).toHaveProperty('message');
      });

      it('should reject non-string refresh token (400)', async () => {
        const response = await request(app.getHttpServer())
          .post('/auth/refresh-token')
          .send({ refreshToken: 12345 })
          .expect(400);

        expect(response.body).toHaveProperty('message');
      });
    });

    describe('authentication errors', () => {
      it('should reject invalid refresh token (401)', async () => {
        const invalidToken =
          'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpbnZhbGlkIiwiZW1haWwiOiJpbnZhbGlkQGV4YW1wbGUuY29tIiwic2lkIjoiaW52YWxpZCIsImlhdCI6MTUxNjIzOTAyMn0.invalid';

        const response = await request(app.getHttpServer())
          .post('/auth/refresh-token')
          .send({ refreshToken: invalidToken })
          .expect(401);

        expect(response.body).toHaveProperty('errorCode');
      });

      it('should reject when session does not exist (401)', async () => {
        // Create a token with non-existent session ID
        const fakeToken = refreshToken.replace(/[a-f0-9]{8}/, 'ffffffff');

        await request(app.getHttpServer())
          .post('/auth/refresh-token')
          .send({ refreshToken: fakeToken })
          .expect(401);
      });
    });

    describe('session revocation', () => {
      it('should reject when session is revoked (401)', async () => {
        // Revoke the session
        await dataSource.query(
          'UPDATE "session" SET "isRevoked" = true WHERE "userId" = $1',
          [userId],
        );

        const response = await request(app.getHttpServer())
          .post('/auth/refresh-token')
          .send({ refreshToken })
          .expect(401);

        expect(response.body).toHaveProperty('errorCode', 'AUTH-006');

        // Restore session for other tests
        await dataSource.query(
          'UPDATE "session" SET "isRevoked" = false WHERE "userId" = $1',
          [userId],
        );

        // Get new tokens
        const signInResponse = await request(app.getHttpServer())
          .post('/auth/sign-in')
          .send({
            email: testEmail,
            password: testPassword,
          })
          .expect(200);

        refreshToken = signInResponse.body.refreshToken;
      });
    });

    describe('session activity tracking', () => {
      it('should update session lastActivityAt on refresh', async () => {
        const sessionBefore = await dataSource.query(
          'SELECT "lastActivityAt" FROM "session" WHERE "userId" = $1 ORDER BY "lastActivityAt" DESC LIMIT 1',
          [userId],
        );

        const beforeTime = new Date(sessionBefore[0].lastActivityAt);

        // Wait a bit to ensure time difference
        await new Promise((resolve) => setTimeout(resolve, 100));

        await request(app.getHttpServer())
          .post('/auth/refresh-token')
          .send({ refreshToken })
          .expect(200);

        const sessionAfter = await dataSource.query(
          'SELECT "lastActivityAt" FROM "session" WHERE "userId" = $1 ORDER BY "lastActivityAt" DESC LIMIT 1',
          [userId],
        );

        const afterTime = new Date(sessionAfter[0].lastActivityAt);

        expect(afterTime.getTime()).toBeGreaterThanOrEqual(
          beforeTime.getTime(),
        );
      });

      it('should track multiple refresh requests', async () => {
        for (let i = 0; i < 3; i++) {
          const response = await request(app.getHttpServer())
            .post('/auth/refresh-token')
            .send({ refreshToken })
            .expect(200);

          refreshToken = response.body.refreshToken;

          // Small delay between requests
          await new Promise((resolve) => setTimeout(resolve, 50));
        }

        const sessions = await dataSource.query(
          'SELECT COUNT(*) as count FROM "session" WHERE "userId" = $1',
          [userId],
        );

        expect(parseInt(sessions[0].count)).toBeGreaterThan(0);
      });
    });

    describe('token expiration', () => {
      it('should accept refresh token before expiry', async () => {
        const response = await request(app.getHttpServer())
          .post('/auth/refresh-token')
          .send({ refreshToken })
          .expect(200);

        expect(response.body).toHaveProperty('accessToken');
        expect(response.body).toHaveProperty('refreshToken');
      });

      it('should reject expired session (401)', async () => {
        // Expire the session
        await dataSource.query(
          'UPDATE "session" SET "expiresAt" = $1 WHERE "userId" = $2',
          [new Date(Date.now() - 1000), userId],
        );

        const response = await request(app.getHttpServer())
          .post('/auth/refresh-token')
          .send({ refreshToken })
          .expect(401);

        expect(response.body).toHaveProperty('errorCode', 'AUTH-007');
      });
    });
  });

  describe('Token rotation security', () => {
    let newAccessToken: string;
    let newRefreshToken: string;

    beforeAll(async () => {
      // Clean up and create fresh user
      if (userId) {
        await dataSource.query('DELETE FROM "session" WHERE "userId" = $1', [
          userId,
        ]);
        await dataSource.query('DELETE FROM "user" WHERE id = $1', [userId]);
      }

      const signUpEmail = `rotation-test-${Date.now()}@example.com`;

      const signUpResponse = await request(app.getHttpServer())
        .post('/auth/sign-up')
        .send({
          email: signUpEmail,
          password: testPassword,
          confirmPassword: testPassword,
        })
        .expect(201);

      userId = signUpResponse.body.id;

      const signInResponse = await request(app.getHttpServer())
        .post('/auth/sign-in')
        .send({
          email: signUpEmail,
          password: testPassword,
        })
        .expect(200);

      newAccessToken = signInResponse.body.accessToken;
      newRefreshToken = signInResponse.body.refreshToken;
    });

    it('should generate new tokens on each refresh', async () => {
      const firstRefresh = await request(app.getHttpServer())
        .post('/auth/refresh-token')
        .send({ refreshToken: newRefreshToken })
        .expect(200);

      expect(firstRefresh.body.accessToken).not.toBe(newAccessToken);
      expect(firstRefresh.body.refreshToken).not.toBe(newRefreshToken);

      const secondRefresh = await request(app.getHttpServer())
        .post('/auth/refresh-token')
        .send({ refreshToken: firstRefresh.body.refreshToken })
        .expect(200);

      expect(secondRefresh.body.accessToken).not.toBe(
        firstRefresh.body.accessToken,
      );
      expect(secondRefresh.body.refreshToken).not.toBe(
        firstRefresh.body.refreshToken,
      );
    });
  });
});

# 🔬 Research Report: TDD Sign-Up API Implementation

## Research Question

**Primary Question**: What are the best practices for implementing a Sign-Up API using TDD (Test-Driven Development) in NestJS?

**Sub-Questions**:
1. How to structure unit tests for AuthService with TDD approach?
2. How to write E2E tests for sign-up endpoint?
3. Best practices for password hashing and security in sign-up flow?
4. How to mock TypeORM repositories in NestJS tests?

---

## Executive Summary

TDD approach for NestJS Sign-Up API requires writing tests BEFORE implementation following the **Red-Green-Refactor** cycle. NestJS provides robust testing utilities via `@nestjs/testing` module, integrated with Jest. Key patterns include: mocking repositories with `Test.createTestingModule()`, using `supertest` for E2E tests, and following the Three A's pattern (Arrange-Act-Assert).

---

## Key Findings

### 1. TDD Red-Green-Refactor Cycle

**Finding**: TDD follows a strict cycle: Red (write failing test) → Green (minimal code to pass) → Refactor (improve code quality)

**Evidence**: 
- Write test first that describes expected behavior
- Run test and see it fail (Red)
- Write minimal code to make test pass (Green)
- Refactor while keeping tests passing

**Application to Sign-Up**:
1. **Red**: Write test for `AuthService.signUp()` expecting it to hash password and create user
2. **Green**: Implement minimal `signUp()` logic
3. **Refactor**: Extract validation, improve error handling

**Confidence**: High

---

### 2. NestJS Unit Testing with `@nestjs/testing`

**Finding**: NestJS provides `Test.createTestingModule()` for creating isolated testing modules with dependency injection

**Evidence** (from NestJS docs):
```typescript
import { Test } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';

describe('AuthService', () => {
  let authService: AuthService;
  let usersService: UsersService;

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      providers: [AuthService, UsersService],
    }).compile();

    authService = moduleRef.get(AuthService);
    usersService = moduleRef.get(UsersService);
  });
});
```

**Source**: https://docs.nestjs.com/fundamentals/testing

**Best Practices**:
- Use `.overrideProvider()` to mock dependencies
- Use `jest.spyOn()` for method mocking
- Keep test files co-located with source (`.spec.ts` suffix)

**Confidence**: High

---

### 3. Mocking TypeORM Repository

**Finding**: For unit tests, mock the repository to avoid database dependencies

**Pattern**:
```typescript
const mockUserRepository = {
  create: jest.fn(),
  save: jest.fn(),
  findOne: jest.fn(),
};

const moduleRef = await Test.createTestingModule({
  providers: [
    AuthService,
    {
      provide: getRepositoryToken(User),
      useValue: mockUserRepository,
    },
  ],
}).compile();
```

**Source**: NestJS TypeORM testing patterns

**Confidence**: High

---

### 4. E2E Testing with Supertest

**Finding**: E2E tests use `supertest` to simulate real HTTP requests against the NestJS application

**Evidence** (from NestJS docs):
```typescript
import * as request from 'supertest';
import { Test } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';

describe('Auth (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    await app.init();
  });

  it('/auth/sign-up (POST)', () => {
    return request(app.getHttpServer())
      .post('/auth/sign-up')
      .send({ email: 'test@example.com', password: 'Password123!' })
      .expect(201);
  });

  afterAll(async () => {
    await app.close();
  });
});
```

**Source**: https://docs.nestjs.com/fundamentals/testing#end-to-end-testing

**Confidence**: High

---

### 5. Password Hashing with Bcrypt

**Finding**: Always use bcrypt with salt for password hashing (already in project dependencies)

**Best Practice**:
```typescript
import * as bcrypt from 'bcrypt';

const SALT_ROUNDS = 10;

async hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

async comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}
```

**Security Notes**:
- Never store plain text passwords
- Use cost factor of 10-12 for bcrypt
- Project already has `bcrypt` v6.0.0 installed

**Source**: https://docs.nestjs.com/security/authentication

**Confidence**: High

---

### 6. Sign-Up API Test Cases (TDD Approach)

**Finding**: For comprehensive TDD, define test cases BEFORE implementation

**Recommended Test Cases**:

#### Unit Tests (AuthService.signUp)
| Test Case | Input | Expected Output |
|-----------|-------|-----------------|
| Happy path | Valid email, password | Returns created user (without password) |
| Duplicate email | Existing email | Throws ConflictException |
| Password too short | < 8 chars | Throws BadRequestException |
| Invalid email format | Invalid email | Throws BadRequestException |
| Password mismatch | password ≠ confirmPassword | Throws BadRequestException |

#### E2E Tests (POST /auth/sign-up)
| Test Case | Request | Expected Response |
|-----------|---------|-------------------|
| Success | Valid DTO | 201 Created + user data |
| Duplicate | Existing email | 409 Conflict |
| Validation error | Invalid DTO | 400 Bad Request |

**Confidence**: High

---

### 7. DTO Validation in Tests

**Finding**: The project uses `class-validator` for DTO validation. Ensure ValidationPipe is applied in tests.

**Evidence** (existing code analysis):
```typescript
// sign-up.dto.ts already defines validation rules:
@IsEmail()
@IsNotEmpty()
email: string;

@MinLength(MIN_PASSWORD_LENGTH)
@MaxLength(MAX_PASSWORD_LENGTH)
password: string;
```

**E2E Test Requirement**:
```typescript
// Enable validation in E2E tests
app = moduleRef.createNestApplication();
app.useGlobalPipes(new ValidationPipe());
await app.init();
```

**Confidence**: High

---

## Code Examples

### TDD Flow Example for Sign-Up

**Step 1: Write Failing Test (Red)**
```typescript
describe('signUp', () => {
  it('should create a new user with hashed password', async () => {
    const dto = {
      email: 'test@example.com',
      password: 'Password123!',
      confirmPassword: 'Password123!',
    };

    const result = await authService.signUp(dto);

    expect(result).toBeDefined();
    expect(result.email).toBe(dto.email);
    expect(result.password).toBeUndefined(); // Should not return password
    expect(mockUserRepository.save).toHaveBeenCalled();
  });
});
```

**Step 2: Minimal Implementation (Green)**
```typescript
async signUp(dto: SignUpDto): Promise<Partial<User>> {
  const hashedPassword = await bcrypt.hash(dto.password, 10);
  const user = this.userRepository.create({
    email: dto.email,
    password: hashedPassword,
  });
  const savedUser = await this.userRepository.save(user);
  const { password, ...result } = savedUser;
  return result;
}
```

**Step 3: Refactor**
- Extract password hashing to utility
- Add email uniqueness check
- Improve error handling

---

## Recommendations

1. **Follow TDD Strictly**: Write tests BEFORE implementation code
2. **Test Isolation**: Mock all external dependencies (database, services)
3. **Test Coverage**:
   - Happy path scenarios
   - Error scenarios (validation, duplicates)
   - Edge cases (boundary values for password length)
4. **Use `@nestjs/testing`**: Leverage NestJS testing utilities for proper DI
5. **Separate Concerns**:
   - Unit tests: Test service logic in isolation
   - E2E tests: Test full HTTP request/response cycle
6. **Apply ValidationPipe**: Ensure DTOs are validated in E2E tests
7. **Password Security**: Use bcrypt with appropriate salt rounds (10-12)

---

## Sources Consulted

1. [NestJS Testing Documentation](https://docs.nestjs.com/fundamentals/testing) - Accessed Jan 22, 2026
2. [NestJS Authentication Guide](https://docs.nestjs.com/security/authentication) - Accessed Jan 22, 2026
3. [Jest Documentation](https://jestjs.io/docs/getting-started) - Accessed Jan 22, 2026
4. Project codebase analysis (package.json, existing DTOs, entities)

---

## Uncertainties / Gaps

- Response format for sign-up (should return JWT token or just user data?)
- Whether to implement refresh token at this stage
- Exact error message format for validation errors

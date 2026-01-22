# 🔭 Codebase Intelligence Report: TDD Sign-Up API

## Mission

**Objective**: Analyze codebase structure, existing patterns, and integration points for implementing Sign-Up API using TDD
**Scope**: src/auth/, src/entities/, src/core/, test/

---

## Project Structure

```
techtus-training-quiz-app-be/
├── src/
│   ├── app.module.ts           # Root module (imports CoreModule)
│   ├── app.controller.ts       # Root controller
│   ├── app.service.ts          # Root service
│   ├── app.controller.spec.ts  # ✅ Example unit test pattern
│   ├── main.ts                 # Bootstrap with Helmet, Swagger
│   ├── auth/
│   │   ├── auth.service.spec.ts  # ⚠️ Empty - needs TDD implementation
│   │   └── dto/
│   │       └── sign-up.dto.ts    # ✅ Already defined with validation
│   ├── common/
│   │   └── constants/
│   │       └── auth.constant.ts  # MIN/MAX password length constants
│   ├── core/
│   │   ├── core.module.ts        # ConfigModule + DatabaseModule
│   │   ├── database/
│   │   │   └── database.module.ts  # TypeORM setup with User entity
│   │   ├── security/
│   │   │   ├── cors.setup.ts
│   │   │   └── helmet.setup.ts
│   │   └── swagger/
│   │       └── swagger.setup.ts
│   └── entities/
│       ├── Base.ts               # UUID PK + timestamps + soft delete
│       └── User.ts               # email + password (hashed)
├── test/
│   ├── app.e2e-spec.ts           # ✅ Example E2E test pattern
│   └── jest-e2e.json             # E2E Jest config
├── package.json                  # Dependencies defined
└── tsconfig.json                 # Path aliases: @/*, @core/*
```

---

## Key Findings

### 1. Existing Test Patterns

**Location**: [src/app.controller.spec.ts](src/app.controller.spec.ts)

**Pattern - Unit Test Structure**:
```typescript
import { Test, TestingModule } from '@nestjs/testing';

describe('AppController', () => {
  let appController: AppController;

  beforeEach(async () => {
    const app: TestingModule = await Test.createTestingModule({
      controllers: [AppController],
      providers: [AppService],
    }).compile();

    appController = app.get<AppController>(AppController);
  });

  describe('methodName', () => {
    it('should do something', () => {
      expect(appController.getHello()).toBe('Hello World!');
    });
  });
});
```

**MUST FOLLOW**: This pattern for AuthService.spec.ts

**Relevance**: Establishes project testing conventions

---

### 2. Existing E2E Test Pattern

**Location**: [test/app.e2e-spec.ts](test/app.e2e-spec.ts)

**Pattern - E2E Test Structure**:
```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { AppModule } from './../src/app.module';

describe('AppController (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  it('/ (GET)', () => {
    return request(app.getHttpServer())
      .get('/')
      .expect(200)
      .expect('Hello World!');
  });
});
```

**MUST FOLLOW**: This pattern for auth.e2e-spec.ts

**Relevance**: Establishes E2E testing conventions

---

### 3. User Entity Definition

**Location**: [src/entities/User.ts](src/entities/User.ts)

**Pattern**:
```typescript
@Entity()
export class User extends Base {
  @Column({ unique: true, nullable: false })
  email: string;

  @Column({ select: false, nullable: false })
  password: string;
}
```

**Key Constraints**:
- Email is UNIQUE → Must handle ConflictException for duplicates
- Password has `select: false` → Won't be returned by default queries
- Extends Base → Has UUID id, createdAt, updatedAt, deletedAt (soft delete)

**MUST FOLLOW**: 
- Hash password before saving
- Handle unique constraint violation (duplicate email)

---

### 4. SignUpDto Validation

**Location**: [src/auth/dto/sign-up.dto.ts](src/auth/dto/sign-up.dto.ts)

**Pattern**:
```typescript
export class SignUpDto {
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(MIN_PASSWORD_LENGTH)  // 8
  @MaxLength(MAX_PASSWORD_LENGTH)  // 32
  password: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(MIN_PASSWORD_LENGTH)
  @MaxLength(MAX_PASSWORD_LENGTH)
  @ValidateIf((object, value) => value === object.password)
  confirmPassword: string;
}
```

**MUST FOLLOW**:
- Password constraints: 8-32 characters
- DTO validates confirmPassword matches password
- Use class-validator decorators

**⚠️ Issue Noted**: `@ValidateIf` condition appears incorrect. Should use custom validator like `@Match('password')` or manual validation.

---

### 5. Auth Constants

**Location**: [src/common/constants/auth.constant.ts](src/common/constants/auth.constant.ts)

**Values**:
```typescript
export const MIN_PASSWORD_LENGTH = 8;
export const MAX_PASSWORD_LENGTH = 32;
```

**MUST FOLLOW**: Use these constants for password validation

---

### 6. Module Structure Pattern

**Location**: [src/app.module.ts](src/app.module.ts), [src/core/core.module.ts](src/core/core.module.ts)

**Pattern**:
```typescript
@Module({
  imports: [CoreModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
```

**Integration Point**: 
- AuthModule should be imported in AppModule
- AuthModule should import TypeOrmModule.forFeature([User])

---

### 7. Database Configuration

**Location**: [src/core/database/database.module.ts](src/core/database/database.module.ts)

**Pattern**:
```typescript
TypeOrmModule.forRootAsync({
  inject: [ConfigService],
  useFactory: (config: ConfigService) => ({
    type: config.get<any>('DB_TYPE'),
    host: config.get<string>('DB_HOST'),
    // ... other config
    entities: [User],
    autoLoadEntities: true,
  }),
})
```

**MUST FOLLOW**:
- New entities added automatically via `autoLoadEntities: true`
- User entity already registered

---

### 8. Path Aliases

**Location**: [tsconfig.json](tsconfig.json)

**Aliases**:
```json
{
  "paths": {
    "@/*": ["src/*"],
    "@core/*": ["src/core/*"]
  }
}
```

**MUST FOLLOW**:
- Use `@/` for src imports (e.g., `@/entities/User`)
- Use `@core/` for core imports (e.g., `@core/database/database.module`)

---

### 9. Installed Dependencies

**Location**: [package.json](package.json)

**Relevant Dependencies**:
| Package | Version | Purpose |
|---------|---------|---------|
| `@nestjs/testing` | ^11.0.1 | Testing utilities |
| `bcrypt` | ^6.0.0 | Password hashing |
| `class-validator` | ^0.14.3 | DTO validation |
| `class-transformer` | ^0.5.1 | DTO transformation |
| `jest` | ^30.0.0 | Test framework |
| `supertest` | ^7.0.0 | E2E HTTP testing |
| `@types/bcrypt` | ^6.0.0 | Bcrypt types |
| `typeorm` | ^0.3.28 | ORM |
| `@nestjs/typeorm` | ^11.0.0 | NestJS TypeORM integration |

**All required packages are already installed** ✅

---

### 10. Missing Files (To Be Created)

| File | Purpose | Status |
|------|---------|--------|
| `src/auth/auth.module.ts` | Auth module definition | ❌ Missing |
| `src/auth/auth.service.ts` | Auth business logic | ❌ Missing |
| `src/auth/auth.controller.ts` | Auth API endpoints | ❌ Missing |
| `test/auth.e2e-spec.ts` | Auth E2E tests | ❌ Missing |

---

## Code Patterns Identified

| Pattern | Example Location | MUST FOLLOW |
|---------|------------------|-------------|
| Unit test structure | `src/app.controller.spec.ts` | Use `Test.createTestingModule()` |
| E2E test structure | `test/app.e2e-spec.ts` | Use `supertest` with `app.getHttpServer()` |
| Entity with soft delete | `src/entities/Base.ts` | Extend Base for new entities |
| Module imports | `src/app.module.ts` | Import modules in AppModule |
| Path aliases | `tsconfig.json` | Use `@/` and `@core/` prefixes |
| DTO validation | `src/auth/dto/sign-up.dto.ts` | Use class-validator decorators |

---

## Integration Points

### Where to Add New Code

1. **AuthModule** → Create at `src/auth/auth.module.ts`
   - Import `TypeOrmModule.forFeature([User])`
   - Register AuthService, AuthController

2. **AppModule** → Import AuthModule
   - Add `AuthModule` to imports array

3. **Auth E2E Tests** → Create at `test/auth.e2e-spec.ts`
   - Follow existing E2E pattern
   - Add ValidationPipe for DTO validation

---

## Recommendations

1. **Fix SignUpDto Validation**: Replace `@ValidateIf` with proper custom validator for password matching
2. **Add SALT_ROUNDS Constant**: Create constant for bcrypt salt rounds
3. **Enable Global ValidationPipe**: Add in main.ts for consistent validation
4. **Follow TDD**: Write tests in `auth.service.spec.ts` BEFORE implementing `auth.service.ts`

---

## ⚠️ Concerns

1. **Empty Test File**: `auth.service.spec.ts` has only a TODO comment
2. **Incorrect DTO Validation**: `@ValidateIf` in SignUpDto doesn't correctly validate password match
3. **No Global ValidationPipe**: main.ts doesn't set up global validation pipe (needed for E2E tests)
4. **Missing Auth Module Files**: No auth.module.ts, auth.service.ts, or auth.controller.ts exist yet

import { HttpException } from '@nestjs/common';

export async function expectExceptionWithCode(
  promise: Promise<unknown>,
  exceptionType: new (...args: any[]) => Error,
  expectedErrorCode: string,
) {
  try {
    await promise;
    fail('Expected exception to be thrown');
  } catch (error) {
    expect(error).toBeInstanceOf(exceptionType);

    if (error instanceof HttpException) {
      const response = error.getResponse();
      const errorCode =
        typeof response === 'object' && response !== null
          ? (response as { errorCode?: string }).errorCode
          : undefined;
      expect(errorCode).toBe(expectedErrorCode);
    }
  }
}

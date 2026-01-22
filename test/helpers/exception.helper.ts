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
    expect((error as any).getResponse?.()?.errorCode).toBe(expectedErrorCode);
  }
}

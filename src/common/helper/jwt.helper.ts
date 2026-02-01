export function convertExpiry(expiry: string): number {
  const timeValue = parseInt(expiry.slice(0, -1), 10);
  const timeUnit = expiry.slice(-1);

  switch (timeUnit) {
    case 's':
      return timeValue;
    case 'm':
      return timeValue * 60;
    case 'h':
      return timeValue * 3600;
    case 'd':
      return timeValue * 86400;
    default:
      throw new Error('Invalid expiry format');
  }
}
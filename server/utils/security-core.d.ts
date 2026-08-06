export function isValidDomainName(domain: string): boolean;
export function hostMatchesPattern(host: string, pattern: string): boolean;
export function originAllowed(
  origin: string | undefined,
  allowedOrigins: string[],
  opts?: { production?: boolean; allowDevLoopback?: boolean }
): boolean;

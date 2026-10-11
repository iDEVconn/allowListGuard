import { SetMetadata } from "@nestjs/common";

export const SKIP_IP_ALLOWLIST_KEY = "skipIpAllowlist";

/**
 * Exempts a route (or controller) from the guard. For callers whose IPs cannot
 * be pinned down and that authenticate by other means (e.g. provider webhooks
 * verified by an HMAC signature).
 */
export const SkipIpAllowlist = (): MethodDecorator & ClassDecorator =>
  SetMetadata(SKIP_IP_ALLOWLIST_KEY, true);

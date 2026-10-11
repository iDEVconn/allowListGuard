import {
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  type CanActivate,
  type ExecutionContext,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { isIP } from "node:net";
import { IP_ALLOWLIST_OPTIONS, type BlockReason, type IpAllowlistOptions } from "./options.js";
import { parseIpAllowlist, type IpMatcher } from "./ip-matcher.js";
import { SKIP_IP_ALLOWLIST_KEY } from "./skip-ip-allowlist.decorator.js";

// Default log line is rate-limited per IP; the map is bounded by evicting the OLDEST
// entry, so rotating through many IPs can never switch logging off.
const LOG_INTERVAL_MS = 60_000;
const MAX_TRACKED_IPS = 1000;

/**
 * Restricts routes by source IP. Reads `request.ip`, which Express/Fastify
 * resolve through their own `trust proxy` setting — configure it so `req.ip`
 * is the real client behind your proxy (see `buildTrustProxy` in the
 * `/fastify` entry). `X-Forwarded-For` is never read here.
 */
@Injectable()
export class IpAllowlistGuard implements CanActivate {
  private readonly logger = new Logger(IpAllowlistGuard.name);
  private readonly protectedMatcher: IpMatcher | null;
  private readonly publicMatcher: IpMatcher | null;
  private readonly denyMatcher: IpMatcher | null;
  private readonly publicKey: string;
  private readonly lastLogged = new Map<string, number>();

  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(IP_ALLOWLIST_OPTIONS) private readonly options: IpAllowlistOptions,
  ) {
    const parse = { allowLoopback: options.allowLoopback ?? true };
    this.protectedMatcher = parseIpAllowlist(options.protected, "protected", parse);
    this.publicMatcher = parseIpAllowlist(options.public, "public", parse);
    // The denylist never adds loopback implicitly: only what the operator lists.
    this.denyMatcher = parseIpAllowlist(options.deny, "deny", { allowLoopback: false });
    this.publicKey = options.publicMetadataKey ?? "isPublic";
  }

  canActivate(ctx: ExecutionContext): boolean {
    // Only microservice (RPC) traffic is exempt: it has no client IP and is internal
    // transport. Any other context type (graphql, ws, ...) is NOT skipped — it has no
    // resolvable `req.ip` here, so it is denied when an allowlist is enforced (fail closed).
    const type = ctx.getType<string>();
    if (type === "rpc") return true;
    if (!this.protectedMatcher && !this.publicMatcher && !this.denyMatcher) return true;

    const ip = type === "http" ? ctx.switchToHttp().getRequest<{ ip?: string }>().ip : undefined;

    // Denylist first, on every route (including @SkipIpAllowlist ones): it wins over any allow.
    if (this.denyMatcher?.(ip)) return this.reject(ip, "denied");

    if (!this.protectedMatcher && !this.publicMatcher) return true;
    const targets = [ctx.getHandler(), ctx.getClass()];
    if (this.reflector.getAllAndOverride<boolean>(SKIP_IP_ALLOWLIST_KEY, targets)) return true;

    const isPublic = this.reflector.getAllAndOverride<boolean>(this.publicKey, targets);
    const matcher = isPublic ? this.publicMatcher : this.protectedMatcher;
    if (!matcher) return true;
    if (matcher(ip)) return true;

    return this.reject(ip, "not_allowed");
  }

  private reject(ip: string | undefined, reason: BlockReason): never {
    this.notifyBlocked(ip, reason);
    throw new ForbiddenException("ip_not_allowed");
  }

  private notifyBlocked(ip: string | undefined, reason: BlockReason): void {
    this.options.onBlocked?.(ip, reason);

    // Never log attacker-controlled text: only a well-formed IP is echoed.
    const key = ip && isIP(ip) ? ip : "invalid";
    const logKey = `${reason}:${key}`;
    const now = Date.now();
    const last = this.lastLogged.get(logKey);
    if (last !== undefined && now - last < LOG_INTERVAL_MS) return;
    this.lastLogged.delete(logKey);
    this.lastLogged.set(logKey, now);
    if (this.lastLogged.size > MAX_TRACKED_IPS) {
      const oldest = this.lastLogged.keys().next().value;
      if (oldest !== undefined) this.lastLogged.delete(oldest);
    }
    if (!this.options.onBlocked) {
      this.logger.warn(
        reason === "denied"
          ? `Blocked request from denylisted IP ${key}`
          : `Blocked request from non-allowlisted IP ${key}`,
      );
    }
  }
}

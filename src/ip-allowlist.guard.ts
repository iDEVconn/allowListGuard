import {
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  type CanActivate,
  type ExecutionContext,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { IP_ALLOWLIST_OPTIONS, type IpAllowlistOptions } from "./options.js";
import { parseIpAllowlist, type IpMatcher } from "./ip-matcher.js";
import { SKIP_IP_ALLOWLIST_KEY } from "./skip-ip-allowlist.decorator.js";

const MAX_LOGGED_IPS = 1000;

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
  private readonly publicKey: string;
  private readonly loggedIps = new Set<string>();

  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(IP_ALLOWLIST_OPTIONS) private readonly options: IpAllowlistOptions,
  ) {
    this.protectedMatcher = parseIpAllowlist(options.protected, "protected");
    this.publicMatcher = parseIpAllowlist(options.public, "public");
    this.publicKey = options.publicMetadataKey ?? "isPublic";
  }

  canActivate(ctx: ExecutionContext): boolean {
    if (ctx.getType() !== "http") return true;
    if (!this.protectedMatcher && !this.publicMatcher) return true;

    const targets = [ctx.getHandler(), ctx.getClass()];
    if (this.reflector.getAllAndOverride<boolean>(SKIP_IP_ALLOWLIST_KEY, targets)) return true;

    const isPublic = this.reflector.getAllAndOverride<boolean>(this.publicKey, targets);
    const matcher = isPublic ? this.publicMatcher : this.protectedMatcher;
    if (!matcher) return true;

    const { ip } = ctx.switchToHttp().getRequest<{ ip?: string }>();
    if (matcher(ip)) return true;

    this.notifyBlocked(ip);
    throw new ForbiddenException("ip_not_allowed");
  }

  private notifyBlocked(ip: string | undefined): void {
    const key = ip ?? "unknown";
    // One report per distinct IP (bounded) — a scanner must not flood the log.
    if (this.loggedIps.has(key) || this.loggedIps.size >= MAX_LOGGED_IPS) return;
    this.loggedIps.add(key);
    if (this.options.onBlocked) this.options.onBlocked(ip);
    else this.logger.warn(`Blocked request from non-allowlisted IP ${key}`);
  }
}

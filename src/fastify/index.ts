import { parseIpAllowlist, type IpMatcher } from "../ip-matcher.js";

/**
 * Fastify `trustProxy` function equal to Express's `trust proxy = 1`: trusts
 * only hop 0 (the socket peer, i.e. your reverse proxy), so a client cannot
 * walk past it with extra X-Forwarded-For entries.
 *
 * Hop 0 is the socket peer itself: if the app port is reachable directly (not
 * only through the proxy), ANY client is hop 0 and can forge X-Forwarded-For,
 * defeating the allowlist. Pass `trustedProxies` (IPs/CIDRs of your proxy) to
 * trust hop 0 only when the peer is one of them; a direct client's header is
 * then ignored. Loopback is always included.
 */
export function buildTrustProxy(
  trustedProxies?: string | readonly string[],
): (address: string, hop: number) => boolean {
  const matcher = parseIpAllowlist(trustedProxies, "trustedProxies");
  return (address, hop) => hop === 0 && (!matcher || matcher(address));
}

/**
 * Structural slice of a Fastify instance — deliberately not `FastifyInstance`, so
 * it type-checks even when the app and `@nestjs/platform-fastify` resolve two
 * different copies of `fastify`.
 */
export interface FastifyHookHost {
  addHook(
    name: "onRequest",
    hook: (
      req: { ip: string; routeOptions?: { url?: string } },
      reply: { code(statusCode: number): { send(payload: unknown): unknown } },
      done: () => void,
    ) => void,
  ): unknown;
}

/**
 * Restricts Fastify-native routes that live outside Nest's guard pipeline
 * (e.g. Swagger UI under `/api/docs`) with the same allowlist. Register BEFORE
 * those routes are added.
 *
 * Matches on the ROUTE Fastify resolved (`routeOptions.url`), not the raw
 * `req.url`: Fastify percent-decodes the path before routing, so `/api/%64ocs`
 * reaches the docs handler while `req.url.startsWith('/api/docs')` is false.
 */
export function restrictRoutesToAllowlist(
  instance: FastifyHookHost,
  allowed: IpMatcher,
  routePrefix: string,
): void {
  instance.addHook("onRequest", (req, reply, done) => {
    const route = req.routeOptions?.url ?? "";
    if (route.startsWith(routePrefix) && !allowed(req.ip)) {
      void reply.code(403).send({ statusCode: 403, message: "ip_not_allowed" });
      return;
    }
    done();
  });
}

export { parseIpAllowlist, type IpMatcher } from "../ip-matcher.js";

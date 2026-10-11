# @idevconn/allowlist-guard

Global NestJS guard that restricts routes by **source IP / CIDR**. Two independent allowlists: one for protected (authenticated) routes, one for public ("open") routes. Works on Fastify and Express. No runtime dependencies (uses `node:net` `BlockList`).

## Features

- IPv4 + IPv6, single addresses and CIDR ranges; IPv4-mapped IPv6 (`::ffff:1.2.3.4`) is normalised.
- Separate lists for `protected` and `public` routes. A list that is unset/blank is **not enforced**, so adopting the guard is non-breaking.
- Loopback (`127.0.0.0/8`, `::1`) is allowed once a list is set (local dev, health probes) — disable with `allowLoopback: false` (see below).
- `@SkipIpAllowlist()` exempts a route or controller (e.g. HMAC-signed provider webhooks whose IPs you cannot pin).
- A malformed entry throws at boot naming the option — a typo never silently becomes "everyone allowed" or "everyone blocked".
- Rejects with `403 ip_not_allowed`. Default log line is rate-limited per IP (1/min, bounded memory, never echoes malformed input); `onBlocked` is called on **every** blocked request for metrics/alerting.
- Fails closed: only microservice (`rpc`) contexts are exempt; other non-HTTP contexts (GraphQL, WebSocket) have no resolvable `req.ip` and are denied while a list is enforced.
- `/fastify` subpath: `buildTrustProxy` and `restrictRoutesToAllowlist` (for routes outside Nest's guard pipeline, e.g. Swagger UI).

## Install

```bash
npm install @idevconn/allowlist-guard
```

Peer dependencies: `@nestjs/common`, `@nestjs/core` (10 or 11), `reflect-metadata`, `rxjs`; `fastify` only if you use the `/fastify` subpath.

## Usage

```ts
import { Module } from "@nestjs/common";
import { IpAllowlistModule } from "@idevconn/allowlist-guard";

@Module({
  imports: [
    // Import BEFORE the module that registers your auth guard, so a blocked IP
    // is rejected before any authentication work.
    IpAllowlistModule.forRoot({
      protected: process.env.API_IP_ALLOWLIST, // "203.0.113.5, 10.0.0.0/8"
      public: process.env.API_PUBLIC_IP_ALLOWLIST, // login, lead capture, ...
    }),
    AuthModule,
  ],
})
export class AppModule {}
```

| Option              | Meaning                                                                                              |
| ------------------- | ---------------------------------------------------------------------------------------------------- |
| `protected`         | Comma-separated string or array of IPs/CIDRs for non-public routes. Unset/blank = not enforced.      |
| `public`            | Same, for public routes.                                                                             |
| `publicMetadataKey` | Metadata key marking a route public. Default `'isPublic'` (the common `@Public()` decorator's key).  |
| `allowLoopback`     | Default `true`. Set `false` if a reverse proxy runs on the same host (see below).                    |
| `onBlocked`         | `(ip) => void`, called on every blocked request. Default: a rate-limited Nest `Logger.warn`.         |

**The two lists are independent.** Setting only `protected` leaves `@Public` routes (login, lead capture, ...) open to everyone, and vice versa. Set both if you want the whole surface restricted; exempt individual routes with `@SkipIpAllowlist()`.

Exempt a route:

```ts
import { SkipIpAllowlist } from "@idevconn/allowlist-guard";

@Public()
@SkipIpAllowlist() // authenticated by an HMAC signature instead
@Post("webhooks/:provider")
receive() {}
```

## Getting the real client IP (read this)

The guard reads `request.ip` and **never** parses `X-Forwarded-For` itself. Behind a reverse proxy/load balancer, configure your framework's trust-proxy setting so `req.ip` is the real client:

- **Express:** `app.set("trust proxy", 1)`.
- **Fastify:**

  ```ts
  import { buildTrustProxy } from "@idevconn/allowlist-guard/fastify";

  new FastifyAdapter({ trustProxy: buildTrustProxy(process.env.TRUSTED_PROXIES) });
  ```

  `buildTrustProxy()` trusts one hop. Hop 0 is the socket peer, so **if the app port is reachable directly, any client can forge `X-Forwarded-For` and pass the allowlist**. Either make the port reachable only via your proxy, or pass `trustedProxies` (the proxy's IP/CIDR) so a direct client's header is ignored.

Without any trust-proxy setting `req.ip` is the proxy's own address for every client. If that proxy runs on the **same host**, that address is loopback — which is allowed by default, so the allowlist would be wide open. Set `allowLoopback: false` in that setup (and keep trust-proxy configured).

## Routes outside Nest (Swagger UI)

Fastify-native routes never reach Nest guards. Restrict them with the same list, **before** registering them:

```ts
import { parseIpAllowlist, restrictRoutesToAllowlist } from "@idevconn/allowlist-guard/fastify";

const allowed = parseIpAllowlist(process.env.API_IP_ALLOWLIST);
if (allowed) restrictRoutesToAllowlist(app.getHttpAdapter().getInstance(), allowed, "/api/docs");
SwaggerModule.setup("api/docs", app, document);
```

It matches on the resolved route (`routeOptions.url`), not the raw URL, so percent-encoded paths such as `/api/%64ocs` cannot slip past.

## Limits

An IP allowlist only helps when your legitimate clients have known IPs. It cannot tell a browser from Postman/Playwright on the same IP — use authentication, rate limiting and bot protection for open APIs.

## License

Apache-2.0

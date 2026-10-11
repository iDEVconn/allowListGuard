# @idevconn/allowlist-guard

Global NestJS guard that restricts routes by **source IP / CIDR**. Two independent allowlists (one for protected/authenticated routes, one for public/"open" routes) plus a global **denylist** to block specific addresses. Works on Fastify and Express. No runtime dependencies (uses `node:net` `BlockList`).

> [!IMPORTANT]
> **What this guard does NOT protect against.**
> It decides by the caller's **IP address only**. It does **not** stop Postman, curl, scripts or Playwright/Puppeteer **coming from an allowed IP** — to the server those requests look exactly like your own front end:
>
> - `Origin`, `Referer`, `User-Agent` and `Sec-Fetch-*` headers are trivially forged by Postman/curl, so header checks give no protection.
> - Playwright/Puppeteer drive a real Chromium; headers and fingerprint are indistinguishable from a human's browser.
> - A secret embedded in a front-end bundle (API key, HMAC) is extractable in a minute.
> - Anyone with a valid login can replay requests from a script.
>
> The allowlist only helps when your legitimate clients have **known, stable IPs** (office, VPN, your own servers): a request from anywhere else gets `403`. For an **open** API (any user from the internet) an IP list is the wrong tool — use authentication, per-account rate limits and quotas, CAPTCHA / bot protection at the edge (e.g. Cloudflare Turnstile / Bot Management), and registration controls. The denylist is not a substitute either: banned clients just change address. Treat this guard as an outer perimeter, not as bot protection.

## Features

- IPv4 + IPv6, single addresses and CIDR ranges; IPv4-mapped IPv6 (`::ffff:1.2.3.4`) is normalised.
- **Allow** (`protected`, `public`) and **deny** (`deny`) lists: "only these", "everyone except these", or both. Deny always wins.
- Separate allowlists for `protected` and `public` routes. A list that is unset/blank is **not enforced**, so adopting the guard is non-breaking.
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

Peer dependencies: `@nestjs/common`, `@nestjs/core` (10 or 11), `reflect-metadata`, `rxjs`. The `/fastify` subpath has no `fastify` dependency (it is typed structurally).

## Usage

### Minimal (NestJS on Express, the default adapter)

```ts
// app.module.ts
import { Module } from "@nestjs/common";
import { IpAllowlistModule } from "@idevconn/allowlist-guard";
import { AuthModule } from "./auth/auth.module";

@Module({
  imports: [
    // Import BEFORE the module that registers your auth guard, so a blocked IP
    // is rejected before any authentication work.
    IpAllowlistModule.forRoot({
      protected: "203.0.113.5, 10.0.0.0/8, 2001:db8::/32", // authenticated routes
      public: "198.51.100.0/24", // @Public routes: login, lead capture, ...
    }),
    AuthModule,
  ],
})
export class AppModule {}
```

```ts
// main.ts
import { NestFactory } from "@nestjs/core";
import type { NestExpressApplication } from "@nestjs/platform-express";
import { AppModule } from "./app.module";

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  app.set("trust proxy", 1); // behind ONE reverse proxy; see "Getting the real client IP"
  await app.listen(3000);
}
bootstrap();
```

### Options

| Option              | Meaning                                                                                              |
| ------------------- | ---------------------------------------------------------------------------------------------------- |
| `protected`         | Comma-separated string or array of IPs/CIDRs for non-public routes. Unset/blank = not enforced.      |
| `public`            | Same, for public routes.                                                                             |
| `deny`              | Denylist for **all** routes: comma-separated string or array of IPs/CIDRs that are always rejected. Wins over the allowlists. Unset/blank = nothing denied. |
| `publicMetadataKey` | Metadata key marking a route public. Default `'isPublic'` (the common `@Public()` decorator's key).  |
| `allowLoopback`     | Default `true`. Set `false` if a reverse proxy runs on the same host (see below).                    |
| `onBlocked`         | `(ip, reason) => void`, called on every blocked request; `reason` is `"denied"` or `"not_allowed"`. Default: a rate-limited Nest `Logger.warn`. |

**The two lists are independent.** Setting only `protected` leaves `@Public` routes (login, lead capture, ...) open to everyone, and vice versa. Set both if you want the whole surface restricted; exempt individual routes with `@SkipIpAllowlist()`.

### Configuration from the environment (`@nestjs/config`)

`forRoot()` takes plain values, so read them from `process.env`. `ConfigModule.forRoot()` loads `.env` synchronously, so list it **before** the allowlist module:

```ts
@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    IpAllowlistModule.forRoot({
      protected: process.env.API_IP_ALLOWLIST, // unset/blank => not enforced
      public: process.env.API_PUBLIC_IP_ALLOWLIST,
      allowLoopback: process.env.API_IP_ALLOWLIST_ALLOW_LOOPBACK !== "false",
    }),
    AuthModule,
  ],
})
export class AppModule {}
```

```bash
# .env
API_IP_ALLOWLIST=203.0.113.5,10.0.0.0/8
API_PUBLIC_IP_ALLOWLIST=198.51.100.0/24
```

A malformed entry (`API_IP_ALLOWLIST=203.0.113.5,banana`) throws at boot naming the option, so a typo never silently opens or closes the API.

### NestJS on Fastify

```ts
// main.ts
import { NestFactory } from "@nestjs/core";
import { FastifyAdapter, type NestFastifyApplication } from "@nestjs/platform-fastify";
import { DocumentBuilder, SwaggerModule } from "@nestjs/swagger";
import { buildTrustProxy, parseIpAllowlist, restrictRoutesToAllowlist } from "@idevconn/allowlist-guard/fastify";
import { AppModule } from "./app.module";

async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({
      // One trusted hop, and only when the socket peer is one of YOUR proxies.
      trustProxy: buildTrustProxy(process.env.TRUSTED_PROXIES),
    }),
  );

  // Swagger UI is a Fastify route outside Nest's guard pipeline: restrict it too,
  // BEFORE SwaggerModule.setup registers it.
  const allowed = parseIpAllowlist(process.env.API_IP_ALLOWLIST);
  const denied = parseIpAllowlist(process.env.API_IP_DENYLIST, "deny", { allowLoopback: false });
  if (allowed || denied) {
    restrictRoutesToAllowlist(app.getHttpAdapter().getInstance(), allowed, "/api/docs", denied);
  }
  const document = SwaggerModule.createDocument(app, new DocumentBuilder().build());
  SwaggerModule.setup("api/docs", app, document);

  await app.listen(3000, "0.0.0.0");
}
bootstrap();
```

### What gets blocked: allow vs deny

| Configured                               | Result                                                                                         |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------- |
| nothing                                  | Guard off: everyone is let in (today's behaviour).                                             |
| `deny` only                              | **Everyone except the listed IPs/CIDRs** ("block these, allow the rest").                      |
| `protected` and/or `public` only         | **Only the listed IPs**, per route class (the other class stays open).                         |
| allowlist(s) + `deny`                    | Allowed IPs get in, **except** any that are also denied. Deny always wins.                     |

Order of checks per request: RPC contexts are exempt → **`deny`** (every route, including `@SkipIpAllowlist` ones) → `@SkipIpAllowlist()` → the route's allowlist (`public` for public routes, otherwise `protected`).

### Blocking specific IPs (denylist)

Let everyone in, but reject some addresses:

```ts
IpAllowlistModule.forRoot({
  // IPs and CIDRs (IPv4 + IPv6), comma-separated string or array.
  deny: "203.0.113.5, 198.51.100.0/24, 2001:db8::/32",
});
```

Combine with an allowlist — e.g. a whole office range except one compromised host:

```ts
IpAllowlistModule.forRoot({
  protected: "10.0.0.0/8",
  deny: ["10.1.2.3"], // inside the allowed range, still blocked
});
```

From the environment:

```ts
IpAllowlistModule.forRoot({
  protected: process.env.API_IP_ALLOWLIST,
  public: process.env.API_PUBLIC_IP_ALLOWLIST,
  deny: process.env.API_IP_DENYLIST, // "203.0.113.5,198.51.100.0/24"
});
```

Notes:

- `deny` applies to **every** route, including ones marked `@SkipIpAllowlist()` (e.g. webhooks): a banned address is banned everywhere. Be careful not to list a range your providers call from.
- Loopback is **never** denied implicitly (only if you list it). It is also not allowed implicitly by `deny` alone, because without an allowlist everything not denied is allowed anyway.
- A malformed entry throws at boot (`deny: invalid IP/CIDR "banana"`), so a typo never silently disables the ban.
- Identify why a request was blocked in `onBlocked((ip, reason) => ...)`: `"denied"` vs `"not_allowed"`. The default log line differs too (`denylisted IP` / `non-allowlisted IP`).
- Both outcomes return the same `403 ip_not_allowed`.
- Without an allowlist the guard can only judge requests that carry a client IP (HTTP). Non-HTTP contexts such as GraphQL/WebSocket have no resolvable `req.ip` here, so a deny-only setup cannot ban them (with an allowlist they are denied, fail closed).

**Limits of IP bans.** An address changes with a VPN, proxy or mobile network, and a ban on a shared address (office, carrier NAT) blocks everyone behind it. To stop a specific *person*, suspend their account; use the denylist for abusive addresses, scanners and floods. For permanent, high-volume blocking prefer the edge (nginx `deny`, Cloudflare WAF, firewall), which stops traffic before it reaches your app.

### Exempting routes

```ts
import { Controller, Post, SetMetadata } from "@nestjs/common";
import { SkipIpAllowlist } from "@idevconn/allowlist-guard";

const Public = () => SetMetadata("isPublic", true); // your existing @Public()

@Controller("webhooks")
export class WebhooksController {
  // Providers call from IPs you cannot pin; authenticate by HMAC signature instead.
  @Public()
  @SkipIpAllowlist()
  @Post(":provider")
  receive() {}
}
```

`@SkipIpAllowlist()` also works on a whole controller class (e.g. a health check controller). It exempts a route from the **allowlists only**; the `deny` list still applies.

### Using your own "public" decorator

If your project marks open routes with a different metadata key, tell the guard:

```ts
export const OPEN_ROUTE = "openRoute";
export const Open = () => SetMetadata(OPEN_ROUTE, true);

IpAllowlistModule.forRoot({ public: "198.51.100.0/24", publicMetadataKey: OPEN_ROUTE });
```

### Alerting on blocked requests

`onBlocked` runs on **every** blocked request (the default log line is rate-limited to one per IP per minute), so feed metrics from it:

```ts
IpAllowlistModule.forRoot({
  protected: process.env.API_IP_ALLOWLIST,
  onBlocked: (ip, reason) =>
    metrics.increment("ip_allowlist.blocked", { ip: ip ?? "unknown", reason }), // "denied" | "not_allowed"
});
```

### Using the matcher on its own

```ts
import { parseIpAllowlist } from "@idevconn/allowlist-guard";

const isAllowed = parseIpAllowlist("203.0.113.5, 10.0.0.0/8", "myList");
isAllowed?.("10.4.5.6"); // true  (returns null when the list is blank = not enforced)
isAllowed?.("::ffff:203.0.113.5"); // true  (IPv4-mapped IPv6 is normalised)
isAllowed?.("8.8.8.8"); // false

// A denylist matcher: no implicit loopback.
const isBanned = parseIpAllowlist("203.0.113.5", "deny", { allowLoopback: false });
isBanned?.("203.0.113.5"); // true
```

### Local development and tests

Leave the lists (`protected`, `public`, `deny`) unset: nothing is enforced, so `localhost`, Postman and e2e tests work as usual. With a list set, loopback (`127.0.0.1`, `::1`) is still allowed unless `allowLoopback: false`. In e2e tests either leave the lists unset or set `protected` to a test IP and send requests from it (Fastify `app.inject({ remoteAddress })`; Express with `trust proxy` + `X-Forwarded-For`).

## Getting the real client IP (read this)

The guard reads `request.ip` and **never** parses `X-Forwarded-For` itself. Behind a reverse proxy/load balancer, configure your framework's trust-proxy setting so `req.ip` is the real client:

- **Express:** `app.set("trust proxy", 1)` (one proxy in front).
- **Fastify:** `buildTrustProxy(...)` from `@idevconn/allowlist-guard/fastify` (see the Fastify example above). It trusts one hop. Hop 0 is the socket peer, so **if the app port is reachable directly, any client can forge `X-Forwarded-For` and pass the allowlist**. Either make the port reachable only via your proxy, or pass `trustedProxies` (the proxy's IP/CIDR) so a direct client's header is ignored.

Make the proxy **overwrite** the header with the address it saw, not append to a client-supplied one. nginx:

```nginx
location /api/ {
  proxy_pass http://127.0.0.1:3000;
  proxy_set_header X-Forwarded-For $remote_addr;   # overwrite, do not use $proxy_add_x_forwarded_for
}
```

Without any trust-proxy setting `req.ip` is the proxy's own address for every client. If that proxy runs on the **same host**, that address is loopback — which is allowed by default, so the allowlist would be wide open. Set `allowLoopback: false` in that setup (and keep trust-proxy configured). Behind a CDN (e.g. Cloudflare) the proxy chain has two hops; configure the trusted hop count/CIDRs of your CDN accordingly rather than trusting arbitrary headers.

## Routes outside Nest (Swagger UI)

Fastify-native routes never reach Nest guards; `restrictRoutesToAllowlist(instance, allowed, routePrefix, denied?)` (see the Fastify example) applies the same lists to them. Pass `null` as `allowed` to use only a denylist. It matches on the resolved route (`routeOptions.url`), not the raw URL, so percent-encoded paths such as `/api/%64ocs` cannot slip past.

## Limits

See the notice at the top: an IP allowlist is a network perimeter, not bot protection. It cannot tell a browser from Postman or Playwright on the same IP.

## License

Apache-2.0

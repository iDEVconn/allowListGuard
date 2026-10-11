---
"@idevconn/allowlist-guard": minor
---

Initial release: global `IpAllowlistGuard` (`IpAllowlistModule.forRoot`) with separate protected/public IP allowlists, `@SkipIpAllowlist()`, IPv4/IPv6 + CIDR matching, an `allowLoopback` switch, a rate-limited default log plus an every-block `onBlocked` hook, fail-closed handling of non-HTTP contexts, and a `/fastify` subpath with `buildTrustProxy` and `restrictRoutesToAllowlist`.

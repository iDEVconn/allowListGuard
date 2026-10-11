---
"@idevconn/allowlist-guard": minor
---

Initial release: global `IpAllowlistGuard` (`IpAllowlistModule.forRoot`) with separate protected/public IP allowlists, `@SkipIpAllowlist()`, IPv4/IPv6 + CIDR matching, and a `/fastify` subpath with `buildTrustProxy` and `restrictRoutesToAllowlist`.

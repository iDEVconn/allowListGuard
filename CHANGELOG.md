# @idevconn/allowlist-guard

## 0.2.0

### Minor Changes

- 4c6c379: Add a global `deny` option (denylist): block specific IPs/CIDRs on every route and let everyone else in (deny alone), or combine it with the allowlists to carve exceptions out of an allowed range. Deny always wins and also applies to `@SkipIpAllowlist()` routes. `onBlocked` now receives a second `reason` argument (`"denied" | "not_allowed"`) and the default log line distinguishes the two. `restrictRoutesToAllowlist` takes an optional `denied` matcher and accepts `null` as `allowed`. New exported type `BlockReason`.

## 0.1.0

### Minor Changes

- 00cac13: Initial release: global `IpAllowlistGuard` (`IpAllowlistModule.forRoot`) with separate protected/public IP allowlists, `@SkipIpAllowlist()`, IPv4/IPv6 + CIDR matching, an `allowLoopback` switch, a rate-limited default log plus an every-block `onBlocked` hook, fail-closed handling of non-HTTP contexts, and a `/fastify` subpath with `buildTrustProxy` and `restrictRoutesToAllowlist`.

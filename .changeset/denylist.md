---
"@idevconn/allowlist-guard": minor
---

Add a global `deny` option (denylist): block specific IPs/CIDRs on every route and let everyone else in (deny alone), or combine it with the allowlists to carve exceptions out of an allowed range. Deny always wins and also applies to `@SkipIpAllowlist()` routes. `onBlocked` now receives a second `reason` argument (`"denied" | "not_allowed"`) and the default log line distinguishes the two. `restrictRoutesToAllowlist` takes an optional `denied` matcher and accepts `null` as `allowed`. New exported type `BlockReason`.
